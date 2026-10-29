//! The full-screen menu: `unbihex-cli` started in a terminal without a command,
//! or `unbihex-cli tui`. Servers with their ping, the connection, live speed and
//! the log on one screen, driven by keys. The engine runs in this process, so
//! quitting the menu disconnects.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use ratatui::crossterm::execute;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Clear, Paragraph, Row, Sparkline, Table, TableState};
use ratatui::{DefaultTerminal, Frame};
use tokio::sync::mpsc;
use unbihex_client_core::model::now_secs;
use unbihex_client_core::{AppData, Client, PingResult, ProxyMode, RoutingMode, Server, Status};
use uuid::Uuid;

/// Lines kept for the log pane.
const LOG_LINES: usize = 300;
/// Seconds of speed history kept for the graphs.
const HISTORY: usize = 300;

/// Log lines shared by `tracing` and the log pane.
#[derive(Clone, Default)]
pub struct LogBuffer(Arc<Mutex<VecDeque<String>>>);

impl LogBuffer {
    fn push(&self, line: String) {
        let mut q = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() == LOG_LINES {
            q.pop_front();
        }
        q.push_back(line);
    }

    /// The last `n` lines, oldest first.
    fn tail(&self, n: usize) -> Vec<String> {
        let q = self.0.lock().unwrap_or_else(|e| e.into_inner());
        q.iter().skip(q.len().saturating_sub(n)).cloned().collect()
    }
}

/// A `tracing` writer for one event: its text goes to the buffer line by line
/// when the event is written out.
pub struct LogWriter {
    buf: LogBuffer,
    pending: Vec<u8>,
}

impl Write for LogWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.pending.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for LogWriter {
    fn drop(&mut self) {
        for line in String::from_utf8_lossy(&self.pending).lines() {
            if !line.trim().is_empty() {
                self.buf.push(line.to_owned());
            }
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> LogWriter {
        LogWriter {
            buf: self.clone(),
            pending: Vec::new(),
        }
    }
}

/// What background jobs report back to the screen.
enum Msg {
    /// A job finished; the text goes to the status line and the log.
    Done(String),
    /// A job is still running; the text replaces the status line.
    Progress(String),
    /// One server's ping, as soon as it is known.
    Pinged(PingResult),
}

struct App {
    client: Arc<Client>,
    logs: LogBuffer,
    tx: mpsc::UnboundedSender<Msg>,
    data: AppData,
    status: Status,
    table: TableState,
    /// The running job, if any: one at a time.
    busy: Option<String>,
    /// The last message for the status line.
    note: String,
    /// The "add" prompt while it is open.
    input: Option<String>,
    /// Ping results of the running ping, before they are saved.
    live: HashMap<Uuid, PingResult>,
    down: VecDeque<u64>,
    up: VecDeque<u64>,
    last: Option<(Instant, u64, u64)>,
    quit: bool,
}

/// Runs the menu until the user quits; the terminal is restored afterwards.
pub fn run(runtime: &tokio::runtime::Runtime, client: Client, logs: LogBuffer) -> Result<(), String> {
    let mut terminal = ratatui::try_init().map_err(|e| format!("terminal: {e}"))?;
    let _ = execute!(std::io::stdout(), EnableBracketedPaste);
    let result = runtime.block_on(main_loop(&mut terminal, Arc::new(client), logs));
    let _ = execute!(std::io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    result
}

async fn main_loop(
    terminal: &mut DefaultTerminal,
    client: Arc<Client>,
    logs: LogBuffer,
) -> Result<(), String> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (key_tx, mut keys) = mpsc::unbounded_channel();
    // crossterm reads block; the thread ends with the process.
    std::thread::spawn(move || {
        while let Ok(ev) = event::read() {
            if key_tx.send(ev).is_err() {
                break;
            }
        }
    });

    // A fresh install starts in system-proxy mode, which needs a desktop (as `connect`).
    let mut settings = client.settings();
    if settings.mode == ProxyMode::SystemProxy {
        settings.mode = ProxyMode::ProxyOnly;
        let _ = client.set_settings(settings);
    }
    let data = client.snapshot();
    let mut table = TableState::default();
    let start = data
        .selected
        .and_then(|id| data.servers.iter().position(|s| s.id == id))
        .unwrap_or(0);
    table.select((!data.servers.is_empty()).then_some(start));
    let note = if data.servers.is_empty() {
        "нет серверов: нажмите a и вставьте ссылку на подписку".to_owned()
    } else {
        "Enter — подключиться к выделенному серверу".to_owned()
    };
    let mut app = App {
        client,
        logs,
        tx,
        data,
        status: Status::default(),
        table,
        busy: None,
        note,
        input: None,
        live: HashMap::new(),
        down: VecDeque::new(),
        up: VecDeque::new(),
        last: None,
        quit: false,
    };

    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut stop = std::pin::pin!(crate::stop_signal());
    while !app.quit {
        terminal.draw(|f| app.draw(f)).map_err(|e| e.to_string())?;
        tokio::select! {
            Some(ev) = keys.recv() => app.on_event(ev),
            Some(msg) = rx.recv() => app.on_msg(msg).await,
            _ = tick.tick() => app.on_tick().await,
            _ = &mut stop => app.quit = true,
        }
        app.data = app.client.snapshot();
        app.clamp_selection();
    }
    if app.client.status().await.connected {
        app.note = "отключаюсь…".into();
        let _ = terminal.draw(|f| app.draw(f));
        app.client.disconnect().await;
    }
    Ok(())
}

impl App {
    fn on_event(&mut self, ev: Event) {
        match ev {
            Event::Key(k) if k.kind != KeyEventKind::Release => self.on_key(k),
            Event::Paste(text) => {
                if let Some(buf) = &mut self.input {
                    buf.push_str(text.trim());
                }
            }
            _ => {}
        }
    }

    fn on_key(&mut self, k: KeyEvent) {
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if let Some(buf) = &mut self.input {
            match k.code {
                KeyCode::Esc => self.input = None,
                KeyCode::Enter => {
                    let text = buf.trim().to_owned();
                    self.input = None;
                    if !text.is_empty() {
                        self.add(text);
                    }
                }
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Char(c) => buf.push(c),
                _ => {}
            }
            return;
        }
        match k.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Up | KeyCode::Char('k') => self.move_by(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_by(1),
            KeyCode::PageUp => self.move_by(-10),
            KeyCode::PageDown => self.move_by(10),
            KeyCode::Home | KeyCode::Char('g') => self.table.select_first(),
            KeyCode::End | KeyCode::Char('G') => self.table.select_last(),
            KeyCode::Enter => self.toggle(),
            KeyCode::Char('d') => self.disconnect(),
            KeyCode::Char('p') => self.ping(),
            KeyCode::Char('u') => self.update(),
            KeyCode::Char('a') => self.input = Some(String::new()),
            KeyCode::Char('m') => self.next_mode(),
            KeyCode::Char('r') => self.next_routing(),
            _ => {}
        }
    }

    async fn on_msg(&mut self, msg: Msg) {
        match msg {
            Msg::Done(text) => {
                self.busy = None;
                self.live.clear();
                self.logs.push(text.clone());
                self.note = text;
                self.status = self.client.status().await;
            }
            Msg::Progress(text) => self.note = text,
            Msg::Pinged(r) => {
                self.live.insert(r.id, r);
            }
        }
    }

    /// Once a second: connection state and the speed graphs.
    async fn on_tick(&mut self) {
        self.status = self.client.status().await;
        let s = &self.status;
        let (down, up) = (s.proxy_down + s.direct_down, s.proxy_up + s.direct_up);
        let now = Instant::now();
        if let Some((at, d0, u0)) = self.last {
            let secs = now.duration_since(at).as_secs_f64().max(0.001);
            // Counters start over on reconnect: that second shows 0, not a jump.
            push(&mut self.down, (down.saturating_sub(d0) as f64 / secs) as u64);
            push(&mut self.up, (up.saturating_sub(u0) as f64 / secs) as u64);
        }
        self.last = Some((now, down, up));
    }

    fn clamp_selection(&mut self) {
        let n = self.data.servers.len();
        match self.table.selected() {
            _ if n == 0 => self.table.select(None),
            None => self.table.select(Some(0)),
            Some(i) if i >= n => self.table.select(Some(n - 1)),
            Some(_) => {}
        }
    }

    fn move_by(&mut self, delta: isize) {
        let n = self.data.servers.len();
        if n == 0 {
            return;
        }
        let i = self.table.selected().unwrap_or(0) as isize + delta;
        self.table.select(Some(i.clamp(0, n as isize - 1) as usize));
    }

    fn highlighted(&self) -> Option<Server> {
        self.table
            .selected()
            .and_then(|i| self.data.servers.get(i))
            .cloned()
    }

    fn connected_to(&self) -> Option<Uuid> {
        self.status.info.as_ref().map(|i| i.server_id)
    }

    /// Starts a background job unless one is already running.
    fn spawn(&mut self, label: &str, job: impl Future<Output = String> + Send + 'static) {
        if let Some(b) = &self.busy {
            self.note = format!("подождите: {b}");
            return;
        }
        self.busy = Some(label.to_owned());
        self.note = format!("{label}…");
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let text = job.await;
            let _ = tx.send(Msg::Done(text));
        });
    }

    /// Enter: disconnects from the connected server, otherwise connects to the
    /// highlighted one (switching on the fly when already connected).
    fn toggle(&mut self) {
        let Some(server) = self.highlighted() else {
            self.input = Some(String::new());
            return;
        };
        if self.status.connected && self.connected_to() == Some(server.id) {
            self.disconnect();
            return;
        }
        if let Some(why) = &server.unsupported {
            self.note = format!("{}: не поддерживается ({why})", server.name);
            return;
        }
        if self.ssh_tun_warning() {
            return;
        }
        let client = self.client.clone();
        let connected = self.status.connected;
        self.spawn("подключение", async move {
            if let Err(e) = client.select(server.id) {
                return format!("ошибка: {e}");
            }
            if connected {
                match client.reload().await {
                    Ok(Some(info)) => return format!("переключено: {}", info.server_name),
                    Ok(None) => {}
                    Err(e) => {
                        tracing::info!("switch on the fly failed ({e}), reconnecting");
                        client.disconnect().await;
                    }
                }
            }
            connect(&client).await
        });
    }

    fn disconnect(&mut self) {
        if !self.status.connected {
            self.note = "не подключено".into();
            return;
        }
        let client = self.client.clone();
        self.spawn("отключение", async move {
            client.disconnect().await;
            "отключено".to_owned()
        });
    }

    fn ping(&mut self) {
        let client = self.client.clone();
        let tx = self.tx.clone();
        let total = self.data.servers.len();
        self.spawn("пинг", async move {
            let done = Arc::new(AtomicUsize::new(0));
            let results = client
                .ping(&[], move |r| {
                    let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                    let _ = tx.send(Msg::Pinged(r));
                    let _ = tx.send(Msg::Progress(format!("пинг… {n}/{total}")));
                })
                .await;
            let ok = results.iter().filter(|r| r.ms.is_some()).count();
            format!("пинг: отвечают {ok} из {}", results.len())
        });
    }

    fn update(&mut self) {
        if self.data.subscriptions.is_empty() {
            self.note = "подписок нет: нажмите a и вставьте ссылку".into();
            return;
        }
        let client = self.client.clone();
        self.spawn("обновление подписок", async move {
            let results = client.update_all(true).await;
            let names: HashMap<Uuid, String> = client
                .snapshot()
                .subscriptions
                .into_iter()
                .map(|s| (s.id, s.name))
                .collect();
            let (mut ok, mut servers) = (0, 0);
            for (id, r) in results.iter() {
                let name = names.get(id).cloned().unwrap_or_else(|| id.to_string());
                match r {
                    Ok(n) => {
                        ok += 1;
                        servers += n;
                    }
                    Err(e) => tracing::warn!("{name}: {e}"),
                }
            }
            format!("подписки: обновлено {ok} из {}, серверов {servers}", results.len())
        });
    }

    fn add(&mut self, text: String) {
        let client = self.client.clone();
        self.spawn("добавление", async move {
            match client.add_input(&text).await {
                Ok(r) => {
                    for e in &r.errors {
                        tracing::warn!("{e}");
                    }
                    let mut msg = format!(
                        "добавлено: подписок {}, серверов {}",
                        r.subscriptions, r.servers
                    );
                    if !r.errors.is_empty() {
                        msg.push_str(&format!(", ошибок {} (в журнале)", r.errors.len()));
                    }
                    msg
                }
                Err(e) => format!("не добавлено: {e}"),
            }
        });
    }

    fn next_mode(&mut self) {
        if self.busy.is_some() {
            self.note = "подождите, идёт другое действие".into();
            return;
        }
        let mut s = self.client.settings();
        s.mode = match s.mode {
            ProxyMode::ProxyOnly => ProxyMode::Tun,
            ProxyMode::Tun => ProxyMode::SystemProxy,
            ProxyMode::SystemProxy => ProxyMode::ProxyOnly,
        };
        let mode = s.mode;
        if let Err(e) = self.client.set_settings(s) {
            self.note = format!("ошибка: {e}");
            return;
        }
        self.note = format!("режим: {}", mode_label(mode));
        if mode == ProxyMode::Tun && under_ssh() {
            self.note.push_str(" — по SSH он может оборвать сессию");
        }
        if self.status.connected {
            let client = self.client.clone();
            self.spawn("переподключение", async move {
                client.disconnect().await;
                connect(&client).await
            });
        }
    }

    fn next_routing(&mut self) {
        if self.busy.is_some() {
            self.note = "подождите, идёт другое действие".into();
            return;
        }
        let mut s = self.client.settings();
        s.routing = match s.routing {
            RoutingMode::Global => RoutingMode::BypassRu,
            RoutingMode::BypassRu => RoutingMode::OnlyListed,
            RoutingMode::OnlyListed => RoutingMode::BlockedOnly,
            RoutingMode::BlockedOnly => RoutingMode::Global,
        };
        let routing = s.routing;
        if let Err(e) = self.client.set_settings(s) {
            self.note = format!("ошибка: {e}");
            return;
        }
        self.note = format!("маршрутизация: {}", routing_label(routing));
        if self.status.connected {
            let client = self.client.clone();
            self.spawn("применение правил", async move {
                if let Some(Err(e)) = client.update_geodata_if_due().await {
                    tracing::warn!("rule databases: {e}");
                }
                match client.reload().await {
                    Ok(_) => format!("маршрутизация: {}", routing_label(routing)),
                    Err(e) => format!("ошибка: {e}"),
                }
            });
        }
    }

    /// The first Enter in TUN mode over SSH only warns; the second connects.
    fn ssh_tun_warning(&mut self) -> bool {
        let s = self.client.settings();
        let risky = !self.status.connected && s.mode == ProxyMode::Tun && s.tun_routes && under_ssh();
        let warned = self.note.starts_with("TUN по SSH");
        if risky && !warned {
            self.note =
                "TUN по SSH: весь трафик, включая SSH, уйдёт в туннель и сессия может оборваться. Enter ещё раз — подключить".into();
            return true;
        }
        false
    }

    fn draw(&mut self, f: &mut Frame) {
        let [top, middle, log, keys] = Layout::vertical([
            Constraint::Length(5),
            Constraint::Min(8),
            Constraint::Length(8),
            Constraint::Length(1),
        ])
        .areas(f.area());
        let [list, side] =
            Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)]).areas(middle);
        self.draw_status(f, top);
        self.draw_servers(f, list);
        self.draw_speed(f, side);
        self.draw_log(f, log);
        let help = Line::from(vec![
            key("↑↓"),
            Span::raw(" выбор  "),
            key("Enter"),
            Span::raw(" подкл./откл.  "),
            key("p"),
            Span::raw(" пинг  "),
            key("u"),
            Span::raw(" обновить  "),
            key("a"),
            Span::raw(" добавить  "),
            key("m"),
            Span::raw(" режим  "),
            key("r"),
            Span::raw(" маршруты  "),
            key("q"),
            Span::raw(" выход"),
        ]);
        f.render_widget(Paragraph::new(help), keys);
        if let Some(buf) = &self.input {
            draw_input(f, buf);
        }
    }

    fn draw_status(&self, f: &mut Frame, area: Rect) {
        let s = self.client.settings();
        let state = match &self.status.info {
            Some(info) if self.status.connected => Line::from(vec![
                Span::styled("● подключено ", Style::new().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::styled(info.server_name.clone(), Style::new().add_modifier(Modifier::BOLD)),
                Span::raw(format!("  {}", duration(now_secs().saturating_sub(info.since)))),
            ]),
            _ => Line::from(Span::styled("○ не подключено", Style::new().fg(Color::DarkGray))),
        };
        let host = if s.allow_lan { "0.0.0.0" } else { "127.0.0.1" };
        let mut ports = String::new();
        if let Some(info) = self.status.info.as_ref().filter(|_| self.status.connected) {
            if let Some(p) = info.socks_port {
                ports.push_str(&format!("  SOCKS5 {host}:{p}"));
            }
            if let Some(p) = info.http_port {
                ports.push_str(&format!("  HTTP {host}:{p}"));
            }
        }
        let settings = Line::from(vec![
            Span::styled("режим ", Style::new().fg(Color::DarkGray)),
            Span::raw(mode_label(s.mode)),
            Span::styled("  маршрутизация ", Style::new().fg(Color::DarkGray)),
            Span::raw(routing_label(s.routing)),
            Span::styled(ports, Style::new().fg(Color::Cyan)),
        ]);
        let note_style = if self.busy.is_some() {
            Style::new().fg(Color::Yellow)
        } else {
            Style::new()
        };
        let note = Line::from(Span::styled(self.note.clone(), note_style));
        let title = format!(" Unbihex {} ", env!("CARGO_PKG_VERSION"));
        f.render_widget(
            Paragraph::new(vec![state, settings, note]).block(Block::bordered().title(title)),
            area,
        );
    }

    fn draw_servers(&mut self, f: &mut Frame, area: Rect) {
        let connected = self.connected_to().filter(|_| self.status.connected);
        let rows: Vec<Row> = self
            .data
            .servers
            .iter()
            .map(|s| {
                let mark = if Some(s.id) == connected {
                    Span::styled("▶", Style::new().fg(Color::Green))
                } else if Some(s.id) == self.data.selected {
                    Span::raw("·")
                } else {
                    Span::raw(" ")
                };
                let (ms, err) = match self.live.get(&s.id) {
                    Some(r) => (r.ms, r.error.clone()),
                    None => (s.ping_ms, s.ping_error.clone()),
                };
                let ping = match (ms, err) {
                    (Some(ms), _) => {
                        let color = match ms {
                            0..150 => Color::Green,
                            150..400 => Color::Yellow,
                            _ => Color::Red,
                        };
                        Span::styled(format!("{ms} мс"), Style::new().fg(color))
                    }
                    (None, Some(e)) => Span::styled(e, Style::new().fg(Color::Red)),
                    (None, None) => Span::raw(""),
                };
                let row = Row::new(vec![
                    Cell::from(mark),
                    Cell::from(s.name.clone()),
                    Cell::from(format!("{} {}", s.protocol, s.transport)),
                    Cell::from(ping),
                ]);
                if s.is_supported() {
                    row
                } else {
                    row.style(Style::new().fg(Color::DarkGray))
                }
            })
            .collect();
        let title = format!(" Серверы ({}) ", self.data.servers.len());
        let table = Table::new(
            rows,
            [
                Constraint::Length(1),
                Constraint::Fill(3),
                Constraint::Fill(2),
                Constraint::Length(14),
            ],
        )
        .block(Block::bordered().title(title))
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED));
        f.render_stateful_widget(table, area, &mut self.table);
    }

    fn draw_speed(&self, f: &mut Frame, area: Rect) {
        let [down_area, up_area, totals] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Length(4),
        ])
        .areas(area);
        let width = usize::from(area.width.saturating_sub(2));
        for (series, title, color, rect) in [
            (&self.down, "↓ загрузка", Color::Green, down_area),
            (&self.up, "↑ отдача", Color::Magenta, up_area),
        ] {
            let data: Vec<u64> = series
                .iter()
                .skip(series.len().saturating_sub(width))
                .copied()
                .collect();
            let now = data.last().copied().unwrap_or(0);
            let title = format!(" {title} {} ", rate(now));
            f.render_widget(
                Sparkline::default()
                    .block(Block::bordered().title(title))
                    .data(&data)
                    .style(Style::new().fg(color)),
                rect,
            );
        }
        let s = &self.status;
        let lines = vec![
            Line::from(format!("через VPN  ↓ {}  ↑ {}", bytes(s.proxy_down), bytes(s.proxy_up))),
            Line::from(format!("напрямую   ↓ {}  ↑ {}", bytes(s.direct_down), bytes(s.direct_up))),
        ];
        f.render_widget(
            Paragraph::new(lines).block(Block::bordered().title(" трафик ")),
            totals,
        );
    }

    fn draw_log(&self, f: &mut Frame, area: Rect) {
        let lines: Vec<Line> = self
            .logs
            .tail(usize::from(area.height.saturating_sub(2)))
            .into_iter()
            .map(Line::from)
            .collect();
        f.render_widget(
            Paragraph::new(lines).block(Block::bordered().title(" журнал ")),
            area,
        );
    }
}

/// Connects to the selected server; the result as a status line.
async fn connect(client: &Client) -> String {
    if let Some(Err(e)) = client.update_geodata_if_due().await {
        tracing::warn!("rule databases: {e}");
    }
    match client.connect().await {
        Ok(info) => format!("подключено: {} ({})", info.server_name, info.mode),
        Err(e) => format!("ошибка подключения: {e}"),
    }
}

fn draw_input(f: &mut Frame, buf: &str) {
    let area = f.area();
    let width = area.width.saturating_sub(8).clamp(20, 100);
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + area.height / 3,
        width: width.min(area.width),
        height: 3,
    };
    // Show the end of a long link, where the cursor is.
    let room = usize::from(rect.width.saturating_sub(3));
    let shown: String = {
        let chars: Vec<char> = buf.chars().map(|c| if c == '\n' { ' ' } else { c }).collect();
        chars[chars.len().saturating_sub(room)..].iter().collect()
    };
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(format!("{shown}▏")).block(
            Block::bordered()
                .title(" ссылка, подписка или JSON — Enter добавить, Esc отмена ")
                .border_style(Style::new().fg(Color::Cyan)),
        ),
        rect,
    );
}

fn key(k: &str) -> Span<'_> {
    Span::styled(k, Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
}

fn push(series: &mut VecDeque<u64>, v: u64) {
    if series.len() == HISTORY {
        series.pop_front();
    }
    series.push_back(v);
}

fn under_ssh() -> bool {
    std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some()
}

fn mode_label(m: ProxyMode) -> &'static str {
    match m {
        ProxyMode::ProxyOnly => "только порт (proxy)",
        ProxyMode::Tun => "весь трафик (TUN)",
        ProxyMode::SystemProxy => "системный прокси",
    }
}

fn routing_label(r: RoutingMode) -> &'static str {
    match r {
        RoutingMode::Global => "всё через VPN",
        RoutingMode::BypassRu => "Россия напрямую",
        RoutingMode::OnlyListed => "только выбранные сайты",
        RoutingMode::BlockedOnly => "только заблокированные",
    }
}

fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} Б")
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

fn rate(n: u64) -> String {
    format!("{}/с", bytes(n))
}

fn duration(secs: u64) -> String {
    format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(bytes(512), "512 Б");
        assert_eq!(bytes(1536), "1.5 КБ");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 МБ");
        assert_eq!(rate(0), "0 Б/с");
        assert_eq!(duration(3725), "01:02:05");
    }

    /// Draws the whole screen on a virtual terminal: servers, prompt and status fit.
    #[tokio::test]
    async fn draws_the_screen() {
        let dir = std::env::temp_dir().join(format!("unbihex-tui-{}", Uuid::new_v4()));
        let client = Arc::new(Client::open(&dir));
        let link = "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=tcp#Test%20server";
        let report = client.add_input(link).await.expect("add");
        assert_eq!(report.servers, 1);
        let (tx, _rx) = mpsc::unbounded_channel();
        let data = client.snapshot();
        let mut app = App {
            client,
            logs: LogBuffer::default(),
            tx,
            data,
            status: Status::default(),
            table: TableState::default().with_selected(Some(0)),
            busy: None,
            note: "Enter — подключиться к выделенному серверу".into(),
            input: None,
            live: HashMap::new(),
            down: (0..60).map(|i| i * 1000).collect(),
            up: VecDeque::from([0, 10, 5]),
            last: None,
            quit: false,
        };
        app.logs.push("WARN something happened".into());
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(110, 30)).expect("terminal");
        term.draw(|f| app.draw(f)).expect("draw");
        let screen = format!("{}", term.backend());
        println!("{screen}");
        for want in ["Unbihex", "Test server", "не подключено", "Серверы (1)", "журнал", "something happened"] {
            assert!(screen.contains(want), "{want:?} not on screen");
        }
        app.on_key(KeyEvent::from(KeyCode::Char('a')));
        app.on_event(Event::Paste("vless://x".into()));
        term.draw(|f| app.draw(f)).expect("draw");
        let screen = format!("{}", term.backend());
        println!("{screen}");
        assert!(screen.contains("vless://x"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn log_buffer_keeps_whole_lines() {
        let logs = LogBuffer::default();
        {
            let mut w = tracing_subscriber::fmt::MakeWriter::make_writer(&logs);
            let _ = w.write_all(b"first\nsecond");
            let _ = w.write_all(b" part\n\n");
        }
        assert_eq!(logs.tail(10), ["first", "second part"]);
        for i in 0..LOG_LINES + 5 {
            logs.push(i.to_string());
        }
        assert_eq!(logs.tail(1), [(LOG_LINES + 4).to_string()]);
        assert_eq!(logs.tail(usize::MAX).len(), LOG_LINES);
    }
}
