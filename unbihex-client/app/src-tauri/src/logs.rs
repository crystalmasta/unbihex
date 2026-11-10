//! In-memory log for the "Журнал" tab, plus stderr in debug builds.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::Arc;

use parking_lot::Mutex;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, reload};

const MAX_LINES: usize = 1000;

/// Shared ring buffer of formatted log lines.
#[derive(Clone, Default)]
pub struct LogBuffer(Arc<Mutex<VecDeque<String>>>);

impl LogBuffer {
    /// All lines, oldest first.
    pub fn lines(&self) -> Vec<String> {
        self.0.lock().iter().cloned().collect()
    }

    /// Removes everything.
    pub fn clear(&self) {
        self.0.lock().clear();
    }

    fn push(&self, line: String) {
        let mut q = self.0.lock();
        if q.len() >= MAX_LINES {
            q.pop_front();
        }
        q.push_back(line);
    }
}

/// Collects one event and stores it on drop.
pub struct LineWriter {
    buf: Vec<u8>,
    target: LogBuffer,
}

impl Write for LineWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for LineWriter {
    fn drop(&mut self) {
        let text = String::from_utf8_lossy(&self.buf);
        let line = text.trim_end();
        if !line.is_empty() {
            #[cfg(debug_assertions)]
            eprintln!("{line}");
            self.target.push(line.to_string());
        }
    }
}

impl<'a> MakeWriter<'a> for LogBuffer {
    type Writer = LineWriter;
    fn make_writer(&'a self) -> LineWriter {
        LineWriter {
            buf: Vec::new(),
            target: self.clone(),
        }
    }
}

/// Changes the log level at run time.
pub type LevelHandle = reload::Handle<EnvFilter, tracing_subscriber::Registry>;

fn filter(level: &str) -> EnvFilter {
    let level = match level {
        "error" | "warn" | "info" | "debug" | "trace" => level,
        _ => "info",
    };
    // Third-party crates stay quiet unless something is wrong.
    EnvFilter::new(format!(
        "warn,unbihex_engine={level},unbihex_client_core={level},unbihex_client_lib={level}"
    ))
}

/// Called for each engine connection that timed out, whatever level the log shows.
static ON_TIMEOUT: std::sync::OnceLock<Box<dyn Fn() + Send + Sync>> = std::sync::OnceLock::new();

/// Sets what a timed-out engine connection calls (the whitelist checks: a run of
/// them makes a check out of turn).
pub fn on_connect_timeout(f: impl Fn() + Send + Sync + 'static) {
    let _ = ON_TIMEOUT.set(Box::new(f));
}

/// Watches the dispatcher's debug lines for "connect timed out" on its own
/// filter, so the log level the user picked does not hide them.
struct TimeoutWatch;

impl<S: tracing::Subscriber> Layer<S> for TimeoutWatch {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Message(bool);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}").ends_with("connect timed out");
                }
            }
        }
        let mut m = Message(false);
        event.record(&mut m);
        if m.0
            && let Some(f) = ON_TIMEOUT.get()
        {
            f();
        }
    }
}

/// Installs the global subscriber.
pub fn init(level: &str) -> (LogBuffer, Option<LevelHandle>) {
    let buffer = LogBuffer::default();
    let (filter, handle) = reload::Layer::new(filter(level));
    let fmt = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(false)
        .with_writer(buffer.clone())
        .with_filter(filter);
    let timeouts = TimeoutWatch.with_filter(Targets::new().with_target("unbihex_engine::dispatcher", tracing::Level::DEBUG));
    let ok = tracing_subscriber::registry().with(fmt).with(timeouts).try_init().is_ok();
    (buffer, ok.then_some(handle))
}

/// Applies a new level.
pub fn set_level(handle: &Option<LevelHandle>, level: &str) {
    if let Some(h) = handle {
        let _ = h.reload(filter(level));
    }
}
