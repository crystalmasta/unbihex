// Connection journal records (engine events with owners, see client-core devlog.rs)
// as table rows: `open` and `close` of one connection become one row; DNS
// queries, auto-select switches and notes are rows of their own.

const OK_REASONS = new Set(["closed", "idle"]);

export const REASONS = {
  closed: "закрыто",
  idle: "простой",
  timeout: "таймаут подключения",
  refused: "отказ в соединении",
  reset: "сброс (RST)",
  handshake: "ошибка рукопожатия с сервером",
  dns: "ошибка DNS",
  blocked: "заблокировано правилом",
  forbidden: "запрещённый адрес",
  limit: "лимит соединений",
  remote: "сервер оборвал поток",
  error: "ошибка",
};

export function createModel() {
  return { rows: new Map(), order: [], apps: new Set(), header: null, end: null };
}

// "1.2.3.4:443" / "[::1]:443" / "name:443" → [host, port].
function splitAddr(a) {
  const s = String(a || "");
  const i = s.lastIndexOf(":");
  if (i <= 0) return [s, ""];
  return [s.slice(0, i).replace(/^\[|\]$/g, ""), s.slice(i + 1)];
}

export function addRecords(m, records) {
  for (const r of records) {
    if (r.ev === "header") {
      m.header = r;
      continue;
    }
    if (r.ev === "end") {
      m.end = r;
      continue;
    }
    let row;
    if (r.ev === "open" || r.ev === "close") {
      const key = `c${r.conn}`;
      row = m.rows.get(key);
      if (!row) {
        row = { key, kind: "conn", seqs: [] };
        m.rows.set(key, row);
        m.order.push(row);
      }
      if (r.ev === "open") row.open = r;
      else row.close = r;
    } else {
      const key = `e${m.order.length}:${r.seq ?? ""}`;
      row = { key, kind: r.ev, seqs: [], rec: r };
      m.rows.set(key, row);
      m.order.push(row);
    }
    if (r.seq !== undefined) row.seqs.push(r.seq);
    if (r.app) {
      row.app = r.app;
      m.apps.add(r.app);
    }
    row.d = null;
  }
}

// What a row shows (cached until the row changes).
export function describe(row) {
  if (row.d) return row.d;
  let d;
  if (row.kind === "conn") {
    const o = row.open || {}, c = row.close;
    const any = c || o;
    const [ip, port] = splitAddr(any.dst);
    const reason = c ? c.reason : "";
    const routeKind = c ? c.route || "none" : "pending";
    const route = { direct: "напрямую", proxy: (c && (c.server || c.outbound)) || "сервер", block: "блок", none: "—", pending: "…" }[routeKind];
    d = {
      ts: o.ts || (c && c.start) || 0,
      app: row.app || "",
      host: any.host || ip,
      addr: ip,
      port,
      proto: any.net || "",
      route,
      routeKind,
      up: c ? c.up : null,
      down: c ? c.down : null,
      ms: c ? c.ms : null,
      error: c && !OK_REASONS.has(reason) ? `${REASONS[reason] || reason}${c.error ? `: ${c.error}` : ""}` : "",
      reason,
      details: [
        ["Правило", c && c.rule],
        ["Выход", c && [c.outbound, c.member && c.member !== c.outbound ? `(${c.member})` : ""].filter(Boolean).join(" ")],
        ["Сервер", c && c.server],
        ["Откуда", any.src],
        ["Куда", any.dst],
        ["Вход", any.inbound],
        ["Закрытие", c && `${REASONS[reason] || reason}${c.error ? ` — ${c.error}` : ""}`],
        ["№", any.conn],
      ],
    };
  } else if (row.kind === "dns") {
    const r = row.rec;
    const failed = Boolean(r.error) || (r.rcode && r.rcode !== "NoError");
    d = {
      ts: r.ts,
      app: "",
      host: r.name,
      addr: (r.answer || []).join(", "),
      port: r.qtype,
      proto: "dns",
      route: r.resolver,
      routeKind: "dns",
      up: null,
      down: null,
      ms: r.ms,
      error: failed ? [r.rcode, r.error].filter(Boolean).join(": ") : "",
      details: [["Резолвер", r.resolver], ["Ответ", (r.answer || []).join(", ")], ["Код", r.rcode], ["Ошибка", r.error]],
    };
  } else {
    const r = row.rec;
    const text = r.ev === "switch"
      ? `Автовыбор: ${r.from_server || r.from || "—"} → ${r.to_server || r.to}`
      : r.text || "";
    d = {
      ts: r.ts,
      app: "",
      host: text,
      addr: "",
      port: "",
      proto: r.ev === "switch" ? "автовыбор" : r.category || "событие",
      route: "",
      routeKind: "event",
      up: null,
      down: null,
      ms: null,
      error: "",
      details: [["Причина", r.reason], ["Балансировщик", r.balancer], ["Категория", r.category]],
    };
  }
  row.d = d;
  return d;
}

// Rows passing filter `f` ({period, from, to, app, route, errors, q}); `now` — ms.
export function filterRows(m, f, now) {
  const q = (f.q || "").trim().toLowerCase();
  let from = 0, to = Infinity;
  if (f.period === "custom") {
    if (f.from) from = f.from;
    if (f.to) to = f.to;
  } else if (f.period && f.period !== "all") {
    from = now - Number(f.period) * 60_000;
  }
  return m.order.filter((row) => {
    const d = describe(row);
    if (d.ts < from || d.ts > to) return false;
    if (f.app === "__none" ? d.app : f.app && d.app !== f.app) return false;
    if (f.route && d.routeKind !== f.route) return false;
    if (f.errors && !d.error) return false;
    if (q) {
      const hay = [d.host, d.addr, d.app, d.route, row.kind === "conn" && (row.close || row.open || {}).dst].join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

// The filter in words, for the report header.
export function describeFilter(f) {
  const parts = [];
  const period = { 5: "5 мин", 15: "15 мин", 60: "1 ч" }[f.period];
  if (period) parts.push(`последние ${period}`);
  if (f.period === "custom") {
    const t = (ms) => (ms ? new Date(ms).toLocaleString("ru-RU") : "…");
    parts.push(`${t(f.from)} – ${t(f.to)}`);
  }
  if (f.app) parts.push(`приложение: ${f.app === "__none" ? "неизвестно" : f.app}`);
  if (f.route) parts.push(`маршрут: ${f.route}`);
  if (f.errors) parts.push("только ошибки");
  if (f.q) parts.push(`поиск: ${f.q}`);
  return parts.join("; ") || "без фильтров";
}

// The model of a saved report (JSON Lines).
export function parseReport(text) {
  const m = createModel();
  const records = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      records.push(JSON.parse(line));
    } catch {}
  }
  addRecords(m, records);
  return m;
}
