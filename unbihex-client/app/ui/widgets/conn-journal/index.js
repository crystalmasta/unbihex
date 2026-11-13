// "Журнал → Соединения" (developer mode): the engine's connections, DNS queries
// and auto-select switches, live or from a saved report, with filters.
import { journalClear, journalPage, reported, reportRead, reportsList } from "../../shared/api/index.js";
import { $, esc, fmtBytes, onDataClick, plural } from "../../shared/lib/index.js";
import { store } from "../../shared/model/index.js";
import { fillSelect, mountDialog, setHtml } from "../../shared/ui/index.js";
import { reportShareLabel, saveReportNow, shareReport } from "../../features/dev-reports/index.js";
import { journalMarkup, reportsDialogMarkup } from "./markup.js";
import { addRecords, createModel, describe, describeFilter, filterRows, parseReport } from "./model.js";
import { rowsHtml } from "./view.js";

// Rows drawn at most (newest first); the filter and the report see all of them.
const SHOWN = 500;

let model = createModel();
let next = 0;
let paused = false;
let lost = 0;
let active = false;
// The saved report on screen, or null for the live journal.
let report = null;
const expanded = new Set();

const toMs = (v) => (v ? new Date(v).getTime() : 0);

function readFilter() {
  return {
    period: $("#j-period").value,
    from: toMs($("#j-from").value),
    to: toMs($("#j-to").value),
    app: $("#j-app").value,
    route: $("#j-route").value,
    errors: $("#j-errors").checked,
    q: $("#j-q").value,
  };
}

// "Now" of a report: its last record.
function lastTs() {
  const last = model.order[model.order.length - 1];
  return last ? describe(last).ts : Date.now();
}

function statusText(total, matched, shown) {
  const parts = [`${matched} из ${total} ${plural(total, "записи", "записей", "записей")}`];
  if (shown < matched) parts.push(`показаны последние ${shown}`);
  if (report) {
    if (model.end && model.end.lost) parts.push(`потеряно событий: ${model.end.lost}`);
    return parts.join(" · ");
  }
  if (lost) parts.push(`потеряно событий: ${lost}`);
  parts.push(paused ? "пауза" : active ? "идёт запись" : "VPN не подключён — новых событий нет");
  return parts.join(" · ");
}

function reportTitle() {
  const h = model.header || {};
  const bits = [`Отчёт ${report}`];
  if (h.client) bits.push(`клиент ${h.client}, ядро ${h.engine}`);
  if (h.os) bits.push(h.os);
  if (h.mode) bits.push(`режим ${h.mode}`);
  if (h.routing) bits.push(`маршрутизация «${h.routing}»`);
  if (h.template) bits.push(`шаблон «${h.template}»`);
  if (h.server) bits.push(`сервер «${h.server}»`);
  if (h.filter) bits.push(`фильтр: ${h.filter}`);
  return bits.join(" · ");
}

function draw() {
  const now = report ? lastTs() : Date.now();
  const f = readFilter();
  $("#j-range").hidden = f.period !== "custom";
  const apps = [...model.apps].sort((a, b) => a.localeCompare(b));
  fillSelect($("#j-app"), [["", "Все приложения"], ["__none", "Неизвестно"], ...apps.map((a) => [a, a])], f.app);
  const rows = filterRows(model, f, now);
  const shown = rows.slice(-SHOWN).reverse();
  setHtml($("#j-rows"), rowsHtml(shown, expanded, !report, now));
  $("#j-status").textContent = statusText(model.order.length, rows.length, shown.length);
  $("#j-report").hidden = !report;
  if (report) $("#j-report-title").textContent = reportTitle();
  $("#j-report-share").textContent = reportShareLabel();
  for (const id of ["#j-pause", "#j-clear", "#j-save"]) $(id).disabled = Boolean(report);
  $("#j-pause").textContent = paused ? "Продолжить" : "Пауза";
}

// Called every second while the view is open.
export async function loadJournal() {
  if (!report && !paused) {
    try {
      const page = await journalPage(next);
      if (page.reset) {
        model = createModel();
        expanded.clear();
      }
      addRecords(model, page.records);
      next = page.next;
      lost = page.lost;
      active = page.active;
    } catch {
      return;
    }
  }
  draw();
}

function backToLive() {
  report = null;
  model = createModel();
  next = 0;
  expanded.clear();
  loadJournal();
}

async function openReport(name) {
  const text = await reported(reportRead(name)).catch(() => null);
  if (text === null) return;
  $("#dlg-reports").close();
  report = name;
  model = parseReport(text);
  expanded.clear();
  draw();
}

async function showReports() {
  const list = await reported(reportsList()).catch(() => null);
  if (!list) return;
  const dir = store.S.data.settings.report_dir;
  $("#reports-dir").textContent = dir ? `Папка: ${dir}` : "Папка приложения (своя папка выбирается в «Настройки → Общие»).";
  const label = esc(reportShareLabel());
  $("#reports-list").innerHTML = list.length
    ? list
        .map(
          (r) => `<div class="report-item">
          <div class="report-name">${esc(r.name)}<span class="hint"> · ${esc(fmtBytes(r.size))}</span></div>
          <button type="button" class="btn small" data-report-open="${esc(r.name)}">Открыть</button>
          <button type="button" class="btn small" data-report-share="${esc(r.name)}">${label}</button>
        </div>`,
        )
        .join("")
    : `<p class="hint">Отчётов пока нет: отчёт пишется за каждое подключение в режиме разработчика.</p>`;
  $("#dlg-reports").showModal();
}

export function mountJournal(el) {
  el.innerHTML = journalMarkup;
  mountDialog(reportsDialogMarkup);
}

export function initJournal() {
  $("#j-pause").addEventListener("click", () => {
    paused = !paused;
    loadJournal();
  });
  $("#j-clear").addEventListener("click", async () => {
    await reported(journalClear()).catch(() => {});
    model = createModel();
    expanded.clear();
    draw();
  });
  $("#j-save").addEventListener("click", (e) => {
    const f = readFilter();
    const seqs = filterRows(model, f, Date.now()).flatMap((r) => r.seqs);
    saveReportNow(seqs, describeFilter(f), e.currentTarget);
  });
  $("#j-reports").addEventListener("click", showReports);
  $("#j-live").addEventListener("click", backToLive);
  $("#j-report-share").addEventListener("click", (e) => shareReport(report, e.currentTarget));
  $("#j-filters").addEventListener("input", draw);
  $("#j-filters").addEventListener("change", draw);
  onDataClick("data-jrow", (t) => {
    const key = t.dataset.jrow;
    if (expanded.has(key)) expanded.delete(key);
    else expanded.add(key);
    draw();
  });
  onDataClick("data-report-open", (t) => openReport(t.dataset.reportOpen));
  onDataClick("data-report-share", (t) => shareReport(t.dataset.reportShare, t));
}
