import { esc } from "../../shared/lib/index.js";
import { pinging } from "./model.js";

export function pingHtml(s) {
  if (pinging.has(s.id)) return '<span class="ping">…</span>';
  if (s.ping_ms != null) {
    const cls = s.ping_ms < 300 ? "good" : s.ping_ms < 800 ? "mid" : "bad";
    return `<span class="ping ${cls}">${s.ping_ms} мс</span>`;
  }
  if (s.ping_error) return `<span class="ping bad">${esc(s.ping_error)}</span>`;
  return '<span class="ping">—</span>';
}
