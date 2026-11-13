// Table rows of the connection journal.
import { esc, fmtBytes } from "../../shared/lib/index.js";
import { describe } from "./model.js";

const time = (ms) => {
  if (!ms) return "";
  const d = new Date(ms);
  const p = (x, n = 2) => String(x).padStart(n, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
};

const dur = (ms) => (ms === null || ms === undefined ? "" : ms < 1000 ? `${ms} мс` : `${(ms / 1000).toFixed(1)} с`);

function details(d) {
  const items = d.details.filter(([, v]) => v !== undefined && v !== null && v !== "");
  return `<tr class="j-details"><td colspan="9"><dl>${items
    .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`)
    .join("")}</dl></td></tr>`;
}

// `open` — keys of the expanded rows; `now` — ms, for connections still open.
export function rowsHtml(rows, open, live, now) {
  return rows
    .map((row) => {
      const d = describe(row);
      const pending = d.routeKind === "pending";
      const ms = pending && live ? `идёт ${dur(Math.max(0, now - d.ts))}` : dur(d.ms);
      const bytes = d.up === null ? "" : `${fmtBytes(d.up)} / ${fmtBytes(d.down)}`;
      const cls = ["j-row", d.error ? "j-err" : "", `j-${d.routeKind}`].filter(Boolean).join(" ");
      const html = `<tr class="${cls}" data-jrow="${esc(row.key)}">
        <td class="j-time">${esc(time(d.ts))}</td>
        <td class="j-app">${esc(d.app || (d.routeKind === "event" || d.routeKind === "dns" ? "" : "—"))}</td>
        <td class="j-host" title="${esc(d.addr)}">${esc(d.host)}</td>
        <td>${esc(d.port)}</td>
        <td>${esc(d.proto)}</td>
        <td class="j-route">${esc(d.route)}</td>
        <td class="j-num">${esc(bytes)}</td>
        <td class="j-num">${esc(ms)}</td>
        <td class="j-error">${esc(d.error)}</td>
      </tr>`;
      return open.has(row.key) ? html + details(d) : html;
    })
    .join("");
}
