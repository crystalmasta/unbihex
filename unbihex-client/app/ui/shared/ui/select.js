// A <select> filled from data that a poll redraws: the options are rebuilt only
// when they really change, and an open (focused) picker is left alone, so it
// neither blinks nor closes under the user's finger.
import { esc } from "../lib/index.js";

// `options` — [[value, label], …]; `value` — the option to show as chosen.
export function fillSelect(sel, options, value) {
  if (document.activeElement === sel) return;
  const key = JSON.stringify(options);
  if (sel.dataset.options !== key) {
    sel.innerHTML = options.map(([v, label]) => `<option value="${esc(v)}">${esc(label)}</option>`).join("");
    sel.dataset.options = key;
  }
  if (sel.value !== value) sel.value = value;
}

// Sets the markup only when it differs: no relayout, text selection survives.
export function setHtml(el, html) {
  if (el.dataset.html !== html) {
    el.innerHTML = html;
    el.dataset.html = html;
  }
}
