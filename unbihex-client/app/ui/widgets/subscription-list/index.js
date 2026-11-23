// Subscription cards: address, traffic, errors, provider links, update and edit buttons.
import { $, esc, onDataClick } from "../../shared/lib/index.js";
import { store } from "../../shared/model/index.js";
import { maskUrl, quotaHtml, serversOf } from "../../entities/subscription/index.js";
import { openSubDialog } from "../../features/subscription-edit/index.js";
import { toggleSubscriptionTrust } from "../../features/trust-cert/index.js";
import { updateSubscription } from "../../features/subscription-update/index.js";

export function renderSubscriptionList() {
  const S = store.S;
  const root = $("#sub-list");
  if (!S.data.subscriptions.length) {
    root.innerHTML = `<div class="empty">Подписок нет.<br/><button class="btn primary" data-open="add">Добавить подписку</button></div>`;
    return;
  }
  root.innerHTML = S.data.subscriptions
    .map((sub) => {
      const n = serversOf(sub.id).length;
      const links = [];
      if (sub.support_url) links.push(`<a data-href="${esc(sub.support_url)}">Поддержка</a>`);
      if (sub.web_page_url) links.push(`<a data-href="${esc(sub.web_page_url)}">Личный кабинет</a>`);
      return `<div class="sub">
        <div class="sub-top">
          <span class="title">${esc(sub.name)}</span>
          <span class="count hint" style="margin:0">${n} серв.</span>
          <button class="btn small" data-update-sub="${sub.id}">Обновить</button>
          <button class="icon-btn" data-edit-sub="${sub.id}" title="Изменить"><svg viewBox="0 0 24 24"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/></svg></button>
        </div>
        <div class="sub-url">${esc(maskUrl(sub.url))}</div>
        ${quotaHtml(sub)}
        <label class="check sub-trust"><input type="checkbox" data-trust-sub="${sub.id}"${sub.trust_certs ? " checked" : ""} /> <span>Доверять сертификатам серверов</span></label>
        ${sub.last_error ? `<div class="sub-error">${esc(sub.last_error)}</div>` : ""}
        ${links.length ? `<div class="sub-links">${links.join("")}</div>` : ""}
      </div>`;
    })
    .join("");
}

export function initSubscriptionList() {
  onDataClick("data-update-sub", (t) => updateSubscription(t, t.dataset.updateSub));
  onDataClick("data-trust-sub", (t, e) => {
    // The switch moves only after the answer: the list is redrawn from the state.
    e.preventDefault();
    toggleSubscriptionTrust(t.dataset.trustSub);
  });
  onDataClick("data-edit-sub", (t) => openSubDialog(t.dataset.editSub));
}
