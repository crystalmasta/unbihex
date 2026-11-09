// The subscription dialog: name, address, User-Agent; removal.
import { editSubscription, removeSubscription, reported } from "../../shared/api/index.js";
import { $ } from "../../shared/lib/index.js";
import { refresh } from "../../shared/model/index.js";
import { mountDialog } from "../../shared/ui/index.js";
import { findSubscription } from "../../entities/subscription/index.js";
import { subDialogMarkup } from "./markup.js";

let editingSub = null;

export function openSubDialog(id) {
  const sub = findSubscription(id);
  if (!sub) return;
  editingSub = id;
  $("#sub-name").value = sub.name;
  $("#sub-url").value = sub.url;
  $("#sub-ua").value = sub.user_agent || "";
  $("#dlg-sub").showModal();
}

export function mountSubscriptionEdit() {
  mountDialog(subDialogMarkup);
  $("#sub-save").addEventListener("click", async () => {
    try {
      await reported(editSubscription(editingSub, $("#sub-name").value, $("#sub-url").value, $("#sub-ua").value));
      $("#dlg-sub").close();
      refresh();
    } catch {}
  });
  $("#sub-delete").addEventListener("click", async () => {
    const sub = findSubscription(editingSub);
    if (!sub || !confirm(`Удалить подписку «${sub.name}» и её серверы?`)) return;
    try {
      await reported(removeSubscription(editingSub));
      $("#dlg-sub").close();
      refresh();
    } catch {}
  });
}
