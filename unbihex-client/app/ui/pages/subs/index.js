// "Подписки": the subscription cards and "Обновить все".
import { $ } from "../../shared/lib/index.js";
import { updateAll } from "../../features/subscription-update/index.js";
import { initSubscriptionList, renderSubscriptionList } from "../../widgets/subscription-list/index.js";
import { subsMarkup } from "./markup.js";

export function mountSubs() {
  $("#view-subs").innerHTML = subsMarkup;
}

export const renderSubs = renderSubscriptionList;

export function initSubs() {
  initSubscriptionList();
  $("#update-all").addEventListener("click", (e) => updateAll(e.target));
}
