import { store } from "../../shared/model/index.js";

export const findSubscription = (id) => store.S.data.subscriptions.find((s) => s.id === id);

// Servers of one subscription; null — the ones added by hand.
export const serversOf = (subId) => store.S.data.servers.filter((s) => s.subscription_id === subId);
