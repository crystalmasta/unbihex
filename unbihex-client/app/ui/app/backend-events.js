// Events from the backend.
import { onBackendEvent } from "../shared/api/index.js";
import { refresh, store } from "../shared/model/index.js";
import { toast } from "../shared/ui/index.js";
import { askAutostartAdmin } from "../features/elevate/index.js";
import { applyPingResult } from "../features/ping/index.js";

export function listenBackend() {
  onBackendEvent("state-changed", () => {
    if (!store.busy) refresh();
  });
  onBackendEvent("ping-result", (e) => applyPingResult(e.payload));
  onBackendEvent("toast", (e) => toast(String(e.payload), "error"));
  onBackendEvent("autostart-admin", () => askAutostartAdmin());
}
