// Events the backend sends: state-changed, ping-result, toast, autostart-admin.
import { listen } from "./tauri.js";

export const onBackendEvent = (name, fn) => listen(name, fn);
