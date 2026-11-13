// Developer mode: seven taps on the version turn it on (as on Android); the
// settings turn it off.
import { reported, setDevMode } from "../../shared/api/index.js";
import { plural } from "../../shared/lib/index.js";
import { refresh, store } from "../../shared/model/index.js";
import { toast } from "../../shared/ui/index.js";

const TAPS = 7;
// Taps further apart than this start the count again.
const GAP_MS = 1500;

let taps = 0;
let last = 0;

export const devModeOn = () => Boolean(store.S && store.S.data.settings.dev_mode);

export async function tapVersion() {
  const now = Date.now();
  taps = now - last > GAP_MS ? 1 : taps + 1;
  last = now;
  if (devModeOn()) {
    if (taps === 1) toast("Режим разработчика уже включён");
    return;
  }
  const left = TAPS - taps;
  if (left > 0) {
    if (left <= 4) toast(`Ещё ${left} ${plural(left, "нажатие", "нажатия", "нажатий")} — и включится режим разработчика`);
    return;
  }
  taps = 0;
  try {
    await reported(setDevMode(true));
  } catch {
    return;
  }
  toast("Режим разработчика включён: в «Журнале» появились соединения", "ok");
  await refresh();
}

export async function disableDevMode(btn) {
  btn.disabled = true;
  try {
    await reported(setDevMode(false));
    toast("Режим разработчика выключен");
    await refresh();
  } catch {
    // shown by reported()
  } finally {
    btn.disabled = false;
  }
}
