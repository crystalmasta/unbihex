import { relaunchAdmin as relaunch, relaunchAdminForAutostart, reported } from "../../shared/api/index.js";
import { toast } from "../../shared/ui/index.js";

// Windows: restarts Unbihex with administrator rights (TUN).
export function relaunchAdmin() {
  reported(relaunch()).catch(() => {});
}

// Autostart with administrator rights switched on or off by an unelevated copy
// (backend event "autostart-admin").
export function askAutostartAdmin() {
  if (confirm("Включить или выключить автозапуск с правами администратора может только Unbihex, запущенный от администратора. Перезапустить его сейчас? Подключение прервётся.")) {
    reported(relaunchAdminForAutostart()).catch(() => {});
  } else {
    toast("Автозапуск не изменён");
  }
}
