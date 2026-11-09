import { updateAdblock as downloadAdblock, updateGeodata } from "../../shared/api/index.js";
import { emit } from "../../shared/lib/index.js";
import { refresh } from "../../shared/model/index.js";
import { toast } from "../../shared/ui/index.js";

// Downloads geosite/geoip now ("geo:changed" after); `btn` shows the progress.
export async function updateGeo(btn) {
  btn.disabled = true;
  btn.textContent = "Скачивание…";
  try {
    const st = await updateGeodata();
    toast(`Базы обновлены: категорий ${st.sites.length}`, "ok");
  } catch (err) {
    toast(String(err), "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Скачать / обновить базы";
    await refresh();
    emit("geo:changed");
  }
}

// Downloads the ad-blocking lists now.
export async function updateAdblock(btn) {
  btn.disabled = true;
  btn.textContent = "Скачивание…";
  try {
    const st = await downloadAdblock();
    toast(`Списки обновлены: доменов ${st.domains.toLocaleString("ru-RU")}`, "ok");
  } catch (err) {
    toast(String(err), "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Скачать / обновить списки";
    await refresh();
  }
}
