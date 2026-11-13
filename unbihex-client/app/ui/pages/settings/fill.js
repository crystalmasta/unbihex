// The form filled from the saved settings, and what follows changes from outside.
import { $ } from "../../shared/lib/index.js";
import { store } from "../../shared/model/index.js";
import { currentSettingsTab, showSettingsTab } from "../../widgets/settings-tabs/index.js";
import { fillAdblock } from "./adblock.js";
import { appsCount } from "./controls.js";
import { checkSettingsDirty, setSettingsBase, settingsBase } from "./dirty.js";
import { syncDnsPresets } from "./dns.js";
import { renderGeo } from "./geo.js";
import { formSettings } from "./read.js";
import { renderTemplates } from "./templates.js";

export function fillSettings() {
  const S = store.S;
  const f = $("#settings-form");
  const s = S.data.settings;
  f.proxy_list.value = s.proxy_list.join("\n");
  f.direct_list.value = s.direct_list.join("\n");
  f.private_names.value = (s.private_names || []).join("\n");
  f.block_list.value = s.block_list.join("\n");
  f.socks_port.value = s.socks_port;
  f.http_port.value = s.http_port;
  f.allow_lan.checked = s.allow_lan;
  f.lan_username.value = s.lan_username;
  f.lan_password.value = s.lan_password;
  $("#lan-auth").hidden = !s.allow_lan;
  f.dns_upstream.value = s.dns_upstream.join(", ");
  f.dns_direct.value = (s.dns_direct || []).join(", ");
  f.mtu.value = s.mtu;
  // An older settings object has no `mux`; the engine defaults it on, so an
  // unticked box must not silently turn it off.
  f.udp_mux.checked = s.mux !== false;
  f.user_agent.value = s.user_agent;
  f.auto_select.value = s.auto_select || "off";
  renderTemplates(s.auto_template || "");
  f.auto_threshold_ms.value = s.auto_threshold_ms ? s.auto_threshold_ms : "";
  f.send_hwid.checked = s.send_hwid;
  f.device_name.value = s.device_name || "";
  f.device_name.placeholder = S.device_name || "";
  f.auto_start.checked = s.auto_start;
  f.auto_start_admin.checked = s.auto_start_admin;
  f.auto_start_admin.disabled = !s.auto_start;
  f.auto_start_show_window.checked = s.auto_start_show_window;
  f.auto_start_show_window.disabled = !s.auto_start;
  $("#desktop-autostart").hidden = S.platform !== "windows";
  f.auto_connect.checked = s.auto_connect;
  f.android_notification.checked = s.android_notification;
  $("#android-notification").hidden = S.platform !== "android";
  f.android_apps_mode.value = s.android_apps_mode || "all";
  f.tls_fingerprint.value = s.tls_fingerprint || "";
  $("#android-apps").hidden = S.platform !== "android";
  $("#tab-apps").hidden = S.platform !== "android";
  showSettingsTab(currentSettingsTab());
  appsCount();
  f.log_level.value = s.log_level;
  f.geosite_url.value = s.geosite_url;
  f.geoip_url.value = s.geoip_url;
  f.geo_auto_update.checked = s.geo_auto_update;
  f.fragment.checked = s.fragment;
  f.fragment_length.value = s.fragment_length;
  f.fragment_interval.value = s.fragment_interval;
  renderGeo();
  fillAdblock(s);
  syncDnsPresets();
  setSettingsBase(formSettings());
  checkSettingsDirty();
}

// The active template changed outside the form (the home screen, a deleted
// template): an untouched picker follows it, a changed one keeps the change.
export function syncSavedTemplate() {
  if (!settingsBase) return;
  const saved = store.S.data.settings.auto_template || null;
  if (settingsBase.auto_template === saved) return;
  const f = $("#settings-form");
  if ((f.auto_template.value || null) === settingsBase.auto_template) f.auto_template.value = saved || "";
  settingsBase.auto_template = saved;
  checkSettingsDirty();
}

// A save the backend refused: the tab with the field it is about.
export function showSettingsError(msg) {
  const field = /DNS/.test(msg) ? "dns_upstream" : /пароль/.test(msg) ? "lan_password" : /отпечаток TLS/.test(msg) ? "tls_fingerprint" : null;
  const section = field && $("#settings-form")[field].closest("[data-tab]");
  if (section) showSettingsTab(section.dataset.tab);
}
