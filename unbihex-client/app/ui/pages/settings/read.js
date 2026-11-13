import { $, $$ } from "../../shared/lib/index.js";
import { store } from "../../shared/model/index.js";

// The settings to save: the saved ones with the form's values over them.
export function readSettings() {
  return { ...store.S.data.settings, ...formSettings() };
}

// The settings the form holds (without what it does not show).
export function formSettings() {
  const f = $("#settings-form");
  const lines = (t) => t.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
  const port = (v, d) => {
    const n = parseInt(v, 10);
    return n > 0 && n < 65536 ? n : d;
  };
  return {
    proxy_list: lines(f.proxy_list.value),
    direct_list: lines(f.direct_list.value),
    private_names: lines(f.private_names.value),
    block_list: lines(f.block_list.value),
    socks_port: port(f.socks_port.value, 10808),
    http_port: port(f.http_port.value, 10809),
    allow_lan: f.allow_lan.checked,
    lan_username: f.lan_username.value,
    lan_password: f.lan_password.value,
    dns_upstream: f.dns_upstream.value.split(/[\s,;]+/).filter(Boolean),
    dns_direct: f.dns_direct.value.split(/[\s,;]+/).filter(Boolean),
    mtu: Math.min(9000, Math.max(1280, parseInt(f.mtu.value, 10) || 1500)),
    mux: f.udp_mux.checked,
    user_agent: f.user_agent.value.trim(),
    auto_select: f.auto_select.value,
    auto_template: f.auto_template.value || null,
    auto_threshold_ms: Math.min(60000, Math.max(0, parseInt(f.auto_threshold_ms.value, 10) || 0)),
    send_hwid: f.send_hwid.checked,
    device_name: f.device_name.value.trim(),
    auto_start: f.auto_start.checked,
    auto_start_admin: f.auto_start_admin.checked,
    auto_start_show_window: f.auto_start_show_window.checked,
    auto_connect: f.auto_connect.checked,
    android_notification: f.android_notification.checked,
    android_apps_mode: f.android_apps_mode.value,
    tls_fingerprint: f.tls_fingerprint.value,
    log_level: f.log_level.value,
    geosite_url: f.geosite_url.value.trim(),
    geoip_url: f.geoip_url.value.trim(),
    geo_auto_update: f.geo_auto_update.checked,
    adblock: f.adblock.checked,
    adblock_lists: [
      ...$$("#adblock-presets input:checked").map((i) => i.dataset.url),
      ...lines(f.adblock_custom.value),
    ],
    fragment: f.fragment.checked,
    fragment_length: f.fragment_length.value.trim() || "100-200",
    fragment_interval: f.fragment_interval.value.trim() || "10-20",
  };
}
