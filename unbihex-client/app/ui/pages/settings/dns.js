// "DNS" tab: the ready-made sets offered next to the two DNS fields.
import { $ } from "../../shared/lib/index.js";

// DNS sets the lists offer; a list shows the one the field holds, else "Свой".
const DNS_PRESETS = [["#dns-preset", "dns_upstream"], ["#dns-direct-preset", "dns_direct"]];
const dnsKey = (v) => v.split(/[\s,;]+/).filter(Boolean).join(",").toLowerCase();

export function syncDnsPresets() {
  const f = $("#settings-form");
  for (const [sel, field] of DNS_PRESETS) {
    const key = dnsKey(f[field].value);
    // "-" stands for an empty field (no home DNS).
    const opt = [...$(sel).options].find((o) => o.value && dnsKey(o.value === "-" ? "" : o.value) === key);
    $(sel).value = opt ? opt.value : "";
  }
}

export function initDns() {
  for (const [preset, field] of DNS_PRESETS) {
    // The list keeps the picked set; "Свой" leaves the field as it is.
    $(preset).addEventListener("change", (e) => {
      if (e.target.value) $("#settings-form")[field].value = e.target.value === "-" ? "" : e.target.value;
    });
    $("#settings-form")[field].addEventListener("input", syncDnsPresets);
  }
}
