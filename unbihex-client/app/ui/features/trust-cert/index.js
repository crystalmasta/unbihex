// Trusting a server certificate: one server from its "⋯" menu, or every server of a
// subscription. Nothing is pinned without the user confirming the warning.
import { probeServerCert, reported, setServerTrust, setSubscriptionTrust, trustAllServers } from "../../shared/api/index.js";
import { $ } from "../../shared/lib/index.js";
import { refresh, store } from "../../shared/model/index.js";
import { mountDialog, toast } from "../../shared/ui/index.js";
import { findServer } from "../../entities/server/index.js";
import { findSubscription } from "../../entities/subscription/index.js";
import { trustDialogMarkup } from "./markup.js";

const APPLIES_LATER = "Применится при следующем подключении.";

let trustServer = null;
let trustHash = null;
let trustSub = null;

// "ab12…" -> "AB:12:…" (the form certificate viewers show).
export function formatFingerprint(hex) {
  return (hex.toUpperCase().match(/.{1,2}/g) || []).join(":");
}

// Reads the certificate, then asks. Nothing is saved before "Доверять".
export async function openTrustDialog(id) {
  const s = findServer(id);
  if (!s) return;
  toast("Читаю сертификат сервера…");
  let hash;
  try {
    hash = await reported(probeServerCert(id));
  } catch {
    return;
  }
  trustServer = id;
  trustHash = hash;
  $("#trust-server").textContent = `${s.name} · ${s.host}:${s.port}`;
  $("#trust-hash").textContent = formatFingerprint(hash);
  $("#dlg-trust").showModal();
}

export async function resetTrust(id) {
  try {
    await reported(setServerTrust(id, null));
    toast(`Доверенный сертификат сброшен. ${APPLIES_LATER}`, "ok");
  } catch {}
  await refresh();
}

// The switch on a subscription card: asks before turning on, turns off at once.
export async function toggleSubscriptionTrust(id) {
  const sub = findSubscription(id);
  if (!sub) return;
  if (sub.trust_certs) {
    try {
      await reported(setSubscriptionTrust(id, false));
      toast(`Доверие сертификатам выключено. ${APPLIES_LATER}`, "ok");
    } catch {}
    await refresh();
    return;
  }
  trustSub = id;
  $("#trust-sub-name").textContent = sub.name;
  $("#dlg-trust-sub").showModal();
}

// Servers whose certificate can still be pinned.
export function trustCandidates() {
  return store.S.data.servers.filter((s) => s.can_trust && !s.trusted_sha256);
}

// One-off "trust everyone": asks first, then pins all candidates at once.
export function openTrustAllDialog() {
  const n = trustCandidates().length;
  if (!n) return;
  $("#trust-all-count").textContent = `Серверов: ${n}`;
  $("#dlg-trust-all").showModal();
}

export function mountTrustCert() {
  mountDialog(trustDialogMarkup);
  $("#trust-ok").addEventListener("click", async () => {
    $("#dlg-trust").close();
    try {
      await reported(setServerTrust(trustServer, trustHash));
      toast(`Сертификат закреплён. ${APPLIES_LATER}`, "ok");
    } catch {}
    await refresh();
  });
  $("#trust-all-ok").addEventListener("click", async () => {
    const btn = $("#trust-all-ok");
    btn.disabled = true;
    try {
      const r = await reported(trustAllServers());
      $("#dlg-trust-all").close();
      toast(`Закреплено: ${r.pinned}, ошибок: ${r.failed}. ${APPLIES_LATER}`, r.failed ? "error" : "ok");
    } catch {
      $("#dlg-trust-all").close();
    }
    btn.disabled = false;
    await refresh();
  });
  $("#trust-sub-ok").addEventListener("click", async () => {
    const btn = $("#trust-sub-ok");
    btn.disabled = true;
    try {
      const r = await reported(setSubscriptionTrust(trustSub, true));
      $("#dlg-trust-sub").close();
      toast(`Закреплено: ${r.pinned}, ошибок: ${r.failed}. ${APPLIES_LATER}`, r.failed ? "error" : "ok");
    } catch {
      $("#dlg-trust-sub").close();
    }
    btn.disabled = false;
    await refresh();
  });
}
