// TLS fingerprint of one server (the "⋯" menu): kept across subscription updates.
import { reported, setServerFingerprint } from "../../shared/api/index.js";
import { $ } from "../../shared/lib/index.js";
import { refresh } from "../../shared/model/index.js";
import { mountDialog } from "../../shared/ui/index.js";
import { findServer } from "../../entities/server/index.js";
import { fpDialogMarkup } from "./markup.js";

let fpServer = null;

export function openFpDialog(id) {
  const s = findServer(id);
  if (!s) return;
  fpServer = id;
  $("#fp-server").textContent = s.name;
  $("#fp-select").value = s.fingerprint || "";
  $("#dlg-fp").showModal();
}

async function saveFp() {
  const fingerprint = $("#fp-select").value || null;
  $("#dlg-fp").close();
  await reported(setServerFingerprint(fpServer, fingerprint)).catch(() => {});
  await refresh();
}

export function mountFingerprint() {
  mountDialog(fpDialogMarkup);
  $("#fp-save").addEventListener("click", saveFp);
}
