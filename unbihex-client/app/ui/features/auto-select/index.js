import { reported, setServerAuto, setTemplateServer } from "../../shared/api/index.js";
import { emit } from "../../shared/lib/index.js";
import { refresh } from "../../shared/model/index.js";
import { findServer } from "../../entities/server/index.js";

// Excludes the server from the auto-select group without a template, or takes it back.
export async function toggleAuto(id) {
  const s = findServer(id);
  if (!s) return;
  await reported(setServerAuto(id, !s.auto_excluded)).catch(() => {});
  await refresh();
}

// Adds the server to a template or removes it ("templates:changed" after).
export async function toggleTemplateServer(templateId, serverId, member) {
  await reported(setTemplateServer(templateId, serverId, member)).catch(() => {});
  await refresh();
  emit("templates:changed");
}
