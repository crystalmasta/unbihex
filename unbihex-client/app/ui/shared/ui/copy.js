import { toast } from "./toast.js";

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Скопировано", "ok");
  } catch {
    toast("Не удалось скопировать", "error");
  }
}
