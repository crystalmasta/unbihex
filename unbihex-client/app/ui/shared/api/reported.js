import { toast } from "../ui/index.js";

// A command whose error is shown as a toast and passed on to the caller.
export async function reported(promise) {
  try {
    return await promise;
  } catch (e) {
    toast(String(e), "error");
    throw e;
  }
}
