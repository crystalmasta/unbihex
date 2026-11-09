import { removeServer as removeOnBackend, reported } from "../../shared/api/index.js";
import { refresh } from "../../shared/model/index.js";

// Removes a server added by hand.
export function removeServer(id) {
  return reported(removeOnBackend(id)).then(refresh).catch(() => {});
}
