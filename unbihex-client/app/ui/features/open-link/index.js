import { openUrl } from "../../shared/api/index.js";
import { onDataClick } from "../../shared/lib/index.js";
import { toast } from "../../shared/ui/index.js";

// Links marked data-href="<url>" open in the system browser.
export function initOpenLinks() {
  onDataClick("data-href", (t, e) => {
    e.preventDefault(); // <a href="#"> не должен уводить WebView
    openUrl(t.dataset.href).catch((err) => toast(String(err), "error"));
  });
}
