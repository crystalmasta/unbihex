// Adds a <dialog> to the page, after the ones added before (they sit between the app
// and the toasts, as in the original single index.html).
export function mountDialog(html) {
  document.getElementById("toasts").insertAdjacentHTML("beforebegin", `${html}\n\n  `);
}
