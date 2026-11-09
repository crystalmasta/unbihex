// ⓘ opens a setting's description (a tap, not a hover: phones have no hover).
// The button names the description: data-info="<id of the .info paragraph>".
export function bindInfoButtons(root) {
  root.addEventListener("click", (e) => {
    const b = e.target.closest(".info-btn");
    if (!b) return;
    // Inside a label the tap must not tick its checkbox.
    e.preventDefault();
    const el = document.getElementById(b.dataset.info);
    if (!el) return;
    el.hidden = !el.hidden;
    b.setAttribute("aria-expanded", String(!el.hidden));
  });
}
