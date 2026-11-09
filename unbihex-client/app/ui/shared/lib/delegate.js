// One document click listener for elements marked with data attributes (rows and
// buttons rendered as HTML). The nearest marked ancestor of the click decides, so a
// "⋯" button inside a server row opens the menu and does not select the row.
const actions = [];

// `attr` is the attribute name ("data-server"); `fn(element, event)` runs when it is set.
export function onDataClick(attr, fn) {
  actions.push([attr, fn]);
}

export function startDataClicks() {
  document.addEventListener("click", (e) => {
    const t = e.target.closest(actions.map(([attr]) => `[${attr}]`).join(","));
    if (!t) return;
    const hit = actions.find(([attr]) => t.getAttribute(attr));
    if (hit) hit[1](t, e);
  });
}
