import assert from "node:assert/strict";
import test from "node:test";

let elements;
let calls;
let handler;
let update;
let install;
const checkInterval = globalThis.setInterval;
globalThis.window = {
  __TAURI__: {
    core: {
      async invoke(name, args) {
        calls.push([name, args]);
        if (name === "check_release_update") return update;
        if (name === "install_release_update") return install();
        if (name === "plugin:opener|open_url") return;
        throw new Error(name);
      },
    },
    event: { listen() {} },
  },
};
globalThis.document = { querySelector(selector) { return elements[selector]; } };

const { initAppUpdate } = await import("../../app/ui/features/app-update/index.js");

async function mount(release, installUpdate) {
  update = release;
  install = installUpdate;
  calls = [];
  elements = {
    "#app-update": { hidden: true },
    "#app-update-status": { textContent: "" },
    "#app-update-action": {
      textContent: "",
      disabled: false,
      addEventListener(event, fn) { assert.equal(event, "click"); handler = fn; },
    },
  };
  globalThis.setInterval = () => 1;
  try {
    initAppUpdate();
  } finally {
    globalThis.setInterval = checkInterval;
  }
  await new Promise(setImmediate);
}

test("shows a release and requests installation only after a click", async () => {
  let finished;
  await mount({ version: "0.3.0", can_install: true }, () => new Promise(resolve => { finished = resolve; }));
  assert.equal(elements["#app-update"].hidden, false);
  assert.match(elements["#app-update-status"].textContent, /0\.3\.0/);
  assert.equal(elements["#app-update-action"].textContent, "Обновить");
  assert.equal(calls.length, 1);
  const clicked = handler();
  await handler();
  assert.equal(elements["#app-update-action"].disabled, true);
  assert.deepEqual(calls[1], ["install_release_update", { version: "0.3.0" }]);
  assert.equal(calls.length, 2);
  finished();
  await clicked;
  assert.match(elements["#app-update-status"].textContent, /Запускается установка/);
});

test("can open a release when there is no matching installer", async () => {
  const url = "https://github.com/crystalmasta/unbihex/releases/tag/v0.3.0";
  await mount({ version: "0.3.0", url, can_install: false });
  assert.equal(elements["#app-update-action"].textContent, "Открыть релиз");
  await handler();
  assert.deepEqual(calls[1], ["plugin:opener|open_url", { url }]);
});

test("hides the update panel when the installed version is current", async () => {
  await mount(null);
  assert.equal(elements["#app-update"].hidden, true);
});
