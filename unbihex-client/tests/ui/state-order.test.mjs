import assert from "node:assert/strict";
import test, { beforeEach } from "node:test";

const requests = [];
globalThis.window = {
  __TAURI__: {
    core: {
      invoke(command) {
        return new Promise(resolve => requests.push({ command, resolve }));
      },
    },
    event: { listen() {} },
  },
};
globalThis.document = { body: { classList: { toggle() {} } } };

const { onRender, refresh, refreshStatus, store } = await import("../../app/ui/shared/model/index.js");
onRender("home", () => {});
beforeEach(() => {
  requests.length = 0;
  store.S = null;
  store.busy = false;
});

const answer = (index, command, response) => {
  assert.equal(requests[index].command, command);
  requests[index].resolve(response);
};

test("a late full snapshot cannot overwrite a more recent one", async () => {
  const older = refresh();
  const newer = refresh();
  answer(1, "get_state", { data: "current", status: { connected: true } });
  await newer;
  answer(0, "get_state", { data: "old", status: { connected: false } });
  await older;
  assert.equal(store.S.data, "current");
  assert.equal(store.S.status.connected, true);
});

test("a stale poll cannot replace status from a newer full refresh", async () => {
  store.S = { status: { connected: false } };
  const poll = refreshStatus();
  const full = refresh();
  answer(1, "get_state", { status: { connected: true } });
  await full;
  answer(0, "status", { connected: false });
  assert.equal(await poll, false);
  assert.equal(store.S.status.connected, true);
});

test("a full refresh can update data without reverting a newer status poll", async () => {
  store.S = { data: "old", status: { connected: false } };
  const full = refresh();
  const poll = refreshStatus();
  answer(1, "status", { connected: true });
  assert.equal(await poll, true);
  answer(0, "get_state", { data: "current", status: { connected: false } });
  await full;
  assert.equal(store.S.data, "current");
  assert.equal(store.S.status.connected, true);
});
