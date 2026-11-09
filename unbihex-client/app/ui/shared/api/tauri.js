// The only module that touches the Tauri globals (withGlobalTauri in tauri.conf.json).
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

export { invoke, listen };
