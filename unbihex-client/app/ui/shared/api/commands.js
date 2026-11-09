// Backend commands (app/src-tauri/src/lib.rs). Each returns the invoke promise as is.
import { invoke } from "./tauri.js";

// State and connection
export const getState = () => invoke("get_state");
export const getStatus = () => invoke("status");
export const connect = () => invoke("connect");
export const disconnect = () => invoke("disconnect");

// Settings
export const saveSettings = (settings) => invoke("save_settings", { settings });
export const defaultSettings = () => invoke("default_settings");
export const setPingMethod = (method) => invoke("set_ping_method", { method });

// Servers
export const pingServers = (ids) => invoke("ping", { ids });
export const selectServer = (id) => invoke("select_server", { id });
export const removeServer = (id) => invoke("remove_server", { id });
export const setServerAuto = (id, excluded) => invoke("set_server_auto", { id, excluded });
export const setServerFingerprint = (id, fingerprint) => invoke("set_server_fingerprint", { id, fingerprint });

// Auto-select templates
export const createTemplate = (name, servers) => invoke("create_template", { name, servers });
export const updateTemplate = (id, name, servers) => invoke("update_template", { id, name, servers });
export const deleteTemplate = (id) => invoke("delete_template", { id });
export const setTemplateServer = (id, server, member) => invoke("set_template_server", { id, server, member });

// Subscriptions and links
export const addInput = (text) => invoke("add_input", { text });
export const updateSubscription = (id) => invoke("update_subscription", { id });
export const updateAllSubscriptions = () => invoke("update_all");
export const editSubscription = (id, name, url, userAgent) => invoke("edit_subscription", { id, name, url, userAgent });
export const removeSubscription = (id) => invoke("remove_subscription", { id });

// Rule databases and ad-blocking lists
export const updateGeodata = () => invoke("update_geodata");
export const updateAdblock = () => invoke("update_adblock");
export const adblockPresets = () => invoke("adblock_presets");

// Platform
export const androidApps = () => invoke("android_apps");
export const relaunchAdmin = () => invoke("relaunch_admin");
export const relaunchAdminForAutostart = () => invoke("relaunch_admin", { autostart: true });
export const storeAppsLoopback = (allow) => invoke("store_apps_loopback", { allow });
export const openUrl = (url) => invoke("plugin:opener|open_url", { url });

// Log
export const getLogs = () => invoke("get_logs");
export const clearLogs = () => invoke("clear_logs");
