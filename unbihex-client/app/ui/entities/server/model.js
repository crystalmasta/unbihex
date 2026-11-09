import { store } from "../../shared/model/index.js";

// Servers whose ping is being measured.
export const pinging = new Set();

export const findServer = (id) => store.S.data.servers.find((x) => x.id === id);

export function selectedServer() {
  const S = store.S;
  return S.data.servers.find((s) => s.id === S.data.selected) || null;
}

// TLS fingerprint of one server: kept across subscription updates, like the auto-select marks.
const FP_PROTOCOLS = ["vless", "vmess", "trojan", "trusttunnel", "naive"];

export const hasFp = (s) => !s.unsupported && FP_PROTOCOLS.includes(s.protocol);

// TCP and ICMP only need the server address, so they also test unsupported servers.
export const pingUsesProtocol = () => ["proxy_get", "proxy_head"].includes(store.S.data.settings.ping_method);
