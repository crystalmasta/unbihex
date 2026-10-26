import NetworkExtension
import os.log

/// Runs the Unbihex engine (libunbihex.a from crates/unbihex-ffi) inside the
/// Network Extension process. The app passes the engine config JSON through the
/// start options (and saves it in providerConfiguration for on-demand restarts).
class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = OSLog(subsystem: "com.unbihex.client.tunnel", category: "tunnel")
    private var handle: Int32 = 0

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let fromOptions = options?["config"] as? String
        let fromProfile = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["config"] as? String
        guard let config = fromOptions ?? fromProfile, !config.isEmpty else {
            completionHandler(tunnelError("Нет конфигурации: подключитесь из приложения Unbihex"))
            return
        }

        // Must match the TUN inbound of the config: 10.199.233.1/30 and
        // fdb5:2f3c:9a17::1/126, fake DNS 10.199.233.2.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.199.233.2")
        let ipv4 = NEIPv4Settings(addresses: ["10.199.233.1"], subnetMasks: ["255.255.255.252"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        // IPv6 goes into the tunnel too, so it cannot bypass the VPN.
        let ipv6 = NEIPv6Settings(addresses: ["fdb5:2f3c:9a17::1"], networkPrefixLengths: [126])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6
        let dns = NEDNSSettings(servers: ["10.199.233.2"])
        dns.matchDomains = [""] // all queries go to the fake DNS
        settings.dnsSettings = dns
        settings.mtu = 1500

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                completionHandler(error)
                return
            }
            guard let fd = self.tunnelFileDescriptor else {
                completionHandler(self.tunnelError("Не найден дескриптор utun"))
                return
            }
            let h = config.withCString { unbihex_start($0, fd, nil, nil) }
            if h <= 0 {
                let msg = String(cString: unbihex_last_error())
                os_log("unbihex_start failed (%d): %{public}@", log: self.log, type: .error, h, msg)
                completionHandler(self.tunnelError("Ядро не запустилось: \(msg)"))
                return
            }
            self.handle = h
            os_log("unbihex %{public}@ started", log: self.log, type: .info, String(cString: unbihex_version()))
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        if handle > 0 {
            _ = unbihex_stop(handle)
            handle = 0
        }
        completionHandler()
    }

    /// Traffic counters for the app: send any message, get "up,down,directUp,directDown".
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        var pu: UInt64 = 0, pd: UInt64 = 0, du: UInt64 = 0, dd: UInt64 = 0
        _ = unbihex_stats(&pu, &pd, &du, &dd)
        completionHandler?("\(pu),\(pd),\(du),\(dd)".data(using: .utf8))
    }

    private func tunnelError(_ text: String) -> NSError {
        NSError(domain: "com.unbihex.tunnel", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }

    /// The utun descriptor is not exposed by the API: find it among open fds.
    private var tunnelFileDescriptor: Int32? {
        var buf = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        for fd: Int32 in 0...1024 {
            var len = socklen_t(buf.count)
            // SYSPROTO_CONTROL = 2, UTUN_OPT_IFNAME = 2
            if getsockopt(fd, 2, 2, &buf, &len) == 0 && String(cString: buf).hasPrefix("utun") {
                return fd
            }
        }
        return nil
    }
}
