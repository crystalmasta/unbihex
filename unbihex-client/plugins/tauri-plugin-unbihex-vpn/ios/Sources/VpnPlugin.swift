import NetworkExtension
import SwiftRs
import Tauri
import UIKit

class StartArgs: Decodable {
    var mtu: Int?
    var address: String?
    var prefix: Int?
    var dns: String?
    var session: String?
    var configJson: String
    var serverAddress: String?
}

/// Starts and stops the Unbihex Packet Tunnel extension.
///
/// The engine itself runs inside the extension (target `PacketTunnel`, bundle id
/// `<app bundle id>.tunnel`), which receives the engine config JSON through the
/// start options and the provider configuration.
class VpnPlugin: Plugin {
    private func loadManager(_ done: @escaping (NETunnelProviderManager?, Error?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error = error {
                done(nil, error)
                return
            }
            done(managers?.first ?? NETunnelProviderManager(), nil)
        }
    }

    private func tunnelBundleId() -> String {
        if let custom = Bundle.main.object(forInfoDictionaryKey: "UnbihexTunnelBundleId") as? String {
            return custom
        }
        return (Bundle.main.bundleIdentifier ?? "com.unbihex.client") + ".tunnel"
    }

    @objc public func start(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(StartArgs.self)
        loadManager { manager, error in
            guard let manager = manager else {
                invoke.reject(error?.localizedDescription ?? "Не удалось загрузить настройки VPN")
                return
            }
            let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
            proto.providerBundleIdentifier = self.tunnelBundleId()
            proto.serverAddress = args.serverAddress ?? "Unbihex"
            proto.providerConfiguration = ["config": args.configJson]
            proto.disconnectOnSleep = false
            manager.protocolConfiguration = proto
            manager.localizedDescription = args.session ?? "Unbihex"
            manager.isEnabled = true
            manager.saveToPreferences { error in
                if let error = error {
                    invoke.reject("Не удалось сохранить профиль VPN: \(error.localizedDescription)")
                    return
                }
                // Reload, otherwise the first start after saving fails with "configuration is stale".
                manager.loadFromPreferences { error in
                    if let error = error {
                        invoke.reject(error.localizedDescription)
                        return
                    }
                    do {
                        try manager.connection.startVPNTunnel(options: ["config": args.configJson as NSString])
                        invoke.resolve(["fd": NSNull()])
                    } catch {
                        invoke.reject("Не удалось запустить VPN: \(error.localizedDescription)")
                    }
                }
            }
        }
    }

    @objc public func stop(_ invoke: Invoke) throws {
        loadManager { manager, _ in
            manager?.connection.stopVPNTunnel()
            invoke.resolve()
        }
    }

    @objc public func status(_ invoke: Invoke) throws {
        NETunnelProviderManager.loadAllFromPreferences { managers, _ in
            let status = managers?.first?.connection.status ?? .invalid
            let state: String
            switch status {
            case .connected: state = "connected"
            case .connecting, .reasserting: state = "connecting"
            case .disconnecting: state = "disconnecting"
            case .disconnected: state = "disconnected"
            default: state = "invalid"
            }
            invoke.resolve([
                "active": status == .connected || status == .connecting || status == .reasserting,
                "state": state,
            ])
        }
    }
}

@_cdecl("init_plugin_unbihex_vpn")
func initPlugin() -> Plugin {
    return VpnPlugin()
}
