import NetworkExtension
import WireGuardKit
import os

/// The device end of the mesh: WireGuardKit inside the system's packet
/// tunnel. Configuration arrives as wg-quick text in the provider
/// configuration (staged by hand for the spike; provisioned by the
/// ceremony thereafter).
class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = Logger(subsystem: "systems.reach.keeper.tunnel", category: "provider")

    private lazy var adapter = WireGuardAdapter(with: self) { _, message in
        Logger(subsystem: "systems.reach.keeper.tunnel", category: "wg").info("\(message, privacy: .public)")
    }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard
            let proto = protocolConfiguration as? NETunnelProviderProtocol,
            let config = proto.providerConfiguration?["wgQuickConfig"] as? String,
            let tunnelConfiguration = try? TunnelConfiguration(fromWgQuickConfig: config, called: "reach")
        else {
            log.error("missing or malformed wgQuickConfig")
            completionHandler(NEVPNError(.configurationInvalid))
            return
        }
        adapter.start(tunnelConfiguration: tunnelConfiguration) { [log] error in
            if let error {
                log.error("adapter start failed: \(error.localizedDescription, privacy: .public)")
            } else {
                log.info("adapter up")
            }
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        adapter.stop { _ in completionHandler() }
    }
}
