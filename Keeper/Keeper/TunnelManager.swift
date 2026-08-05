import Foundation
import NetworkExtension
import Observation

/// The keeper's tunnel organ, spike-grade: installs the packet-tunnel
/// provider with a WireGuard configuration staged as a file (the ceremony
/// replaces the file with enrollment over the wire). The system's own VPN
/// consent dialog on first save is a ceremony beat, not a bug.
@Observable @MainActor
final class TunnelManager {
    enum State: Equatable {
        case noConfiguration
        case notInstalled
        case installed(NEVPNStatus)
        case failed(String)
    }

    var state: State = .notInstalled
    var log: [String] = []

    /// Whether the tunnel rises on its own whenever this device has a network.
    ///
    /// A cache of the authority, not a preference. The real value is
    /// `NETunnelProviderManager.isOnDemandEnabled`, which the system owns and
    /// which a person can change from Settings behind this app's back — so it
    /// is re-read from the manager at every point that touches it, and never
    /// mirrored into storage of our own. It has to be a stored property all
    /// the same, because `NEVPNManager` is not observable and a computed one
    /// would never move the view.
    private(set) var risesOnItsOwn = false

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

    static let providerBundleID = "systems.reach.keeper.tunnel"

    private var stagedConfig: String? {
        guard let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?
            .appendingPathComponent("keeper-wg.conf"),
            let text = try? String(contentsOf: url, encoding: .utf8)
        else { return nil }
        return text
    }

    func bootstrap() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = managers.first
            if let manager {
                risesOnItsOwn = manager.isOnDemandEnabled
                state = .installed(manager.connection.status)
                observeStatus()
            } else if stagedConfig == nil {
                state = .noConfiguration
            } else {
                state = .notInstalled
            }
        } catch {
            state = .failed("\(error)")
        }
        append("bootstrap: \(state)")
    }

    /// Installs (or updates) the tunnel — first save triggers the system's
    /// VPN consent. If a tunnel is already running (e.g. a prior config),
    /// it is stopped first so the provider reloads the new configuration
    /// rather than keeping the stale one — starting an already-connected
    /// tunnel is otherwise a no-op.
    func install() async {
        guard let config = stagedConfig else {
            state = .noConfiguration
            return
        }
        // Nothing to install when the installed configuration is already this
        // one. That case is ordinary now rather than exotic: the phone keeps its
        // mesh key, so a re-pair against the same host produces a byte-identical
        // conf — and the first thing this function otherwise does is stop a
        // running tunnel, which would tear the mesh down and rebuild it for no
        // reason, mid-ceremony, on the one leg the demo is about.
        if let manager,
           let installed = (manager.protocolConfiguration as? NETunnelProviderProtocol)?
               .providerConfiguration?["wgQuickConfig"] as? String,
           installed == config {
            state = .installed(manager.connection.status)
            observeStatus()
            append("tunnel already carries this configuration — nothing to install")
            // A tunnel installed before this app could rule the away road has
            // no rules at all, and this early return is the ordinary path for
            // it: the conf is byte-identical on a re-pair, so nothing below
            // ever runs again. Give it the ruled default here or it would
            // never get one.
            if manager.onDemandRules?.isEmpty ?? true {
                await setRisesOnItsOwn(true)
            }
            return
        }
        do {
            let manager = self.manager ?? NETunnelProviderManager()
            let firstInstall = self.manager == nil
            if manager.connection.status == .connected || manager.connection.status == .connecting {
                manager.connection.stopVPNTunnel()
                append("stopping stale tunnel before reinstall")
                try? await Task.sleep(for: .seconds(1))
            }
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.providerBundleID
            proto.providerConfiguration = ["wgQuickConfig": config]
            proto.serverAddress = "Reach mesh"
            manager.protocolConfiguration = proto
            manager.localizedDescription = "Reach"
            manager.isEnabled = true
            // The rules are always present so the flag has something to obey.
            // The flag itself defaults on exactly once, at first install — a
            // person who has turned this off has ruled, and a re-pair is not a
            // reason to overrule them.
            manager.onDemandRules = [Self.riseOnAnyNetwork()]
            manager.isOnDemandEnabled = firstInstall ? true : manager.isOnDemandEnabled
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            self.manager = manager
            risesOnItsOwn = manager.isOnDemandEnabled
            state = .installed(manager.connection.status)
            observeStatus()
            append("tunnel installed")
        } catch {
            state = .failed("install: \(error)")
            append("install failed: \(error)")
        }
    }

    /// Connect on any interface — the rule that makes a cold dial from a café
    /// possible at all, because a granted app cannot raise this tunnel and
    /// must not be able to. Something has to want the road up, and with this
    /// rule the road is up whenever the device has a network, including after
    /// a reboot where nobody has opened the Keeper.
    private static func riseOnAnyNetwork() -> NEOnDemandRule {
        let rule = NEOnDemandRuleConnect()
        rule.interfaceTypeMatch = .any
        return rule
    }

    /// Rules the away road up or down, without touching the configuration.
    ///
    /// Its own save, because `install()` is the only other path that saves and
    /// it returns early when the staged conf is unchanged — which is the
    /// ordinary case, so a toggle that only set the flag there would take
    /// effect on a re-pair and never otherwise.
    func setRisesOnItsOwn(_ on: Bool) async {
        guard let manager else { return }
        do {
            manager.onDemandRules = [Self.riseOnAnyNetwork()]
            manager.isOnDemandEnabled = on
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            risesOnItsOwn = manager.isOnDemandEnabled
            append(risesOnItsOwn
                ? "away road on — the tunnel rises whenever this device has a network"
                : "away road off — the tunnel is up only when it is started here")
        } catch {
            // Not `.failed`: the tunnel is installed and working, and only the
            // ruling did not take. Say so and put the switch back where the
            // system actually has it.
            risesOnItsOwn = manager.isOnDemandEnabled
            append("away road unchanged: \(error)")
        }
    }

    func start() {
        guard let manager else { return }
        do {
            try manager.connection.startVPNTunnel()
            append("start requested")
        } catch {
            append("start failed: \(error)")
        }
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
        append("stop requested")
    }

    private func observeStatus() {
        guard observer == nil, let connection = manager?.connection else { return }
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: connection, queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, let manager = self.manager else { return }
                // A status change says how the tunnel is doing, not whether
                // it installed. Overwriting .failed here erased the only
                // record that it never did — and the next status notification
                // always arrives, so the failure could not survive to be read.
                if case .failed = self.state { return }
                self.state = .installed(manager.connection.status)
                self.append("status: \(manager.connection.status.label)")
            }
        }
    }

    private func append(_ line: String) {
        log.append(line)
        print("[keeper] \(line)")
    }
}

extension NEVPNStatus {
    var label: String {
        switch self {
        case .invalid: "invalid"
        case .disconnected: "disconnected"
        case .connecting: "connecting"
        case .connected: "connected"
        case .reasserting: "reasserting"
        case .disconnecting: "disconnecting"
        @unknown default: "unknown"
        }
    }
}
