import SwiftUI

struct TunnelView: View {
    @Bindable var manager: TunnelManager

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            HStack {
                Button("Install tunnel") { Task { await manager.install() } }
                    .buttonStyle(.borderedProminent)
                Button("Start") { manager.start() }
                Button("Stop") { manager.stop() }
            }
            awayRoad
            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(manager.log.enumerated()), id: \.offset) { _, line in
                        Text(line).font(.caption.monospaced())
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    /// The person's ruling on whether this device stays reachable away from
    /// home. Both costs are stated rather than implied: the keepalive, and
    /// that the mesh range belongs to the tunnel while it is up.
    @ViewBuilder private var awayRoad: some View {
        VStack(alignment: .leading, spacing: 4) {
            Toggle(
                "Stay reachable away from home",
                isOn: Binding(
                    get: { manager.risesOnItsOwn },
                    set: { on in Task { await manager.setRisesOnItsOwn(on) } }
                )
            )
            Text("""
                The mesh rises on its own whenever this device has a network, so a granted app can \
                reach the cluster from anywhere — including after a restart, without opening Keeper. \
                It costs a keepalive every 25 seconds, and while the tunnel is up the 10.86.0.0/24 \
                range belongs to it.
                """)
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .disabled(!isInstalled)
    }

    private var isInstalled: Bool {
        if case .installed = manager.state { return true }
        return false
    }

    @ViewBuilder private var header: some View {
        switch manager.state {
        case .noConfiguration:
            Label("No staged configuration (Documents/keeper-wg.conf)", systemImage: "exclamationmark.triangle")
                .foregroundStyle(.orange)
        case .notInstalled:
            Label("Configuration staged — tunnel not installed", systemImage: "circle.dashed")
        case .installed(let status):
            Label("Tunnel \(status.label)", systemImage: status == .connected ? "lock.shield.fill" : "lock.shield")
                .foregroundStyle(status == .connected ? .green : .primary)
        case .failed(let message):
            Label(message, systemImage: "xmark.octagon")
                .foregroundStyle(.red)
                .lineLimit(3)
        }
    }
}
