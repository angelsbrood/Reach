import SwiftUI

struct TunnelView: View {
    @State private var manager = TunnelManager()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            HStack {
                Button("Install tunnel") { Task { await manager.install() } }
                    .buttonStyle(.borderedProminent)
                Button("Start") { manager.start() }
                Button("Stop") { manager.stop() }
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(manager.log.enumerated()), id: \.offset) { _, line in
                        Text(line).font(.caption.monospaced())
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding()
        .task { await manager.bootstrap() }
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
