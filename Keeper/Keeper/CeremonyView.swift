import SwiftUI

/// One gesture, two keys: scan, and walk away paired.
struct CeremonyView: View {
    enum Phase: Equatable {
        case idle
        case scanning
        case enrolling
        case paired(cluster: String, meshIP: String, applyPending: Bool)
        case failed(String)
    }

    @State private var phase: Phase = .idle
    @Bindable var tunnel: TunnelManager

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            switch phase {
            case .idle:
                Button {
                    phase = .scanning
                } label: {
                    Label("Scan to pair", systemImage: "qrcode.viewfinder")
                        .font(.title3)
                }
                .buttonStyle(.borderedProminent)
            case .scanning:
                ScannerView { code in
                    phase = .enrolling
                    Task { await enroll(code) }
                }
                .frame(minHeight: 320)
                .clipShape(RoundedRectangle(cornerRadius: 12))
            case .enrolling:
                HStack(spacing: 12) {
                    ProgressView()
                    Text("Enrolling — issuing your certificate, joining the mesh…")
                }
            case .paired(let cluster, let meshIP, let applyPending):
                Label("Paired with \(cluster)", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(.green)
                    .font(.title3)
                Text("Device certificate in the Secure Enclave. Mesh address \(meshIP).")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                if applyPending {
                    // The host writes the peer block; loading it is the
                    // operator's one visible sudo, and the daemon cannot see the
                    // interface to know whether it happened. Saying "paired"
                    // without saying this is how a phone leaves the room
                    // believing in a mesh that is not carrying anything yet.
                    Label(
                        "The host has your key but has not loaded it yet — it needs one wg-quick down/up before the mesh carries anything.",
                        systemImage: "exclamationmark.triangle"
                    )
                    .font(.callout)
                    .foregroundStyle(.orange)
                }
            case .failed(let message):
                Label(message, systemImage: "xmark.octagon")
                    .foregroundStyle(.red)
                Button("Try again") { phase = .idle }
            }
        }
    }

    private func enroll(_ code: String) async {
        do {
            let outcome = try await EnrollmentClient.enroll(
                qrText: code,
                deviceName: UIDevice.current.name
            )
            // The tunnel half: stage the ceremony's config and install with
            // the system's consent.
            let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("keeper-wg.conf")
            try outcome.wgQuickConfig.write(to: url, atomically: true, encoding: .utf8)
            await tunnel.install()
            // "Paired" is a claim about the mesh, not about the certificate,
            // so it waits until the tunnel is actually installed. install()
            // reports failure by setting its own state and returning normally
            // — nothing throws — and the LAN leg never touches wg, so an
            // uninstalled tunnel stays invisible until the walk-out, which is
            // the worst possible moment to discover it.
            guard case .installed = tunnel.state else {
                phase = .failed("Certificate issued, but the tunnel did not install: \(tunnel.state). The mesh will not carry anything until this is fixed.")
                return
            }
            tunnel.start()
            phase = .paired(
                cluster: outcome.clusterName,
                meshIP: outcome.assignedIP,
                applyPending: outcome.applyPending
            )
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }
}
