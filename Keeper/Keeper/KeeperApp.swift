import SwiftUI

@main
struct KeeperApp: App {
    @State private var tunnel = TunnelManager()

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                ScrollView {
                    VStack(alignment: .leading, spacing: 24) {
                        CeremonyView(tunnel: tunnel)
                        Divider()
                        TunnelView(manager: tunnel)
                    }
                    .padding()
                }
                .navigationTitle("Keeper")
            }
            .task { await tunnel.bootstrap() }
        }
    }
}
