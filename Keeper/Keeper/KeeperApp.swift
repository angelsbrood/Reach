import SwiftUI

@main
struct KeeperApp: App {
    @State private var tunnel = TunnelManager()
    @State private var console = GrantConsole()

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                ScrollView {
                    VStack(alignment: .leading, spacing: 24) {
                        CeremonyView(tunnel: tunnel)
                        Divider()
                        GrantConsoleView(console: console)
                        Divider()
                        TunnelView(manager: tunnel)
                    }
                    .padding()
                }
                .navigationTitle("Keeper")
            }
            .task { await tunnel.bootstrap() }
            .task { console.start() }
        }
    }
}
