import SwiftUI

@main
struct KeeperApp: App {
    @Environment(\.scenePhase) private var scenePhase
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
            // The desk announces a parked request once, to whoever is
            // subscribed at that instant — and while the operator is in the
            // asking app, this console is subscribed but suspended, so the
            // announce is delivered to a stream nobody is draining. Coming
            // back to the foreground is the moment to become a new
            // subscriber and collect the replay. `onChange` does not fire
            // for the initial value, so launch still dials exactly once.
            .onChange(of: scenePhase) { _, phase in
                if phase == .active { console.refresh() }
            }
        }
    }
}
