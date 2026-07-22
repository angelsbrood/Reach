import ReachTransport
import SwiftUI

struct ContentView: View {
    @State private var model = ExampleModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            HStack {
                TextField("Host", text: $model.host)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 200)
                TextField("Model", text: $model.modelID)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 160)
            }
            if !model.clusters.isEmpty {
                Text("On this network: " + model.clusters.map(\.name).joined(separator: ", "))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            HStack {
                TextField("Prompt", text: $model.prompt, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .lineLimit(1...3)
                    .onSubmit { model.send() }
                Button(model.isStreaming ? "…" : "Send") { model.send() }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.isStreaming)
            }
            ScrollView {
                Text(model.output.isEmpty ? " " : model.output)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
            .frame(minHeight: 160)
            Text(model.status)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding()
        .task { await model.bootstrap() }
    }

    @ViewBuilder private var header: some View {
        switch model.identityState {
        case .registered(let cluster):
            Label("Paired with \(cluster)", systemImage: "checkmark.seal")
                .foregroundStyle(.green)
        case .missing:
            Label("No identity — issue one with reachd ca issue-client", systemImage: "exclamationmark.triangle")
                .foregroundStyle(.orange)
        case .failed(let message):
            Label("Identity failed: \(message)", systemImage: "xmark.seal")
                .foregroundStyle(.red)
                .lineLimit(2)
        }
    }
}

#Preview {
    ContentView()
}
