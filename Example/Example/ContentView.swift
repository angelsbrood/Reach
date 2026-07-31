import ReachTransport
import SwiftUI

struct ContentView: View {
    @State private var model = ExampleModel()

    /// Zero-height marker at the end of the transcript; the streaming view
    /// scrolls to this rather than to the text, which has no stable id.
    private static let streamTail = "stream-tail"

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
            // The stream follows itself down, so nobody touches the phone
            // while it is being filmed.
            //
            // ⚠️ `.defaultScrollAnchor(.bottom, for: .sizeChanges)` was tried
            // first and does NOT do this: it preserves whatever anchor the
            // scroll view currently has, and the view starts at the top with
            // empty content — so "preserve" means "stay at the top" and the
            // text piles up out of frame. Measured on device, not reasoned
            // about. Scrolling to an explicit tail marker is unconditional.
            //
            // The .onChange adds no invalidation the body did not already
            // have: it renders `model.output`, so it re-evaluates per chunk
            // regardless.
            ScrollViewReader { proxy in
                ScrollView {
                    Text(model.output.isEmpty ? " " : model.output)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                    Color.clear
                        .frame(height: 1)
                        .id(Self.streamTail)
                }
                .frame(minHeight: 160)
                .onChange(of: model.output) {
                    // No animation: at ~100 tokens/second an animated scroll
                    // per chunk fights itself and reads as stutter on camera.
                    proxy.scrollTo(Self.streamTail, anchor: .bottom)
                }
            }
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
            // Named when the name is known, and plainly "Paired" when it is not.
            // Never a stand-in: the header's whole job is to say what the app is
            // actually attached to.
            Label(cluster.map { "Paired with \($0)" } ?? "Paired", systemImage: "checkmark.seal")
                .foregroundStyle(.green)
        case .missing:
            Label("Not paired yet — the first send asks your keeper", systemImage: "hand.raised")
                .foregroundStyle(.secondary)
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
