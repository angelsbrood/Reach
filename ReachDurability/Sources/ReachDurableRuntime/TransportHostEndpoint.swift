import Foundation
import ReachWire
import ReachTransport

/// Explicit loopback service. One admitted connection is processed serially;
/// every reconnect authenticates anew and gets a fresh fenced adapter.
public final class TransportHostEndpoint {
    private let worker = TransportHostWorker()
    public init() {}
    public func run(root: String, report: String?, progress: Bool, independent: Bool = false) async throws {
        try await worker.open(root: root, independent: independent)
        do {
            let identity = try await worker.call { $0.identity }
            let listener = try BoundedQUICListener(port: identity.selection.port, parameters: identity.parameters())
            do {
                try await listener.waitUntilReady()
                try TransportConnection.progress(.init(role: "host", stage: "listening"), enabled: progress)
                for try await stream in listener.streams {
                    if Task.isCancelled { await stream.cancelAndWait(); break }
                    let token = UUID()
                    var attached = false
                    do {
                        try await TransportConnection.deadline(.seconds(10)) {
                            try await stream.waitUntilReady()
                            _ = try identity.requirePeer(stream)
                            let hello = try await TransportConnection.read(stream).decode(Hello.self)
                            guard hello.versions == [2], hello.client.utf8.count <= 256 else { throw TransportRuntimeError.protocolRefused }
                            let ack = HelloAck(version: 2, cluster: identity.selection.application, models: [.init(id: TransportContract.model, displayName: "Local Llama", capabilities: ["durable"] )])
                            try await TransportConnection.send(FrameCodec.encode(ack, for: 2), on: stream)
                        }
                        let peer = try identity.requirePeer(stream)
                        let caps = try await worker.call { try $0.connect(token, peerDigest: peer) }
                        attached = true
                        try await TransportConnection.send(caps, on: stream)
                        var accepted = false
                        while !accepted {
                            let raw = try await TransportConnection.read(stream)
                            let responses = try await worker.call { try $0.receive(raw, token: token) }
                            for response in responses { try await TransportConnection.send(response, on: stream) }
                            guard let response = responses.first else { throw TransportRuntimeError.invalid }
                            switch try TransportConnection.message(response) {
                            case .accepted: accepted = true
                            case .opened: break
                            default: throw TransportRuntimeError.protocolRefused
                            }
                        }
                        while !stream.isClosed && !Task.isCancelled {
                            let publication = try await worker.call { try $0.publication(token, observe: progress) }
                            try TransportConnection.progress(.init(role: "host", stage: publication.bytes == nil ? "boundary" : "publishing", high: publication.high, nativeCalls: publication.nativeCalls, checkpoint: publication.checkpoint), enabled: progress)
                            if stream.isClosed || Task.isCancelled { break }
                            if let bytes = publication.bytes {
                                try await TransportConnection.send(bytes, on: stream)
                                if publication.terminal {
                                    // No terminal retirement receipt is part of this route.
                                    _ = try await TransportConnection.read(stream, timeout: .seconds(60))
                                    throw TransportRuntimeError.protocolRefused
                                }
                                let raw = try await TransportConnection.read(stream)
                                guard case .receipt = try DurableMessage.decode(raw, version: 2) else { throw TransportRuntimeError.protocolRefused }
                                let responses = try await worker.call { try $0.receive(raw, token: token) }
                                guard responses.count == 1, case .receiptAccepted = try TransportConnection.message(responses[0]) else { throw TransportRuntimeError.protocolRefused }
                                try await TransportConnection.send(responses[0], on: stream)
                            } else if publication.terminal { break }
                        }
                    } catch {
                        let transportLoss = error is BoundedTransportError || error is CancellationError
                        if attached && !transportLoss && !stream.isClosed && !Task.isCancelled {
                            // A returned host/store/preparation failure is a
                            // protocol refusal, not a fabricated provider ending
                            // or a transient disconnect to retry indefinitely.
                            try? await TransportConnection.send(FrameCodec.encode(ErrorFrame(code: "durable-unavailable", message: "Durable host operation unavailable."), for: 2), on: stream)
                        }
                        try? TransportConnection.progress(.init(role: "host", stage: transportLoss ? "disconnected" : "operation-failed"), enabled: progress)
                    }
                    // No new connection can mutate this owner before the prior
                    // stream is drained and its native attachment is fenced.
                    await stream.cancelAndWait()
                    if attached { try await worker.call { try $0.disconnect(token) } }
                }
                await listener.cancelAndWait()
            } catch { await listener.cancelAndWait(); throw error }
            let state = try await worker.call { $0.report(stage: "stopped") }
            try TransportContract.write(state, to: report)
            await worker.close()
        } catch {
            if let state = try? await worker.call({ $0.report(stage: "error") }) { try? TransportContract.write(state, to: report) }
            await worker.close(); throw error
        }
    }
    public func cancelLocal(root: String, report: String?, independent: Bool = false) async throws {
        try await worker.open(root: root, independent: independent)
        do {
            let state = try await worker.call { runtime in try runtime.cancelLocal(); return runtime.report(stage: "cancelled") }
            try TransportContract.write(state, to: report); await worker.close()
        } catch { await worker.close(); throw error }
    }
}
