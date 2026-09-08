import Foundation
import Network
import ReachWire
import ReachTransport

public final class TransportClientEndpoint {
    private let runtime: TransportClientRuntime
    public init(root: String) throws { runtime = try TransportClientRuntime(root: root) }
    public func run(requestPath: String?, report: String?, progress: Bool) async throws {
        do {
            let request = try requestPath.map { try LocalDurableRuntime.request(from: $0) }
            if request != nil { try runtime.requireEmpty() }
            else { guard try runtime.registered() else { throw TransportRuntimeError.unavailable } }
            var first = true, loss: ContinuousClock.Instant?, backoff = Duration.milliseconds(250)
            let clock = ContinuousClock()
            while true {
                try Task.checkCancellation()
                let beginning = first && request != nil
                let token = UUID()
                var stream: BoundedQUICStream?
                do {
                    var allowance = Duration.seconds(10)
                    if let loss {
                        let remaining = loss.duration(to: clock.now)
                        guard remaining < .seconds(60) else { throw TransportRuntimeError.reconnectExhausted }
                        allowance = min(allowance, .seconds(60) - remaining, try runtime.remainingAuthority())
                    } else if !beginning { allowance = min(allowance, try runtime.remainingAuthority()) }
                    let attemptStarted = clock.now
                    let identity = runtime.identity
                    let connection = try await BoundedQUICStream.open(endpoint: .hostPort(host: "127.0.0.1", port: .init(rawValue: runtime.selection.port)!), parameters: identity.parameters(), timeout: allowance)
                    stream = connection
                    let peer = try identity.requirePeer(connection)
                    let handshakeRemaining = allowance - attemptStarted.duration(to: clock.now)
                    guard handshakeRemaining > .zero else { throw BoundedTransportError.timeout }
                    let caps = try await TransportConnection.deadline(handshakeRemaining) {
                        try await TransportConnection.send(FrameCodec.encode(Hello(versions: [2], client: TransportContract.application), for: 2), on: connection)
                        let ack = try await TransportConnection.read(connection).decode(HelloAck.self)
                        guard ack.version == 2, ack.cluster == TransportContract.application,
                              ack.models.map(\.id) == [TransportContract.model], ack.addrs == nil, ack.port == nil, ack.roads == nil, ack.relayRoads == nil else { throw TransportRuntimeError.protocolRefused }
                        return try await TransportConnection.read(connection)
                    }
                    try runtime.connect(token, peer: peer, begin: beginning)
                    guard case .capabilities = try runtime.receive(caps, token: token) else { throw TransportRuntimeError.protocolRefused }
                    var acceptanceAllowance = Duration.seconds(10)
                    if let loss {
                        acceptanceAllowance = min(acceptanceAllowance, .seconds(60) - loss.duration(to: clock.now), try runtime.remainingAuthority())
                        guard acceptanceAllowance > .zero else { throw TransportRuntimeError.reconnectExhausted }
                    }
                    try await TransportConnection.deadline(acceptanceAllowance) { [self] in
                    if beginning {
                        try await TransportConnection.send(runtime.open(token), on: connection)
                        guard case .opened = try runtime.receive(await TransportConnection.read(connection), token: token) else { throw TransportRuntimeError.protocolRefused }
                        try await TransportConnection.send(runtime.begin(request!, token: token), on: connection)
                    } else {
                        try await TransportConnection.send(runtime.recover(token), on: connection)
                    }
                    guard case .accepted = try runtime.receive(await TransportConnection.read(connection), token: token) else { throw TransportRuntimeError.protocolRefused }
                    guard try runtime.registered() else { throw TransportRuntimeError.unknownLost }
                    }
                    loss = nil; backoff = .milliseconds(250); first = false
                    try TransportConnection.progress(.init(role: "client", stage: "registered"), enabled: progress)
                    // A terminal recovery can have no suffix because its durable
                    // witness already covers the terminal. Do not send retirement.
                    while !(try runtime.witness(token).terminal) {
                        let raw = try await TransportConnection.read(connection, timeout: .seconds(60))
                        guard case .batch = try runtime.receive(raw, token: token) else { throw TransportRuntimeError.protocolRefused }
                        let witness = try runtime.witness(token)
                        try TransportConnection.progress(.init(role: "client", stage: "batch-persisted", high: witness.high), enabled: progress)
                        if witness.terminal { break }
                        try await TransportConnection.send(runtime.receipt(token), on: connection)
                        try TransportConnection.progress(.init(role: "client", stage: "receipt-sent", high: witness.high), enabled: progress)
                        guard case .receiptAccepted = try runtime.receive(await TransportConnection.read(connection), token: token) else { throw TransportRuntimeError.protocolRefused }
                        try TransportConnection.progress(.init(role: "client", stage: "receipt-accepted", high: witness.high), enabled: progress)
                    }
                    await connection.cancelAndWait(); runtime.disconnect(token)
                    try TransportContract.write(runtime.report(stage: "settled"), to: report)
                    runtime.close(); return
                } catch {
                    let detectedLoss = clock.now
                    await stream?.cancelAndWait(); runtime.disconnect(token)
                    if Task.isCancelled { throw CancellationError() }
                    // Only transport loss is retryable. Pin/protocol/root/store
                    // errors stop; incomplete registration never causes begin replay.
                    guard let transport = error as? BoundedTransportError,
                          transport == .closed || transport == .timeout else { throw error }
                    guard try runtime.registered() else { throw TransportRuntimeError.unknownLost }
                    first = false
                    if loss == nil { loss = detectedLoss }
                    let remaining = .seconds(60) - loss!.duration(to: clock.now)
                    guard remaining > .zero else { throw TransportRuntimeError.reconnectExhausted }
                    let delay = min(backoff, remaining, try runtime.remainingAuthority())
                    try TransportConnection.progress(.init(role: "client", stage: "reconnecting"), enabled: progress)
                    try await Task.sleep(for: delay)
                    runtime.retried(); backoff = min(backoff * 2, .seconds(2))
                }
            }
        } catch {
            let stage: String
            switch error {
            case TransportRuntimeError.unknownLost: stage = "unknown-lost"
            case TransportRuntimeError.reconnectExhausted: stage = "reconnect-exhausted"
            case is CancellationError: stage = "stopped"
            default: stage = "error"
            }
            if let state = try? runtime.report(stage: stage) { try? TransportContract.write(state, to: report) }
            runtime.close(); throw error
        }
    }
}
