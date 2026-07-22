import Foundation
import Network
import ReachWire

/// A cluster seen on the local network.
public struct DiscoveredCluster: Sendable {
    public let name: String
    public let endpoint: NWEndpoint
    public let txt: [String: String]
}

/// Browses `_reach._udp` on the local network.
public final class ClusterBrowser: Sendable {
    private let browser: NWBrowser
    public let clusters: AsyncStream<[DiscoveredCluster]>

    public init() {
        let parameters = NWParameters()
        parameters.includePeerToPeer = true
        browser = NWBrowser(
            for: .bonjourWithTXTRecord(type: Wire.bonjourService, domain: nil),
            using: parameters
        )
        let (stream, continuation) = AsyncStream<[DiscoveredCluster]>.makeStream()
        clusters = stream
        browser.browseResultsChangedHandler = { results, _ in
            let discovered = results.compactMap { result -> DiscoveredCluster? in
                guard case .service(let name, _, _, _) = result.endpoint else { return nil }
                var txt: [String: String] = [:]
                if case .bonjour(let record) = result.metadata {
                    txt = record.dictionary
                }
                return DiscoveredCluster(name: name, endpoint: result.endpoint, txt: txt)
            }
            continuation.yield(discovered)
        }
        browser.stateUpdateHandler = { state in
            if case .failed = state {
                continuation.finish()
            }
        }
        browser.start(queue: transportQueue)
    }

    public func cancel() {
        browser.cancel()
    }
}
