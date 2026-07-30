import Foundation

/// Enough of a wg-quick config to answer three questions: which key does this
/// file claim the host is, how many peers does it admit, and which key does each
/// peer hold under which address. The third one is what lets doctor compare the
/// conf against the device registry by key rather than by count — a count says a
/// re-paired device has a road when what the file actually holds is the block it
/// walked in with.
///
/// The line discipline is taken from the parser already vendored in this
/// repository (`Keeper/PacketTunnel/TunnelConfiguration+WgQuickConfig.swift`,
/// itself upstream WireGuardKit) rather than invented, because every place the
/// two could disagree is a place doctor would report a fault in a file that
/// works. In particular:
///
/// - **The value starts after the FIRST `=`.** A base64 key is 44 characters
///   ending in one `=` of padding, so a rule that takes the last separator
///   reads every real key as empty. That is not a hypothetical: it is the bug
///   this parser exists to not have.
/// - **Keys and section headers are case-insensitive.** `privatekey` and
///   `[interface]` are legal, and wg-quick reads them with `nocasematch`.
/// - **A `#` begins a comment and is stripped before anything else**, so
///   `# see [Interface] above` is not a section.
/// - **`PrivateKey` only counts inside `[Interface]`.** Any `[`-headed line
///   ends the current section, and a key under `[Peer]` is a peer's business.
///
/// Where it deliberately differs from the vendored parser: it does not reject
/// unrecognized keys. WireGuardKit refuses `PostUp`, `Table` and `SaveConfig`
/// because iOS cannot honour them; wg-quick on this host accepts them all, and
/// a diagnostic that refused to read a working file would be worse than the
/// silence it replaces.
struct WireGuardConf {
    enum Trouble: Error, CustomStringConvertible {
        case multipleInterfaceSections(Int)

        var description: String {
            switch self {
            case .multipleInterfaceSections(let count):
                "the file has \(count) [Interface] sections; wg-quick accepts one"
            }
        }
    }

    /// Attributes of the `[Interface]` section, keys lowercased. Empty when
    /// the file has no such section at all.
    let interface: [String: String]
    let hasInterfaceSection: Bool
    /// One dictionary per `[Peer]` block, in file order, keys lowercased.
    let peers: [[String: String]]

    var peerCount: Int { peers.count }

    var privateKey: String? { interface["privatekey"] }

    /// The `AllowedIPs` a peer block claims, split and trimmed. wg-quick takes a
    /// comma-separated list, and the daemon writes exactly one `/32`.
    static func allowedIPs(of peer: [String: String]) -> [String] {
        (peer["allowedips"] ?? "")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// Peer public keys as raw bytes, keyed nowhere — compared as bytes rather
    /// than as strings because two spellings of one key are still one key, and a
    /// diagnostic that reports a fault over whitespace is worse than no
    /// diagnostic. Same rule the host-key check already follows.
    static func publicKey(of peer: [String: String]) -> Data? {
        guard let text = peer["publickey"] else { return nil }
        return Data(base64Encoded: text.trimmingCharacters(in: .whitespaces))
            .flatMap { $0.count == 32 ? $0 : nil }
    }

    static func parse(_ text: String) throws -> WireGuardConf {
        enum Section { case none, interface, peer }

        var section = Section.none
        var interface: [String: String] = [:]
        var interfaceSections = 0
        var peers: [[String: String]] = []

        for rawLine in text.split(omittingEmptySubsequences: false, whereSeparator: { $0.isNewline }) {
            let uncommented = rawLine.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0]
            let line = uncommented.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty else { continue }

            if line.hasPrefix("[") {
                switch line.lowercased() {
                case "[interface]":
                    section = .interface
                    interfaceSections += 1
                case "[peer]":
                    section = .peer
                    peers.append([:])
                default:
                    section = .none
                }
                continue
            }

            guard section != .none, let equals = line.firstIndex(of: "=") else { continue }
            let key = line[..<equals].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = line[line.index(after: equals)...].trimmingCharacters(in: .whitespacesAndNewlines)
            // First wins in both sections, so a duplicate cannot quietly replace
            // the real key — and in a peer block the rule is per block, not per
            // file, because every block has its own PublicKey.
            switch section {
            case .interface:
                if interface[key] == nil { interface[key] = value }
            case .peer:
                if peers[peers.count - 1][key] == nil { peers[peers.count - 1][key] = value }
            case .none:
                continue
            }
        }

        guard interfaceSections <= 1 else {
            throw Trouble.multipleInterfaceSections(interfaceSections)
        }
        return WireGuardConf(
            interface: interface,
            hasInterfaceSection: interfaceSections == 1,
            peers: peers
        )
    }
}
