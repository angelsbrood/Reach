import Foundation
import Network
import Security
import ReachIdentity
import ReachTransport
import ReachWire
import RequestPreparationContract

final class TransportIdentity {
    let role: TransportRole, selection: TransportSelectionBinding
    private let identity: SecIdentity, ca: SecCertificate
    init(root: String, selection: TransportSelectionBinding, audit: TransportRoleAudit) throws {
        role = selection.role; self.selection = selection
        let bytes = try LocalFiles.read(root + "/" + role.rawValue + "/identity.p12", maximum: 1 << 20)
        guard PreparationEncoding.hash(bytes) == selection.archiveDigest else { throw TransportRuntimeError.peer }
        audit.tls()
        identity = try IdentityStore.identity(fromPKCS12: bytes, passphrase: TransportContract.archivePassphrase)
        ca = try IdentityStore.certificate(fromDER: selection.pins.caDER)
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate,
              PreparationEncoding.hash(SecCertificateCopyData(certificate) as Data) == (role == .host ? selection.pins.hostLeaf : selection.pins.clientLeaf) else { throw TransportRuntimeError.peer }
    }
    func parameters() -> NWParameters {
        let options: NWProtocolQUIC.Options
        if role == .host {
            options = TLSBuilder.serverOptions(alpn: Wire.alpn, identity: identity, clientTrustRoots: [ca], idleMilliseconds: 120_000)
        } else {
            options = TLSBuilder.clientOptions(alpn: Wire.alpn, identity: identity, serverTrustRoots: [ca]); options.idleTimeout = 120_000
        }
        options.initialMaxData = 32 << 20
        options.initialMaxStreamDataBidirectionalLocal = (14 << 20) + 5
        options.initialMaxStreamDataBidirectionalRemote = (14 << 20) + 5
        options.initialMaxStreamDataUnidirectional = 0
        options.initialMaxStreamsBidirectional = 1; options.initialMaxStreamsUnidirectional = 0
        return .reachQUIC(options: options)
    }
    func requirePeer(_ stream: BoundedQUICStream) throws -> String {
        guard let der = stream.peerCertificateDER() else { throw TransportRuntimeError.peer }
        let digest = PreparationEncoding.hash(der)
        guard digest == (role == .host ? selection.pins.clientLeaf : selection.pins.hostLeaf) else { throw TransportRuntimeError.peer }
        return digest
    }
}
