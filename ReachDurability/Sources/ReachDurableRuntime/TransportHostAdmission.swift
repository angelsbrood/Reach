import Foundation
import Darwin
import DurableRootKeys
import DurableStoreBootstrap
import ReachWire
import RequestPreparationContract

struct TransportAdmissionBinding: Codable {
    let revision: String, selection: String, caller: String, reference: DurableGenerationReference, requestDigest: String
}
private struct TransportAdmissionRecord: Codable { let binding: TransportAdmissionBinding, confirmation: Data }
/// One immutable reservation under the already-held exclusive host lifecycle
/// owner. A partial/invalid record refuses; absence is the only unreserved state.
final class TransportHostAdmission {
    private let path: String, selection: TransportSelectionBinding, core: BootstrapCore, key: RootKeyMaterial
    private(set) var reservation: TransportAdmissionBinding?
    init(root: String, selection: TransportSelectionBinding, core: BootstrapCore, key: RootKeyMaterial) throws {
        path = root + "/host/admission.json"; self.selection = selection; self.core = core; self.key = key
        var info = stat()
        if lstat(path, &info) != 0 { guard errno == ENOENT else { throw TransportRuntimeError.invalid }; return }
        let bytes = try LocalFiles.read(path, maximum: 16384)
        let record = try JSONDecoder().decode(TransportAdmissionRecord.self, from: bytes)
        guard try TransportContract.encode(record) == bytes else { throw TransportRuntimeError.invalid }
        try validate(record.binding)
        try key.confirm(record.confirmation, reference: core.reference(.hostCatalog), binding: PreparationEncoding.digest(record.binding))
        reservation = record.binding
    }
    private func validate(_ value: TransportAdmissionBinding) throws {
        try value.reference.validate()
        guard value.revision == TransportContract.revision, value.selection == (try PreparationEncoding.digest(selection)),
              value.caller == (try PreparationEncoding.digest(selection.pins.hostAuthorization.caller)),
              value.reference.session.modelID == selection.descriptor.model, value.reference.session.profile == DurableWire.profile,
              PreparationEncoding.isDigest(value.requestDigest) else { throw TransportRuntimeError.invalid }
    }
    func reserve(_ reference: DurableGenerationReference, requestDigest: String) throws {
        guard reservation == nil else { throw TransportRuntimeError.reserved }
        let binding = try TransportAdmissionBinding(revision: TransportContract.revision, selection: PreparationEncoding.digest(selection), caller: PreparationEncoding.digest(selection.pins.hostAuthorization.caller), reference: reference, requestDigest: requestDigest)
        try validate(binding)
        let confirmation = try key.confirmation(core.reference(.hostCatalog), binding: PreparationEncoding.digest(binding))
        try LocalFiles.writeNew(TransportContract.encode(TransportAdmissionRecord(binding: binding, confirmation: confirmation)), to: path)
        reservation = binding
    }
}
