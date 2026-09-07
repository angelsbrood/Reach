import Foundation
import DurableRootKeys

struct BootstrapIntent: Codable {
    var state = "creating"
    let core: BootstrapCore
}
extension BootstrapFileSystem {
    func intent(_ core: BootstrapCore, hook: BootstrapHook) throws {
        try hook(.beforeIntentWrite)
        try write("intent.json",bytes:RootKeyCodec.encode(BootstrapIntent(core:core),limit:BootstrapLimits.record),hook:hook)
        try sync(); try hook(.afterIntent)
    }
    func ready(_ descriptor: BootstrapReady, hook: BootstrapHook) throws {
        try write("selection.tmp",bytes:RootKeyCodec.encode(descriptor,limit:BootstrapLimits.record),hook:hook)
        try selectReady(hook:hook); try hook(.afterReady)
    }
    func loadReady(expected: BootstrapPolicy) throws -> BootstrapReady {
        let names = try scan()
        guard names.contains("ready.json"), !names.contains("selection.tmp") else { throw BootstrapError.incomplete }
        let intent = try RootKeyCodec.decode(BootstrapIntent.self,read("intent.json"),limit:BootstrapLimits.record)
        let selected = try RootKeyCodec.decode(BootstrapReady.self,read("ready.json"),limit:BootstrapLimits.record)
        guard intent.state == "creating", try RootKeyCodec.encode(intent.core,limit:BootstrapLimits.record) == RootKeyCodec.encode(selected.core,limit:BootstrapLimits.record) else { throw BootstrapError.invalid }
        try selected.validate(expected:expected); return selected
    }
}
