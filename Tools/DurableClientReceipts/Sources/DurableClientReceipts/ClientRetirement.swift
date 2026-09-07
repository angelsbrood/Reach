import Foundation

extension DurableClientReceipts {
    /// Owned maintenance carries no caller payload. Expired identity and key disappear before any fallible unlink.
    public func maintenance() throws {
        let old = try refresh(); let now = try observe(old)
        var m = old, changed = false
        for i in m.records.indices {
            if let live = m.records[i].live, now >= live.expires {
                m.records[i].cleanup = live.snapshot; m.records[i].live = nil; changed = true
            }
        }
        if changed {
            m.revision = try crAdd(m.revision, 1); m = try commit(m, old: old)
            try hook(.afterRetirement)
        }
        // recover() has already discarded authenticated, unreferenced prepared metadata (including old keys).
        for record in m.records where record.cleanup != nil {
            let ref = record.cleanup!
            try hook(.duringDeletion)
            if try fs.exists(ref.name) {
                let bytes = try fs.read(ref.name)
                let f = try ClientCrypto.inspect(bytes, role: "snapshot", environment: environment, rootKey: rootKey)
                guard crHash(bytes) == ref.digest, f.generation == record.id, f.revision == ref.revision else { throw ClientError.unavailable }
                try fs.unlink(ref.name)
            }
            try fs.sync(); try hook(.afterDeletion)
            let prior = m; m.records.removeAll { $0.id == record.id }; m.revision = try crAdd(m.revision, 1)
            m = try commit(m, old: prior)
        }
    }
}
