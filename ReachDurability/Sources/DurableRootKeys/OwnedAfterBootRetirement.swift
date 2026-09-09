import Foundation
import Darwin
import Security

/// A current directory pin. The original device remains binding provenance;
/// it is not assumed to be a persistent device number across boots.
public final class OwnedAfterBootRoot {
    public let original: OwnedContainerIdentity, device: Int32, inode: UInt64
    private let descriptor: Int32, process = getpid()
    private init(original: OwnedContainerIdentity, descriptor: Int32, value: stat) {
        self.original = original; self.descriptor = descriptor
        device = value.st_dev; inode = UInt64(value.st_ino)
    }
    public static func open(_ original: OwnedContainerIdentity) throws -> OwnedAfterBootRoot? {
        _ = try RootKeyCodec.parent(original.root); try RootKeyCodec.require(original.inode > 0)
        var named = stat()
        if lstat(original.root,&named) != 0 { try RootKeyCodec.require(errno == ENOENT); return nil }
        try RootKeyCodec.directory(original.root)
        try RootKeyCodec.require(RootKeyCodec.canonicalExisting(original.root) == original.root && UInt64(named.st_ino) == original.inode)
        let descriptor = Darwin.open(original.root,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        guard descriptor >= 0 else { throw RootKeyError.invalid }
        var value = stat()
        guard fstat(descriptor,&value) == 0 && value.st_dev == named.st_dev && value.st_ino == named.st_ino else {
            _ = Darwin.close(descriptor); throw RootKeyError.invalid
        }
        let current = OwnedAfterBootRoot(original:original,descriptor:descriptor,value:value)
        try current.check(); return current
    }
    private func held() throws {
        var value = stat()
        try RootKeyCodec.require(process == getpid() && fstat(descriptor,&value) == 0 &&
            value.st_dev == device && UInt64(value.st_ino) == inode && value.st_uid == getuid() &&
            value.st_mode&S_IFMT == S_IFDIR && value.st_mode&0o7777 == 0o700)
    }
    public func check() throws {
        try held(); _ = try RootKeyCodec.parent(original.root)
        try RootKeyCodec.directory(original.root)
        var named = stat()
        try RootKeyCodec.require(lstat(original.root,&named) == 0 && named.st_dev == device &&
            UInt64(named.st_ino) == inode && RootKeyCodec.canonicalExisting(original.root) == original.root)
    }
    public func absent() throws -> Bool {
        try held(); _ = try RootKeyCodec.parent(original.root)
        var named = stat()
        if lstat(original.root,&named) != 0 { try RootKeyCodec.require(errno == ENOENT); return true }
        try check(); return false
    }
    /// Inspect metadata only, refusing links and descendant filesystem crossings.
    public func inspect(_ path: String) throws -> stat {
        try check(); try RootKeyCodec.require(path.hasPrefix(original.root+"/"))
        let relative = String(path.dropFirst(original.root.count+1))
        let parts = relative.split(separator:"/",omittingEmptySubsequences:false)
        try RootKeyCodec.require(!parts.isEmpty && parts.allSatisfy { !["",".",".."].contains(String($0)) })
        var selected = original.root, value = stat()
        for (index,part) in parts.enumerated() {
            selected += "/"+part
            try RootKeyCodec.require(lstat(selected,&value) == 0)
            try Self.requireMember(value,on:device,leaf:index == parts.count-1)
        }
        try check(); return value
    }
    static func requireMember(_ value: stat, on device: Int32, leaf: Bool) throws {
        try RootKeyCodec.require(value.st_dev == device && value.st_uid == getuid())
        let directory = value.st_mode&S_IFMT == S_IFDIR
        try RootKeyCodec.require(directory || leaf && value.st_mode&S_IFMT == S_IFREG && value.st_nlink == 1)
        try RootKeyCodec.require(value.st_mode&0o7777 == (directory ? 0o700 : 0o600))
    }
    deinit { _ = Darwin.close(descriptor) }
}

/// Constructed only after all original keys have confirmed under the caller's
/// lease and current root pin. The same exact handle survives the entire body.
public final class OwnedAfterBootRetirement {
    private let selected: OwnedContainerSelection, current: OwnedAfterBootRoot, container: OwnedFileKeychain
    private var deleted = false
    private init(selected: OwnedContainerSelection, current: OwnedAfterBootRoot, container: OwnedFileKeychain) {
        self.selected = selected; self.current = current; self.container = container
    }
    public func confirms(_ selection: OwnedContainerSelection, current: OwnedAfterBootRoot) -> Bool {
        selected == selection && self.current === current && !deleted
    }
    public static func perform<T>(_ selected: OwnedContainerSelection, expectedDigest: String,
        current: OwnedAfterBootRoot, credential: UnlockCredential, verifySelection: () throws -> Void,
        operation: (OwnedAfterBootRetirement) throws -> T) throws -> T {
        try OwnedFileKeychain.disableInteraction(); try selected.validate()
        try RootKeyCodec.require(selected.digest() == expectedDigest && selected.boot != RootKeyCodec.boot() && current.original == selected.identity)
        try selected.executable.validate()
        guard let running = Bundle.main.executableURL?.path else { throw RootKeyError.invalid }
        try RootKeyCodec.require(RootKeyCodec.canonicalExisting(running) == selected.executable.path)
        try current.check(); _ = try current.inspect(selected.identity.container); try verifySelection()
        let metadata = try KeychainMetadata.read()
        let owned: Set<String> = [selected.identity.container]
        try RootKeyCodec.require(metadata.preservesUnrelated(metadata,owned:owned))
        let container = try OwnedFileKeychain.openExisting(at:selected.identity.container)
        func unlocked() throws -> Bool {
            var state: SecKeychainStatus = 0
            try RootKeyCodec.check(SecKeychainGetStatus(container.reference,&state),"after-boot-status")
            return state & kSecUnlockStateStatus != 0
        }
        let initiallyUnlocked = try unlocked()
        let authority = OwnedAfterBootRetirement(selected:selected,current:current,container:container)
        return try credential.consume { bytes in
            try OwnedRetirementTransaction.run(initiallyUnlocked:initiallyUnlocked, unlock:{
                try OwnedFileKeychain.disableInteraction()
                try RootKeyCodec.check(bytes.withUnsafeBytes {
                    SecKeychainUnlock(container.reference,UInt32(bytes.count),$0.baseAddress!,true)
                },"after-boot-unlock")
            }, isUnlocked:unlocked, containerPresent:{
                if authority.deleted { return false }
                try current.check()
                var value = stat()
                if lstat(selected.identity.container,&value) != 0 { try RootKeyCodec.require(errno == ENOENT); return false }
                return true
            }, relock:{
                try OwnedFileKeychain.disableInteraction()
                try RootKeyCodec.check(SecKeychainLock(container.reference),"after-boot-relock")
            }, operation:{
                try current.check(); _ = try current.inspect(selected.identity.container)
                try RootKeyCodec.require(OwnedFileKeychain.path(container.reference) == selected.identity.container)
                let provider = MacKeychainProvider(container:container)
                for (reference,confirmation) in zip(selected.references,selected.confirmations) {
                    let key = try provider.load(reference,binding:selected.binding)
                    try key.confirm(confirmation,reference:reference,binding:selected.binding)
                }
                try verifySelection(); try current.check()
                try RootKeyCodec.require(KeychainMetadata.read() == metadata)
                return try operation(authority)
            })
        }
    }
    public func deleteAuthenticated() throws {
        try OwnedFileKeychain.disableInteraction(); try current.check()
        try RootKeyCodec.require(!deleted && OwnedFileKeychain.path(container.reference) == selected.identity.container)
        _ = try current.inspect(selected.identity.container)
        _ = try RootKeyCodec.regular(selected.identity.container,maximum:64<<20)
        let before = try KeychainMetadata.read()
        let owned: Set<String> = [selected.identity.container]
        try RootKeyCodec.require(before.preservesUnrelated(before,owned:owned))
        try RootKeyCodec.check(SecKeychainDelete(container.reference),"after-boot-delete")
        var value = stat()
        try RootKeyCodec.require(lstat(selected.identity.container,&value) != 0 && errno == ENOENT)
        deleted = true
        try current.check()
        let after = try KeychainMetadata.read()
        try RootKeyCodec.require(after.preservesUnrelated(before,owned:owned) && after.excludes(owned))
    }
}
