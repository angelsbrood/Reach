import Foundation
import Darwin

/// One caller-owned descriptor. No Codable, retained password file or verifier.
public final class UnlockCredential {
    public static let policy = "caller-supplied-v1"
    private var descriptor: Int32
    public init(consumingDescriptor descriptor: Int32) throws {
        guard descriptor > STDERR_FILENO else { throw RootKeyError.invalid }
        self.descriptor = descriptor
        do {
            let flags = fcntl(descriptor, F_GETFD)
            guard flags >= 0, fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0 else { throw RootKeyError.invalid }
            _ = try inspect()
        } catch { close(); throw error }
    }
    private func inspect() throws -> stat {
        var value = stat()
        let access = fcntl(descriptor, F_GETFL)
        guard descriptor > STDERR_FILENO, access >= 0, access & O_ACCMODE == O_RDONLY,
              fstat(descriptor, &value) == 0, value.st_mode & S_IFMT == S_IFREG,
              value.st_uid == getuid(), value.st_mode & 0o7777 == 0o600,
              (32...128).contains(value.st_size) else { throw RootKeyError.invalid }
        return value
    }
    /// Reads from file offset zero without trimming, at most 129 bytes. The
    /// consumed descriptor is closed before the supplied operation begins.
    public func consume<T>(_ body: (Data) throws -> T) throws -> T {
        defer { close() }
        let before = try inspect()
        var bytes = Data(), buffer = [UInt8](repeating: 0, count: 129)
        while bytes.count < buffer.count {
            let count = pread(descriptor, &buffer, buffer.count - bytes.count, off_t(bytes.count))
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw RootKeyError.invalid }
            if count == 0 { break }
            bytes.append(contentsOf: buffer.prefix(count))
        }
        let after = try inspect()
        guard before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size, bytes.count == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              (32...128).contains(bytes.count), bytes.allSatisfy({
                  (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
              }) else { throw RootKeyError.invalid }
        close()
        return try body(bytes)
    }
    public func close() {
        if descriptor > STDERR_FILENO { _ = Darwin.close(descriptor); descriptor = -1 }
    }
    deinit { close() }
}
