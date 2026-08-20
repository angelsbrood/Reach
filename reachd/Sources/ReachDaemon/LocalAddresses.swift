import Foundation

public enum LocalAddresses {
    package struct IPv4Entry: Sendable, Equatable {
        package var interface: String
        package var address: [UInt8]
    }

    /// IPv4 addresses of the host's non-loopback interfaces, plus loopback —
    /// the SAN set for the server certificate.
    public static func ipv4() -> [[UInt8]] {
        var addresses: [[UInt8]] = [[127, 0, 0, 1]]
        for entry in ipv4Entries() where entry.address != [127, 0, 0, 1] {
            addresses.append(entry.address)
        }
        return addresses
    }

    package static func ipv4Entries() -> [IPv4Entry] {
        var addresses: [IPv4Entry] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return addresses }
        defer { freeifaddrs(ifaddr) }
        for pointer in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let interface = pointer.pointee
            guard let sa = interface.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) else { continue }
            guard let name = interface.ifa_name else { continue }
            let sin = UnsafeRawPointer(sa).assumingMemoryBound(to: sockaddr_in.self).pointee
            let raw = sin.sin_addr.s_addr.bigEndian
            let bytes: [UInt8] = [
                UInt8((raw >> 24) & 0xFF), UInt8((raw >> 16) & 0xFF),
                UInt8((raw >> 8) & 0xFF), UInt8(raw & 0xFF),
            ]
            addresses.append(IPv4Entry(interface: String(cString: name), address: bytes))
        }
        return addresses
    }
}
