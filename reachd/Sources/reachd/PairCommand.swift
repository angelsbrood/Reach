import ArgumentParser
import CoreImage
import CoreImage.CIFilterBuiltins
import ImageIO
import Crypto
import Foundation
import ReachDaemon

/// The operator surface, deliberately thin: `reachd pair` renders the QR —
/// cluster identity, a one-time enrollment token, and where to enroll —
/// because the first device paired holds the admin grant and the real
/// console lives in the pocket.
struct Pair: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Render the pairing QR for a new device."
    )

    @Option(name: .long, help: "Also write the QR as a PNG at this path.")
    var png: String?

    struct Payload: Codable {
        var v = 1
        var cluster: UUID
        var name: String
        var addrs: [String]
        var port: UInt16
        var caHash: Data
        var token: String
    }

    func run() async throws {
        var config = DaemonConfig.load()
        try? config.save()   // persists a fresh clusterID on first use

        let caDirectory = DaemonInfo.stateDirectory.appendingPathComponent("ca", isDirectory: true)
        let ca: ClusterCA
        if let loaded = try? ClusterCA.load(from: caDirectory) {
            ca = loaded
        } else {
            ca = try ClusterCA.create(commonName: config.clusterName)
            try ca.save(to: caDirectory)
        }

        let addrs = LocalAddresses.ipv4()
            .map { $0.map(String.init).joined(separator: ".") }
            .filter { $0 != "127.0.0.1" }
        let token = TokenStore().mint()
        let payload = Payload(
            cluster: config.clusterID,
            name: config.clusterName,
            addrs: addrs,
            port: config.enrollPort,
            caHash: Data(SHA256.hash(data: try ca.certificateDER())),
            token: token
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let json = try encoder.encode(payload)

        print("\(config.clusterName) — scan with the keeper (token valid 10 minutes):\n")
        print(Self.renderQR(json) ?? String(decoding: json, as: UTF8.self))
        print("enrollment: \(addrs.joined(separator: ", ")) port \(config.enrollPort)")
        if let png {
            try Self.writePNG(json, to: URL(fileURLWithPath: png))
            print("png: \(png)")
        }
    }

    static func writePNG(_ data: Data, to url: URL) throws {
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return }
        filter.setValue(data, forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let image = filter.outputImage else { return }
        let scaled = image.transformed(by: CGAffineTransform(scaleX: 16, y: 16))
        let context = CIContext()
        guard let cg = context.createCGImage(scaled, from: scaled.extent),
              let destination = CGImageDestinationCreateWithURL(url as CFURL, "public.png" as CFString, 1, nil)
        else { return }
        CGImageDestinationAddImage(destination, cg, nil)
        CGImageDestinationFinalize(destination)
    }

    /// CoreImage QR → ANSI half-blocks; each text row carries two pixel rows.
    static func renderQR(_ data: Data) -> String? {
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(data, forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let image = filter.outputImage else { return nil }
        let context = CIContext()
        guard let cg = context.createCGImage(image, from: image.extent) else { return nil }
        let width = cg.width
        let height = cg.height
        var pixels = [UInt8](repeating: 0, count: width * height)
        guard let bitmap = CGContext(
            data: &pixels, width: width, height: height,
            bitsPerComponent: 8, bytesPerRow: width,
            space: CGColorSpaceCreateDeviceGray(),
            bitmapInfo: CGImageAlphaInfo.none.rawValue
        ) else { return nil }
        bitmap.draw(cg, in: CGRect(x: 0, y: 0, width: width, height: height))

        func dark(_ x: Int, _ y: Int) -> Bool {
            guard x < width, y < height else { return false }
            return pixels[y * width + x] < 128
        }

        var out = ""
        let quiet = 1
        for y in stride(from: -quiet * 2, to: height + quiet * 2, by: 2) {
            for x in (-quiet)..<(width + quiet) {
                let top = x >= 0 && y >= 0 ? dark(x, y) : false
                let bottom = x >= 0 && y + 1 >= 0 ? dark(x, y + 1) : false
                switch (top, bottom) {
                case (true, true): out += "█"
                case (true, false): out += "▀"
                case (false, true): out += "▄"
                case (false, false): out += " "
                }
            }
            out += "\n"
        }
        return out
    }
}
