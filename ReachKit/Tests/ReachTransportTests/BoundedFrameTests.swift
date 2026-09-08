import Foundation
import Testing
import ReachWire
@testable import ReachTransport

@Suite struct BoundedFrameTests {
    private func header(_ count: UInt32, _ type: FrameType = .hello) -> Data {
        var value = count.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) } + Data([type.rawValue])
    }
    @Test func headerRejectsOversizeBeforeBodyAllocation() throws {
        #expect(try BoundedFrameHeader(header(UInt32(DurableWire.controlLimit + 1))).bodyLength == DurableWire.controlLimit)
        #expect(throws: BoundedTransportError.self) { try BoundedFrameHeader(header(UInt32(DurableWire.controlLimit + 2))) }
        #expect(try BoundedFrameHeader(header(UInt32(DurableWire.bulkLimit + 1), .durableBatch)).bodyLength == DurableWire.bulkLimit)
        #expect(throws: BoundedTransportError.self) { try BoundedFrameHeader(header(UInt32(DurableWire.bulkLimit + 2), .durableBatch)) }
        #expect(throws: BoundedTransportError.self) { try BoundedFrameHeader(header(0)) }
        #expect(throws: BoundedTransportError.self) { try BoundedFrameHeader(Data([0, 0, 0, 1, 255])) }
    }
    @Test func truncatedHeaderNeverBecomesAFrame() {
        for count in 0..<5 { #expect(throws: BoundedTransportError.self) { try BoundedFrameHeader(Data(repeating: 0, count: count)) } }
    }
}
