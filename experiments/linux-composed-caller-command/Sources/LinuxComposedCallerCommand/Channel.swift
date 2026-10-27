import CComposedSupport
import Foundation
import Glibc
import LinuxApprovalFixtureCore
import LinuxOSObservation

/// Bounded JSON frames over an inherited SEQPACKET socket; descriptors arrive close-on-exec and owned.
final class FrameChannel {
    let descriptor: Int32
    init(_ descriptor: Int32) { self.descriptor = descriptor }

    func send(_ value: [String: Any]) throws {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        try require(data.count <= 4096, "frameSize")
        try require(data.withUnsafeBytes { ccs_send(descriptor, $0.baseAddress, $0.count) } == 0, "frameSend")
    }

    func receive(descriptors expected: Int = 0, timeoutMilliseconds: Int32 = 3000) throws -> ([String: Any], [OwnedFD]) {
        var buffer = [UInt8](repeating: 0, count: 4096)
        var received = [Int32](repeating: -1, count: 16)
        var count: Int32 = 0
        let length = ccs_receive(descriptor, &buffer, buffer.count, &received, 16, &count, timeoutMilliseconds)
        try require(length > 0, "frameReceive")
        let owned = try received.prefix(Int(count)).map { try OwnedFD($0) }
        try require(owned.count == expected, "frameDescriptors")
        guard let value = try JSONSerialization.jsonObject(with: Data(buffer.prefix(length))) as? [String: Any] else {
            throw FixtureError.failed("frameShape")
        }
        return (value, owned)
    }
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
    init?(hex: String) {
        guard hex.count % 2 == 0, hex.allSatisfy(\.isHexDigit) else { return nil }
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}
