/// Two lowercase hexadecimal digits per byte, the text `String(format: "%02x", byte)` produces, without a Foundation
/// format call per byte. Paths, service names and record names are built from it on every verification.
enum LowercaseHexadecimal {
    private static let digits = Array("0123456789abcdef".utf8)

    static func encode<Bytes: Sequence>(_ value: Bytes) -> String where Bytes.Element == UInt8 {
        var output: [UInt8] = []
        output.reserveCapacity(value.underestimatedCount * 2)
        for byte in value {
            output.append(digits[Int(byte >> 4)])
            output.append(digits[Int(byte & 0x0f)])
        }
        return String(decoding: output, as: UTF8.self)
    }
}
