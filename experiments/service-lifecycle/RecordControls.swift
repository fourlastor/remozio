import Foundation
import Darwin
import LocalAuthentication

@main struct RecordControls {
    static func main() throws {
        let point = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        let publicKey = Data(stride(from: 0, to: point.count, by: 2).map { offset in
            let start = point.index(point.startIndex, offsetBy: offset)
            return UInt8(point[start..<point.index(start, offsetBy: 2)], radix: 16)!
        })
        let record = try EnclaveProbeRecord(publicKey: publicKey, wrappedKey: Data([17, 23]))
        let bytes = record.encode(), decoded = try EnclaveProbeRecord.decode(bytes)
        precondition(decoded.encode() == bytes && decoded.publicFingerprint == record.publicFingerprint)
        precondition(record.description == "EnclaveProbeRecord(redacted)")
        var mutations: [Data] = [Data(), bytes.dropLast(), bytes + Data([1]), Data(repeating: 0, count: EnclaveProbeRecord.fixedBytes + 16_385)]
        for index in [0, EnclaveProbeRecord.magic.count, EnclaveProbeRecord.magic.count + 1,
                      EnclaveProbeRecord.magic.count + 1 + 65] {
            var changed = bytes; changed[index] ^= 255; mutations.append(changed)
        }
        var zeroLength = bytes
        let lengthStart = EnclaveProbeRecord.magic.count + 1 + 65
        for index in lengthStart..<(lengthStart + 4) { zeroLength[index] = 0 }
        mutations.append(zeroLength)
        for mutation in mutations {
            do { _ = try EnclaveProbeRecord.decode(mutation); fatalError("Malformed record accepted") }
            catch EnclaveProbeError.invalidState {}
        }
        guard getuid() != 0, getuid() == geteuid() else { throw EnclaveProbeError.wrongAccount }
        do { _ = try EnclaveProbeNamespace(); fatalError("Ordinary-account namespace access accepted") }
        catch EnclaveProbeError.wrongAccount {}
        let context = LAContext(); context.interactionNotAllowed = true
        defer { context.invalidate() }
        do { _ = try record.restore(context: context); fatalError("Ordinary-account hardware restore accepted") }
        catch EnclaveProbeError.wrongAccount {}
        print("Key record controls passed. Synthetic wrapped bytes only; no private key created, hardware restore attempted, file persisted or service changed.")
    }
}
