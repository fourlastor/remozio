import CryptoKit
import Darwin
import Foundation
import LocalAuthentication

enum EnclaveProbeError: Error { case invalidState, wrongAccount, unavailable, unsafePlacement }

struct EnclaveProbeRecord: CustomStringConvertible {
    static let magic = Array("RemozioEnclaveProbeStateV1".utf8)
    static let maximumWrappedBytes = 16_384
    static let fixedBytes = magic.count + 1 + 65 + 4
    let publicKey: Data
    private let wrappedKey: Data
    var description: String { "EnclaveProbeRecord(redacted)" }
    var publicFingerprint: String { SHA256.hash(data: publicKey).map { String(format: "%02x", $0) }.joined() }

    init(publicKey: Data, wrappedKey: Data) throws {
        guard publicKey.count == 65, publicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: publicKey)) != nil,
              (1...Self.maximumWrappedBytes).contains(wrappedKey.count) else { throw EnclaveProbeError.invalidState }
        self.publicKey = publicKey; self.wrappedKey = wrappedKey
    }
    func encode() -> Data {
        let count = UInt32(wrappedKey.count)
        return Data(Self.magic + [1]) + publicKey
            + Data([UInt8(count >> 24), UInt8((count >> 16) & 255), UInt8((count >> 8) & 255), UInt8(count & 255)]) + wrappedKey
    }
    static func decode(_ encoded: Data) throws -> Self {
        guard (fixedBytes + 1...fixedBytes + maximumWrappedBytes).contains(encoded.count) else {
            throw EnclaveProbeError.invalidState
        }
        let bytes = Array(encoded), policyIndex = magic.count, publicStart = policyIndex + 1, lengthStart = publicStart + 65
        guard bytes.prefix(magic.count).elementsEqual(magic), bytes[policyIndex] == 1 else { throw EnclaveProbeError.invalidState }
        let length = bytes[lengthStart..<(lengthStart + 4)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length > 0, length <= maximumWrappedBytes, Int(length) == bytes.count - fixedBytes else {
            throw EnclaveProbeError.invalidState
        }
        return try Self(publicKey: Data(bytes[publicStart..<lengthStart]), wrappedKey: Data(bytes[fixedBytes...]))
    }
    func restore(context: LAContext) throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard getuid() == 0, geteuid() == 0 else { throw EnclaveProbeError.wrongAccount }
        guard context.interactionNotAllowed, SecureEnclave.isAvailable else { throw EnclaveProbeError.unavailable }
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: wrappedKey, authenticationContext: context)
        guard key.publicKey.x963Representation == publicKey else { throw EnclaveProbeError.invalidState }
        return key
    }
}
