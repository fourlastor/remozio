import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import RemozioProtocol

/// Dedicated transport key material. This local record must never enter a shared setup export.
public struct GatewayWakeKeyRecord: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let binding: GatewaySubmissionBinding
    public let credentialID: Data
    public let publicKey: Data
    public let custody: GatewayWakeKeyCustody
    fileprivate let representation: Data
    public var description: String { "GatewayWakeKeyRecord(redacted)" }
    public var debugDescription: String { description }

    public init(binding: GatewaySubmissionBinding, credentialID: Data, key: SecureEnclave.P256.Signing.PrivateKey) throws {
        try self.init(binding: binding, credentialID: credentialID, publicKey: key.publicKey.x963Representation,
            custody: .secureEnclave, representation: key.dataRepresentation)
    }
    /// Explicit file custody applies only to this transport key, never to authority or recipient keys.
    public init(binding: GatewaySubmissionBinding, credentialID: Data, fileKey: P256.Signing.PrivateKey) throws {
        try self.init(binding: binding, credentialID: credentialID, publicKey: fileKey.publicKey.x963Representation,
            custody: .protectedFile, representation: fileKey.rawRepresentation)
    }
    init(binding: GatewaySubmissionBinding, credentialID: Data, publicKey: Data,
         custody: GatewayWakeKeyCustody, representation: Data) throws {
        guard credentialID.count == 16, publicKey.count == 65, publicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: publicKey)) != nil,
              (1...16_384).contains(representation.count),
              custody != .protectedFile || representation.count == 32 else { throw GatewayWakeSignerError.invalidRecord }
        self.binding = binding; self.credentialID = credentialID; self.publicKey = publicKey
        self.custody = custody; self.representation = representation
    }
    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: GatewayWakeKeyScope.encode(binding),
            2: .bytes(credentialID), 3: .bytes(publicKey), 4: .unsigned(custody.rawValue), 5: .bytes(representation)]), limits: Self.limits())
    }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
              Set(fields.keys) == Set(UInt64(0)...5), fields[0] == .unsigned(1), let scope = fields[1],
              case .bytes(let credential) = fields[2], case .bytes(let key) = fields[3],
              case .unsigned(let mode) = fields[4], let custody = GatewayWakeKeyCustody(rawValue: mode),
              case .bytes(let representation) = fields[5] else { throw GatewayWakeSignerError.invalidRecord }
        let record = try Self(binding: GatewayWakeKeyScope.decode(scope), credentialID: credential, publicKey: key,
            custody: custody, representation: representation)
        guard try record.encode() == bytes else { throw GatewayWakeSignerError.invalidRecord }
        return record
    }
    private static func limits() throws -> CBORLimits { try CBORLimits(maxBytes: 16_640, maxDepth: 2, maxItems: 24) }
}

/// Restores a provisioned wake key without dialogs, key creation, rotation, or custody fallback.
public final class GatewayWakeSigner: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let binding: GatewaySubmissionBinding
    public let credentialID: Data
    public let publicKey: Data
    private enum Key { case enclave(SecureEnclave.P256.Signing.PrivateKey), file(P256.Signing.PrivateKey) }
    private let key: Key
    private let context: LAContext?
    private let lock = NSLock()
    public var description: String { "GatewayWakeSigner(redacted)" }
    public var debugDescription: String { description }
    private init(record: GatewayWakeKeyRecord, key: Key, context: LAContext?) {
        binding = record.binding; credentialID = record.credentialID; publicKey = record.publicKey
        self.key = key; self.context = context
    }
    deinit { context?.invalidate() }

    public static func load(configuration: GatewayWakeSignerConfiguration) throws -> GatewayWakeSigner {
        try configuration.requireNativeProcess()
        return try load(configuration: configuration, realUID: getuid(), effectiveUID: geteuid(),
            read: ProtectedServiceConfiguration.readServicePrivate)
    }
    /// The fixture seam keeps the same account and record validation before key restoration.
    static func load(configuration: GatewayWakeSignerConfiguration, realUID: UInt32, effectiveUID: UInt32,
                     read: (String, uid_t) throws -> Data) throws -> GatewayWakeSigner {
        try configuration.requireProcess(realUID: realUID, effectiveUID: effectiveUID)
        let record = try GatewayWakeKeyRecord.decode(read(configuration.keyRecordPath, configuration.transportUID))
        guard record.binding == configuration.binding, record.credentialID == configuration.credentialID,
              record.publicKey == configuration.publicKey, record.custody == configuration.custody else {
            throw GatewayWakeSignerError.wrongIdentity
        }
        let key: Key, context: LAContext?
        switch record.custody {
        case .protectedFile:
            context = nil
            guard let restored = try? P256.Signing.PrivateKey(rawRepresentation: record.representation),
                  restored.publicKey.x963Representation == record.publicKey else { throw GatewayWakeSignerError.invalidRecord }
            key = .file(restored)
        case .secureEnclave:
            guard SecureEnclave.isAvailable else { throw GatewayWakeSignerError.unavailable }
            let authentication = LAContext(); authentication.interactionNotAllowed = true
            do {
                let restored = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: record.representation,
                    authenticationContext: authentication)
                guard restored.publicKey.x963Representation == record.publicKey else { throw GatewayWakeSignerError.wrongIdentity }
                key = .enclave(restored); context = authentication
            } catch {
                authentication.invalidate()
                if let error = error as? GatewayWakeSignerError { throw error }
                throw GatewayWakeSignerError.unavailable
            }
        }
        return GatewayWakeSigner(record: record, key: key, context: context)
    }

    /// Only a canonical wake with this protected identity can reach the key.
    public func sign(_ submission: GatewayWakeSubmission) throws -> Data {
        guard submission.binding == binding, submission.credentialID == credentialID else { throw GatewayWakeSignerError.wrongIdentity }
        let input = try submission.signingInput()
        return try lock.withLock {
            let signature: P256.Signing.ECDSASignature
            do {
                switch key {
                case .enclave(let key): signature = try key.signature(for: input)
                case .file(let key): signature = try key.signature(for: input)
                }
            } catch { throw GatewayWakeSignerError.unavailable }
            guard try P256.Signing.PublicKey(x963Representation: publicKey).isValidSignature(signature, for: input) else {
                throw GatewayWakeSignerError.wrongIdentity
            }
            return signature.rawRepresentation
        }
    }
}
