import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security
import RemozioProtocol

public enum AuthorityRequestSignerError: Error, Equatable {
    case invalidRecord, wrongIdentity, unavailable
}

/// Device-bound wrapped key storage. This record must never enter a shared setup export.
public struct AuthoritySigningKeyRecord: Sendable, CustomStringConvertible {
    public static let maximumBytes = 16_640
    public let macID: Data
    public let accountID: Data
    public let publicKey: Data
    fileprivate let representation: Data

    /// The privileged setup controller supplies an already-provisioned Secure Enclave key.
    public init(macID: Data, accountID: Data, key: SecureEnclave.P256.Signing.PrivateKey) throws {
        try self.init(macID: macID, accountID: accountID, publicKey: key.publicKey.x963Representation,
            representation: key.dataRepresentation)
    }
    init(macID: Data, accountID: Data, publicKey: Data, representation: Data) throws {
        guard macID.count == 16, accountID.count == 16, publicKey.count == 65, publicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: publicKey)) != nil,
              (1...16_384).contains(representation.count) else { throw AuthorityRequestSignerError.invalidRecord }
        self.macID = macID; self.accountID = accountID; self.publicKey = publicKey; self.representation = representation
    }
    public var description: String { "AuthoritySigningKeyRecord(redacted)" }
    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID),
            3: .bytes(publicKey), 4: .bytes(representation)]), limits: Self.limits())
    }
    static func decode(_ bytes: Data) throws -> AuthoritySigningKeyRecord {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
              Set(fields.keys) == Set(UInt64(0)...4), fields[0] == .unsigned(1),
              case .bytes(let mac) = fields[1], case .bytes(let account) = fields[2],
              case .bytes(let publicKey) = fields[3], case .bytes(let representation) = fields[4] else {
            throw AuthorityRequestSignerError.invalidRecord
        }
        return try AuthoritySigningKeyRecord(macID: mac, accountID: account, publicKey: publicKey, representation: representation)
    }
    private static func limits() throws -> CBORLimits {
        try CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 11)
    }
}

/// Restores only a Secure Enclave key. Loading and signing never allow an authentication dialog or rotate a missing key.
public final class EnclaveAuthorityRequestSigner: @unchecked Sendable, CustomStringConvertible {
    public let macID: Data
    public let accountID: Data
    public let publicKey: Data
    private let key: SecureEnclave.P256.Signing.PrivateKey
    private let context: LAContext
    private let lock = NSLock()

    private init(record: AuthoritySigningKeyRecord, key: SecureEnclave.P256.Signing.PrivateKey, context: LAContext) {
        macID = record.macID; accountID = record.accountID; publicKey = record.publicKey
        self.key = key; self.context = context
    }
    deinit { context.invalidate() }
    public var description: String { "EnclaveAuthorityRequestSigner(redacted)" }

    /// Requires the current authority code policy and root-private storage. The public-key pin comes from trusted provisioning.
    public static func load(path: String, configuration: AuthorityServiceConfiguration,
                            expectedPublicKey: Data, journal: AuthorityJournal) throws -> EnclaveAuthorityRequestSigner {
        guard geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try journal.read { transaction in
            try AuthoritySelfValidation.validate(transaction: transaction)
            let trust = try transaction.approvalTrustSnapshot()
            guard trust.macID == configuration.macID, trust.accountID == configuration.accountID else {
                throw AuthorityRequestSignerError.wrongIdentity
            }
        }
        return try restore(ProtectedServiceConfiguration.read(path: path), configuration: configuration,
            expectedPublicKey: expectedPublicKey)
    }

    /// Hardware-only fixture seam. It cannot restore software key bytes.
    static func restore(_ bytes: Data, configuration: AuthorityServiceConfiguration,
                        expectedPublicKey: Data) throws -> EnclaveAuthorityRequestSigner {
        let record = try AuthoritySigningKeyRecord.decode(bytes)
        guard record.macID == configuration.macID, record.accountID == configuration.accountID,
              record.publicKey == expectedPublicKey else { throw AuthorityRequestSignerError.wrongIdentity }
        guard SecureEnclave.isAvailable else { throw AuthorityRequestSignerError.unavailable }
        let context = LAContext()
        context.interactionNotAllowed = true
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: record.representation, authenticationContext: context)
            guard key.publicKey.x963Representation == expectedPublicKey else { throw AuthorityRequestSignerError.wrongIdentity }
            return EnclaveAuthorityRequestSigner(record: record, key: key, context: context)
        } catch {
            context.invalidate()
            if let error = error as? AuthorityRequestSignerError { throw error }
            throw AuthorityRequestSignerError.unavailable
        }
    }
    func sign(_ input: Data) throws -> Data {
        try lock.withLock {
            do { return try key.signature(for: input).rawRepresentation }
            catch { throw AuthorityRequestSignerError.unavailable }
        }
    }
}

extension AuthoritySigningKeyRecord {
    /// Fixed-purpose hardware proof for setup. This is not an approval or enrollment signature.
    func verifyProvisioningHardware() throws {
        guard SecureEnclave.isAvailable else { throw AuthorityRequestSignerError.unavailable }
        let context = LAContext(); context.interactionNotAllowed = true
        defer { context.invalidate() }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: representation, authenticationContext: context)
            guard key.publicKey.x963Representation == publicKey else { throw AuthorityRequestSignerError.wrongIdentity }
            let message = Data("Remozio/authority-key-provisioning/v1\0".utf8)
            let signature = try key.signature(for: message)
            guard key.publicKey.isValidSignature(signature, for: message) else { throw AuthorityRequestSignerError.unavailable }
        } catch {
            if let failure = error as? AuthorityRequestSignerError { throw failure }
            throw AuthorityRequestSignerError.unavailable
        }
    }
}
