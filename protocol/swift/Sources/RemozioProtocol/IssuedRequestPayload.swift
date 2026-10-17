#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
import Foundation

public enum IssuedRequestError: Error, Equatable {
    case invalidFields, unsupportedWrapper, unsupportedContract, unsupportedFeatures
    case invalidBytes, invalidTimes, invalidFeatures, invalidActions, invalidCapture, captureDigestMismatch
}

/// The common request wrapper. Capture semantics, authority identity, and current validity remain separate checks.
public struct IssuedRequestPayload: Equatable, Sendable {
    public let contract: RequestContract
    public let macID: Data
    public let accountID: Data
    public let requestID: Data
    public let challenge: Data
    public let requiredFeatures: Set<UInt64>
    public let createdUnixMilliseconds: UInt64
    public let expiresUnixMilliseconds: UInt64
    public let canonicalCapture: Data
    public let captureDigest: Data
    public let permittedActions: [CapturedAction]

    public init(contract: RequestContract, macID: Data, accountID: Data, requestID: Data, challenge: Data,
                requiredFeatures: Set<UInt64>, createdUnixMilliseconds: UInt64, expiresUnixMilliseconds: UInt64,
                canonicalCapture: Data, permittedActions: [CapturedAction], bodyLimits: CBORLimits, captureLimits: CBORLimits) throws {
        guard contract.wireVersion == 1 else { throw IssuedRequestError.unsupportedContract }
        guard [macID, accountID, requestID].allSatisfy({ $0.count == 16 }), challenge.count == 32 else {
            throw IssuedRequestError.invalidBytes
        }
        guard createdUnixMilliseconds < expiresUnixMilliseconds else { throw IssuedRequestError.invalidTimes }
        guard requiredFeatures.count <= bodyLimits.maxItems, permittedActions.count <= bodyLimits.maxItems else {
            throw CBORError.limitExceeded(.items)
        }
        guard canonicalCapture.count <= bodyLimits.maxBytes else { throw CBORError.limitExceeded(.bytes) }
        guard case .map = try DeterministicCBOR.decode(canonicalCapture, limits: captureLimits) else {
            throw IssuedRequestError.invalidCapture
        }
        let actions = Set(permittedActions)
        guard !actions.isEmpty, actions.count == permittedActions.count else { throw IssuedRequestError.invalidActions }
        do {
            for action in permittedActions {
                _ = try ActionPolicy.requirement(for: action, requestKind: contract.requestKind, retainedPermittedActions: actions)
            }
        } catch { throw IssuedRequestError.invalidActions }
        self.contract = contract
        self.macID = macID
        self.accountID = accountID
        self.requestID = requestID
        self.challenge = challenge
        self.requiredFeatures = requiredFeatures
        self.createdUnixMilliseconds = createdUnixMilliseconds
        self.expiresUnixMilliseconds = expiresUnixMilliseconds
        self.canonicalCapture = canonicalCapture
        self.captureDigest = Data(SHA256.hash(data: canonicalCapture))
        self.permittedActions = permittedActions
        _ = try encode(limits: bodyLimits)
    }

    public func encode(limits: CBORLimits) throws -> Data {
        guard requiredFeatures.count <= limits.maxItems, permittedActions.count <= limits.maxItems else {
            throw CBORError.limitExceeded(.items)
        }
        return try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(requestID), 4: .bytes(challenge),
            5: .unsigned(Self.kindTag(contract.requestKind)), 6: .unsigned(contract.schemaVersion),
            7: .array(requiredFeatures.sorted().map { .unsigned($0) }),
            8: .unsigned(createdUnixMilliseconds), 9: .unsigned(expiresUnixMilliseconds),
            10: .bytes(canonicalCapture), 11: .bytes(captureDigest),
            12: .array(permittedActions.map { ActionWire.encode($0) }),
        ]), limits: limits)
    }

    public func requestDigest(bodyLimits: CBORLimits, signingLimits: CBORLimits) throws -> Data {
        let body = try encode(limits: bodyLimits)
        let input = try SigningInput.make(wireVersion: contract.wireVersion, messageType: .request, purpose: .issuedRequest,
            canonicalPayload: body, payloadLimits: bodyLimits, inputLimits: signingLimits)
        return Data(SHA256.hash(data: input))
    }

    public static func decode(_ bytes: Data, bodyLimits: CBORLimits, captureLimits: CBORLimits,
                              localCapabilities: ContractCapabilities) throws -> IssuedRequestPayload {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: bodyLimits),
              Set(fields.keys) == Set(UInt64(0)...12) else { throw IssuedRequestError.invalidFields }
        guard fields[0] == .unsigned(1) else { throw IssuedRequestError.unsupportedWrapper }
        func uint(_ key: UInt64) throws -> UInt64 {
            guard case let .unsigned(value) = fields[key] else { throw IssuedRequestError.invalidFields }
            return value
        }
        func data(_ key: UInt64) throws -> Data {
            guard case let .bytes(value) = fields[key] else { throw IssuedRequestError.invalidBytes }
            return value
        }
        let kind: RequestKind
        switch try uint(5) {
        case 0: kind = .command
        case 1: kind = .onePasswordAccess
        case 2: kind = .onePasswordUnlock
        case 3: kind = .littleSnitch
        default: throw IssuedRequestError.unsupportedContract
        }
        let schema = try uint(6)
        guard schema > 0 else { throw IssuedRequestError.unsupportedContract }
        let contract = try RequestContract(requestKind: kind, wireVersion: 1, schemaVersion: schema)
        guard let supportedFeatures = localCapabilities.contracts[contract] else { throw IssuedRequestError.unsupportedContract }
        guard case let .array(featureValues) = fields[7] else { throw IssuedRequestError.invalidFeatures }
        var features = Set<UInt64>(), previous: UInt64?
        for feature in featureValues {
            guard case let .unsigned(value) = feature, previous == nil || value > previous! else {
                throw IssuedRequestError.invalidFeatures
            }
            features.insert(value)
            previous = value
        }
        guard features.isSubset(of: supportedFeatures) else { throw IssuedRequestError.unsupportedFeatures }
        guard case let .array(actionValues) = fields[12] else { throw IssuedRequestError.invalidActions }
        let actions: [CapturedAction]
        do { actions = try actionValues.map { try ActionWire.decode($0) } }
        catch { throw IssuedRequestError.invalidActions }
        let result = try IssuedRequestPayload(contract: contract, macID: data(1), accountID: data(2), requestID: data(3),
            challenge: data(4), requiredFeatures: features, createdUnixMilliseconds: uint(8), expiresUnixMilliseconds: uint(9),
            canonicalCapture: data(10), permittedActions: actions, bodyLimits: bodyLimits, captureLimits: captureLimits)
        guard try data(11) == result.captureDigest else { throw IssuedRequestError.captureDigestMismatch }
        return result
    }

    private static func kindTag(_ kind: RequestKind) -> UInt64 {
        switch kind {
        case .command: 0
        case .onePasswordAccess: 1
        case .onePasswordUnlock: 2
        case .littleSnitch: 3
        }
    }
}
