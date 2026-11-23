import Foundation
import RemozioProtocol

/// A historical signed operation. Reading a receipt does not authorize delivery or restore an enrollment.
public struct GatewayRecipientReceipt: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let control: GatewayStoredRecipient
    public let canonicalPayload: Data
    public let signature: Data
    public var kind: GatewayRecipientKind { control.kind }
    public var revision: UInt64 { control.revision }
    public var operationID: Data { control.operationID }
    public var phoneID: Data { control.phoneID }
    public var enrollmentEpoch: Data { control.enrollmentEpoch }
    public var description: String { "GatewayRecipientReceipt(redacted)" }
    public var debugDescription: String { description }
}

public struct GatewayRecipientApplication: Sendable {
    public let receipt: GatewayRecipientReceipt
    public let inserted: Bool
}

/// Verified stored mapping evidence. A provider send still requires current authority and a separate dispatch permit.
public struct GatewayActiveMapping: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let activation: GatewayMappingActivation
    public let receipt: GatewayRecipientReceipt
    let registrationToken: String
    public var description: String { "GatewayActiveMapping(redacted)" }
    public var debugDescription: String { description }
}

enum GatewayStoredRecipient: Sendable {
    case activation(GatewayMappingActivation)
    case revocation(GatewayPhoneRevocation)
    var kind: GatewayRecipientKind { switch self { case .activation: .activation; case .revocation: .phoneRevocation } }
    var revision: UInt64 { switch self { case .activation(let v): v.revision; case .revocation(let v): v.revision } }
    var operationID: Data { switch self { case .activation(let v): v.operationID; case .revocation(let v): v.operationID } }
    var issued: UInt64 { switch self { case .activation(let v): v.issuedAtUnixMillis; case .revocation(let v): v.issuedAtUnixMillis } }
    var expires: UInt64 { switch self { case .activation(let v): v.expiresAtUnixMillis; case .revocation(let v): v.expiresAtUnixMillis } }
    var phoneID: Data { switch self { case .activation(let v): v.binding.phoneID; case .revocation(let v): v.binding.phoneID } }
    var enrollmentEpoch: Data { switch self { case .activation(let v): v.binding.enrollmentEpoch; case .revocation(let v): v.binding.enrollmentEpoch } }
    func matches(_ identity: GatewayRegistrationIdentity) -> Bool {
        switch self {
        case .activation(let v): return identity.matches(v.binding)
        case .revocation(let v):
            let b = v.binding
            return b.ownerID == identity.ownerID && b.macID == identity.macID && b.accountID == identity.accountID &&
                b.gatewayID == identity.gatewayID && b.lifecycleEpoch == identity.lifecycleEpoch
        }
    }
    static func decode(_ data: Data, kind: GatewayRecipientKind, limits: CBORLimits) throws -> Self {
        switch kind {
        case .activation: .activation(try GatewayMappingActivation.decode(data, limits: limits))
        case .phoneRevocation: .revocation(try GatewayPhoneRevocation.decode(data, limits: limits))
        }
    }
}

/// One coherent local counter and its root-signed historical receipt. This is not an authenticated network reply.
public struct GatewayHeadEvidence: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let registration: GatewayRegistrationIdentity
    public let revision: UInt64
    public let receipt: GatewayControlReceipt?
    public var description: String { "GatewayHeadEvidence(redacted)" }
    public var debugDescription: String { description }
}

/// Historical control evidence. Its signature does not prove the gateway's current head or authorize delivery.
public enum GatewayControlReceipt: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case candidate(GatewayCandidateReceipt)
    case recipient(GatewayRecipientReceipt)
    case submission(GatewaySubmissionReceipt)
    case tombstone(GatewayControlTombstoneReceipt)

    public var kind: UInt64 {
        switch self {
        case .candidate: 1
        case .recipient(let value): value.kind.rawValue
        case .submission(let value): value.control.kind.rawValue
        case .tombstone: GatewayControlTombstone.receiptKind
        }
    }

    public var revision: UInt64 {
        switch self { case .candidate(let value): value.candidate.revision; case .recipient(let value): value.revision; case .submission(let value): value.control.revision; case .tombstone(let value): value.tombstone.revision }
    }
    public var operationID: Data {
        switch self { case .candidate(let value): value.candidate.operationID; case .recipient(let value): value.operationID; case .submission(let value): value.control.operationID; case .tombstone(let value): value.tombstone.operationID }
    }
    public var canonicalPayload: Data {
        switch self { case .candidate(let value): value.canonicalPayload; case .recipient(let value): value.canonicalPayload; case .submission(let value): value.canonicalPayload; case .tombstone(let value): value.canonicalPayload }
    }
    public var signature: Data {
        switch self { case .candidate(let value): value.signature; case .recipient(let value): value.signature; case .submission(let value): value.signature; case .tombstone(let value): value.signature }
    }
    public var description: String { "GatewayControlReceipt(redacted)" }
    public var debugDescription: String { description }
}
