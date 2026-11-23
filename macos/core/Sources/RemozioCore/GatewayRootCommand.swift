import Foundation
import RemozioProtocol

/// Versioned local IPC commands. Only the signed Root process may send these commands.
/// This version is independent of the phone envelope and signed control versions.
public enum GatewayRootCommand: Sendable {
    case head(Data)
    case history(Data)
    case candidate(payload: Data, signature: Data, wireVersion: UInt64, phoneID: Data, token: String)
    case recipient(payload: Data, signature: Data, wireVersion: UInt64, phoneID: Data, kind: GatewayRecipientKind)
    case recoverPhoneRevocation(payload: Data, signature: Data, phoneID: Data, expectedHead: UInt64)
    case abandonGrant(payload: Data, signature: Data, expectedHead: UInt64)

    // Probe through the existing head path. An older gateway rejects the inner query without closing the channel.
    static let phoneRevocationRecoveryProbe = Data("remozio.gateway.phone-revocation-recovery.v1".utf8)
    static let abandonGrantProbe = Data("remozio.gateway.grant-tombstone.v1".utf8)
    case probe(operationID: Data, phoneID: Data)
    case wake(PhoneRequestDelivery)
    case withdraw(UUID)
    case registerWake(PhoneRequestDelivery)
    case submission(payload: Data, signature: Data, wireVersion: UInt64)

    public var protocolVersion: UInt64 {
        switch self { case .registerWake: 3; case .submission: 2; default: 1 }
    }

    public func encode() throws -> Data {
        let value: CBORValue
        switch self {
        case .head(let query): value = .array([.unsigned(1), .unsigned(0), .bytes(query)])
        case .history(let query): value = .array([.unsigned(1), .unsigned(1), .bytes(query)])
        case .candidate(let payload, let signature, let version, let phone, let token):
            value = .array([.unsigned(1), .unsigned(2), .bytes(payload), .bytes(signature), .unsigned(version), .bytes(phone), .text(token)])
        case .recipient(let payload, let signature, let version, let phone, let kind):
            value = .array([.unsigned(1), .unsigned(3), .bytes(payload), .bytes(signature), .unsigned(version), .bytes(phone), .unsigned(kind.rawValue)])
        case .recoverPhoneRevocation(let payload, let signature, let phone, let expectedHead):
            value = .array([.unsigned(1), .unsigned(9), .bytes(payload), .bytes(signature), .bytes(phone), .unsigned(expectedHead)])
        case .abandonGrant(let payload, let signature, let expectedHead):
            value = .array([.unsigned(1), .unsigned(10), .bytes(payload), .bytes(signature), .unsigned(expectedHead)])
        case .probe(let operation, let phone): value = .array([.unsigned(1), .unsigned(4), .bytes(operation), .bytes(phone)])
        case .wake(let delivery), .registerWake(let delivery):
            value = .array([.unsigned(protocolVersion), .unsigned(protocolVersion == 3 ? 8 : 5), .bytes(GatewayHostSnapshot.bytes(delivery.id)),
                .bytes(delivery.recipient.phoneID), .bytes(delivery.recipient.enrollmentEpoch), .bytes(delivery.requestID),
                .bytes(GatewayHostSnapshot.bytes(delivery.admittedAt.epoch)), .unsigned(delivery.admittedAt.milliseconds),
                .unsigned(delivery.deadlineMilliseconds)])
        case .submission(let payload, let signature, let version):
            value = .array([.unsigned(2), .unsigned(7), .bytes(payload), .bytes(signature), .unsigned(version)])
        case .withdraw(let id): value = .array([.unsigned(1), .unsigned(6), .bytes(GatewayHostSnapshot.bytes(id))])
        }
        let bytes = try DeterministicCBOR.encode(value, limits: Self.limits)
        _ = try Self.decode(bytes)
        return bytes
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .array(let values) = try DeterministicCBOR.decode(bytes, limits: limits), values.count >= 3,
              case .unsigned(let version) = values[0], case .unsigned(let kind) = values[1],
              (version == 1 && (kind <= 6 || kind == 9 || kind == 10)) || (version == 2 && kind == 7) ||
              (version == 3 && kind == 8) else { throw GatewayServiceError.invalidMessage }
        func blob(_ i: Int, count: Int? = nil, maximum: Int = 65536) throws -> Data {
            guard i < values.count, case .bytes(let bytes) = values[i], !bytes.isEmpty, bytes.count <= maximum,
                  count == nil || bytes.count == count else { throw GatewayServiceError.invalidMessage }; return bytes
        }
        func number(_ i: Int) throws -> UInt64 {
            guard i < values.count, case .unsigned(let value) = values[i] else { throw GatewayServiceError.invalidMessage }; return value
        }
        switch kind {
        case 0, 1:
            guard values.count == 3 else { throw GatewayServiceError.invalidMessage }
            let query = try blob(2, maximum: 1024)
            return kind == 0 ? .head(query) : .history(query)
        case 2:
            guard values.count == 7, case .text(let token) = values[6], !token.isEmpty, token.utf8.count <= 4096 else {
                throw GatewayServiceError.invalidMessage
            }
            return try .candidate(payload: blob(2), signature: blob(3, count: 64), wireVersion: number(4), phoneID: blob(5, count: 16), token: token)
        case 3:
            guard values.count == 7, let recipient = try GatewayRecipientKind(rawValue: number(6)) else { throw GatewayServiceError.invalidMessage }
            return try .recipient(payload: blob(2), signature: blob(3, count: 64), wireVersion: number(4), phoneID: blob(5, count: 16), kind: recipient)
        case 9:
            guard values.count == 6 else { throw GatewayServiceError.invalidMessage }
            return try .recoverPhoneRevocation(payload: blob(2, maximum: 4096), signature: blob(3, count: 64),
                phoneID: blob(4, count: 16), expectedHead: number(5))
        case 10:
            guard values.count == 5 else { throw GatewayServiceError.invalidMessage }
            return try .abandonGrant(payload: blob(2, maximum: 1024), signature: blob(3, count: 64), expectedHead: number(4))
        case 4:
            guard values.count == 4 else { throw GatewayServiceError.invalidMessage }
            return try .probe(operationID: blob(2, count: 16), phoneID: blob(3, count: 16))
        case 5, 8:
            guard values.count == 9 else { throw GatewayServiceError.invalidMessage }
            let delivery = try PhoneRequestDelivery(id: GatewayHostSnapshot.uuid(blob(2, count: 16)),
                recipient: DeliveryRecipient(phoneID: blob(3, count: 16), enrollmentEpoch: blob(4, count: 16)),
                requestID: blob(5, count: 16), admittedAt: AuthorityMoment(epoch: GatewayHostSnapshot.uuid(blob(6, count: 16)),
                    milliseconds: number(7)), deadlineMilliseconds: number(8))
            return kind == 5 ? .wake(delivery) : .registerWake(delivery)
        case 7:
            guard values.count == 5 else { throw GatewayServiceError.invalidMessage }
            return try .submission(payload: blob(2), signature: blob(3, count: 64), wireVersion: number(4))
        case 6:
            guard values.count == 3 else { throw GatewayServiceError.invalidMessage }
            return try .withdraw(GatewayHostSnapshot.uuid(blob(2, count: 16)))
        default: throw GatewayServiceError.invalidMessage
        }
    }
    static var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 131072, maxDepth: 1, maxItems: 16) } }
    static func reply(_ fields: [CBORValue], version: UInt64 = 1) throws -> Data {
        guard (1...3).contains(version) else { throw GatewayServiceError.invalidMessage }
        return try DeterministicCBOR.encode(.array([.unsigned(version)] + fields), limits: CBORLimits(maxBytes: 1_100_128, maxDepth: 1, maxItems: 8))
    }
}
