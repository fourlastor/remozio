import Foundation
import RemozioProtocol

public enum PhoneRevocationStatus: UInt64, Sendable {
    case unknown = 0
    case active = 1
    case staleSelection = 2
    case revokedOnMac = 3
    case gatewayPending = 4
    case gatewayApplied = 5
    case gatewayBlocked = 6
    case gatewayUnsupported = 7
    case gatewayUnavailable = 8
    case gatewayNotRequired = 9
    case gatewayInconclusive = 10
}

public enum PairedPhoneRevocationAvailability: UInt64, Sendable {
    case available = 0
    case gatewayUnsupported = 1
    case gatewayUnavailable = 2
}

public enum GatewayRevocationHealth: UInt64, Sendable {
    case clear, pending, blocked, gatewayUpdateNeeded
    case grantAbandonmentInconclusive, pushDisabled, registrationChanged, waitingForGrantExpiry

    static func read(_ enrollments: [StoredApprovalEnrollment], availability: PairedPhoneRevocationAvailability,
                     registration: GatewayRegistrationIdentity? = nil, pushEnabled: Bool? = nil,
                     grantHealth: Self = .clear, hasBlockedRevocation: Bool = false) -> Self {
        let intents = enrollments.compactMap(\.gatewayRevocation).filter { $0.progress != .applied }
        let needsDelivery = !intents.isEmpty || hasBlockedRevocation
        if grantHealth == .gatewayUpdateNeeded || (needsDelivery && availability == .gatewayUnsupported) {
            return .gatewayUpdateNeeded
        }
        if let registration, intents.contains(where: { $0.registration != registration }) { return .registrationChanged }
        if pushEnabled == false, needsDelivery { return .pushDisabled }
        if grantHealth == .blocked || hasBlockedRevocation || intents.contains(where: { $0.progress == .blocked }) { return .blocked }
        if grantHealth != .clear { return grantHealth }
        return intents.isEmpty ? .clear : .pending
    }
}

/// Read-only health reported by the authenticated local authority.
public struct GatewayRevocationStatus: Equatable, Sendable {
    public let health: GatewayRevocationHealth
    public let inconclusiveSinceUnixMillis: UInt64?
}

enum PairedPhoneOperation: UInt64 {
    case list, status, revoke, listForRePair, validateRePair, discardExpiredRePair
}

public struct PairedPhoneSelection: Sendable {
    let macID: Data
    let accountID: Data
    let revision: UUID
    public let phone: DeliveryRecipient

    var predecessor: PairingReplacement {
        get throws { try PairingReplacement(phoneID: phone.phoneID, epoch: phone.enrollmentEpoch) }
    }

    func encode() throws -> Data {
        try DeterministicCBOR.encode(.array([.bytes(macID), .bytes(accountID), .bytes(GatewayHostSnapshot.bytes(revision)),
            .bytes(phone.phoneID), .bytes(phone.enrollmentEpoch)]), limits: Self.limits)
    }

    static func decode(_ data: Data) throws -> Self {
        guard case .array(let fields) = try DeterministicCBOR.decode(data, limits: limits), fields.count == 5,
              case .bytes(let macID) = fields[0], case .bytes(let accountID) = fields[1],
              case .bytes(let revision) = fields[2], case .bytes(let phoneID) = fields[3], case .bytes(let epoch) = fields[4],
              [macID, accountID, revision, phoneID, epoch].allSatisfy({ $0.count == 16 }) else {
            throw AuthorityPairingChannelError.invalidMessage
        }
        let result = try Self(macID: macID, accountID: accountID, revision: GatewayHostSnapshot.uuid(revision),
            phone: DeliveryRecipient(phoneID: phoneID, enrollmentEpoch: epoch))
        guard try result.encode() == data else { throw AuthorityPairingChannelError.invalidMessage }
        return result
    }

    private static var limits: CBORLimits { get throws { try .init(maxBytes: 128, maxDepth: 2, maxItems: 8) } }
}

public struct PairedPhoneSnapshot: Sendable {
    let macID: Data
    let accountID: Data
    let revision: UUID
    public let phones: [DeliveryRecipient]
    public let rePairablePhones: [DeliveryRecipient]
    public let revocationAvailability: PairedPhoneRevocationAvailability
    public let gatewayRevocationHealth: GatewayRevocationHealth
    public let gatewayInconclusiveSinceUnixMillis: UInt64?

    public var gatewayRevocationStatus: GatewayRevocationStatus {
        .init(health: gatewayRevocationHealth, inconclusiveSinceUnixMillis: gatewayInconclusiveSinceUnixMillis)
    }

    public func selection(for phone: DeliveryRecipient) -> PairedPhoneSelection? {
        guard phones.contains(phone) else { return nil }
        return PairedPhoneSelection(macID: macID, accountID: accountID, revision: revision, phone: phone)
    }

    public func rePairSelection(for phone: DeliveryRecipient) -> PairedPhoneSelection? {
        guard rePairablePhones.contains(phone) else { return nil }
        return PairedPhoneSelection(macID: macID, accountID: accountID, revision: revision, phone: phone)
    }

    func encode(includeRePair: Bool = false) throws -> Data {
        func rows(_ phones: [DeliveryRecipient]) -> CBORValue {
            .array(phones.map { .array([.bytes($0.phoneID), .bytes($0.enrollmentEpoch)]) })
        }
        var fields: [CBORValue] = [.bytes(macID), .bytes(accountID), .bytes(GatewayHostSnapshot.bytes(revision)),
            rows(phones), .unsigned(revocationAvailability.rawValue), .unsigned(gatewayRevocationHealth.rawValue),
            gatewayInconclusiveSinceUnixMillis.map(CBORValue.unsigned) ?? .null]
        if includeRePair { fields.append(rows(rePairablePhones)) }
        return try DeterministicCBOR.encode(.array(fields), limits: Self.limits)
    }

    static func decode(_ data: Data, macID: Data, accountID: Data, includeRePair: Bool = false) throws -> Self {
        guard case .array(let fields) = try DeterministicCBOR.decode(data, limits: limits),
              fields.count == (includeRePair ? 8 : 7), fields[0] == .bytes(macID), fields[1] == .bytes(accountID),
              case .bytes(let revision) = fields[2], revision.count == 16, case .array(let rows) = fields[3],
              case .unsigned(let availability) = fields[4],
              let revocationAvailability = PairedPhoneRevocationAvailability(rawValue: availability),
              case .unsigned(let health) = fields[5], let gatewayRevocationHealth = GatewayRevocationHealth(rawValue: health) else {
            throw AuthorityPairingChannelError.invalidMessage
        }
        func decodeRows(_ rows: [CBORValue]) throws -> [DeliveryRecipient] {
            guard rows.count <= EnrollmentJournal.maximumRows else { throw AuthorityPairingChannelError.invalidMessage }
            return try rows.map { row in
                guard case .array(let values) = row, values.count == 2, case .bytes(let phoneID) = values[0],
                      case .bytes(let epoch) = values[1], phoneID.count == 16, epoch.count == 16 else {
                    throw AuthorityPairingChannelError.invalidMessage
                }
                return DeliveryRecipient(phoneID: phoneID, enrollmentEpoch: epoch)
            }
        }
        let phones = try decodeRows(rows)
        let rePairablePhones: [DeliveryRecipient]
        if includeRePair, case .array(let retained) = fields[7] {
            rePairablePhones = try decodeRows(retained)
        } else if includeRePair {
            throw AuthorityPairingChannelError.invalidMessage
        } else {
            rePairablePhones = []
        }
        guard phones.count + rePairablePhones.count <= EnrollmentJournal.maximumRows,
              Set(phones.map(\.phoneID)).count == phones.count,
              Set(phones.map(\.phoneID)).isDisjoint(with: rePairablePhones.map(\.phoneID)),
              Set((phones + rePairablePhones).map(\.enrollmentEpoch)).count == phones.count + rePairablePhones.count else {
            throw AuthorityPairingChannelError.invalidMessage
        }
        let inconclusiveSince: UInt64?
        switch fields[6] {
        case .null: inconclusiveSince = nil
        case .unsigned(let value) where gatewayRevocationHealth == .grantAbandonmentInconclusive: inconclusiveSince = value
        default: throw AuthorityPairingChannelError.invalidMessage
        }
        let result = try Self(macID: macID, accountID: accountID, revision: GatewayHostSnapshot.uuid(revision),
            phones: phones, rePairablePhones: rePairablePhones, revocationAvailability: revocationAvailability, gatewayRevocationHealth: gatewayRevocationHealth,
            gatewayInconclusiveSinceUnixMillis: inconclusiveSince)
        guard try result.encode(includeRePair: includeRePair) == data else { throw AuthorityPairingChannelError.invalidMessage }
        return result
    }

    private static var limits: CBORLimits { get throws { try .init(maxBytes: 38_000, maxDepth: 4, maxItems: 3_100) } }
}
