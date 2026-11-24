import Foundation
import RemozioProtocol

/// A durable terminal re-pair stage reported by the local authority.
public struct ExpiredRePairRecord: Equatable, Sendable, CustomReflectable {
    public let phoneID: Data
    public let originalExpiryUnixMilliseconds: UInt64
    public let reason: PairingExpiryReason

    let macID: Data
    let accountID: Data
    let setupID: Data
    let transcriptDigest: Data

    var selection: Data { setupID + transcriptDigest }

    public var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }

    init(macID: Data, accountID: Data, phoneID: Data, originalExpiryUnixMilliseconds: UInt64,
         reason: PairingExpiryReason, setupID: Data, transcriptDigest: Data) {
        self.macID = macID
        self.accountID = accountID
        self.phoneID = phoneID
        self.originalExpiryUnixMilliseconds = originalExpiryUnixMilliseconds
        self.reason = reason
        self.setupID = setupID
        self.transcriptDigest = transcriptDigest
    }
}

struct ExpiredRePairSnapshot: Sendable {
    let macID: Data
    let accountID: Data
    let records: [ExpiredRePairRecord]

    func encode() throws -> Data {
        let rows = records.map { record in
            CBORValue.array([.bytes(record.phoneID), .unsigned(record.originalExpiryUnixMilliseconds),
                .unsigned(record.reason.rawValue), .bytes(record.setupID), .bytes(record.transcriptDigest)])
        }
        return try DeterministicCBOR.encode(.array([.bytes(macID), .bytes(accountID), .array(rows)]), limits: Self.limits)
    }

    static func decode(_ data: Data, macID: Data, accountID: Data) throws -> Self {
        guard case .array(let fields) = try DeterministicCBOR.decode(data, limits: limits), fields.count == 3,
              fields[0] == .bytes(macID), fields[1] == .bytes(accountID), case .array(let rows) = fields[2],
              rows.count <= PairingRecoveryStageJournal.maximumSlots else {
            throw AuthorityPairingChannelError.invalidMessage
        }
        let records = try rows.map { row in
            guard case .array(let values) = row, values.count == 5,
                  case .bytes(let phoneID) = values[0], phoneID.count == 16,
                  case .unsigned(let expiry) = values[1], expiry > 0,
                  case .unsigned(let reasonCode) = values[2], let reason = PairingExpiryReason(rawValue: reasonCode),
                  case .bytes(let setupID) = values[3], setupID.count == 16,
                  case .bytes(let digest) = values[4], digest.count == 32 else {
                throw AuthorityPairingChannelError.invalidMessage
            }
            return ExpiredRePairRecord(macID: macID, accountID: accountID, phoneID: phoneID,
                originalExpiryUnixMilliseconds: expiry, reason: reason, setupID: setupID, transcriptDigest: digest)
        }
        let result = Self(macID: macID, accountID: accountID, records: records)
        guard Set(records.map(\.phoneID)).count == records.count,
              Set(records.map(\.setupID)).count == records.count, try result.encode() == data else {
            throw AuthorityPairingChannelError.invalidMessage
        }
        return result
    }

    private static var limits: CBORLimits { get throws { try .init(maxBytes: 4_096, maxDepth: 4, maxItems: 220) } }
}
