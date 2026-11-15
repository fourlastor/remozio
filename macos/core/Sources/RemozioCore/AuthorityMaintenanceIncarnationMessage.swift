import Foundation
import RemozioProtocol

/// Asks the authenticated Authority for its live clock epoch. These bytes cannot open, reserve, release or read any store.
struct AuthorityMaintenanceIncarnationRequest: Equatable, Sendable {
    let accountID: Data, challenge: Data
    init(accountID: Data, challenge: Data) throws {
        guard accountID.count == 16, challenge.count == 16 else { throw RuntimePreparationError.invalidRecord }
        self.accountID = accountID; self.challenge = challenge
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("authority.maintenance-incarnation-request"),
            2: .bytes(accountID), 3: .bytes(challenge)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...3),
              f[0] == .unsigned(1), f[1] == .text("authority.maintenance-incarnation-request") else { throw RuntimePreparationError.invalidRecord }
        let value = try Self(accountID: incarnationData(f[2]), challenge: incarnationData(f[3]))
        guard try value.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return value
    }
    private static let limits = try! CBORLimits(maxBytes: 128, maxDepth: 1, maxItems: 9)
}

/// Echoes the exact account and challenge with the epoch that pairing admission puts in every binding.
struct AuthorityMaintenanceIncarnationResponse: Equatable, Sendable {
    let accountID: Data, incarnation: Data, challenge: Data
    init(request: AuthorityMaintenanceIncarnationRequest, incarnation: Data) throws {
        guard incarnation.count == 16 else { throw RuntimePreparationError.invalidRecord }
        accountID = request.accountID; self.incarnation = incarnation; challenge = request.challenge
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("authority.maintenance-incarnation-response"),
            2: .bytes(accountID), 3: .bytes(incarnation), 4: .bytes(challenge)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data, expected: AuthorityMaintenanceIncarnationRequest) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...4),
              f[0] == .unsigned(1), f[1] == .text("authority.maintenance-incarnation-response"),
              f[2] == .bytes(expected.accountID), f[4] == .bytes(expected.challenge) else { throw RuntimePreparationError.invalidRecord }
        let value = try Self(request: expected, incarnation: incarnationData(f[3]))
        guard try value.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return value
    }
    private static let limits = try! CBORLimits(maxBytes: 128, maxDepth: 1, maxItems: 11)
}

private func incarnationData(_ value: CBORValue?) throws -> Data {
    guard case .bytes(let value) = value else { throw RuntimePreparationError.invalidRecord }; return value
}
