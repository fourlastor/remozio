import Foundation
import RemozioProtocol

/// A release acknowledgement is not evidence that ordinary account admission is available.
struct AuthorityMaintenanceUnboundReleaseResponse: Equatable, Sendable {
    enum Outcome: UInt64, Sendable { case released = 0, alreadyReleased = 1, busy = 2, refused = 3 }
    let request: AuthorityMaintenanceUnboundRequest
    let outcome: Outcome
    init(request: AuthorityMaintenanceUnboundRequest, outcome: Outcome) throws {
        guard request.kind == .release else { throw RuntimePreparationError.invalidRecord }
        self.request = request; self.outcome = outcome
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("authority.maintenance-unbound-release.reply"),
            2: .bytes(try request.encoded), 3: .unsigned(outcome.rawValue)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...3), fields[0] == .unsigned(1),
              fields[1] == .text("authority.maintenance-unbound-release.reply"),
              case .bytes(let request) = fields[2], case .unsigned(let value) = fields[3],
              let outcome = Outcome(rawValue: value) else { throw RuntimePreparationError.invalidRecord }
        let result = try Self(request: .decode(request), outcome: outcome)
        guard try result.encoded == bytes else { throw RuntimePreparationError.invalidRecord }
        return result
    }
    private static let limits = try! CBORLimits(maxBytes: 1024, maxDepth: 1, maxItems: 9)
}
