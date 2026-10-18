import Foundation
import RemozioProtocol

/// Report bytes only. The Root host must authenticate the running gateway and match its pending intent before accepting this report.
struct GatewayJournalSetupReport: CustomStringConvertible, CustomDebugStringConvertible {
    let intentID: Data
    let scopeDigest: Data
    let created: Bool
    var description: String { "GatewayJournalSetupReport(redacted)" }
    var debugDescription: String { description }
    init(intentID: Data, scopeDigest: Data, created: Bool) throws {
        guard intentID.count == 16, scopeDigest.count == 32 else { throw GatewayPreparationError.invalidRecord }
        self.intentID = intentID; self.scopeDigest = scopeDigest; self.created = created
    }
    func validate(intent: GatewayJournalSetupIntent) throws {
        guard intentID == intent.id, try scopeDigest == intent.digest else { throw GatewayPreparationError.changedScope }
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-journal-prepared"),
            2: .bytes(intentID), 3: .bytes(scopeDigest), 4: .boolean(created)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...4),
              fields[0] == .unsigned(1), fields[1] == .text("remozio-gateway-journal-prepared"),
              case .bytes(let id) = fields[2], case .bytes(let digest) = fields[3], case .boolean(let created) = fields[4] else {
            throw GatewayPreparationError.invalidRecord
        }
        let value = try Self(intentID: id, scopeDigest: digest, created: created)
        guard try value.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return value
    }
    static var limits: CBORLimits { get throws { try .init(maxBytes: 512, maxDepth: 1, maxItems: 11) } }
}

/// Initialization report composition below the authenticated setup endpoint. Startup alone grants no creation permission.
enum GatewayJournalPreparationOperation {
    // Owned fixtures use the real initializer without claiming native UID admission, protected publication or report authentication.
    static func execute(intent: GatewayJournalSetupIntent,
                        initialize: (GatewayServiceConfiguration, GatewayJournalFileIdentity) throws -> GatewayJournalInitialization.Result) throws -> Data {
        let result = try initialize(intent.configuration, intent.files)
        guard result.head.registration == intent.configuration.registration, result.head.revision == 0, result.head.receipt == nil else {
            throw GatewayPreparationError.changedScope
        }
        return try GatewayJournalSetupReport(intentID: intent.id, scopeDigest: intent.digest, created: result.initialized).encoded
    }
}
