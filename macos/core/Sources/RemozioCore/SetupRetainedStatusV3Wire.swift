import Foundation
import RemozioProtocol

/// Status-only codec. Applicability is a snapshot and grants no recovery authority.
enum SetupRetainedStatusV3Wire {
    static let version: UInt64 = 3
    static let formatName = "setup.retained-status"
    enum Applicability: UInt64, Equatable, Sendable {
        case noAction = 0, restore, adoptRecordedCompletion, releaseWindowFree
    }

    static func supports(_ release: SignedReleaseEvidence) -> Bool {
        [AuthorityCodeRole.app, .setupController].allSatisfy { role in
            release.manifest.components.first { $0.role == role }?.formats.contains {
                $0.name == formatName && $0.readers.contains(version) && $0.writers.contains(version)
            } == true
        }
    }

    private static var requestLimits: CBORLimits { get throws {
        try .init(maxBytes: SetupRetainedStatusWire.maximumRequestBytes, maxDepth: 2, maxItems: 8)
    } }
    private static var replyLimits: CBORLimits { get throws {
        try .init(maxBytes: SetupRetainedStatusWire.maximumReplyBytes, maxDepth: 4, maxItems: 64)
    } }

    struct Request {
        let legacy: SetupRetainedStatusWire.Request
        var bytes: Data { get throws {
            try DeterministicCBOR.encode(.map([0: .unsigned(version), 1: .text(SetupRetainedStatusWire.requestName),
                2: .bytes(legacy.requestID)]), limits: requestLimits)
        } }

        static func decode(_ bytes: Data) throws -> Self {
            guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: requestLimits),
                  Set(fields.keys) == [0, 1, 2], fields[0] == .unsigned(version),
                  fields[1] == .text(SetupRetainedStatusWire.requestName), case .bytes(let id) = fields[2] else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            let request = try Self(legacy: .init(requestID: id))
            guard try request.bytes == bytes else { throw AdministrativeSetupChannelError.invalidMessage }
            return request
        }
    }

    static func reply(_ request: Request, _ status: SetupRetainedStatusProjection) throws -> Data {
        let legacy = try SetupRetainedStatusWire.reply(request.legacy, status.v1)
        guard case .map(var fields) = try DeterministicCBOR.decode(legacy, limits: replyLimits) else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        fields[0] = .unsigned(version)
        fields[11] = status.applicability.map { .unsigned($0.rawValue) } ?? .null
        return try DeterministicCBOR.encode(.map(fields), limits: replyLimits)
    }

    static func decodeReply(_ bytes: Data, matching request: Request) throws -> SetupRetainedStatusWire.Observation {
        let invalid = AdministrativeSetupChannelError.invalidMessage
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: replyLimits),
              Set(fields.keys) == Set(UInt64(0)...11), fields[0] == .unsigned(version),
              try DeterministicCBOR.encode(.map(fields), limits: replyLimits) == bytes else { throw invalid }
        let value = fields.removeValue(forKey: 11)
        fields[0] = .unsigned(SetupRetainedStatusWire.version)
        let legacy = try DeterministicCBOR.encode(.map(fields), limits: replyLimits)
        var observation = try SetupRetainedStatusWire.decodeReply(legacy, matching: request.legacy)
        if value == .null { return observation }
        guard case .unsigned(let code) = value, let applicability = Applicability(rawValue: code) else { throw invalid }
        if applicability != .noAction {
            guard observation.identity != nil, observation.reservation == .orphan || observation.reservation == .recovering,
                  observation.worker == .idle, observation.cleanup == .joined else { throw invalid }
            switch applicability {
            case .restore, .adoptRecordedCompletion: guard observation.window != nil else { throw invalid }
            case .releaseWindowFree: guard observation.window == nil else { throw invalid }
            case .noAction: break
            }
        }
        observation.applicability = applicability
        return observation
    }
}
