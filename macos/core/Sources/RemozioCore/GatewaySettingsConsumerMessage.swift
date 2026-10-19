import CryptoKit
import Foundation
import RemozioProtocol

/// Companion control is separate from Root control1. Its binding and purposes cannot decode as Root messages.
enum GatewaySettingsConsumerInterface {
    static let version: UInt64 = 1
    static let supportedVersions: Set<UInt64> = [version]
}
enum GatewaySettingsConsumerRole: UInt64, CaseIterable, Sendable {
    case gateway = 1, transport = 2
    var codeRole: AuthorityCodeRole { self == .gateway ? .notificationGateway : .transport }
    var formatName: String { self == .gateway ? "gateway.gateway-settings-control" : "transport.gateway-settings-control" }
    func serviceName(accountID: Data) throws -> String {
        let prefix = try RuntimePreparationPaths(accountID: accountID).namespace
        return prefix + (self == .gateway ? ".gateway-settings-consumer" : ".transport-settings-consumer")
    }
}

/// A native owner creates a fresh generation for its lifetime. This decoded value grants no native authority.
struct GatewaySettingsConsumerBinding: Equatable, Sendable, CustomStringConvertible {
    let role: GatewaySettingsConsumerRole
    let macID: Data
    let accountID: Data
    let generation: UUID
    var description: String { "GatewaySettingsConsumerBinding(redacted)" }
    init(role: GatewaySettingsConsumerRole, macID: Data, accountID: Data, generation: UUID = UUID()) throws {
        guard macID.count == 16, accountID.count == 16 else { throw GatewayPreparationError.invalidRecord }
        self.role = role; self.macID = macID; self.accountID = accountID; self.generation = generation
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(GatewaySettingsConsumerInterface.version),
            1: .text("remozio-gateway-settings-consumer-binding"), 2: .unsigned(role.rawValue),
            3: .bytes(macID), 4: .bytes(accountID), 5: .bytes(GatewaySettingsControlBinding.epochBytes(generation))]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...5),
              fields[0] == .unsigned(GatewaySettingsConsumerInterface.version), fields[1] == .text("remozio-gateway-settings-consumer-binding"),
              case .unsigned(let raw) = fields[2], let role = GatewaySettingsConsumerRole(rawValue: raw),
              case .bytes(let mac) = fields[3], case .bytes(let account) = fields[4], case .bytes(let generation) = fields[5],
              generation.count == 16 else { throw GatewayPreparationError.invalidRecord }
        let b = Array(generation)
        let uuid = UUID(uuid: (b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]))
        let result = try Self(role: role, macID: mac, accountID: account, generation: uuid)
        guard try result.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return result
    }
    private static let limits = try! CBORLimits(maxBytes: 256, maxDepth: 1, maxItems: 13)
}

/// The current authenticated peer and exact protected record must match before an operation can act.
struct GatewaySettingsConsumerRequest: Sendable, CustomStringConvertible {
    let binding: GatewaySettingsConsumerBinding
    let fenceDigest: Data
    let change: AuthorityPhonePushSettingsChange
    let action: GatewaySettingsControlAction
    let challenge: Data
    var description: String { "GatewaySettingsConsumerRequest(redacted)" }
    init(binding: GatewaySettingsConsumerBinding, fence: GatewayRuntimeSettingsFence,
         action: GatewaySettingsControlAction, challenge: Data) throws {
        guard binding.macID == fence.macID, binding.accountID == fence.accountID else { throw GatewayPreparationError.changedScope }
        try self.init(binding: binding, fenceDigest: Data(SHA256.hash(data: fence.encoded)),
            change: .init(revisionDigest: fence.revision.digest, previousCommitDigest: fence.previous.observationDigest,
                selectedCommitDigest: fence.selected.observationDigest), action: action, challenge: challenge)
    }
    private init(binding: GatewaySettingsConsumerBinding, fenceDigest: Data, change: AuthorityPhonePushSettingsChange,
                 action: GatewaySettingsControlAction, challenge: Data) throws {
        guard fenceDigest.count == 32, challenge.count == 32 else { throw GatewayPreparationError.invalidRecord }
        self.binding = binding; self.fenceDigest = fenceDigest; self.change = change; self.action = action; self.challenge = challenge
    }
    func validate(binding current: GatewaySettingsConsumerBinding, fence: GatewayRuntimeSettingsFence) throws {
        let expected = try Self(binding: current, fence: fence, action: action, challenge: challenge)
        guard try encoded == expected.encoded else { throw GatewayPreparationError.changedScope }
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(GatewaySettingsConsumerInterface.version),
            1: .text("remozio-gateway-settings-consumer-request"), 2: .bytes(binding.encoded), 3: .bytes(fenceDigest),
            4: .bytes(change.revisionDigest), 5: .bytes(change.previousCommitDigest), 6: .bytes(change.selectedCommitDigest),
            7: .unsigned(action.rawValue), 8: .bytes(challenge)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...8),
              fields[0] == .unsigned(GatewaySettingsConsumerInterface.version), fields[1] == .text("remozio-gateway-settings-consumer-request"),
              case .unsigned(let raw) = fields[7], let action = GatewaySettingsControlAction(rawValue: raw) else {
            throw GatewayPreparationError.invalidRecord
        }
        func data(_ key: UInt64) throws -> Data {
            guard case .bytes(let value) = fields[key] else { throw GatewayPreparationError.invalidRecord }; return value
        }
        let result = try Self(binding: .decode(data(2)), fenceDigest: data(3), change: .init(revisionDigest: data(4),
            previousCommitDigest: data(5), selectedCommitDigest: data(6)), action: action, challenge: data(8))
        guard try result.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return result
    }
    private static let limits = try! CBORLimits(maxBytes: 768, maxDepth: 1, maxItems: 19)
}

enum GatewaySettingsConsumerObservation: UInt64, CaseIterable, Sendable {
    case unknown = 0, quiescing = 1, paused = 2, accepted = 3, runtimeStarted = 4
}
/// A receipt for one exact current-generation request. A started runtime does not prove provider delivery.
struct GatewaySettingsConsumerResponse: Sendable, CustomStringConvertible {
    let request: GatewaySettingsConsumerRequest
    let observation: GatewaySettingsConsumerObservation
    var description: String { "GatewaySettingsConsumerResponse(redacted)" }
    init(request: GatewaySettingsConsumerRequest, observation: GatewaySettingsConsumerObservation) throws {
        guard request.action != .quiesce || observation == .paused,
              request.action != .accept || observation == .accepted || observation == .runtimeStarted else {
            throw GatewayPreparationError.changedScope
        }
        self.request = request; self.observation = observation
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(GatewaySettingsConsumerInterface.version),
            1: .text("remozio-gateway-settings-consumer-response"), 2: .bytes(request.encoded),
            3: .unsigned(observation.rawValue)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data, expected: GatewaySettingsConsumerRequest) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...3),
              fields[0] == .unsigned(GatewaySettingsConsumerInterface.version), fields[1] == .text("remozio-gateway-settings-consumer-response"),
              fields[2] == .bytes(try expected.encoded), case .unsigned(let raw) = fields[3],
              let observation = GatewaySettingsConsumerObservation(rawValue: raw) else { throw GatewayPreparationError.invalidRecord }
        let result = try Self(request: expected, observation: observation)
        guard try result.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return result
    }
    private static let limits = try! CBORLimits(maxBytes: 1024, maxDepth: 1, maxItems: 9)
}
