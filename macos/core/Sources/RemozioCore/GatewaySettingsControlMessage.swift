import Foundation
import RemozioProtocol

public enum GatewaySettingsControlInterface {
    public static let version: UInt64 = 1
    public static let supportedVersions: Set<UInt64> = [version]
}
enum GatewaySettingsControlAction: UInt64, Sendable { case observe = 1, quiesce = 2, accept = 3 }
enum GatewaySettingsControlObservation: UInt64, Sendable { case unknown = 0, quiescing = 1, suspended = 2, accepted = 3, providerInstalled = 4 }

/// One live Root process. Decoding this binding authenticates neither the process nor its account.
struct GatewaySettingsControlBinding: Equatable, Sendable {
    let accountID: Data
    let rootEpoch: UUID
    init(accountID: Data, rootEpoch: UUID) throws {
        guard accountID.count == 16 else { throw GatewayPreparationError.invalidRecord }
        self.accountID = accountID; self.rootEpoch = rootEpoch
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-root-gateway-settings-binding"),
            2: .bytes(accountID), 3: .bytes(Self.epochBytes(rootEpoch))]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...3),
              f[0] == .unsigned(1), f[1] == .text("remozio-root-gateway-settings-binding"),
              case .bytes(let account) = f[2], case .bytes(let epoch) = f[3], epoch.count == 16 else { throw GatewayPreparationError.invalidRecord }
        let v = try Self(accountID: account, rootEpoch: epochUUID(epoch))
        guard try v.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return v
    }
    static func epochBytes(_ id: UUID) -> Data { withUnsafeBytes(of: id.uuid) { Data($0) } }
    private static func epochUUID(_ data: Data) -> UUID {
        let b = Array(data)
        return UUID(uuid: (b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]))
    }
    private static let limits = try! CBORLimits(maxBytes: 128, maxDepth: 1, maxItems: 9)
}

/// One explicit native operation. The original XPC invocation must authenticate the setup helper independently.
struct GatewaySettingsControlRequest: Sendable {
    let binding: GatewaySettingsControlBinding
    let change: AuthorityPhonePushSettingsChange
    let action: GatewaySettingsControlAction
    let challenge: Data
    init(binding: GatewaySettingsControlBinding, change: AuthorityPhonePushSettingsChange,
         action: GatewaySettingsControlAction, challenge: Data) throws {
        guard challenge.count == 32 else { throw GatewayPreparationError.invalidRecord }
        self.binding = binding; self.change = change; self.action = action; self.challenge = challenge
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-root-gateway-settings-request"),
            2: .bytes(binding.encoded), 3: .bytes(change.revisionDigest), 4: .bytes(change.previousCommitDigest),
            5: .bytes(change.selectedCommitDigest), 6: .unsigned(action.rawValue), 7: .bytes(challenge)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...7),
              f[0] == .unsigned(1), f[1] == .text("remozio-root-gateway-settings-request"),
              case .bytes(let binding) = f[2], case .bytes(let revision) = f[3], case .bytes(let previous) = f[4],
              case .bytes(let selected) = f[5], case .unsigned(let raw) = f[6], let action = GatewaySettingsControlAction(rawValue: raw),
              case .bytes(let challenge) = f[7] else { throw GatewayPreparationError.invalidRecord }
        let v = try Self(binding: .decode(binding), change: .init(revisionDigest: revision, previousCommitDigest: previous,
            selectedCommitDigest: selected), action: action, challenge: challenge)
        guard try v.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return v
    }
    private static let limits = try! CBORLimits(maxBytes: 512, maxDepth: 1, maxItems: 17)
}

/// A bounded reply for the exact request. Its observation grants no authorization or provider delivery claim.
struct GatewaySettingsControlResponse: Sendable {
    let request: GatewaySettingsControlRequest
    let observation: GatewaySettingsControlObservation
    init(request: GatewaySettingsControlRequest, observation: GatewaySettingsControlObservation) throws {
        guard request.action != .quiesce || observation == .suspended,
              request.action != .accept || observation == .accepted || observation == .providerInstalled else {
            throw GatewayPreparationError.changedScope
        }
        self.request = request; self.observation = observation
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-root-gateway-settings-response"),
            2: .bytes(request.encoded), 3: .unsigned(observation.rawValue)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data, expected: GatewaySettingsControlRequest) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...3),
              f[0] == .unsigned(1), f[1] == .text("remozio-root-gateway-settings-response"),
              f[2] == .bytes(try expected.encoded), case .unsigned(let raw) = f[3],
              let observation = GatewaySettingsControlObservation(rawValue: raw) else { throw GatewayPreparationError.invalidRecord }
        let v = try Self(request: expected, observation: observation)
        guard try v.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return v
    }
    private static let limits = try! CBORLimits(maxBytes: 640, maxDepth: 1, maxItems: 9)
}
