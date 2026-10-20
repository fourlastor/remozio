import Foundation
import RemozioProtocol

/// Historical settings records. These records do not report current service health or grant mutation rights.
public struct SetupGatewaySettingsProgress: Equatable, Sendable {
    public enum Stage: UInt64, Sendable { case retained, quiesced, filesPublished, consumersObserved }
    public let activation: SetupGatewayActivationProgress
    public let stage: Stage?
    public let initialSelection: GatewayRuntimeSettingsSelection
    /// Retained host support only. This flag does not report running service health or grant mutation rights.
    public let supportsSettingsChanges: Bool
    public static let maximumByteCount = 90_000
    public var currentSelection: GatewayRuntimeSettingsSelection { get throws { try activeSelection ?? initialSelection } }
    private let activeBytes: Data?
    private let pendingBytes: Data?
    var active: GatewayRuntimeSettingsRevision? { get throws { try activeBytes.map(GatewayRuntimeSettingsRevision.decode) } }
    var pending: GatewayRuntimeSettingsRevision? { get throws { try pendingBytes.map(GatewayRuntimeSettingsRevision.decode) } }
    public var activeSelection: GatewayRuntimeSettingsSelection? { get throws { try active?.selection } }
    public var pendingSelection: GatewayRuntimeSettingsSelection? { get throws { try pending?.selection } }
    public var activeDigest: Data? { get throws { try active?.digest } }
    public var pendingDigest: Data? { get throws { try pending?.digest } }

    init(activation: SetupGatewayActivationProgress, state: GatewayRuntimeSettingsState, initialSelection: GatewayRuntimeSettingsSelection, supportsSettingsChanges: Bool) throws {
        try self.init(activation: activation, activeBytes: state.active?.encoded,
            pendingBytes: state.pending?.encoded, initialSelection: initialSelection, stage: state.phase.map { Stage(rawValue: UInt64($0.rawValue))! }, supportsSettingsChanges: supportsSettingsChanges)
    }
    private init(activation: SetupGatewayActivationProgress, activeBytes: Data?, pendingBytes: Data?, initialSelection: GatewayRuntimeSettingsSelection, stage: Stage?, supportsSettingsChanges: Bool) throws {
        guard activation.filesPublished, activation.jobRegistered, let activationDigest = activation.planDigest,
              (pendingBytes == nil) == (stage == nil) else { throw GatewayPreparationError.invalidRecord }
        guard activation.settings == initialSelection.activation else { throw GatewayPreparationError.changedScope }
        let active = try activeBytes.map(GatewayRuntimeSettingsRevision.decode)
        let pending = try pendingBytes.map(GatewayRuntimeSettingsRevision.decode)
        for value in [active, pending].compactMap({ $0 }) {
            guard value.accountID == activation.setup.accountID, value.activationDigest == activationDigest else {
                throw GatewayPreparationError.changedScope
            }
        }
        if let pending {
            if let active {
                guard active.sequence < UInt64.max, pending.sequence == active.sequence + 1,
                      pending.id != active.id, try pending.previousDigest == active.digest else {
                    throw GatewayPreparationError.changedScope
                }
            } else {
                guard pending.sequence == 1, pending.previousDigest == activationDigest else {
                    throw GatewayPreparationError.changedScope
                }
            }
        }
        self.activation = activation; self.activeBytes = activeBytes; self.pendingBytes = pendingBytes; self.stage = stage; self.initialSelection = initialSelection; self.supportsSettingsChanges = supportsSettingsChanges
    }
    public static func == (lhs: Self, rhs: Self) -> Bool {
        guard let left = try? lhs.initialSelection.bytes, let right = try? rhs.initialSelection.bytes else { return false }
        return lhs.activation == rhs.activation && lhs.stage == rhs.stage && lhs.activeBytes == rhs.activeBytes &&
            lhs.pendingBytes == rhs.pendingBytes && left == right && lhs.supportsSettingsChanges == rhs.supportsSettingsChanges
    }
    public var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.purpose), 2: .bytes(activation.bytes),
            3: activeBytes.map(CBORValue.bytes) ?? .null, 4: pendingBytes.map(CBORValue.bytes) ?? .null,
            5: stage.map { .unsigned($0.rawValue) } ?? .null, 6: .bytes(initialSelection.bytes), 7: .boolean(supportsSettingsChanges)]), limits: Self.limits)
    } }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...7),
              f[0] == .unsigned(1), f[1] == .text(purpose), case .bytes(let activation) = f[2], case .bytes(let initial) = f[6], case .boolean(let supported) = f[7] else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        func optional(_ key: UInt64) throws -> Data? {
            if f[key] == .null { return nil }
            guard case .bytes(let value) = f[key] else { throw AdministrativeSetupChannelError.invalidMessage }; return value
        }
        let stage: Stage?
        if f[5] == .null { stage = nil }
        else {
            guard case .unsigned(let raw) = f[5], let value = Stage(rawValue: raw) else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            stage = value
        }
        let value = try Self(activation: .decode(activation), activeBytes: optional(3), pendingBytes: optional(4), initialSelection: .decode(initial), stage: stage, supportsSettingsChanges: supported)
        guard try value.bytes == bytes else { throw AdministrativeSetupChannelError.invalidMessage }; return value
    }
    func validateRetention(of expected: Self, selection: GatewayRuntimeSettingsSelection) throws {
        guard supportsSettingsChanges, expected.supportsSettingsChanges, activation == expected.activation, try initialSelection.bytes == expected.initialSelection.bytes, expected.pendingBytes == nil, activeBytes == expected.activeBytes,
              stage == .retained, let pending = try pending, try pending.selection.bytes == selection.bytes else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
    }
    func validateApplication(of expected: Self, selection: GatewayRuntimeSettingsSelection) throws {
        guard supportsSettingsChanges, expected.supportsSettingsChanges, activation == expected.activation, try initialSelection.bytes == expected.initialSelection.bytes,
              pendingBytes == nil, stage == nil, let active = try active, try active.selection.bytes == selection.bytes else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        if try expected.pending != nil { try validateCompletion(of: expected); return }
        if let previous = try expected.active {
            guard previous.sequence < UInt64.max, active.sequence == previous.sequence + 1,
                  active.id != previous.id, try active.previousDigest == previous.digest else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
        } else {
            guard active.sequence == 1, active.previousDigest == activation.planDigest else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
        }
    }
    func validateCompletion(of expected: Self) throws {
        guard supportsSettingsChanges, expected.supportsSettingsChanges, activation == expected.activation, try initialSelection.bytes == expected.initialSelection.bytes, let pending = try expected.pending,
              pendingBytes == nil, stage == nil, try active?.encoded == pending.encoded else {
            throw AdministrativeSetupError.staleProgress
        }
    }
    private static let purpose = "remozio-gateway-settings-progress"
    private static let limits = try! CBORLimits(maxBytes: maximumByteCount, maxDepth: 1, maxItems: 17)
}
