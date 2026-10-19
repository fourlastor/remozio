import Foundation
import RemozioProtocol

/// Selected wake timings. The app must retain the explicit selection across setup retries.
public struct GatewayRuntimeActivationSettings: Equatable, Sendable {
    public let wakePollMilliseconds: UInt64
    public let wakeTimeoutMilliseconds: UInt64
    public init(wakePollMilliseconds: UInt64 = 1000, wakeTimeoutMilliseconds: UInt64 = 5000) throws {
        guard (100...60000).contains(wakePollMilliseconds), (1...60000).contains(wakeTimeoutMilliseconds) else {
            throw GatewayPreparationError.invalidRecord
        }
        self.wakePollMilliseconds = wakePollMilliseconds; self.wakeTimeoutMilliseconds = wakeTimeoutMilliseconds
    }
    public var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.purpose),
            2: .unsigned(wakePollMilliseconds), 3: .unsigned(wakeTimeoutMilliseconds)]), limits: Self.limits)
    } }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...3),
              f[0] == .unsigned(1), f[1] == .text(purpose), case .unsigned(let poll) = f[2],
              case .unsigned(let timeout) = f[3] else { throw GatewayPreparationError.invalidRecord }
        let value = try Self(wakePollMilliseconds: poll, wakeTimeoutMilliseconds: timeout)
        guard try value.bytes == bytes else { throw GatewayPreparationError.invalidRecord }; return value
    }
    private static let purpose = "remozio-gateway-activation-settings"
    private static let limits = try! CBORLimits(maxBytes: 256, maxDepth: 1, maxItems: 9)
}

/// Historical setup markers and selected timings. This value makes no claim about current service or phone health.
public struct SetupGatewayActivationProgress: Equatable, Sendable {
    public let setup: SetupGatewayProgress
    public let planDigest: Data?
    public let settings: GatewayRuntimeActivationSettings?
    public let filesPublished: Bool
    public let jobRegistered: Bool

    init(setup: SetupGatewayProgress, state: GatewayRuntimeActivationState) throws {
        var digest: Data?, settings: GatewayRuntimeActivationSettings?
        if let plan = state.plan {
            let scope = plan.extensions.authority, runtime = scope.material.runtime
            guard setup.journalInitialized, plan.accountID == setup.accountID, runtime.services.macID == setup.macID,
                  runtime.services.ownerUID == setup.ownerUID, runtime.materialID == setup.runtimeMaterialID,
                  scope.foregroundDigest == setup.foregroundDigest, scope.material.materialID == setup.gatewayMaterialID,
                  plan.journalIntentDigest == setup.journalIntentDigest,
                  let wake = plan.extensions.transport.wake else { throw GatewayPreparationError.changedScope }
            digest = try plan.digest
            settings = try .init(wakePollMilliseconds: wake.pollMilliseconds, wakeTimeoutMilliseconds: wake.wake.timeoutMilliseconds)
        }
        try self.init(setup: setup, planDigest: digest, settings: settings,
            filesPublished: state.filesPublished, jobRegistered: state.jobRegistered)
    }
    private init(setup: SetupGatewayProgress, planDigest: Data?, settings: GatewayRuntimeActivationSettings?,
                 filesPublished: Bool, jobRegistered: Bool) throws {
        guard (planDigest == nil) == (settings == nil), planDigest == nil || (planDigest?.count == 32 && setup.journalInitialized),
              !filesPublished || planDigest != nil, !jobRegistered || filesPublished else { throw GatewayPreparationError.invalidRecord }
        self.setup = setup; self.planDigest = planDigest; self.settings = settings
        self.filesPublished = filesPublished; self.jobRegistered = jobRegistered
    }
    public var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.purpose), 2: .bytes(setup.bytes),
            3: planDigest.map(CBORValue.bytes) ?? .null, 4: try settings.map { .bytes(try $0.bytes) } ?? .null,
            5: .boolean(filesPublished), 6: .boolean(jobRegistered)]), limits: Self.limits)
    } }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...6),
              f[0] == .unsigned(1), f[1] == .text(purpose), case .bytes(let setup) = f[2],
              case .boolean(let published) = f[5], case .boolean(let registered) = f[6] else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        func optional(_ key: UInt64) throws -> Data? {
            if f[key] == .null { return nil }
            guard case .bytes(let value) = f[key] else { throw AdministrativeSetupChannelError.invalidMessage }; return value
        }
        let value = try Self(setup: .decode(setup), planDigest: optional(3),
            settings: optional(4).map(GatewayRuntimeActivationSettings.decode), filesPublished: published, jobRegistered: registered)
        guard try value.bytes == bytes else { throw AdministrativeSetupChannelError.invalidMessage }; return value
    }
    func validateActivation(of expected: Self, selectedSettings: GatewayRuntimeActivationSettings) throws {
        guard setup == expected.setup, setup.journalInitialized, planDigest != nil, settings == selectedSettings,
              filesPublished, jobRegistered,
              expected.planDigest == nil || expected.planDigest == planDigest,
              expected.settings == nil || expected.settings == settings else { throw AdministrativeSetupChannelError.invalidMessage }
    }
    private static let purpose = "remozio-gateway-activation-progress"
    private static let limits = try! CBORLimits(maxBytes: 1280, maxDepth: 1, maxItems: 15)
}
