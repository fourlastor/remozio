import Foundation
import RemozioProtocol

/// Immutable public bootstrap inputs. Decoding does not authenticate the publisher or start a backend.
struct GatewaySettingsConsumerHostConfiguration: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    private final class Storage: Sendable {
        let role: GatewaySettingsConsumerRole
        let releaseBinding: RuntimeReleaseBinding?
        let retainedSetupBinding: RuntimeRetainedSetupReleaseBinding?
        let retainedSetupCompletionBinding: RuntimeRetainedSetupCompletionBinding?
        let policyStage: RuntimeReleasePolicyStage?
        let runtime: RuntimeMaterialReference
        let bundlePath: String
        let codePolicy: AuthorityCodePolicy

        @inline(never)
        init(role: GatewaySettingsConsumerRole, runtime: RuntimeMaterialReference, bundlePath: String,
            codePolicy: AuthorityCodePolicy, releaseBinding: RuntimeReleaseBinding?,
            retainedSetupBinding: RuntimeRetainedSetupReleaseBinding?,
            retainedSetupCompletionBinding: RuntimeRetainedSetupCompletionBinding?, policyStage: RuntimeReleasePolicyStage?) {
            self.role = role; self.runtime = runtime; self.bundlePath = bundlePath; self.codePolicy = codePolicy
            self.releaseBinding = releaseBinding; self.retainedSetupBinding = retainedSetupBinding
            self.retainedSetupCompletionBinding = retainedSetupCompletionBinding; self.policyStage = policyStage
        }
    }
    private let storage: Storage

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.role == rhs.role && lhs.releaseBinding == rhs.releaseBinding &&
            lhs.retainedSetupBinding == rhs.retainedSetupBinding &&
            lhs.retainedSetupCompletionBinding == rhs.retainedSetupCompletionBinding && lhs.policyStage == rhs.policyStage &&
            lhs.runtime == rhs.runtime && lhs.bundlePath == rhs.bundlePath && lhs.codePolicy == rhs.codePolicy
    }

    static let version: UInt64 = 1
    static let releaseBoundVersion: UInt64 = 2
    static var releaseBoundFormatRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController].map { role in
            try .init(role: role, name: formatName, readVersions: [releaseBoundVersion],
                writeVersions: role == .setupController ? [releaseBoundVersion] : [])
        }
    } }
    static let retainedSetupVersion: UInt64 = 3
    static let retainedSetupCompletionVersion: UInt64 = 4
    static let supportedVersions: Set<UInt64> = [version]
    static let formatName = "runtime.gateway-settings-consumer-host"
    var role: GatewaySettingsConsumerRole { storage.role }
    var releaseBinding: RuntimeReleaseBinding? { storage.releaseBinding }
    var retainedSetupBinding: RuntimeRetainedSetupReleaseBinding? { storage.retainedSetupBinding }
    var retainedSetupCompletionBinding: RuntimeRetainedSetupCompletionBinding? { storage.retainedSetupCompletionBinding }
    var policyStage: RuntimeReleasePolicyStage? { storage.policyStage }
    var formatVersion: UInt64 { retainedSetupCompletionBinding != nil ? Self.retainedSetupCompletionVersion : retainedSetupBinding != nil ? Self.retainedSetupVersion : releaseBinding == nil ? Self.version : Self.releaseBoundVersion }
    var installedReleaseDigest: Data { retainedSetupCompletionBinding?.startupBinding.installedReleaseDigest ?? retainedSetupBinding?.installedReleaseDigest ?? releaseBinding?.installedReleaseDigest ?? runtime.services.releaseDigest }
    var runtime: RuntimeMaterialReference { storage.runtime }
    var bundlePath: String { storage.bundlePath }
    var codePolicy: AuthorityCodePolicy { storage.codePolicy }
    var description: String { "GatewaySettingsConsumerHostConfiguration(redacted)" }
    var debugDescription: String { description }
    var consumerCode: AuthorityCodeEntry { codePolicy.entries.first { $0.role == role.codeRole && $0.active }! }
    var setupCode: AuthorityCodeEntry { codePolicy.entries.first { $0.role == .setupController && $0.active }! }
    var serviceRole: ServiceAccountRole { role == .transport ? .transport : .gateway }
    var activity: ServiceReleaseActivityReference { runtime.serviceActivity! }
    var serviceUID: UInt32 { runtime.services.claims.first { $0.role == serviceRole }!.number }
    var serviceName: String { get throws { try role.serviceName(accountID: runtime.services.accountID) } }

    init(role: GatewaySettingsConsumerRole, runtime: RuntimeMaterialReference, bundlePath: String,
         codePolicy: AuthorityCodePolicy,
         releaseBinding: RuntimeReleaseBinding? = nil, policyStage: RuntimeReleasePolicyStage? = nil) throws {
        try self.init(role: role, runtime: runtime, bundlePath: bundlePath, codePolicy: codePolicy,
            releaseBinding: releaseBinding, policyStage: policyStage,
            retainedSetupBinding: nil, retainedSetupCompletionBinding: nil)
    }
    private init(role: GatewaySettingsConsumerRole, runtime: RuntimeMaterialReference, bundlePath: String,
         codePolicy: AuthorityCodePolicy, releaseBinding: RuntimeReleaseBinding?, policyStage: RuntimeReleasePolicyStage?,
         retainedSetupBinding: RuntimeRetainedSetupReleaseBinding?,
         retainedSetupCompletionBinding: RuntimeRetainedSetupCompletionBinding?) throws {
        let parts = bundlePath.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        let required: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway, .setupController]
        let codes = required.compactMap { role in codePolicy.entries.first { $0.role == role && $0.active } }
        guard runtime.serviceActivity != nil, bundlePath.hasPrefix("/"), bundlePath.hasSuffix(".app"),
              bundlePath.utf8.count < 4096, !parts.isEmpty,
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }),
              codes.count == required.count, Set(codes.map(\.teamID)).count == 1,
              Set(codes.map(\.identifier)).count == codes.count else { throw GatewayPreparationError.invalidRecord }
        try runtime.serviceActivity?.validate(services: runtime.services)
        guard [releaseBinding != nil, retainedSetupBinding != nil, retainedSetupCompletionBinding != nil].filter({ $0 }).count <= 1 else {
            throw GatewayPreparationError.invalidRecord
        }
        if let releaseBinding {
            guard let policyStage else { throw GatewayPreparationError.invalidRecord }
            try releaseBinding.requireHistoricalRuntime(runtime)
            try releaseBinding.requirePolicy(codePolicy, stage: policyStage)
        } else if let retainedSetupBinding {
            guard policyStage == .startup else { throw GatewayPreparationError.invalidRecord }
            try retainedSetupBinding.requireHistoricalRuntime(runtime)
            try retainedSetupBinding.requireStartupPolicy(codePolicy)
        } else if let retainedSetupCompletionBinding {
            guard policyStage == .completion else { throw GatewayPreparationError.invalidRecord }
            try retainedSetupCompletionBinding.requireHistoricalRuntime(runtime)
            try retainedSetupCompletionBinding.requireCompletionPolicy(codePolicy)
        } else {
            guard policyStage == nil else { throw GatewayPreparationError.invalidRecord }
        }
        storage = .init(role: role, runtime: runtime, bundlePath: bundlePath, codePolicy: codePolicy,
            releaseBinding: releaseBinding, retainedSetupBinding: retainedSetupBinding,
            retainedSetupCompletionBinding: retainedSetupCompletionBinding, policyStage: policyStage)
        _ = try encoded
    }
    /// Retains startup metadata only. Ordinary decoders and native admission remain separate.
    static func retainedSetup(role: GatewaySettingsConsumerRole, runtime: RuntimeMaterialReference,
        bundlePath: String, codePolicy: AuthorityCodePolicy, binding: RuntimeRetainedSetupReleaseBinding) throws -> Self {
        try .init(role: role, runtime: runtime, bundlePath: bundlePath, codePolicy: codePolicy,
            releaseBinding: nil, policyStage: .startup, retainedSetupBinding: binding, retainedSetupCompletionBinding: nil)
    }
    /// Preserves the exact release binding when selecting the other consumer role.
    func selecting(role: GatewaySettingsConsumerRole) throws -> Self {
        try .init(role: role, runtime: runtime, bundlePath: bundlePath, codePolicy: codePolicy,
            releaseBinding: releaseBinding, policyStage: policyStage, retainedSetupBinding: retainedSetupBinding,
            retainedSetupCompletionBinding: retainedSetupCompletionBinding)
    }
    /// Checks configuration values only. It does not admit native startup or authenticate current files.
    func requireConfigurationScope(account: AccountPreparationIntent, inventory: InstallationInventory) throws {
        let services = runtime.services
        try runtime.validate(account: account, services: services)
        guard inventory.macID == services.macID, inventory.installationID == services.installationID,
              inventory.releaseDigest == installedReleaseDigest, inventory.bundlePath == bundlePath else {
            throw GatewayPreparationError.changedScope
        }
        if let releaseBinding, let policyStage {
            try releaseBinding.requireHistoricalRuntime(runtime)
            try releaseBinding.requirePolicy(codePolicy, stage: policyStage)
        } else if let retainedSetupBinding {
            try retainedSetupBinding.requirePreparation(account)
            try retainedSetupBinding.requireHistoricalRuntime(runtime)
            try retainedSetupBinding.requireStartupPolicy(codePolicy)
        } else if let retainedSetupCompletionBinding {
            try retainedSetupCompletionBinding.startupBinding.requirePreparation(account)
            try retainedSetupCompletionBinding.requireHistoricalRuntime(runtime)
            try retainedSetupCompletionBinding.requireCompletionPolicy(codePolicy)
        } else {
            guard try codePolicy.bytes == account.initialAuthority.codePolicy.bytes else { throw GatewayPreparationError.changedScope }
        }
    }
    /// Setup must compare these inputs with the current retained account and installation before publication.
    func validate(account: AccountPreparationIntent, inventory: InstallationInventory) throws {
        guard retainedSetupBinding == nil, retainedSetupCompletionBinding == nil else {
            throw GatewayPreparationError.changedScope
        }
        let services = runtime.services
        try runtime.validate(account: account, services: services)
        guard inventory.macID == services.macID, inventory.installationID == services.installationID,
              inventory.releaseDigest == services.releaseDigest, inventory.bundlePath == bundlePath,
              try codePolicy.bytes == account.initialAuthority.codePolicy.bytes else { throw GatewayPreparationError.changedScope }
    }
    /// Update health keeps ordinary startup closed. The native scope must still authenticate code, placement and the dedicated account.
    func requireUpdateHealthStartupSupported() throws {
        guard formatVersion == Self.releaseBoundVersion, let releaseBinding,
              releaseBinding.formatVersion == Self.releaseBoundVersion, policyStage == .startup else {
            throw GatewayPreparationError.changedScope
        }
        try releaseBinding.requireHistoricalRuntime(runtime)
        try releaseBinding.requireStartupPolicy(codePolicy)
    }
    /// Actual signature inspection and protected placement remain prerequisites for native startup.
    func validateRelease(_ release: SignedReleaseEvidence) throws {
        guard try InstallationInventory.digest(release) == installedReleaseDigest else { throw GatewayPreparationError.changedScope }
        try ReleaseGenerationPreflight.validate(release, against: codePolicy)
        for code in codePolicy.entries where code.active {
            guard let component = release.manifest.components.first(where: { $0.role == code.role }),
                  component.generation == code.installedGeneration,
                  release.codeDirectoryHashes[code.role] == code.codeDirectoryHash else { throw GatewayPreparationError.changedScope }
        }
        try GatewaySettingsConsumerReleaseValidation.validate(release, role: role, consumer: consumerCode, setup: setupCode)
        for code in [role.codeRole, .setupController] {
            guard let format = release.manifest.components.first(where: { $0.role == code })?.formats.first(where: { $0.name == Self.formatName }),
                  format.readers.contains(formatVersion), code != .setupController || format.writers.contains(formatVersion) else {
                throw GatewayPreparationError.changedScope
            }
        }
    }
    func validate(transport: ApprovalTransportConfiguration, pairing: TransportPairingControlConfiguration) throws {
        let services = runtime.services, paths = try RuntimePreparationPaths(accountID: runtime.services.accountID)
        guard role == .transport, transport.macID == services.macID, transport.accountID == services.accountID,
              transport.ownerUID == services.ownerUID, transport.serviceUID == serviceUID,
              transport.identityPublicKeyInfo == runtime.transportPublicKeyInfo,
              transport.identitySource == .protectedFile(path: paths.transportIdentity),
              transport.authorityServiceName == paths.authorityService, pairing.serviceName == paths.pairingService,
              pairing.macID == services.macID, pairing.accountID == services.accountID,
              pairing.ownerUID == services.ownerUID, pairing.transportUID == serviceUID else { throw GatewayPreparationError.changedScope }
        func require(_ actual: XPCPeerPolicy, role: AuthorityCodeRole, uid: UInt32) throws {
            let code = codePolicy.entries.first { $0.role == role && $0.active }!
            let expected = try XPCPeerPolicy(teamID: code.teamID, componentIdentifier: code.identifier,
                approvedCodeDirectoryHashes: [code.codeDirectoryHash], expectedUserID: uid)
            guard actual.expectedUserID == uid, actual.requirement == expected.requirement else { throw GatewayPreparationError.changedScope }
        }
        try require(transport.authorityPolicy, role: .authority, uid: 0)
        try require(pairing.appPolicy, role: .app, uid: services.ownerUID)
        try require(pairing.transportPolicy, role: .transport, uid: serviceUID)
    }
    var encoded: Data { get throws {
        var fields: [UInt64: CBORValue] = [0: .unsigned(formatVersion), 1: .text("remozio-gateway-settings-consumer-host"),
            2: .unsigned(role.rawValue), 3: .bytes(try runtime.encoded), 4: .text(bundlePath), 5: .bytes(try codePolicy.bytes)]
        if let releaseBinding, let policyStage {
            fields[6] = .bytes(try releaseBinding.encoded)
            fields[7] = .unsigned(policyStage.rawValue)
        }
        if let retainedSetupBinding {
            fields[6] = .bytes(try retainedSetupBinding.encoded)
            fields[7] = .unsigned(RuntimeReleasePolicyStage.startup.rawValue)
        }
        if let retainedSetupCompletionBinding {
            fields[6] = .bytes(try retainedSetupCompletionBinding.encoded)
            fields[7] = .unsigned(RuntimeReleasePolicyStage.completion.rawValue)
        }
        return try DeterministicCBOR.encode(.map(fields), limits: formatVersion == Self.version ? Self.limits : Self.archiveLimits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        try decode(bytes, allowReleaseBound: false)
    }
    /// Reads archived host metadata. Native startup also decodes here.
    /// GatewaySettingsConsumerStartupMode.select accepts ordinary format 1 or update-health format 2.
    static func decodeForReleaseArchive(_ bytes: Data) throws -> Self {
        try decode(bytes, allowReleaseBound: true)
    }
    /// Retained setup archives cannot select the update-health startup purpose.
    static func decodeForUpdateHealthStartup(_ bytes: Data) throws -> Self {
        let host = try decodeForReleaseArchive(bytes)
        try host.requireUpdateHealthStartupSupported()
        return host
    }
    private static func decode(_ bytes: Data, allowReleaseBound: Bool) throws -> Self {
        let allowed: Set<UInt64> = allowReleaseBound
            ? [version, releaseBoundVersion, retainedSetupVersion, retainedSetupCompletionVersion] : [version]
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: allowReleaseBound ? archiveLimits : limits),
              case .unsigned(let selected) = fields[0], allowed.contains(selected),
              Set(fields.keys) == Set(UInt64(0)...(selected == version ? 5 : 7)),
              fields[1] == .text("remozio-gateway-settings-consumer-host"), case .unsigned(let raw) = fields[2],
              let role = GatewaySettingsConsumerRole(rawValue: raw), case .bytes(let runtime) = fields[3],
              case .text(let path) = fields[4], case .bytes(let policy) = fields[5] else { throw GatewayPreparationError.invalidRecord }
        let binding: RuntimeReleaseBinding?, retainedBinding: RuntimeRetainedSetupReleaseBinding?
        let completedBinding: RuntimeRetainedSetupCompletionBinding?, stage: RuntimeReleasePolicyStage?
        if selected == version {
            binding = nil; retainedBinding = nil; completedBinding = nil; stage = nil
        } else {
            guard case .bytes(let retained) = fields[6], case .unsigned(let rawStage) = fields[7],
                  let selectedStage = RuntimeReleasePolicyStage(rawValue: rawStage) else { throw GatewayPreparationError.invalidRecord }
            if selected == releaseBoundVersion {
                binding = try .decode(retained); retainedBinding = nil; completedBinding = nil
            } else if selected == retainedSetupVersion {
                guard selectedStage == .startup else { throw GatewayPreparationError.invalidRecord }
                binding = nil; retainedBinding = try .decode(retained); completedBinding = nil
            } else {
                guard selectedStage == .completion else { throw GatewayPreparationError.invalidRecord }
                binding = nil; retainedBinding = nil; completedBinding = try .decode(retained)
            }
            stage = selectedStage
        }
        let value = try Self(role: role, runtime: .decode(runtime), bundlePath: path, codePolicy: .decode(policy),
            releaseBinding: binding, policyStage: stage, retainedSetupBinding: retainedBinding,
            retainedSetupCompletionBinding: completedBinding)
        guard try value.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return value
    }
    static let limits = try! CBORLimits(maxBytes: 32768, maxDepth: 1, maxItems: 13)
    private static let archiveLimits = try! CBORLimits(maxBytes: 32768, maxDepth: 1, maxItems: 17)
}
