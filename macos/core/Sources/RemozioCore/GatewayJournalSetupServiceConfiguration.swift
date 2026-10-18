import Darwin
import Foundation
import RemozioProtocol

/// Root-owned public setup metadata. Decoding does not authorize initialization or prove the installed release.
struct GatewayJournalSetupServiceConfiguration: CustomStringConvertible {
    static let fileName = "gateway-journal-service.cbor"
    static let executableRelativePath = "Contents/Library/LaunchServices/RemozioGateway"
    let intent: GatewayJournalSetupIntent
    let bundlePath: String
    let codePolicy: AuthorityCodePolicy
    let maximumLifetimeMilliseconds: UInt64
    let canonicalBytes: Data
    var description: String { "GatewayJournalSetupServiceConfiguration(redacted)" }
    var setupCode: AuthorityCodeEntry { codePolicy.entries.first { $0.role == .setupController }! }
    var gatewayCode: AuthorityCodeEntry { codePolicy.entries.first { $0.role == .notificationGateway }! }
    var configurationPath: String { get throws {
        try RuntimePreparationPaths(accountID: intent.accountID).serviceDirectory + "/" + Self.fileName
    } }
    var serviceName: String { get throws { try GatewayJournalSetupAddress.serviceName(accountID: intent.accountID, intentID: intent.id) } }
    var executablePath: String { bundlePath + "/" + Self.executableRelativePath }

    init(intent: GatewayJournalSetupIntent, bundlePath: String, codePolicy: AuthorityCodePolicy,
         maximumLifetimeMilliseconds: UInt64 = 120000) throws {
        let parts = bundlePath.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        let required: Set<AuthorityCodeRole> = [.authority, .transport, .notificationGateway, .setupController]
        let codes = codePolicy.entries.filter { required.contains($0.role) && $0.active }
        guard bundlePath.hasPrefix("/"), bundlePath.hasSuffix(".app"), bundlePath.utf8.count < Int(PATH_MAX),
              !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && $0.utf8.count <= 255 }),
              bundlePath.unicodeScalars.allSatisfy({ (0x20...0xd7ff).contains($0.value) || (0xe000...0xfffd).contains($0.value) || (0x10000...0x10ffff).contains($0.value) }),
              codes.count == required.count, Set(codes.map(\.teamID)).count == 1,
              Set(codes.map(\.identifier)).count == required.count, (1000...300000).contains(maximumLifetimeMilliseconds),
              intent.configuration.settings.handshakeTimeoutMillis <= maximumLifetimeMilliseconds,
              UInt64(intent.configuration.settings.databaseBusyMillis) <= maximumLifetimeMilliseconds,
              let authority = codes.first(where: { $0.role == .authority }),
              let transport = codes.first(where: { $0.role == .transport }), let wake = intent.configuration.wakeEndpoint,
              wake.teamID == transport.teamID, wake.componentIdentifier == transport.identifier else { throw GatewayPreparationError.invalidRecord }
        let authorityPolicy = try XPCPeerPolicy(teamID: authority.teamID, componentIdentifier: authority.identifier,
            approvedCodeDirectoryHashes: [authority.codeDirectoryHash], expectedUserID: 0)
        let transportPolicy = try XPCPeerPolicy(teamID: transport.teamID, componentIdentifier: transport.identifier,
            approvedCodeDirectoryHashes: [transport.codeDirectoryHash], expectedUserID: wake.transportUID)
        guard authorityPolicy.requirement == intent.configuration.authorityPolicy.requirement,
              transportPolicy.requirement == wake.policy.requirement else { throw GatewayPreparationError.changedScope }
        self.intent = intent; self.bundlePath = bundlePath; self.codePolicy = codePolicy; self.maximumLifetimeMilliseconds = maximumLifetimeMilliseconds
        canonicalBytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-journal-service"),
            2: .bytes(intent.encoded), 3: .text(bundlePath), 4: .bytes(codePolicy.bytes), 5: .unsigned(maximumLifetimeMilliseconds)]), limits: Self.limits)
    }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...5),
              fields[0] == .unsigned(1), fields[1] == .text("remozio-gateway-journal-service"), case .bytes(let intent) = fields[2],
              case .text(let bundle) = fields[3], case .bytes(let policy) = fields[4], case .unsigned(let lifetime) = fields[5] else {
            throw GatewayPreparationError.invalidRecord
        }
        let result = try Self(intent: .decode(intent), bundlePath: bundle, codePolicy: .decode(policy), maximumLifetimeMilliseconds: lifetime)
        guard result.canonicalBytes == bytes else { throw GatewayPreparationError.invalidRecord }; return result
    }
    static func load(path: String) throws -> Self {
        let result = try decode(ProtectedServiceConfiguration.readPublic(path: path))
        guard try path == result.configurationPath else { throw GatewayPreparationError.changedScope }
        try result.requireNativeProcess(); return result
    }
    func requireNativeProcess() throws {
        try intent.configuration.requireNativeProcess()
        let code = gatewayCode
        let policy = try XPCPeerPolicy(teamID: code.teamID, componentIdentifier: code.identifier,
            approvedCodeDirectoryHashes: [code.codeDirectoryHash], expectedUserID: intent.configuration.serviceUID)
        try DynamicCodeValidation.validateSelf(requirement: policy.requirement + " and info[\"RemozioSecurityGeneration\"] = \"\(code.installedGeneration)\"")
        guard try DynamicCodeValidation.selfPath() == executablePath else { throw GatewayPreparationError.changedScope }
    }
    /// Logical scope only. The Root caller must additionally validate the signed release and pending checkpoint.
    func validate(foreground: RuntimeActivationPlan, inventory: InstallationInventory) throws {
        let services = intent.material.runtime.services
        guard inventory.bundlePath == bundlePath, inventory.macID == services.macID,
              inventory.installationID == services.installationID, inventory.releaseDigest == services.releaseDigest,
              inventory.accounts.contains(where: { $0.accountID == intent.accountID && $0.ownerUID == services.ownerUID }),
              foreground.host.codePolicy == codePolicy else { throw GatewayPreparationError.changedScope }
        try intent.validate(foreground: foreground, inventory: inventory)
    }
    func validate(foreground: RuntimeActivationPlan, inventory: InstallationInventory, release: SignedReleaseEvidence) throws {
        try validate(foreground: foreground, inventory: inventory); try inventory.compareRelease(release)
        try ReleaseGenerationPreflight.validate(release, against: codePolicy)
        for entry in codePolicy.entries where entry.active {
            guard let component = release.manifest.components.first(where: { $0.role == entry.role }),
                  component.generation == entry.installedGeneration, release.codeDirectoryHashes[entry.role] == entry.codeDirectoryHash else {
                throw GatewayPreparationError.changedScope
            }
        }
        guard release.manifest.components.first(where: { $0.role == .notificationGateway })?.relativePath == Self.executableRelativePath,
              release.manifest.components.first(where: { $0.role == .setupController })?.relativePath == AdministrativeSetupConfiguration.executablePath else {
            throw GatewayPreparationError.changedScope
        }
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: ProtectedServiceConfiguration.maximumBytes, maxDepth: 1, maxItems: 13) } }
}
