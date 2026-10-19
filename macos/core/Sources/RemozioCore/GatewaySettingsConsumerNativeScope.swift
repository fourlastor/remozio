import Darwin
import Foundation

extension GatewaySettingsConsumerHostConfiguration {
    static let gatewayFileName = "gateway-settings-consumer-host.cbor"
    var gatewayConfigurationPath: String { get throws {
        guard role == .gateway else { throw GatewayPreparationError.changedScope }
        return try RuntimePreparationPaths(accountID: runtime.services.accountID).serviceDirectory + "/" + Self.gatewayFileName
    } }
}

/// Holds immutable bootstrap custody and the read-only role activity through actual shutdown.
final class GatewaySettingsConsumerNativeScope: OwnedReleaseActivity, @unchecked Sendable {
    let configuration: GatewaySettingsConsumerHostConfiguration
    private let lock = NSRecursiveLock()
    private let path: String
    private let bytes: Data
    private let placement: ReleaseDestinationLease
    private let bundleIdentity: PreparationFileIdentity
    private let requirement: String
    private var barrier: ServiceReleaseActivityBarrier?
    private var baseline: ServiceReleaseActivityToken?
    private var closed = false

    static func openGateway(path: String) throws -> (scope: GatewaySettingsConsumerNativeScope, release: SignedReleaseEvidence) {
        let bytes = try ProtectedServiceConfiguration.readPublic(path: path)
        let host = try GatewaySettingsConsumerHostConfiguration.decode(bytes)
        guard host.role == .gateway, path == (try host.gatewayConfigurationPath),
              host.bundlePath == MachineBootstrap.bundlePath else { throw GatewayPreparationError.changedScope }
        try DedicatedServiceAccount.requireCurrent(serviceUID: host.serviceUID, ownerUID: host.runtime.services.ownerUID)
        let bundle = URL(fileURLWithPath: host.bundlePath)
        let placement = try ReleaseDestinationLease.readForServiceRegistration(path: bundle.deletingLastPathComponent().path)
        var scope: GatewaySettingsConsumerNativeScope?
        do {
            let code = host.consumerCode
            let requirement = try XPCPeerPolicy(teamID: code.teamID, componentIdentifier: code.identifier,
                approvedCodeDirectoryHashes: [code.codeDirectoryHash], expectedUserID: host.serviceUID).requirement
                + " and info[\"RemozioSecurityGeneration\"] = \"\(code.installedGeneration)\""
            let current = try Self(configuration: host, path: path, bytes: bytes, placement: placement,
                bundleIdentity: placement.preparationCopyIdentity(name: bundle.lastPathComponent), requirement: requirement)
            scope = current
            try current.validateMetadata()
            let activity = host.activity
            let barrier = try ServiceReleaseActivityBarrier.open(services: activity.services, role: host.serviceRole,
                expected: activity.identity(for: host.serviceRole), verifyCurrent: { [weak current] in
                    guard let current else { throw GatewayPreparationError.changedScope }; try current.validateMetadata()
                })
            let baseline = try barrier.acquireShared()
            current.lock.withLock { current.barrier = barrier; current.baseline = baseline }
            // Root updates must take the exclusive role lock before changing this inspected release.
            _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
            let app = host.codePolicy.entries.first { $0.role == .app && $0.active }!
            let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
            try host.validateRelease(release)
            let transportHost = try GatewaySettingsConsumerHostConfiguration(role: .transport, runtime: host.runtime,
                bundlePath: host.bundlePath, codePolicy: host.codePolicy)
            try transportHost.validateRelease(release)
            guard release.manifest.components.first(where: { $0.role == .notificationGateway })?.relativePath
                    == GatewayJournalSetupServiceConfiguration.executableRelativePath,
                  release.manifest.components.first(where: { $0.role == .setupController })?.relativePath
                    == AdministrativeSetupConfiguration.executablePath else { throw GatewayPreparationError.changedScope }
            try current.validate()
            return (current, release)
        } catch { scope?.close(); placement.close(); throw error }
    }
    private init(configuration: GatewaySettingsConsumerHostConfiguration, path: String, bytes: Data,
                 placement: ReleaseDestinationLease, bundleIdentity: PreparationFileIdentity, requirement: String) throws {
        self.configuration = configuration; self.path = path; self.bytes = bytes; self.placement = placement
        self.bundleIdentity = bundleIdentity; self.requirement = requirement
    }
    private func validateMetadata() throws {
        try lock.withLock {
            guard !closed else { throw GatewayPreparationError.changedScope }
            let host = configuration, services = host.runtime.services
            try DedicatedServiceAccount.requireCurrent(serviceUID: host.serviceUID, ownerUID: services.ownerUID)
            guard getgid() == host.serviceUID, getegid() == host.serviceUID,
                  let claim = services.claims.first(where: { $0.role == host.serviceRole }) else { throw GatewayPreparationError.changedScope }
            let directory = try ServiceAccountDirectoryReader()
            guard try directory.state(claim: claim, kind: .user) == .retained,
                  try directory.state(claim: claim, kind: .group) == .retained else { throw GatewayPreparationError.changedScope }
            try DynamicCodeValidation.validateSelf(requirement: requirement)
            guard try DynamicCodeValidation.selfPath() == host.bundlePath + "/" + GatewayJournalSetupServiceConfiguration.executableRelativePath,
                  try ProtectedServiceConfiguration.readPublic(path: path) == bytes else { throw GatewayPreparationError.changedScope }
            try placement.validate()
            guard try placement.preparationCopyIdentity(name: URL(fileURLWithPath: host.bundlePath).lastPathComponent) == bundleIdentity else {
                throw GatewayPreparationError.changedScope
            }
        }
    }
    func validate() throws {
        let token = try lock.withLock { guard !closed, let baseline else { throw GatewayPreparationError.changedScope }; return baseline }
        try token.validate()
    }
    func acquireActivity() throws -> any OwnedReleaseActivity {
        let current = try lock.withLock { guard !closed, let barrier else { throw GatewayPreparationError.changedScope }; return barrier }
        return try current.acquireShared()
    }
    func close() {
        let previous = lock.withLock { () -> ServiceReleaseActivityToken? in
            guard !closed else { return nil }; closed = true
            let old = baseline; baseline = nil
            placement.close(); return old
        }
        // A barrier callback can need the metadata lock. Never close or acquire a token while holding it.
        previous?.close()
    }
    deinit { close() }
}
