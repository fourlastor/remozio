import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AdministrativeSetupServiceTests: XCTestCase {
    private let mac = Data(repeating: 1, count: 16), installation = Data(repeating: 2, count: 16)
    private func release(generation: UInt64 = 1, path: String = AdministrativeSetupConfiguration.executablePath, recovery: Bool = false) throws -> SignedReleaseEvidence {
        let recoveryFormats: [ReleaseFormat] = try recovery
            ? [.init(name: AdministrativeSetupInterface.formatName, readers: AdministrativeSetupInterface.supportedVersions,
                writers: AdministrativeSetupInterface.supportedVersions)] : []
        let components = try [
            ReleaseComponent(role: .app, identifier: "dev.sebastiano.remozio.macos", generation: 1, relativePath: "Contents/MacOS/Remozio",
                codeDirectoryHash: nil, build: "1", teamID: "ABCDEFGHIJ", formats: recoveryFormats),
            ReleaseComponent(role: .authority, identifier: "dev.sebastiano.remozio.macos.authority", generation: 1, relativePath: "Contents/Library/LaunchServices/Authority",
                codeDirectoryHash: Data(repeating: 4, count: 20), build: "1", teamID: "ABCDEFGHIJ", formats: []),
            ReleaseComponent(role: .setupController, identifier: "dev.sebastiano.remozio.macos.setup-controller", generation: generation, relativePath: path,
                codeDirectoryHash: Data(repeating: 8, count: 20), build: "1", teamID: "ABCDEFGHIJ", formats: recoveryFormats)]
        return try .init(manifest: .init(release: "1", build: "1", components: components),
            codeDirectoryHashes: [.app: Data(repeating: 3, count: 20), .authority: Data(repeating: 4, count: 20), .setupController: Data(repeating: 8, count: 20)])
    }
    private func policy(generation: UInt64 = 1, hash: UInt8 = 8, active: Bool = true, app: Bool = true) throws -> AuthorityCodePolicy {
        var entries = [try AuthorityCodeEntry(role: .setupController, teamID: "ABCDEFGHIJ", identifier: "dev.sebastiano.remozio.macos.setup-controller",
            installedGeneration: generation, minimumGeneration: generation, codeDirectoryHash: Data(repeating: hash, count: 20), active: active)]
        if app { entries.append(try .init(role: .app, teamID: "ABCDEFGHIJ", identifier: "dev.sebastiano.remozio.macos",
            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 3, count: 20), active: true)) }
        return try .init(entries: entries)
    }
    private func configuration(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy? = nil) throws -> AdministrativeSetupConfiguration {
        try .init(machineDirectory: "/Library/Remozio/machine", macID: mac, installationID: installation,
            releaseDigest: InstallationInventory.digest(release), codePolicy: policy ?? self.policy())
    }
    private func inventory(_ release: SignedReleaseEvidence, installation: Data? = nil, setup: Bool = true, label: String = "dev.sebastiano.remozio.macos.setup") throws -> InstallationInventory {
        let account = try InstallationAccount(accountID: Data(repeating: 5, count: 16), ownerUID: 501)
        var services = [try InstallationService(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
            label: "dev.sebastiano.remozio.macos.authority", plistName: "dev.sebastiano.remozio.macos.authority.plist", accountID: account.accountID)]
        if setup { services.append(try .init(role: .setupController, kind: .daemon, domainUID: nil, executionUID: 0,
            label: label, plistName: AdministrativeSetupConfiguration.plistName)) }
        return try .init(macID: mac, installationID: installation ?? self.installation, revision: Data(repeating: 6, count: 16),
            bundlePath: "/Library/Remozio/Remozio.app", releaseDigest: InstallationInventory.digest(release), accounts: [account], services: services)
    }
    func testCanonicalConfigurationAndExactRetainedRelease() throws {
        let release = try release(), configuration = try configuration(release)
        XCTAssertEqual(try AdministrativeSetupConfiguration.decode(configuration.canonicalBytes).canonicalBytes, configuration.canonicalBytes)
        XCTAssertNoThrow(try configuration.validate(inventory: inventory(release), release: release))
        XCTAssertFalse(configuration.description.contains("/Library"))
        XCTAssertFalse(configuration.description.contains("ABCDEFGHIJ"))
    }
    func testUnknownVersionExtraFieldsAndOversizedInputsAreRejected() throws {
        let config = try configuration(release())
        let limits = try CBORLimits(maxBytes: 20000, maxDepth: 2, maxItems: 32)
        guard case .map(let original) = try DeterministicCBOR.decode(config.canonicalBytes, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (8, .null), (6, .unsigned(UInt64.max)), (7, .unsigned(0))] {
            var fields = original; fields[key] = value
            XCTAssertThrowsError(try AdministrativeSetupConfiguration.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        }
        XCTAssertThrowsError(try AdministrativeSetupConfiguration.decode(Data(repeating: 0, count: 16385)))
    }
    func testMissingActiveRolesUnsafePathsAndConnectionLimitsAreRejected() throws {
        let release = try release(), digest = try InstallationInventory.digest(release)
        for policy in [try policy(active: false), try policy(app: false)] {
            XCTAssertThrowsError(try AdministrativeSetupConfiguration(machineDirectory: "/Library/Remozio/machine", macID: mac,
                installationID: installation, releaseDigest: digest, codePolicy: policy))
        }
        for path in ["relative", "/", "/Library/../machine", "/Library//machine", "/Library/machine\0"] {
            XCTAssertThrowsError(try AdministrativeSetupConfiguration(machineDirectory: path, macID: mac, installationID: installation,
                releaseDigest: digest, codePolicy: policy()))
        }
        for count in [0, 65] {
            XCTAssertThrowsError(try AdministrativeSetupConfiguration(machineDirectory: "/Library/Remozio/machine", macID: mac,
                installationID: installation, releaseDigest: digest, codePolicy: policy(), maximumConnections: count))
        }
    }
    func testChangedInstallationMissingSetupAndWrongLabelCannotStart() throws {
        let release = try release(), configuration = try configuration(release)
        for inventory in [try inventory(release, installation: Data(repeating: 9, count: 16)),
                          try inventory(release, setup: false), try inventory(release, label: "dev.remozio.other")] {
            XCTAssertThrowsError(try configuration.validate(inventory: inventory, release: release))
        }
    }
    func testSignedCandidateCannotReplaceExactHashGenerationOrHostPath() throws {
        let original = try release()
        for policy in [try policy(hash: 9), try policy(generation: 2)] {
            XCTAssertThrowsError(try configuration(original, policy: policy).validate(release: original))
        }
        let newer = try release(generation: 2)
        // The candidate clears the floor, but is not the retained installed generation.
        XCTAssertThrowsError(try configuration(newer).validate(release: newer))
        let moved = try release(path: "Contents/Helpers/Other")
        XCTAssertThrowsError(try configuration(moved).validate(release: moved))
        XCTAssertThrowsError(try configuration(original).validate(release: newer))
    }
    func testPublicStartupRequiresBothRootIdentitiesBeforeReadingConfiguration() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-owner refusal control") }
        for path in [AdministrativeSetupConfiguration.startupPath, "/private/nonexistent/setup.cbor"] {
            XCTAssertThrowsError(try AdministrativeSetupConfiguration.load(path: path)) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
            XCTAssertThrowsError(try AdministrativeSetupService.open(configurationPath: path)) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        }
    }
    func testNativeSelfPathIsExistingCodeAndInventedRequirementIsDenied() throws {
        let path = try DynamicCodeValidation.selfPath()
        XCTAssertTrue(path.hasPrefix("/")); XCTAssertTrue(FileManager.default.fileExists(atPath: path))
        XCTAssertThrowsError(try DynamicCodeValidation.validateSelf(requirement: "identifier \"dev.remozio.nonexistent-native-control\""))
    }
    private func withRecoveryBinding(_ body: (AdministrativeSetupShutdown, SetupAccountOwner, SetupProcessLease,
        AdministrativeSetupLifecycle.Routing, (Bool, Int) throws -> AdministrativeSetupService.RecoveryBinding) throws -> Void) throws {
        let source = try RuntimeAuditUpgradeOperationTests.Harness(), owner = try source.owner()
        let placement = try ReleaseDestinationLease(anchor: source.activity.root.path, relativeDirectory: "Machine", owner: getuid())
        let lease = try SetupProcessLease.openOwned(directory: .init(anchor: source.activity.root.path, relativeDirectory: "Machine", owner: getuid()))
        let shutdown = AdministrativeSetupShutdown(owner: owner, placement: placement, processLease: lease)
        let routing = AdministrativeSetupLifecycle.Routing(validateStartup: {})
        try routing.install(owner); routing.move(to: .serving)
        defer { try? owner.close(); placement.close(); lease.close() }
        try body(shutdown, owner, lease, routing, { supported, maximum in
            let release = try self.release(recovery: supported)
            let configuration = try AdministrativeSetupConfiguration(machineDirectory: "/Library/Remozio/machine",
                macID: self.mac, installationID: self.installation, releaseDigest: InstallationInventory.digest(release),
                codePolicy: self.policy(), maximumConnections: maximum)
            return try .owned(configuration: configuration, release: release, processLease: lease, shutdown: shutdown, routing: routing)
        })
    }
    func testRecoveryBindingValidatesTheLeaseFormatsAndHostConnectionLimit() throws {
        try withRecoveryBinding { _, owner, lease, _, binding in
            XCTAssertThrowsError(try binding(false, 3).validate())
            for maximum in [1, 2, 3, 64] {
                let value = try binding(true, maximum)
                XCTAssertEqual(value.maximumConnections, maximum); XCTAssertTrue(try value.currentOwner() === owner)
            }
            let value = try binding(true, 3); lease.close(); XCTAssertThrowsError(try value.validate())
        }
    }
    func testRecoveryBindingRechecksTheOwnerAndAdmissionAtRegistration() throws {
        try withRecoveryBinding { shutdown, owner, _, routing, binding in
            let value = try binding(true, 3), source = try RuntimeAuditUpgradeOperationTests.Harness(), foreign = try source.owner()
            defer { try? foreign.close() }
            XCTAssertThrowsError(try value.registerSession(owner: foreign)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            let session = try value.registerSession(owner: owner); session.resolveWithoutWork()
            shutdown.closeRecoveryAdmission()
            XCTAssertThrowsError(try value.registerSession(owner: owner))
            routing.move(to: .retiring); XCTAssertThrowsError(try value.registerSession(owner: owner))
            XCTAssertThrowsError(try routing.recoveryOwner())
            let other = AdministrativeSetupLifecycle.Routing(validateStartup: {})
            try other.install(foreign); other.move(to: .serving)
            let release = try self.release(recovery: true)
            let wrong = try AdministrativeSetupService.RecoveryBinding.owned(configuration: self.configuration(release),
                release: release, processLease: value.processLease, shutdown: shutdown, routing: other)
            XCTAssertThrowsError(try wrong.currentOwner())
        }
    }

}
