import CryptoKit
import Darwin
import Foundation
import RemozioMach
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class InstalledAuthorityCommandConfigurationTests: XCTestCase {
    private let roles: [AuthorityCodeRole] = [.app, .authority, .commandFrontend, .commandMonitor, .commandChild, .transport, .notificationGateway]
    private let bundle = "/Library/Remozio/Remozio.app"
    private func id(_ n: UInt8, _ size: Int = 16) -> Data { Data(repeating: n, count: size) }
    private func identifier(_ role: AuthorityCodeRole) -> String { "dev.remozio.component.\(role.rawValue)" }
    private func relative(_ role: AuthorityCodeRole) -> String {
        switch role {
        case .app: "Contents/MacOS/Remozio"
        case .authority: InstalledAuthorityCommandConfiguration.executablePath
        case .commandMonitor: "Contents/Helpers/RemozioCommandMonitor"
        case .commandChild: "Contents/Helpers/RemozioCommandChild"
        default: "Contents/Helpers/Component\(role.rawValue)"
        }
    }
    private func release() throws -> SignedReleaseEvidence {
        let components = try roles.map { role in
            try ReleaseComponent(role: role, identifier: identifier(role), generation: 1, relativePath: relative(role),
                codeDirectoryHash: role == .app ? nil : id(UInt8(role.rawValue), 20), build: "1", teamID: "ABCDEFGHIJ", formats: [])
        }
        return try .init(manifest: .init(release: "1", build: "1", components: components),
            codeDirectoryHashes: Dictionary(uniqueKeysWithValues: roles.map { ($0, id(UInt8($0.rawValue), 20)) }))
    }
    private func policy(changedAuthorityHash: Bool = false, generation: UInt64 = 1, omit: AuthorityCodeRole? = nil) throws -> AuthorityCodePolicy {
        try .init(entries: roles.filter { $0 != omit }.map { role in
            try .init(role: role, teamID: "ABCDEFGHIJ", identifier: identifier(role),
                installedGeneration: role == .authority ? generation : 1, minimumGeneration: role == .authority ? generation : 1,
                codeDirectoryHash: id(changedAuthorityHash && role == .authority ? 99 : UInt8(role.rawValue), 20), active: true)
        })
    }
    private func command(execution: Bool = true, monitorPath: String? = nil, scoped: Bool = false) throws -> AuthorityCommandStartupConfiguration {
        let paths = try RuntimePreparationPaths(accountID: id(22))
        let key = P256.Signing.PrivateKey().publicKey.x963Representation
        let service = try AuthorityServiceConfiguration(macID: id(21), accountID: id(22), journalDirectory: "/Library/Remozio/journal",
            serviceName: scoped ? paths.authorityService : "dev.remozio.authority", teamID: "ABCDEFGHIJ", transportIdentifier: identifier(.transport),
            transportHashes: [id(UInt8(AuthorityCodeRole.transport.rawValue), 20)], transportUID: 401,
            continuityDirectory: "/Library/Remozio/continuity")
        let request = try AuthorityRequestStartupConfiguration(service: service, keyRecordPath: scoped ? paths.authorityDirectory + "/Key/" + AuthorityKeyProvisioning.recordFileName : "/Library/Remozio/key.cbor", authorityPublicKey: key)
        let wake = try AuthorityWakeStartupConfiguration(request: request,
            registration: .init(ownerID: id(23), macID: id(21), accountID: id(22), gatewayID: id(24), lifecycleEpoch: id(25), rootPublicKey: key),
            gatewayServiceName: scoped ? paths.gatewayService : "dev.remozio.gateway", gatewayUID: 402, teamID: "ABCDEFGHIJ", gatewayIdentifier: identifier(.notificationGateway),
            gatewayHashes: [id(UInt8(AuthorityCodeRole.notificationGateway.rawValue), 20)])
        let presence = try AuthorityPresenceStartupConfiguration(wake: wake, ownerUID: 501, appServiceName: scoped ? paths.presenceService : "dev.remozio.presence",
            teamID: "ABCDEFGHIJ", appIdentifier: identifier(.app), appHashes: [id(1, 20)], policy: .init(observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 1000))
        return try .init(presence: presence, serviceName: scoped ? paths.commandService : "dev.remozio.commands", policyPath: scoped ? paths.policy : "/Library/Remozio/elevation.cbor", environment: [],
            submissionLimits: .init(maxBytes: 8192, maxDepth: 8, maxItems: 1024), captureLimits: .init(maxBytes: 65536, maxDepth: 8, maxItems: 4096),
            execution: execution ? .init(monitorPath: monitorPath ?? (bundle + "/" + relative(.commandMonitor)), childPath: bundle + "/" + relative(.commandChild)) : nil)
    }
    private func config(policy: AuthorityCodePolicy? = nil, command: AuthorityCommandStartupConfiguration? = nil) throws -> InstalledAuthorityCommandConfiguration {
        try .init(machineDirectory: "/Library/Remozio/machine", installationID: id(26), releaseDigest: InstallationInventory.digest(release()),
            codePolicy: policy ?? self.policy(), command: command ?? self.command(), label: "dev.remozio.authority", plistName: "dev.remozio.authority.plist")
    }
    private func inventory(owner: UInt32 = 501, account: Data? = nil, installation: Data? = nil, path: String? = nil,
                           label: String = "dev.remozio.authority") throws -> InstallationInventory {
        let account = account ?? id(22)
        return try .init(macID: id(21), installationID: installation ?? id(26), revision: id(27), bundlePath: path ?? bundle,
            releaseDigest: InstallationInventory.digest(release()), accounts: [.init(accountID: account, ownerUID: owner)],
            services: [.init(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0, label: label,
                plistName: "dev.remozio.authority.plist", accountID: account)])
    }
    private func scopedConfig() throws -> InstalledAuthorityCommandConfiguration {
        let paths = try RuntimePreparationPaths(accountID: id(22)), label = paths.namespace + ".authority"
        return try .init(machineDirectory: MachineBootstrap.machineDirectory, installationID: id(26),
            releaseDigest: InstallationInventory.digest(release()), codePolicy: policy(), command: command(scoped: true),
            label: label, plistName: label + ".plist", jobPlacement: .systemAccount)
    }
    private func scopedInventory(transportUID: UInt32? = 401) throws -> InstallationInventory {
        let paths = try RuntimePreparationPaths(accountID: id(22)), authority = paths.namespace + ".authority"
        var services = [try InstallationService(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
            label: authority, plistName: authority + ".plist", accountID: id(22))]
        if let transportUID {
            services.append(try .init(role: .transport, kind: .daemon, domainUID: nil, executionUID: transportUID,
                label: paths.namespace + ".transport", plistName: paths.namespace + ".transport.plist", accountID: id(22)))
        }
        return try .init(macID: id(21), installationID: id(26), revision: id(27), bundlePath: bundle,
            releaseDigest: InstallationInventory.digest(release()), accounts: [.init(accountID: id(22), ownerUID: 501)], services: services)
    }
    func testVersionTwoExplicitlySelectsProtectedSystemJobsAndPreservesVersionOne() throws {
        let value = try scopedConfig(), decoded = try InstalledAuthorityCommandConfiguration.decode(value.canonicalBytes)
        XCTAssertEqual(decoded.jobPlacement, .systemAccount); XCTAssertEqual(decoded.canonicalBytes, value.canonicalBytes)
        XCTAssertNoThrow(try decoded.validate(inventory: scopedInventory(), release: release(), bundlePath: bundle))
        let legacy = try config()
        XCTAssertEqual(try InstalledAuthorityCommandConfiguration.decode(legacy.canonicalBytes).jobPlacement, .bundled)
        XCTAssertEqual(InstalledAuthorityCommandConfiguration.supportedVersions, [1, 2])
        XCTAssertThrowsError(try decoded.validate(inventory: scopedInventory(transportUID: nil), release: release(), bundlePath: bundle))
        XCTAssertThrowsError(try decoded.validate(inventory: scopedInventory(transportUID: 402), release: release(), bundlePath: bundle))
    }
    func testVersionTwoCannotSelectAnArbitraryHostPathNamespaceOrLegacyCommand() throws {
        let value = try scopedConfig(), limits = try CBORLimits(maxBytes: 131072, maxDepth: 2, maxItems: 32)
        guard case .map(let fields) = try DeterministicCBOR.decode(value.canonicalBytes, limits: limits) else { return XCTFail() }
        for (key, replacement): (UInt64, CBORValue) in [(1, .text("/Library/Other/machine")), (6, .text("dev.remozio.other")),
            (7, .text("dev.remozio.other.plist")), (8, .text("other-placement")), (5, .bytes(try command().canonicalBytes)), (0, .unsigned(1))] {
            var changed = fields; changed[key] = replacement
            XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        var missing = fields; missing.removeValue(forKey: 8)
        XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.decode(DeterministicCBOR.encode(.map(missing), limits: limits)))
    }
    func testCanonicalHostKeepsTheConfiguredExecutionAndAccountScope() throws {
        let original = try config(), decoded = try InstalledAuthorityCommandConfiguration.decode(original.canonicalBytes)
        XCTAssertEqual(decoded.canonicalBytes, original.canonicalBytes)
        XCTAssertEqual(decoded.command.canonicalBytes, original.command.canonicalBytes)
        XCTAssertEqual(decoded.description, "InstalledAuthorityCommandConfiguration(redacted)")
        XCTAssertNoThrow(try decoded.validate(inventory: inventory(), release: release(), bundlePath: bundle))
    }
    func testAdmissionOnlyAndMissingRequiredCodeRolesCannotBecomeAnInstalledExecutionHost() throws {
        XCTAssertThrowsError(try config(command: command(execution: false)))
        for role in roles { XCTAssertThrowsError(try config(policy: policy(omit: role))) }
    }
    func testConfiguredPeerCannotUseADifferentApprovedComponentHash() throws {
        let original = try policy()
        let changed = try AuthorityCodePolicy(entries: original.entries.map { entry in
            try AuthorityCodeEntry(role: entry.role, teamID: entry.teamID, identifier: entry.identifier,
                installedGeneration: entry.installedGeneration, minimumGeneration: entry.minimumGeneration,
                codeDirectoryHash: entry.role == .transport ? id(99, 20) : entry.codeDirectoryHash, active: entry.active)
        })
        XCTAssertThrowsError(try config(policy: changed))
    }

    func testUnknownVersionMissingExtraAndInvalidPathsAreRejected() throws {
        let config = try config(), limits = try CBORLimits(maxBytes: 131072, maxDepth: 2, maxItems: 32)
        guard case .map(let fields) = try DeterministicCBOR.decode(config.canonicalBytes, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (8, .null), (1, .text("relative/path")),
            (1, .text("/Library/../machine")), (6, .text("not-a-remozio-label")), (7, .text("dev.remozio.job"))] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        for key in fields.keys {
            var changed = fields; changed.removeValue(forKey: key)
            XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
    }
    func testWrongInstallationAccountOwnerBundleOrServiceCannotPassValidation() throws {
        let config = try config()
        for value in [try inventory(owner: 502), try inventory(account: id(99)), try inventory(installation: id(99)),
                      try inventory(path: "/Library/Remozio/Other.app"), try inventory(label: "dev.remozio.other")] {
            XCTAssertThrowsError(try config.validate(inventory: value, release: release(), bundlePath: bundle))
        }
    }
    func testAStaleAuthorityHashGenerationOrUnbundledExecutorCannotPass() throws {
        for value in [try config(policy: policy(changedAuthorityHash: true)), try config(policy: policy(generation: 2)),
                      try config(command: command(monitorPath: "/Library/Remozio/AnotherMonitor"))] {
            XCTAssertThrowsError(try value.validate(inventory: inventory(), release: release(), bundlePath: bundle))
        }
    }
    func testCommandServiceManifestBindsAllThreeEndpointsAndRefusesInjectedNames() throws {
        let config = try config(), release = try release(), inventory = try inventory()
        let declaration = try config.validate(inventory: inventory, release: release, bundlePath: bundle)
        let manifest = try InstallationServiceManifest(declaration: declaration, component: release.manifest.components.first { $0.role == .authority }!,
            configurationPath: "/Library/Remozio/command-host.cbor", userName: "root",
            arguments: [InstalledAuthorityCommandConfiguration.executablePath, "--command-configuration", "/Library/Remozio/command-host.cbor"],
            machServices: ["dev.remozio.authority", "dev.remozio.presence", "dev.remozio.commands"], runAtLoad: true, keepAlive: true)
        var values: [String: Any] = ["Label": declaration.label, "BundleProgram": InstalledAuthorityCommandConfiguration.executablePath,
            "ProgramArguments": [InstalledAuthorityCommandConfiguration.executablePath, "--command-configuration", "/Library/Remozio/command-host.cbor"],
            "UserName": "root", "RunAtLoad": true, "KeepAlive": true,
            "MachServices": ["dev.remozio.authority": true, "dev.remozio.presence": true, "dev.remozio.commands": true]]
        XCTAssertNoThrow(try manifest.validate(PropertyListSerialization.data(fromPropertyList: values, format: .xml, options: 0), inventory: inventory, release: release))
        values["MachServices"] = ["dev.remozio.authority": true, "dev.remozio.presence": true, "dev.remozio.commands": true, "dev.remozio.extra": true]
        XCTAssertThrowsError(try manifest.validate(PropertyListSerialization.data(fromPropertyList: values, format: .xml, options: 0), inventory: inventory, release: release))
    }
    func testOrdinaryAccountCannotReadHostConfigurationOrAcquireARegisteredRight() throws {
        guard getuid() > 0, geteuid() > 0 else { throw XCTSkip("Ordinary-owner controls") }
        XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.load(path: "/private/nonexistent/host.cbor")) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertThrowsError(try InstalledAuthorityCommandRegistration.open(path: "/private/nonexistent/host.cbor")) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        var port = mach_port_t(1234)
        XCTAssertEqual("dev.remozio.commands".withCString { remozio_authority_check_in_service($0, &port) }, KERN_NO_ACCESS)
        XCTAssertEqual(port, mach_port_t(MACH_PORT_NULL))
        for name in ["", String(repeating: "x", count: 128)] {
            port = 1234
            XCTAssertEqual(name.withCString { remozio_authority_check_in_service($0, &port) }, KERN_INVALID_ARGUMENT)
            XCTAssertEqual(port, mach_port_t(MACH_PORT_NULL))
        }
    }
}
