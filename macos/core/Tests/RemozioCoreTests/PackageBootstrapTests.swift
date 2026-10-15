import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class PackageBootstrapTests: XCTestCase {
    private final class Fixture {
        let root: URL
        let shared: ProtectedSetupDirectory
        let apps: ProtectedSetupDirectory
        let release: SignedReleaseEvidence
        let seed: MachineBootstrap.Seed
        var machine: URL { URL(fileURLWithPath: shared.path).appendingPathComponent("Machine") }
        init() throws {
            root = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remozio-package-unit-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            shared = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Shared", owner: getuid(), visibility: .sharedMetadata)
            apps = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Apps", owner: getuid(), visibility: .sharedMetadata)
            let app = try ReleaseComponent(role: .app, identifier: "dev.remozio.mac", generation: 1,
                relativePath: "Contents/MacOS/Remozio", codeDirectoryHash: nil, build: "1", teamID: "ABCDEFGHIJ", formats: [])
            let setup = try ReleaseComponent(role: .setupController, identifier: "dev.remozio.setup-controller", generation: 1,
                relativePath: AdministrativeSetupConfiguration.executablePath, codeDirectoryHash: Data(repeating: 2, count: 20),
                build: "1", teamID: "ABCDEFGHIJ", formats: [])
            let evidence = SignedReleaseEvidence(manifest: try .init(release: "1", build: "1", components: [app, setup]),
                codeDirectoryHashes: [.app: Data(repeating: 1, count: 20), .setupController: Data(repeating: 2, count: 20)])
            release = evidence
            let policy = try AuthorityCodePolicy(entries: evidence.manifest.components.map { value in
                try .init(role: value.role, teamID: "ABCDEFGHIJ", identifier: value.identifier, installedGeneration: 1,
                    minimumGeneration: 1, codeDirectoryHash: evidence.codeDirectoryHashes[value.role]!, active: true)
            })
            let config = try AdministrativeSetupConfiguration(machineDirectory: shared.path + "/Machine", macID: Data(repeating: 1, count: 16),
                installationID: Data(repeating: 2, count: 16), releaseDigest: InstallationInventory.digest(release), codePolicy: policy)
            seed = try .init(configuration: config, inventory: .machineBootstrap(macID: config.macID,
                installationID: config.installationID, revision: Data(repeating: 3, count: 16),
                bundlePath: MachineBootstrap.bundlePath, releaseDigest: config.releaseDigest))
        }
        func file(_ kind: AdministrativeSetupPublication.File) -> URL { URL(fileURLWithPath: shared.path).appendingPathComponent(kind.name) }
        func write(_ bytes: Data, _ kind: AdministrativeSetupPublication.File) throws {
            try bytes.write(to: file(kind)); XCTAssertEqual(chmod(file(kind).path, 0o600), 0)
        }
        func plan() throws -> PackageBootstrap.Plan {
            try PackageBootstrap.inspectState(shared: shared, owner: getuid(), bundlePath: MachineBootstrap.bundlePath,
                machinePath: machine.path, release: release)
        }
        func complete(startup: AdministrativeSetupConfiguration? = nil) throws {
            try write(seed.bytes, .bootstrapIntent); try write(seed.bytes, .bootstrapCompletion)
            try write((startup ?? seed.configuration).canonicalBytes, .startup)
            let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Shared/Machine", owner: getuid())
            defer { directory.close() }
            _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .installation, owner: getuid())
            let db = machine.appendingPathComponent("installation.sqlite")
            try Data("nonempty metadata fixture; no SQLite health is claimed".utf8).write(to: db)
            XCTAssertEqual(chmod(db.path, 0o600), 0)
        }
    }
    private func fixture(_ body: (Fixture) throws -> Void) throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-owner fixture") }
        let f = try Fixture()
        defer { f.shared.close(); f.apps.close(); XCTAssertNoThrow(try FileManager.default.removeItem(at: f.root)) }
        try body(f)
    }
    private func profile() throws -> PackageBootstrapProfile {
        try .init(teamID: "ABCDEFGHIJ", setupHash: Data(repeating: 2, count: 20), releaseDigest: Data(repeating: 3, count: 32))
    }
    func testPinnedProfileRoundTripRejectsMalformedOrNoncanonicalInputs() throws {
        let value = try profile()
        XCTAssertEqual(try PackageBootstrapProfile(argument: value.argument), value)
        for input in [value.argument + ":x", value.argument.dropLast().description, value.argument.replacingOccurrences(of: "02", with: "GG"),
                      value.argument.replacingOccurrences(of: "ABCDEFGHIJ", with: "abcdefghij"), "", "../x"] {
            XCTAssertThrowsError(try PackageBootstrapProfile(argument: input))
        }
        XCTAssertThrowsError(try PackageBootstrapProfile(teamID: "ABCDEFGHIJ", setupHash: Data(), releaseDigest: Data(repeating: 1, count: 32)))
    }
    func testPayloadPreflightAcceptsFreshScopeWithoutCreatingAnyTrustState() throws {
        try fixture { f in
            try PackageBootstrap.preparePayload(shared: f.shared, applications: f.apps)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.shared.path), [])
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.apps.path), [])
        }
    }
    func testPayloadPreflightNeverReplacesExistingDirectoryFileOrLink() throws {
        for kind in 0...2 { try fixture { f in
            let path = URL(fileURLWithPath: f.apps.path).appendingPathComponent("Remozio.app")
            if kind == 0 { try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false) }
            else if kind == 1 { try Data("existing data".utf8).write(to: path) }
            else { try FileManager.default.createSymbolicLink(atPath: path.path, withDestinationPath: "/nonexistent/remozio-fixture") }
            var before = stat(), after = stat(); XCTAssertEqual(lstat(path.path, &before), 0)
            XCTAssertThrowsError(try PackageBootstrap.preparePayload(shared: f.shared, applications: f.apps))
            XCTAssertEqual(lstat(path.path, &after), 0); XCTAssertEqual(before.st_ino, after.st_ino)
        } }
    }
    func testPayloadPreflightRejectsRetainedStateEvenWithoutAnApp() throws {
        for name in ["Machine", "setup.cbor", "bootstrap-intent.cbor", "bootstrap-complete.cbor"] {
            try fixture { f in
                let file = URL(fileURLWithPath: f.shared.path).appendingPathComponent(name)
                try Data("retained".utf8).write(to: file)
                XCTAssertThrowsError(try PackageBootstrap.preparePayload(shared: f.shared, applications: f.apps))
                XCTAssertEqual(try Data(contentsOf: file), Data("retained".utf8))
            }
        }
    }
    func testFreshAndPendingInstalledPlansRequestBootstrapWithoutMutatingFiles() throws {
        try fixture { f in
            XCTAssertEqual(try f.plan(), .bootstrap)
            try f.write(f.seed.bytes, .bootstrapIntent)
            XCTAssertEqual(try f.plan(), .bootstrap)
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.file(.bootstrapCompletion).path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.machine.path))
        }
    }
    func testCompletedPlanRetainsSettingsWithoutTakingASecondMachineWriter() throws {
        try fixture { f in
            let config = try AdministrativeSetupConfiguration(machineDirectory: f.machine.path, macID: f.seed.configuration.macID,
                installationID: f.seed.configuration.installationID, releaseDigest: f.seed.configuration.releaseDigest,
                codePolicy: f.seed.configuration.codePolicy, maximumConnections: 12, handshakeTimeoutMilliseconds: 7500)
            try f.complete(startup: config)
            let writer = try InstallationStorageLease(anchor: f.root.path, relativeDirectory: "Shared/Machine", owner: getuid())
            defer { writer.close() }
            XCTAssertEqual(try f.plan(), .retained)
            XCTAssertEqual(try Data(contentsOf: f.file(.startup)), config.canonicalBytes)
        }
    }
    func testCompletedPlanRefusesMissingEmptyOrPublicDatabaseWithoutRecreatingIt() throws {
        for kind in 0...2 { try fixture { f in
            try f.complete(); let path = f.machine.appendingPathComponent("installation.sqlite")
            if kind == 0 { try FileManager.default.removeItem(at: path) }
            else if kind == 1 { let fd = open(path.path, O_WRONLY | O_TRUNC); XCTAssertGreaterThanOrEqual(fd, 0); _ = Darwin.close(fd) }
            else { XCTAssertEqual(chmod(path.path, 0o644), 0) }
            XCTAssertThrowsError(try f.plan())
            if kind == 0 { XCTAssertFalse(FileManager.default.fileExists(atPath: path.path)) }
            if kind == 1 { XCTAssertEqual(try Data(contentsOf: path), Data()) }
        } }
    }
    func testInstalledPlanRefusesConflictingMarkersAndChangedIdentity() throws {
        try fixture { f in
            try f.write(f.seed.bytes, .bootstrapCompletion)
            XCTAssertThrowsError(try f.plan())
            try f.write(f.seed.bytes, .bootstrapIntent); try f.write(f.seed.bytes + Data([0]), .bootstrapCompletion)
            XCTAssertThrowsError(try f.plan())
        }
        try fixture { f in
            try f.complete()
            let wrong = try AdministrativeSetupConfiguration(machineDirectory: f.machine.path, macID: Data(repeating: 9, count: 16),
                installationID: f.seed.configuration.installationID, releaseDigest: f.seed.configuration.releaseDigest, codePolicy: f.seed.configuration.codePolicy)
            try f.write(wrong.canonicalBytes, .startup); XCTAssertThrowsError(try f.plan())
        }
    }
    func testPackagePinsRejectAnotherRelease() throws {
        try fixture { f in
            let good = try PackageBootstrapProfile(teamID: "ABCDEFGHIJ", setupHash: f.release.codeDirectoryHashes[.setupController]!,
                releaseDigest: InstallationInventory.digest(f.release))
            XCTAssertNoThrow(try good.validate(f.release)); XCTAssertThrowsError(try profile().validate(f.release))
        }
    }
    func testApplicationEntryCreationIsExclusiveAndRepeatable() throws {
        try fixture { f in
            try PackageBootstrap.publishEntry(parent: f.apps.path, owner: getuid())
            let path = URL(fileURLWithPath: f.apps.path).appendingPathComponent("Remozio.app")
            var before = stat(), after = stat(); XCTAssertEqual(lstat(path.path, &before), 0)
            try PackageBootstrap.publishEntry(parent: f.apps.path, owner: getuid())
            XCTAssertEqual(lstat(path.path, &after), 0); XCTAssertEqual(before.st_ino, after.st_ino)
            XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: path.path), MachineBootstrap.bundlePath)
        }
    }
    func testApplicationEntryNeverReplacesForeignUserData() throws {
        for link in [false, true] { try fixture { f in
            let path = URL(fileURLWithPath: f.apps.path).appendingPathComponent("Remozio.app")
            if link { try FileManager.default.createSymbolicLink(atPath: path.path, withDestinationPath: "/another/application") }
            else { try Data("user data".utf8).write(to: path) }
            var before = stat(), after = stat(); XCTAssertEqual(lstat(path.path, &before), 0)
            XCTAssertThrowsError(try PackageBootstrap.publishEntry(parent: f.apps.path, owner: getuid()))
            XCTAssertEqual(lstat(path.path, &after), 0); XCTAssertEqual(before.st_ino, after.st_ino)
        } }
    }
    func testEntryPreflightAcceptsMissingOrMatchingLinkWithoutCreatingOrChangingIt() throws {
        try fixture { f in
            try PackageBootstrap.inspectEntry(parent: f.apps.path, owner: getuid())
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.apps.path), [])
            try PackageBootstrap.publishEntry(parent: f.apps.path, owner: getuid())
            let path = URL(fileURLWithPath: f.apps.path).appendingPathComponent("Remozio.app")
            var before = stat(), after = stat(); XCTAssertEqual(lstat(path.path, &before), 0)
            try PackageBootstrap.inspectEntry(parent: f.apps.path, owner: getuid())
            XCTAssertEqual(lstat(path.path, &after), 0); XCTAssertEqual(before.st_ino, after.st_ino)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.shared.path), [])
        }
    }
    func testEntryPreflightRejectsForeignDirectoryFileOrLinkWithoutWritingBootstrapState() throws {
        for kind in 0...2 { try fixture { f in
            let path = URL(fileURLWithPath: f.apps.path).appendingPathComponent("Remozio.app")
            if kind == 0 { try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false) }
            else if kind == 1 { try Data("user data".utf8).write(to: path) }
            else { try FileManager.default.createSymbolicLink(atPath: path.path, withDestinationPath: "/another/application") }
            var before = stat(), after = stat(); XCTAssertEqual(lstat(path.path, &before), 0)
            XCTAssertThrowsError(try PackageBootstrap.inspectEntry(parent: f.apps.path, owner: getuid())) {
                XCTAssertEqual($0 as? PackageBootstrapError, .shortcutConflict)
            }
            XCTAssertEqual(lstat(path.path, &after), 0); XCTAssertEqual(before.st_ino, after.st_ino)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.shared.path), [])
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.machine.path))
        } }
    }
    func testPublicPackageOperationsRejectOrdinaryUserBeforeProtectedPaths() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-user refusal") }
        let value = try profile()
        XCTAssertThrowsError(try PackageBootstrap.preparePayload(value)) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertThrowsError(try PackageBootstrap.inspectInstalled(value)) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertThrowsError(try PackageBootstrap.ensureApplicationEntry(value)) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
    }
}
