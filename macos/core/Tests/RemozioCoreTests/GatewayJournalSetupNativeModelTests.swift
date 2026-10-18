import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewayJournalSetupNativeModelTests: XCTestCase {
    private struct Refused: Error {}
    private static let pem = Result { () throws -> String in
        let process = Process(), output = Pipe(); process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run(); let bytes = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw Refused() }; return String(decoding: bytes, as: UTF8.self)
    }
    static func fixture(_ body: (RuntimeActivationFixture, GatewayPreparationMaterial, GatewayJournalSetupServiceConfiguration) throws -> Void) throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner native metadata fixture") }
        let f = try RuntimeActivationFixture()
        try f.machine.retainRuntimeActivation(f.plan)
        _ = try f.machine.enrollRuntimeActivation(f.plan)
        try f.machine.markRuntimeJobsRegistered(f.plan)
        let provider = try SetupFCMConfiguration(project: "synthetic-project", clientEmail: "fixture@fixture.iam.gserviceaccount.com",
            privateKeyID: "fixture-key", privateKeyPEM: Self.pem.get())
        let material = try GatewayPreparationMaterial.create(runtime: f.material.reference, provider: provider,
            senderID: "123", packageName: "dev.remozio.android", fileWakeCustodyAccepted: true)
        let settings = try GatewayServiceSettings(delivery: .init(maximumFlights: 4, minimumSendIntervalMillis: 1000),
            probe: .init(maximumAttempts: 3, minimumRetryDelayMillis: 1000, maximumTTLSeconds: 300),
            wake: .init(maximumEntries: 32, maximumAttempts: 3, minimumEnrollmentIntervalMillis: 1000, maximumLifetimeMillis: 300000, maximumTTLSeconds: 300))
        let bundle = try GatewayConfigurationBundle(foreground: f.plan, material: material.reference,
            inventory: XCTUnwrap(f.machine.inventory()), settings: settings)
        // Identity values are metadata fixtures. No service file or native launch is claimed here.
        let intent = try GatewayJournalSetupIntent(id: AccountPreparationIntent.randomID(), material: material.reference,
            configuration: bundle.gateway, files: .init(directory: .init(device: 1, inode: 11), writer: .init(device: 1, inode: 12), database: .init(device: 1, inode: 13)))
        let configuration = try GatewayJournalSetupServiceConfiguration(intent: intent, bundlePath: f.plan.bundlePath, codePolicy: f.plan.host.codePolicy)
        try body(f, material, configuration)
    }
    private func replace(_ entry: AuthorityCodeEntry, team: String? = nil, identifier: String? = nil, hash: Data? = nil, active: Bool? = nil) throws -> AuthorityCodeEntry {
        try .init(role: entry.role, teamID: team ?? entry.teamID, identifier: identifier ?? entry.identifier,
            installedGeneration: entry.installedGeneration, minimumGeneration: entry.minimumGeneration,
            codeDirectoryHash: hash ?? entry.codeDirectoryHash, active: active ?? entry.active)
    }
    func testPublicRecordRoundTripContainsOnlySetupScopeAndCodePins() throws {
        try Self.fixture { f, material, configuration in
            let bytes = configuration.canonicalBytes, restored = try GatewayJournalSetupServiceConfiguration.decode(bytes)
            XCTAssertEqual(restored.canonicalBytes, bytes)
            XCTAssertNil(bytes.range(of: material.providerJSON)); XCTAssertNil(bytes.range(of: material.receiptKeyRecord))
            XCTAssertNil(bytes.range(of: try material.wakeKeyRecord.encode()))
            XCTAssertEqual(configuration.setupCode.role, .setupController); XCTAssertEqual(configuration.gatewayCode.role, .notificationGateway)
            XCTAssertEqual(configuration.maximumLifetimeMilliseconds, 120000)
            XCTAssertEqual(String(describing: configuration), "GatewayJournalSetupServiceConfiguration(redacted)")
            XCTAssertLessThanOrEqual(bytes.count, ProtectedServiceConfiguration.maximumBytes)
            try configuration.validate(foreground: f.plan, inventory: XCTUnwrap(f.machine.inventory()))
            XCTAssertThrowsError(try configuration.requireNativeProcess()) { XCTAssertEqual($0 as? GatewayServiceError, .wrongAccount) }
        }
    }
    func testInactiveMissingForeignAndChangedPeerCodeCannotEnterTheRecord() throws {
        try Self.fixture { _, _, configuration in
            for mode in 0...4 {
                var entries = configuration.codePolicy.entries
                switch mode {
                case 0: entries.removeAll { $0.role == .setupController }
                case 1: entries = try entries.map { $0.role == .setupController ? try replace($0, active: false) : $0 }
                case 2: entries = try entries.map { $0.role == .setupController ? try replace($0, team: "ZZZZZZZZZZ") : $0 }
                case 3: entries = try entries.map { $0.role == .authority ? try replace($0, hash: Data(repeating: 77, count: 20)) : $0 }
                default: entries = try entries.map { $0.role == .transport ? try replace($0, hash: Data(repeating: 77, count: 20)) : $0 }
                }
                let policy = try AuthorityCodePolicy(entries: entries)
                XCTAssertThrowsError(try GatewayJournalSetupServiceConfiguration(intent: configuration.intent, bundlePath: configuration.bundlePath, codePolicy: policy))
            }
        }
    }
    func testWrongInventoryOrForegroundCodePolicyCannotValidateASetupScope() throws {
        try Self.fixture { f, _, configuration in
            let original = try XCTUnwrap(f.machine.inventory())
            for mode in 0...3 {
                let inventory = try InstallationInventory(macID: mode == 0 ? Data(repeating: 9, count: 16) : original.macID,
                    installationID: mode == 1 ? Data(repeating: 9, count: 16) : original.installationID,
                    revision: original.revision, bundlePath: mode == 2 ? "/Library/Other.app" : original.bundlePath,
                    releaseDigest: mode == 3 ? Data(repeating: 9, count: 32) : original.releaseDigest,
                    accounts: original.accounts, services: original.services, formatVersion: original.formatVersion)
                XCTAssertThrowsError(try configuration.validate(foreground: f.plan, inventory: inventory))
            }
            let entries = try configuration.codePolicy.entries.map { $0.role == .setupController ? try replace($0, hash: Data(repeating: 77, count: 20)) : $0 }
            let changed = try GatewayJournalSetupServiceConfiguration(intent: configuration.intent, bundlePath: configuration.bundlePath, codePolicy: .init(entries: entries))
            XCTAssertThrowsError(try changed.validate(foreground: f.plan, inventory: original))
        }
    }
    func testUnknownFormatUnsafePathsAndUnboundedProcessLifetimeAreRefused() throws {
        try Self.fixture { _, _, configuration in
            let limits = try CBORLimits(maxBytes: 131072, maxDepth: 2, maxItems: 32)
            guard case .map(var fields) = try DeterministicCBOR.decode(configuration.canonicalBytes, limits: limits) else { throw Refused() }
            fields[0] = .unsigned(2)
            XCTAssertThrowsError(try GatewayJournalSetupServiceConfiguration.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
            for path in ["relative.app", "/Library/../Other.app", "/Library/Bad\t.app", "/Library//Other.app"] {
                XCTAssertThrowsError(try GatewayJournalSetupServiceConfiguration(intent: configuration.intent, bundlePath: path, codePolicy: configuration.codePolicy))
            }
            for lifetime: UInt64 in [0, 999, 4999, 300001, UInt64.max] {
                XCTAssertThrowsError(try GatewayJournalSetupServiceConfiguration(intent: configuration.intent, bundlePath: configuration.bundlePath,
                    codePolicy: configuration.codePolicy, maximumLifetimeMilliseconds: lifetime))
            }
        }
    }
    func testJobUsesOnlyTheGatewayAccountFixedSetupModeAndSeparateDemandEndpoint() throws {
        try Self.fixture { _, _, configuration in
            let job = try GatewayJournalSetupJobManifest(configuration: configuration)
            let plist = try XCTUnwrap(PropertyListSerialization.propertyList(from: job.bytes, format: nil) as? [String: Any])
            XCTAssertEqual(Set(plist.keys), ["Label", "Program", "UserName", "GroupName", "ProgramArguments", "RunAtLoad", "KeepAlive", "MachServices"])
            XCTAssertEqual(plist["RunAtLoad"] as? Bool, false); XCTAssertEqual(plist["KeepAlive"] as? Bool, false)
            XCTAssertEqual(plist["UserName"] as? String, job.userName); XCTAssertEqual(plist["GroupName"] as? String, job.userName)
            XCTAssertEqual(plist["ProgramArguments"] as? [String], [configuration.executablePath, "--journal-setup", try configuration.configurationPath])
            XCTAssertEqual(plist["MachServices"] as? [String: Bool], [job.label: true])
            XCTAssertEqual(job.path, "/Library/LaunchDaemons/" + job.label + ".plist")
            XCTAssertNotEqual(job.label, configuration.intent.configuration.serviceName)
            try job.validateBytes(job.bytes)
            var changed = plist; changed["UserName"] = "root"
            XCTAssertThrowsError(try job.validateBytes(PropertyListSerialization.data(fromPropertyList: changed, format: .xml, options: 0)))
            let special = try GatewayJournalSetupServiceConfiguration(intent: configuration.intent, bundlePath: "/Library/A & B.app", codePolicy: configuration.codePolicy)
            let escaped = try GatewayJournalSetupJobManifest(configuration: special)
            let decoded = try XCTUnwrap(PropertyListSerialization.propertyList(from: escaped.bytes, format: nil) as? [String: Any])
            XCTAssertEqual(decoded["Program"] as? String, special.executablePath)
        }
    }
    func testTypedPublicServiceRecordCannotCreateAStandaloneJournalOrUseOrdinaryOwnership() throws {
        try Self.fixture { _, _, configuration in
            let root = URL(fileURLWithPath: "/private/tmp/remozio-setup-publication-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            defer { XCTAssertNoThrow(try FileManager.default.removeItem(at: root)) }
            XCTAssertEqual(chmod(root.path, 0o755), 0)
            let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Metadata", owner: getuid(), visibility: .sharedMetadata)
            defer { directory.close() }
            let file = AdministrativeSetupPublication.File.gatewayJournalService
            XCTAssertEqual(file.mode, 0o644); XCTAssertTrue(file.requiresSharedDirectory)
            XCTAssertEqual(file.name, GatewayJournalSetupServiceConfiguration.fileName)
            XCTAssertNotEqual(file.name, "gateway-journal-setup.cbor")
            XCTAssertEqual(try AdministrativeSetupPublication.publish(configuration.canonicalBytes, file: file, directory: directory, owner: getuid()), .created)
            let bytes = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name, owner: getuid(), privateFile: false)
            XCTAssertEqual(try GatewayJournalSetupServiceConfiguration.decode(bytes).canonicalBytes, configuration.canonicalBytes)
            XCTAssertThrowsError(try GatewayJournalSetupServiceConfiguration.decode(configuration.intent.encoded))
            XCTAssertThrowsError(try GatewayJournalSetupService.open(path: directory.path + "/" + file.name)) {
                XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
            }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [file.name])
            XCTAssertEqual(try AdministrativeSetupPublication.publish(configuration.canonicalBytes, file: file, directory: directory, owner: getuid()), .retained)
        }
    }
    func testLoadedJobWithWrongAccountEndpointModeOrRestartPropertiesCannotMatch() throws {
        try Self.fixture { _, _, configuration in
            let job = try GatewayJournalSetupJobManifest(configuration: configuration)
            func observation(_ mode: Int) -> LaunchdJobObservation {
                .init(path: job.path, program: job.executablePath, arguments: mode == 3 ? [job.executablePath, "--configuration", "/other.cbor"] : job.arguments,
                    kind: "LaunchDaemon", userName: mode == 1 ? "root" : job.userName, groupName: job.userName,
                    endpoints: mode == 2 ? [configuration.intent.configuration.serviceName] : job.machServices,
                    properties: mode == 4 ? ["runatload"] : mode == 5 ? ["keepalive"] : [])
            }
            XCTAssertTrue(observation(0).matches(job))
            for mode in 1...5 { XCTAssertFalse(observation(mode).matches(job)) }
        }
    }
}
