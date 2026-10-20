import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// In-process protocol exchange with owned SQLite files. No native peer or service admission is simulated as proof.
final class GatewayJournalSetupExchangeTests: XCTestCase, @unchecked Sendable {
    private struct Refused: Error {}
    private static let pem = Result { () throws -> String in
        let process = Process(), output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run(); let bytes = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw Refused() }
        return String(decoding: bytes, as: UTF8.self)
    }
    final class Fixture: @unchecked Sendable {
        let runtime: RuntimeActivationFixture
        let intent: GatewayJournalSetupIntent
        let root: URL
        let parent: ProtectedSetupDirectory
        private let lock = NSRecursiveLock()
        init(nativeConsumerHosts: Bool = false) throws {
            guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner setup exchange") }
            runtime = try .init(nativeConsumerHosts: nativeConsumerHosts)
            try runtime.machine.retainRuntimeActivation(runtime.plan)
            _ = try runtime.machine.enrollRuntimeActivation(runtime.plan)
            try runtime.machine.markRuntimeJobsRegistered(runtime.plan)
            let provider = try SetupFCMConfiguration(project: "synthetic-project", clientEmail: "fixture@fixture.iam.gserviceaccount.com",
                privateKeyID: "fixture-key", privateKeyPEM: GatewayJournalSetupExchangeTests.pem.get())
            let material = try GatewayPreparationMaterial.create(runtime: runtime.material.reference, provider: provider,
                senderID: "123", packageName: "dev.remozio.android", fileWakeCustodyAccepted: true)
            try runtime.machine.retainGatewayMaterial(material.reference)
            let settings = try GatewayServiceSettings(delivery: .init(maximumFlights: 4, minimumSendIntervalMillis: 1000),
                probe: .init(maximumAttempts: 3, minimumRetryDelayMillis: 1000, maximumTTLSeconds: 300),
                wake: .init(maximumEntries: 32, maximumAttempts: 3, minimumEnrollmentIntervalMillis: 1000,
                    maximumLifetimeMillis: 300000, maximumTTLSeconds: 300))
            let bundle = try GatewayConfigurationBundle(foreground: runtime.plan, material: material.reference,
                inventory: XCTUnwrap(runtime.machine.inventory()), settings: settings)
            root = URL(fileURLWithPath: "/private/tmp/remozio-setup-exchange-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            parent = try .init(anchor: root.path, relativePath: "Service", owner: getuid(), visibility: .sharedMetadata)
            let files = try GatewayJournalFileProvisioning.prepare(parent: parent, processOwner: getuid(), serviceUID: getuid(), serviceGID: getgid(),
                mode: .createIfAbsent, expected: nil, verifyCurrent: {}).identity
            intent = try .init(id: AccountPreparationIntent.randomID(), material: material.reference, configuration: bundle.gateway, files: files)
            try runtime.machine.retainGatewayJournalIntent(intent)
        }
        deinit { parent.close(); try? FileManager.default.removeItem(at: root) }
        func verifyPending() throws {
            try lock.withLock {
                let state = try runtime.machine.gatewayJournalPreparation(accountID: intent.accountID)
                guard state.intent == intent, !state.initialized else { throw GatewayPreparationError.changedScope }
            }
        }
        func initialize() throws -> Data {
            try lock.withLock {
                try GatewayJournalPreparationOperation.execute(intent: intent) { configuration, files in
                    try GatewayJournalInitialization.resume(registration: configuration.registration, mayInitializeEmpty: true,
                        verifyCurrent: {}, openJournal: { create in
                            let lease = try ProtectedGatewayLease(anchor: self.root.path, relativeDirectory: "Service/Gateway", serviceUID: getuid(), ancestorUID: getuid())
                            do {
                                guard try lease.fileIdentity() == files else { throw JournalLeaseError.identityChanged }
                                let limits = try CBORLimits(maxBytes: 65536, maxDepth: 8, maxItems: 256), settings = configuration.settings
                                return try GatewayDatabase(lease: lease, identity: configuration.registration, payloadLimits: limits, signingLimits: limits,
                                    maximumOperations: settings.maximumStoredControls, maximumPendingPerEnrollment: settings.maximumPendingPerEnrollment,
                                    maximumLifetimeMillis: settings.maximumCandidateLifetimeMillis, clockEpoch: UUID(), busyMilliseconds: settings.databaseBusyMillis,
                                    initialize: create, probePolicy: settings.probe)
                            } catch { lease.close(); throw error }
                        })
                }
            }
        }
        func state() throws -> GatewayJournalPreparationState {
            try lock.withLock { try runtime.machine.gatewayJournalPreparation(accountID: intent.accountID) }
        }
        func retainCompletion(_ report: GatewayJournalSetupReport) throws {
            try lock.withLock {
                try report.validate(intent: intent)
                // The prepared-report purpose asserts the empty head checked by the actual initializer above.
                // This fixture supplies invocation checks; production must authenticate the live XPC producer first.
                _ = try runtime.machine.completeGatewayJournalInitialization(intent,
                    head: .init(registration: intent.configuration.registration, revision: 0, receipt: nil))
            }
        }
        func validateFiles() throws {
            _ = try GatewayJournalFileProvisioning.prepare(parent: parent, processOwner: getuid(), serviceUID: getuid(), serviceGID: getgid(),
                mode: .requireExisting, expected: intent.files, verifyCurrent: {})
        }
    }
    final class Driver: GatewayJournalSetupDriver, @unchecked Sendable {
        let endpoint: GatewayJournalSetupXPCEndpoint
        let dropResponse: Bool
        init(fixture: Fixture, dropResponse: Bool = false) throws {
            self.dropResponse = dropResponse
            endpoint = try .init(intentID: fixture.intent.id, scopeDigest: fixture.intent.digest, verify: {},
                budget: AuthorityXPCWorkBudget(maximum: 1), invalidate: {}, execute: { try fixture.initialize() })
        }
        func start(closed: @escaping @Sendable () -> Void) {}
        func invoke(_ call: GatewayJournalSetupCall, reply: @escaping @Sendable (GatewayJournalSetupReply) -> Void) {
            switch call {
            case .hello: endpoint.hello { reply(.version($0)) }
            case .prepare(let digest, let challenge): endpoint.prepare(digest, challenge: challenge) { [dropResponse] in
                reply(dropResponse ? .failed : .report($0))
            }
            }
        }
        func close() { endpoint.close() }
    }
    private func channel(_ f: Fixture, drop: Bool = false) throws -> GatewayJournalSetupChannel {
        try .init(driver: Driver(fixture: f, dropResponse: drop), intentID: f.intent.id, scopeDigest: f.intent.digest,
            verifyPending: { try f.verifyPending() }, challenge: { AccountPreparationIntent.randomID() + AccountPreparationIntent.randomID() })
    }
    func testOwnedExchangeInitializesTheRetainedFilesAndCompletesProtectedSetup() async throws {
        let f = try Fixture(), inventory = try f.runtime.machine.inventory(), foreground = try f.runtime.machine.runtimeActivation(accountID: f.intent.accountID)
        let report = try await channel(f).prepare(); XCTAssertTrue(report.created)
        XCTAssertFalse(try f.state().initialized)
        try f.retainCompletion(report); XCTAssertTrue(try f.state().initialized); try f.validateFiles()
        XCTAssertEqual(try f.runtime.machine.inventory(), inventory)
        XCTAssertEqual(try f.runtime.machine.runtimeActivation(accountID: f.intent.accountID).plan?.encoded, try foreground.plan?.encoded)
        do { _ = try await channel(f).prepare(); XCTFail() } catch { XCTAssertEqual(error as? GatewayPreparationError, .changedScope) }
    }
    func testLostReplyRestoresTheSameJournalBeforeRetainingCompletion() async throws {
        let f = try Fixture()
        do { _ = try await channel(f, drop: true).prepare(); XCTFail() } catch {}
        XCTAssertFalse(try f.state().initialized); try f.validateFiles()
        let report = try await channel(f).prepare(); XCTAssertFalse(report.created)
        try f.retainCompletion(report); XCTAssertTrue(try f.state().initialized); try f.validateFiles()
    }
    func testReplacedDatabaseCannotInitializeOrAdvanceTheProtectedCheckpoint() async throws {
        let f = try Fixture(), path = URL(fileURLWithPath: f.parent.path + "/Gateway/gateway.sqlite")
        let original = path.appendingPathExtension("original")
        try FileManager.default.moveItem(at: path, to: original)
        XCTAssertTrue(FileManager.default.createFile(atPath: path.path, contents: Data(), attributes: [.posixPermissions: 0o600]))
        do { _ = try await channel(f).prepare(); XCTFail() } catch {}
        XCTAssertFalse(try f.state().initialized)
        XCTAssertEqual(try Data(contentsOf: path), Data()); XCTAssertEqual(try Data(contentsOf: original), Data())
    }
}
