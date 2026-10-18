import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewayJournalPreparationOperationTests: XCTestCase {
    private struct Refused: Error {}
    private static let pem = Result { () throws -> String in
        let p = Process(), out = Pipe(); p.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        p.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        p.standardOutput = out; p.standardError = FileHandle.nullDevice
        try p.run(); let bytes = out.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        guard p.terminationStatus == 0 else { throw Refused() }; return String(decoding: bytes, as: UTF8.self)
    }
    private func fixture(_ body: (GatewayJournalSetupIntent, GatewayPreparationMaterial, ProtectedSetupDirectory, URL) throws -> Void) throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner setup fixture") }
        let runtime = try RuntimeActivationFixture()
        try runtime.machine.retainRuntimeActivation(runtime.plan); _ = try runtime.machine.enrollRuntimeActivation(runtime.plan)
        try runtime.machine.markRuntimeJobsRegistered(runtime.plan)
        let provider = try SetupFCMConfiguration(project: "synthetic-project", clientEmail: "fixture@fixture.iam.gserviceaccount.com",
            privateKeyID: "fixture-key", privateKeyPEM: Self.pem.get())
        let material = try GatewayPreparationMaterial.create(runtime: runtime.material.reference, provider: provider, senderID: "123",
            packageName: "dev.remozio.android", fileWakeCustodyAccepted: true)
        let settings = try GatewayServiceSettings(delivery: .init(maximumFlights: 4, minimumSendIntervalMillis: 1000),
            probe: .init(maximumAttempts: 3, minimumRetryDelayMillis: 1000, maximumTTLSeconds: 300),
            wake: .init(maximumEntries: 32, maximumAttempts: 3, minimumEnrollmentIntervalMillis: 1000,
                maximumLifetimeMillis: 300000, maximumTTLSeconds: 300))
        let bundle = try GatewayConfigurationBundle(foreground: runtime.plan, material: material.reference,
            inventory: XCTUnwrap(runtime.machine.inventory()), settings: settings)
        let root = URL(fileURLWithPath: "/private/tmp/remozio-gateway-operation-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { XCTAssertNoThrow(try FileManager.default.removeItem(at: root)) }
        XCTAssertEqual(chmod(root.path, 0o755), 0)
        let parent = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Service", owner: getuid(), visibility: .sharedMetadata)
        defer { parent.close() }
        let files = try GatewayJournalFileProvisioning.prepare(parent: parent, processOwner: getuid(), serviceUID: getuid(), serviceGID: getgid(),
            mode: .createIfAbsent, expected: nil, verifyCurrent: {}).identity
        let intent = try GatewayJournalSetupIntent(id: AccountPreparationIntent.randomID(), material: material.reference,
            configuration: bundle.gateway, files: files)
        try body(intent, material, parent, root)
    }
    private func initialize(_ intent: GatewayJournalSetupIntent, root: URL) throws -> GatewayJournalInitialization.Result {
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 8, maxItems: 256)
        return try GatewayJournalInitialization.resume(registration: intent.configuration.registration, mayInitializeEmpty: true,
            verifyCurrent: {}, openJournal: { initialize in
                let lease = try ProtectedGatewayLease(anchor: root.path, relativeDirectory: "Service/Gateway", serviceUID: getuid(), ancestorUID: getuid())
                do {
                    guard try lease.fileIdentity() == intent.files else { throw JournalLeaseError.identityChanged }
                    return try GatewayDatabase(lease: lease, identity: intent.configuration.registration, payloadLimits: limits, signingLimits: limits,
                        maximumOperations: 4096, maximumPendingPerEnrollment: 4, maximumLifetimeMillis: 300000,
                        clockEpoch: UUID(), busyMilliseconds: 100, initialize: initialize)
                } catch { lease.close(); throw error }
            })
    }

    func testExplicitOperationReportsCreationThenRestorationWithTheSameScope() throws {
        try fixture { intent, material, _, root in
            for created in [true,false] {
                let bytes = try GatewayJournalPreparationOperation.execute(intent: intent) { configuration, files in
                    XCTAssertEqual(configuration.canonicalBytes, intent.configuration.canonicalBytes); XCTAssertEqual(files, intent.files)
                    return try self.initialize(intent, root: root)
                }
                let report = try GatewayJournalSetupReport.decode(bytes); try report.validate(intent: intent)
                XCTAssertEqual(report.created, created); XCTAssertEqual(try report.encoded, bytes)
                XCTAssertNil(bytes.range(of: material.providerJSON)); XCTAssertNil(bytes.range(of: material.receiptKeyRecord))
                XCTAssertLessThan(bytes.count, 512)
            }
        }
    }
    func testReportCannotBeAcceptedForAnotherIntentOrModifiedConfiguration() throws {
        try fixture { intent, _, _, _ in
            let report = try GatewayJournalSetupReport(intentID: intent.id, scopeDigest: intent.digest, created: true)
            let other = try GatewayJournalSetupIntent(id: AccountPreparationIntent.randomID(), material: intent.material,
                configuration: intent.configuration, files: intent.files)
            XCTAssertThrowsError(try report.validate(intent: other)) { XCTAssertEqual($0 as? GatewayPreparationError, .changedScope) }
            let altered = try GatewayJournalSetupReport(intentID: intent.id, scopeDigest: Data(repeating: 0, count: 32), created: false)
            XCTAssertThrowsError(try altered.validate(intent: intent))
        }
    }
    func testNonemptyAndForeignHeadsCannotProduceAPreparedReport() throws {
        try fixture { intent, _, _, _ in
            for revision: UInt64 in [1,UInt64.max] {
                XCTAssertThrowsError(try GatewayJournalPreparationOperation.execute(intent: intent) { _,_ in
                    .init(head: .init(registration: intent.configuration.registration, revision: revision, receipt: nil), initialized: false)
                }) { XCTAssertEqual($0 as? GatewayPreparationError, .changedScope) }
            }
            let r = intent.configuration.registration
            let other = try GatewayRegistrationIdentity(ownerID: Data(repeating: 99, count: 16), macID: r.macID, accountID: r.accountID,
                gatewayID: r.gatewayID, lifecycleEpoch: r.lifecycleEpoch, rootPublicKey: r.rootPublicKey)
            XCTAssertThrowsError(try GatewayJournalPreparationOperation.execute(intent: intent) { _,_ in
                .init(head: .init(registration: other, revision: 0, receipt: nil), initialized: true)
            })
        }
    }
    func testUnknownAndOversizedReportsFailWithoutInterpretation() throws {
        let report = try GatewayJournalSetupReport(intentID: Data(repeating: 1, count: 16), scopeDigest: Data(repeating: 2, count: 32), created: true)
        let limits = try GatewayJournalSetupReport.limits
        guard case .map(var fields) = try DeterministicCBOR.decode(report.encoded, limits: limits) else { throw Refused() }
        fields[0] = .unsigned(2)
        XCTAssertThrowsError(try GatewayJournalSetupReport.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        XCTAssertThrowsError(try GatewayJournalSetupReport.decode(Data(repeating: 0, count: 513)))
        XCTAssertEqual(String(reflecting: report), "GatewayJournalSetupReport(redacted)")
    }
}
