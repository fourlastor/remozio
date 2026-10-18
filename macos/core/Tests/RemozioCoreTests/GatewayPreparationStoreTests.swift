import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewayPreparationStoreTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Creations { var count = 0 }
    private static let pem = Result { () throws -> String in
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        try process.run(); let bytes = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw PortableSetupError.rejected }; return String(decoding: bytes, as: UTF8.self)
    }
    private func provider() throws -> SetupFCMConfiguration {
        try .init(project: "synthetic-project", clientEmail: "fixture@fixture.iam.gserviceaccount.com",
            privateKeyID: "fixture-key", privateKeyPEM: Self.pem.get())
    }
    private func fixture(activated: Bool = true) throws -> RuntimeActivationFixture {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner SQLite and file fixture") }
        let f = try RuntimeActivationFixture()
        if activated {
            try f.machine.retainRuntimeActivation(f.plan); _ = try f.machine.enrollRuntimeActivation(f.plan)
            try f.machine.markRuntimeJobsRegistered(f.plan)
        }
        return f
    }
    private func material(_ f: RuntimeActivationFixture) throws -> GatewayPreparationMaterial {
        try .create(runtime: f.material.reference, provider: provider(), senderID: "123",
            packageName: "dev.remozio.android", fileWakeCustodyAccepted: true)
    }
    private func prepare(_ f: RuntimeActivationFixture, directory: ProtectedSetupDirectory, creations: Creations,
                         expected: GatewayPreparationState? = nil, verify: @escaping () throws -> Void = {},
                         stage: (GatewayMaterialPreparationController.Stage) throws -> Void = { _ in }) throws -> GatewayPreparationState {
        let provider = try provider(), state = try expected ?? f.machine.gatewayPreparation(accountID: f.account.accountID)
        return try GatewayMaterialPreparationController.prepare(machine: f.machine, account: f.account, expected: state,
            verifyCurrent: verify, verifyServices: { XCTAssertEqual($0, f.services) }, restoreMaterial: { runtime, reference, verify in
                try GatewayMaterialPreparation.restoreOrCreate(directory: directory, owner: getuid(), runtime: runtime, expected: reference,
                    provider: provider, senderID: "123", packageName: "dev.remozio.android", verifyCurrent: verify,
                    make: { creations.count += 1; return try self.material(f) })
            }, didStage: stage)
    }
    private func directory(_ f: RuntimeActivationFixture) throws -> ProtectedSetupDirectory {
        try .init(anchor: f.f.root.path, relativePath: "gateway-material", owner: getuid())
    }

    func testLegacyReadDoesNotUpgradeAndRetentionLeavesAllForegroundStateUnchanged() throws {
        let f = try fixture(), value = try material(f)
        let inventory = try f.machine.inventory(), runtime = try f.machine.runtimePreparation(accountID: f.account.accountID)
        let activation = try f.machine.runtimeActivation(accountID: f.account.accountID)
        XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 7)
        XCTAssertNil(try f.machine.gatewayPreparation(accountID: f.account.accountID).reference)
        XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 7)
        try f.machine.retainGatewayMaterial(value.reference)
        XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 8)
        XCTAssertEqual(try f.machine.gatewayPreparation(accountID: f.account.accountID).reference, try value.reference)
        XCTAssertEqual(try f.machine.inventory(), inventory)
        XCTAssertEqual(try f.machine.runtimePreparation(accountID: f.account.accountID), runtime)
        let after = try f.machine.runtimeActivation(accountID: f.account.accountID)
        XCTAssertEqual(try after.plan?.encoded, try activation.plan?.encoded); XCTAssertTrue(after.jobsRegistered)
        try f.machine.retainGatewayMaterial(value.reference)
        XCTAssertEqual(try f.f.sql("SELECT COUNT(*) FROM gateway_preparation_v1"), 1)
        try f.machine.close(); let reopened = try f.f.open(); defer { try? reopened.close() }
        XCTAssertEqual(try reopened.gatewayPreparation(accountID: f.account.accountID).reference, try value.reference)
        XCTAssertEqual(PreparationIntentStore.supportedSchemaVersions, [1, 2, 3, 4, 5, 6, 7, 8])
    }
    func testMaterialCannotUpgradeStorageBeforeForegroundRegistrationCompletes() throws {
        let f = try fixture(activated: false), value = try material(f)
        XCTAssertThrowsError(try f.machine.retainGatewayMaterial(value.reference))
        XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 6)
        try f.machine.retainRuntimeActivation(f.plan)
        XCTAssertThrowsError(try f.machine.retainGatewayMaterial(value.reference))
        _ = try f.machine.enrollRuntimeActivation(f.plan)
        XCTAssertThrowsError(try f.machine.retainGatewayMaterial(value.reference))
        XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 7)
        try f.machine.markRuntimeJobsRegistered(f.plan); try f.machine.retainGatewayMaterial(value.reference)
        XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 8)
    }
    func testDifferentMaterialForTheSameAccountCannotReplaceTheRetainedReference() throws {
        let f = try fixture(), first = try material(f), replacement = try material(f)
        try f.machine.retainGatewayMaterial(first.reference)
        XCTAssertThrowsError(try f.machine.retainGatewayMaterial(replacement.reference)) {
            XCTAssertEqual($0 as? GatewayPreparationError, .conflictingMaterial)
        }
        XCTAssertEqual(try f.machine.gatewayPreparation(accountID: f.account.accountID).reference, try first.reference)
    }
    func testLostDatabaseAcknowledgmentRetainsSchemaAndReferenceOnReopen() throws {
        let f = try fixture(), value = try material(f); try f.machine.close()
        var armed = false
        let writer = try f.f.open(hook: { if armed { throw Interrupted() } }); armed = true
        XCTAssertThrowsError(try writer.retainGatewayMaterial(value.reference)) { XCTAssertTrue($0 is Interrupted) }
        XCTAssertThrowsError(try writer.gatewayPreparation(accountID: f.account.accountID))
        try writer.close(); let restored = try f.f.open(); defer { try? restored.close() }
        XCTAssertEqual(try restored.gatewayPreparation(accountID: f.account.accountID).reference, try value.reference)
        try restored.retainGatewayMaterial(value.reference)
        XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 8)
    }
    func testCorruptIndexesIncludingTheAccountKeyRetireTheReaderInsteadOfHidingMaterial() throws {
        for change in ["account=zeroblob(16)", "material=zeroblob(16)", "receipt=zeroblob(65)",
                       "credential=zeroblob(16)", "wake=zeroblob(65)", "digest=zeroblob(32)", "record=x'00'"] {
            let f = try fixture(), value = try material(f); try f.machine.retainGatewayMaterial(value.reference)
            _ = try f.f.sql("UPDATE gateway_preparation_v1 SET " + change)
            XCTAssertThrowsError(try f.machine.gatewayPreparation(accountID: f.account.accountID)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
            XCTAssertThrowsError(try f.machine.gatewayPreparation(accountID: f.account.accountID)) {
                XCTAssertEqual($0 as? PreparationStoreError, .unavailable)
            }
            XCTAssertEqual(try f.f.sql("SELECT COUNT(*) FROM gateway_preparation_v1"), 1)
        }
    }
    func testPrivateCredentialAndKeyRecordsNeverEnterThePublicReference() throws {
        let f = try fixture(), value = try material(f); try f.machine.retainGatewayMaterial(value.reference)
        let retained = try XCTUnwrap(f.machine.gatewayPreparation(accountID: f.account.accountID).reference)
        let bytes = try retained.encoded
        XCTAssertNil(bytes.range(of: value.providerJSON)); XCTAssertNil(bytes.range(of: value.receiptKeyRecord))
        XCTAssertNil(bytes.range(of: try value.wakeKeyRecord.encode()))
        XCTAssertEqual(retained.materialDigest, Data(SHA256.hash(data: try value.encoded)))
    }
    func testControllerRecoversAtEveryStageWithoutReplacingKeysOrRegisteringAnotherJob() throws {
        for stage in 0...2 {
            let f = try fixture(), directory = try directory(f); defer { directory.close() }
            let inventory = try f.machine.inventory(); let creations = Creations()
            XCTAssertThrowsError(try prepare(f, directory: directory, creations: creations, stage: {
                switch (stage, $0) {
                case (0, .materialRestored), (1, .referenceRetained), (2, .completed): throw Interrupted()
                default: break
                }
            })) { XCTAssertTrue($0 is Interrupted) }
            let first = try Data(contentsOf: URL(fileURLWithPath: directory.path + "/gateway-material.cbor"))
            let recovered = try prepare(f, directory: directory, creations: creations)
            XCTAssertEqual(creations.count, 1); XCTAssertEqual(recovered.reference, try GatewayPreparationMaterial.decode(first).reference)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: directory.path + "/gateway-material.cbor")), first)
            XCTAssertEqual(try f.machine.inventory(), inventory)
            XCTAssertTrue(try f.machine.runtimeActivation(accountID: f.account.accountID).jobsRegistered)
            XCTAssertFalse(try XCTUnwrap(f.machine.inventory()).services.contains { $0.role == .notificationGateway })
        }
    }
    func testMissingPrivateFileAfterReferenceRetentionCannotInvokeTheFactory() throws {
        let f = try fixture(), directory = try directory(f); defer { directory.close() }; let creations = Creations()
        let state = try prepare(f, directory: directory, creations: creations)
        try FileManager.default.removeItem(atPath: directory.path + "/gateway-material.cbor")
        XCTAssertThrowsError(try prepare(f, directory: directory, creations: creations, expected: state)) {
            XCTAssertEqual($0 as? GatewayPreparationError, .missingMaterial)
        }
        XCTAssertEqual(creations.count, 1); XCTAssertEqual(try f.machine.gatewayPreparation(accountID: f.account.accountID), state)
    }
    func testStaleExpectedStateAndChangedScopeCannotCreateMaterial() throws {
        let f = try fixture(), directory = try directory(f); defer { directory.close() }; let creations = Creations()
        let empty = GatewayPreparationState(reference: nil)
        let state = try prepare(f, directory: directory, creations: creations)
        XCTAssertThrowsError(try prepare(f, directory: directory, creations: creations, expected: empty)) {
            XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
        }
        XCTAssertThrowsError(try prepare(f, directory: directory, creations: creations, verify: { throw Interrupted() }))
        XCTAssertEqual(creations.count, 1); XCTAssertEqual(try f.machine.gatewayPreparation(accountID: f.account.accountID), state)
    }
    func testNativeControllerRefusesOrdinaryIdentityBeforeProtectedOperations() throws {
        let f = try fixture()
        XCTAssertThrowsError(try GatewayMaterialPreparationController.prepare(machine: f.machine, account: f.account,
            expected: .init(reference: nil), provider: provider(), senderID: "123", packageName: "dev.remozio.android",
            fileWakeCustodyAccepted: true, verifyCurrent: { XCTFail("No native access") })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
