import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import Security
import XCTest
@testable import RemozioCore

final class AccountPreparationTests: XCTestCase {
    private struct Interrupted: Error {}
    private typealias Fixture = AccountPreparationFixture
    private func fixture() throws -> Fixture {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner fixture") }
        return try .init()
    }
    func testReservationCommitsBeforeKeysOrStoresAndDoesNotInventInstalledServices() throws {
        let f = try fixture(), machine = try f.open(initialize: true), inventory = try XCTUnwrap(machine.inventory())
        let intent = try f.begin(machine)
        XCTAssertNil(intent.authorityPublicKey); XCTAssertFalse(intent.storagePrepared)
        XCTAssertEqual(intent.ownerUID, getuid()); XCTAssertEqual(intent.directoryID, f.identity.directoryID)
        XCTAssertEqual(try intent.commandPolicy.allowedTargetUIDs, [0])
        XCTAssertEqual(try machine.inventory(), inventory)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.root.path + "/" + f.directory(intent)))
        try machine.close()
        let restored = try f.open(); defer { try? restored.close() }
        XCTAssertEqual(try restored.accountPreparation(ownerUID: getuid()), intent)
        XCTAssertEqual(try f.sql("PRAGMA user_version"), 4)
    }
    func testReadAndRejectedDisclosureDoNotUpgradeStorage() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        XCTAssertNil(try machine.accountPreparation(ownerUID: getuid()))
        XCTAssertThrowsError(try f.begin(machine, accepted: false)) { XCTAssertEqual($0 as? CommandElevationPolicyError, .disclosureRequired) }
        XCTAssertEqual(try f.sql("PRAGMA user_version"), 2)
        XCTAssertNil(try machine.accountPreparation(ownerUID: getuid()))
    }
    func testRepeatedBeginRestoresTheSameAccountAndEpochWithoutChangingGrants() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let intent = try f.begin(machine), inventory = try XCTUnwrap(machine.inventory())
        let repeated = try machine.beginAccountPreparation(owner: f.identity, allowedTargetUIDs: [0], disclosureAccepted: true,
            expectedInventoryRevision: inventory.revision, makeInitial: { _, _ in XCTFail("No new epoch on retry"); throw Interrupted() })
        XCTAssertEqual(repeated, intent)
        for targets: Set<UInt32> in [[], [0, 123]] { XCTAssertThrowsError(try f.begin(machine, targets: targets)) }
        XCTAssertThrowsError(try f.begin(machine, accepted: false))
        XCTAssertEqual(try machine.accountPreparation(ownerUID: getuid()), intent)
    }
    func testDirectoryReplacementCannotClaimRetainedUIDWhileGroupChangeIsAllowed() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let intent = try f.begin(machine)
        let replacement = LocalAccountIdentity(uid: getuid(), primaryGroupID: getgid(), directoryID: UUID())
        XCTAssertThrowsError(try f.begin(machine, identity: replacement)) { XCTAssertEqual($0 as? LocalAccountLookupError, .ownershipChanged) }
        let groupChanged = LocalAccountIdentity(uid: getuid(), primaryGroupID: 0, directoryID: f.identity.directoryID)
        XCTAssertEqual(try f.begin(machine, identity: groupChanged), intent)
    }
    func testDifferentLocalAccountsHaveIndependentScopeAndGrants() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let first = try f.begin(machine), other = LocalAccountIdentity(uid: getuid() + 1, primaryGroupID: getgid(), directoryID: UUID())
        let second = try f.begin(machine, identity: other, targets: [other.uid])
        XCTAssertNotEqual(first.accountID, second.accountID); XCTAssertNotEqual(first.setupID, second.setupID)
        XCTAssertEqual(try machine.accountPreparation(ownerUID: other.uid), second)
        XCTAssertEqual(try machine.accountPreparation(ownerUID: getuid()), first)
        XCTAssertThrowsError(try first.commandPolicy.authorize(macID: f.mac, accountID: second.accountID, callerUID: other.uid, requestedTargetUID: 0))
        XCTAssertTrue(try XCTUnwrap(machine.inventory()).accounts.isEmpty)
    }
    func testPinningHasCASAndDoesNotReplaceAnEstablishedIdentity() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let intent = try f.begin(machine), pinned = try machine.pinAccountPreparation(expected: intent, publicKey: f.key)
        XCTAssertNotEqual(pinned.revision, intent.revision)
        XCTAssertThrowsError(try machine.pinAccountPreparation(expected: intent, publicKey: f.key)) { XCTAssertEqual($0 as? AccountPreparationError, .staleRevision) }
        XCTAssertThrowsError(try machine.pinAccountPreparation(expected: pinned, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation))
        XCTAssertEqual(try machine.pinAccountPreparation(expected: pinned, publicKey: f.key), pinned)
        XCTAssertThrowsError(try machine.completeAccountPreparation(expected: pinned)) { XCTAssertEqual($0 as? AccountPreparationError, .incomplete) }
    }
    func testUnpinnedOrDifferentInitializationCannotCreateAccountStores() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let intent = try f.begin(machine)
        XCTAssertThrowsError(try f.beginStores(machine, intent))
        let pinned = try machine.pinAccountPreparation(expected: intent, publicKey: f.key)
        let different = try f.initial(mac: f.mac, account: intent.accountID)
        XCTAssertThrowsError(try machine.beginInitialization(initial: different,
            journalPath: f.root.path + "/journal/journal.sqlite", continuityPath: f.root.path + "/continuity/continuity.sqlite",
            expectedInventoryRevision: XCTUnwrap(machine.inventory()).revision))
        let initial = try f.beginStores(machine, pinned)
        XCTAssertEqual(initial.initializationBytes, pinned.initializationBytes)
        XCTAssertNil(initial.checkpoint)
    }
    func testEachControllerInterruptionResumesTheSameIdentityAndStores() throws {
        for interrupted in AccountPreparationController.Stage.allCases {
            let f = try fixture(), machine = try f.open(initialize: true), intent = try f.begin(machine)
            XCTAssertThrowsError(try f.resume(machine, intent, stage: { if $0 == interrupted { throw Interrupted() } }))
            let retained = try XCTUnwrap(machine.accountPreparation(ownerUID: getuid()))
            let priorInitialization = try machine.initialization(accountID: retained.accountID)
            try machine.close()
            let restored = try f.open(); defer { try? restored.close() }
            let result = try f.resume(restored, retained)
            XCTAssertTrue(result.storagePrepared); XCTAssertEqual(result.setupID, intent.setupID); XCTAssertEqual(result.accountID, intent.accountID)
            XCTAssertEqual(result.authorityPublicKey, f.key)
            let finalInitialization = try XCTUnwrap(restored.initialization(accountID: result.accountID))
            XCTAssertTrue(finalInitialization.complete)
            XCTAssertEqual(finalInitialization.initializationBytes, intent.initializationBytes)
            if let priorInitialization { XCTAssertEqual(finalInitialization.setupID, priorInitialization.setupID) }
            XCTAssertTrue(try XCTUnwrap(restored.inventory()).accounts.isEmpty)
            XCTAssertEqual(try restored.pinAccountPreparation(expected: result, publicKey: f.key), result)
        }
    }
    func testCompletedPreparationNeverCreatesKeysOrRepairsMissingStorage() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let result = try f.resume(machine, f.begin(machine))
        let initial = try XCTUnwrap(machine.initialization(accountID: result.accountID))
        try FileManager.default.removeItem(atPath: initial.journalPath)
        XCTAssertEqual(try f.resume(machine, result, provision: { _ in XCTFail("Never recreate completed keys"); throw Interrupted() }), result)
        XCTAssertFalse(FileManager.default.fileExists(atPath: initial.journalPath))
    }
    func testChangedHostBeforeOrAfterKeyProvisioningPreventsFurtherMutation() throws {
        for failAt in [1, 2] {
            let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
            let intent = try f.begin(machine)
            var checks = 0, keys = 0
            XCTAssertThrowsError(try f.resume(machine, intent, verify: { checks += 1; if checks == failAt { throw Interrupted() } },
                provision: { _ in keys += 1; return f.key }))
            XCTAssertEqual(keys, failAt == 1 ? 0 : 1)
            XCTAssertEqual(try machine.accountPreparation(ownerUID: getuid()), intent)
            XCTAssertNil(try machine.initialization(accountID: intent.accountID))
        }
    }
    func testLostAcknowledgmentsRetainTheCommittedReservationPinAndCompletion() throws {
        for phase in 0...2 {
            let f = try fixture(); var armed = false
            let machine = try f.open(initialize: true, hook: { if armed { throw Interrupted() } })
            if phase == 0 {
                armed = true; XCTAssertThrowsError(try f.begin(machine))
            } else {
                let intent = try f.begin(machine)
                if phase == 1 {
                    armed = true; XCTAssertThrowsError(try machine.pinAccountPreparation(expected: intent, publicKey: f.key))
                } else {
                    let pinned = try machine.pinAccountPreparation(expected: intent, publicKey: f.key)
                    _ = try f.resumeStores(machine, f.beginStores(machine, pinned))
                    armed = true; XCTAssertThrowsError(try machine.completeAccountPreparation(expected: pinned))
                }
            }
            try machine.close()
            let restored = try f.open(); defer { try? restored.close() }
            let retained = try XCTUnwrap(restored.accountPreparation(ownerUID: getuid()))
            XCTAssertEqual(retained.authorityPublicKey, phase == 0 ? nil : f.key)
            XCTAssertEqual(retained.storagePrepared, phase == 2)
            XCTAssertEqual(try f.begin(restored), retained)
        }
    }
    func testMalformedRecordRetiresTheConnectionWithoutReset() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        _ = try f.begin(machine)
        _ = try f.sql("UPDATE account_preparation_v1 SET record=x'80'")
        XCTAssertThrowsError(try machine.accountPreparation(ownerUID: getuid())) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
        XCTAssertThrowsError(try machine.inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
        XCTAssertEqual(try f.sql("SELECT COUNT(*) FROM account_preparation_v1"), 1)
    }
    func testCodecRefusesScopeChangesAndInvalidKeys() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let intent = try f.begin(machine), pinned = try machine.pinAccountPreparation(expected: intent, publicKey: f.key)
        XCTAssertEqual(try AccountPreparationIntent.decode(pinned.bytes), pinned)
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (3, .bytes(Data(repeating: 9, count: 16))),
            (6, .bytes(Data(repeating: 9, count: 16))), (7, .unsigned(0)), (11, .bytes(Data(repeating: 4, count: 65)))] {
            guard case .map(var fields) = try DeterministicCBOR.decode(pinned.bytes, limits: f.limits) else { return XCTFail() }
            fields[key] = value
            XCTAssertThrowsError(try AccountPreparationIntent.decode(DeterministicCBOR.encode(.map(fields), limits: f.limits)))
        }
        XCTAssertEqual(pinned.description, "AccountPreparationIntent(redacted)")
    }
    func testOwnerUsesAuthenticatedUIDAndRejectsDirectoryReplacementOnReadAndResume() throws {
        let f = try fixture(), machine = try f.open(initialize: true)
        var current = f.identity, preparations = 0
        let owner = try SetupAccountOwner(machine: machine, expectedReleaseDigest: f.release,
            resume: { _, _ in throw Interrupted() }, accountCodePolicy: f.policy, lookupAccount: { _ in current },
            prepareAccount: { _, _, _ in preparations += 1; throw Interrupted() })
        defer { try? owner.close() }
        XCTAssertNil(try owner.enrollment(callerUID: getuid()))
        let intent = try owner.beginEnrollment(callerUID: getuid(), allowedTargetUIDs: [0], disclosureAccepted: true)
        XCTAssertEqual(try owner.enrollment(callerUID: getuid()), intent)
        XCTAssertThrowsError(try owner.beginEnrollment(callerUID: getuid() + 1, allowedTargetUIDs: [0], disclosureAccepted: true))
        current = LocalAccountIdentity(uid: getuid(), primaryGroupID: getgid(), directoryID: UUID())
        XCTAssertThrowsError(try owner.enrollment(callerUID: getuid())) { XCTAssertEqual($0 as? LocalAccountLookupError, .ownershipChanged) }
        XCTAssertThrowsError(try owner.resumeEnrollment(callerUID: getuid(), setupID: intent.setupID, expectedRevision: intent.revision))
        XCTAssertEqual(preparations, 0)
    }
    func testScopedOwnerReleasesMachineWriterAfterEachEnrollmentOperation() throws {
        let f = try fixture(), first = try f.open(initialize: true)
        try first.close()
        let owner = try SetupAccountOwner(openMachine: { try f.open() }, expectedReleaseDigest: f.release,
            resume: { _, _ in throw Interrupted() }, accountCodePolicy: f.policy, lookupAccount: { _ in f.identity },
            prepareAccount: { machine, expected, verify in try f.resume(machine, expected, verify: verify) })
        defer { try? owner.close() }
        func writerIsFree() throws { let machine = try f.open(); try machine.close() }
        try writerIsFree()
        XCTAssertNil(try owner.enrollment(callerUID: getuid())); try writerIsFree()
        let intent = try owner.beginEnrollment(callerUID: getuid(), allowedTargetUIDs: [0], disclosureAccepted: true)
        try writerIsFree()
        let prepared = try owner.resumeEnrollment(callerUID: getuid(), setupID: intent.setupID, expectedRevision: intent.revision)
        XCTAssertTrue(prepared.storagePrepared); try writerIsFree()
        XCTAssertEqual(try owner.enrollment(callerUID: getuid()), prepared); try writerIsFree()
        XCTAssertThrowsError(try owner.resumeEnrollment(callerUID: getuid(), setupID: intent.setupID, expectedRevision: intent.revision))
        try writerIsFree()
    }
    func testStaleInventoryCannotReserveAnAccountOrUpgradeTheSchema() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        XCTAssertThrowsError(try machine.beginAccountPreparation(owner: f.identity, allowedTargetUIDs: [0], disclosureAccepted: true,
            expectedInventoryRevision: Data(repeating: 0, count: 16), makeInitial: { _, _ in XCTFail(); throw Interrupted() })) {
            XCTAssertEqual($0 as? AccountPreparationError, .staleRevision)
        }
        XCTAssertEqual(try f.sql("PRAGMA user_version"), 2)
        XCTAssertNil(try machine.accountPreparation(ownerUID: getuid()))
    }
    func testPinnedKeyMismatchStopsBeforeStoreInitialization() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let intent = try f.begin(machine), pinned = try machine.pinAccountPreparation(expected: intent, publicKey: f.key)
        XCTAssertThrowsError(try f.resume(machine, pinned, provision: { _ in P256.Signing.PrivateKey().publicKey.x963Representation })) {
            XCTAssertEqual($0 as? AccountPreparationError, .conflict)
        }
        XCTAssertNil(try machine.initialization(accountID: intent.accountID))
        XCTAssertEqual(try machine.accountPreparation(ownerUID: getuid()), pinned)
    }
    func testReleaseChangeRetainsProgressButPreventsResumingIt() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let intent = try f.begin(machine), inventory = try XCTUnwrap(machine.inventory())
        _ = try machine.writeInventory(.init(macID: inventory.macID, installationID: inventory.installationID,
            revision: inventory.revision, bundlePath: inventory.bundlePath, releaseDigest: Data(repeating: 9, count: 32),
            accounts: inventory.accounts, services: inventory.services, formatVersion: inventory.formatVersion), expectedRevision: inventory.revision)
        XCTAssertThrowsError(try f.resume(machine, intent, provision: { _ in XCTFail(); throw Interrupted() })) {
            XCTAssertEqual($0 as? AccountPreparationError, .conflict)
        }
        XCTAssertEqual(try machine.accountPreparation(ownerUID: getuid()), intent)
    }
    private final class LocalDriver: SetupClientDriver, @unchecked Sendable {
        let endpoint: AdministrativeSetupXPCEndpoint
        init(_ endpoint: AdministrativeSetupXPCEndpoint) { self.endpoint = endpoint }
        func start(closed: @escaping @Sendable () -> Void) { }
        func close() { endpoint.close() }
        func invoke(_ call: SetupClientCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            switch call {
            case .enrollmentHello: endpoint.enrollmentHello { reply(.version($0)) }
            case .enrollmentProgress: endpoint.accountEnrollmentProgress { reply(.progress($0)) }
            case .beginEnrollment(let bytes, let form): endpoint.beginAccountEnrollment(bytes, authorization: form) { reply(.progress($0)) }
            case .resumeEnrollment(let expected, let form):
                endpoint.resumeAccountEnrollment(expected.setupID, expectedRevision: expected.revision, authorization: form) { reply(.progress($0)) }
            default: reply(.failed)
            }
        }
    }
    private final class Reply<Value>: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: Value?
        func put(_ value: Value) { lock.withLock { stored = value } }
        var value: Value? { lock.withLock { stored } }
    }
    private func setupOwner(_ f: Fixture, machine: PreparationIntentStore) throws -> SetupAccountOwner {
        try .init(machine: machine, expectedReleaseDigest: f.release,
            resume: { _, _ in throw Interrupted() }, accountCodePolicy: f.policy, lookupAccount: { uid in
                guard uid == f.identity.uid else { throw AdministrativeSetupError.wrongAccount }; return f.identity
            }, prepareAccount: { machine, expected, verify in try f.resume(machine, expected, verify: verify) })
    }
    func testVersionTwoClientAndEndpointPrepareActualScopedStoresWithoutClaimingRuntimeReadiness() async throws {
        let f = try fixture(), machine = try f.open(initialize: true), owner = try setupOwner(f, machine: machine)
        defer { try? owner.close() }
        var authorizations = 0
        let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() },
            authorize: { _ in authorizations += 1 }, invalidate: {})
        let channel = AdministrativeSetupChannel(driver: LocalDriver(endpoint))
        try await channel.start()
        let empty = try await channel.enrollmentProgress()
        XCTAssertNil(empty); XCTAssertEqual(authorizations, 0)
        let request = try AccountEnrollmentRequest(allowedTargetUIDs: [0], independentPolicyDisclosureAccepted: true)
        let form = Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)
        let saved = try await channel.beginEnrollment(request, authorization: form)
        XCTAssertFalse(saved.keyPrepared); XCTAssertFalse(saved.storagePrepared)
        let prepared = try await channel.resumeEnrollment(saved, authorization: form)
        XCTAssertTrue(prepared.keyPrepared); XCTAssertTrue(prepared.storagePrepared)
        XCTAssertEqual(prepared.allowedTargetUIDs, [0]); XCTAssertEqual(prepared.ownerUID, getuid())
        XCTAssertEqual(authorizations, 2)
        let read = try await channel.enrollmentProgress()
        XCTAssertEqual(read, prepared)
        XCTAssertTrue(try XCTUnwrap(machine.inventory()).accounts.isEmpty)
        XCTAssertNil(try prepared.bytes.range(of: Data(f.root.path.utf8)))
        XCTAssertNil(try prepared.bytes.range(of: Data(f.identity.directoryID.uuidString.utf8)))
        await channel.close()
    }
    func testOldHelloAndNoHelloCannotImportEnrollmentAuthorization() throws {
        for versionOne in [false, true] {
            let f = try fixture(), machine = try f.open(initialize: true), owner = try setupOwner(f, machine: machine)
            defer { try? owner.close() }
            var authorizations = 0
            let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() },
                authorize: { _ in authorizations += 1 }, invalidate: {})
            if versionOne { let reply = Reply<UInt64>(); endpoint.hello { reply.put($0) }; XCTAssertEqual(reply.value, 1) }
            let request = try AccountEnrollmentRequest(allowedTargetUIDs: [0], independentPolicyDisclosureAccepted: true)
            let reply = Reply<Data?>()
            endpoint.beginAccountEnrollment(try request.bytes,
                authorization: Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)) { reply.put($0) }
            XCTAssertNil(reply.value ?? nil); XCTAssertEqual(authorizations, 0)
            XCTAssertNil(try machine.accountPreparation(ownerUID: getuid()))
        }
    }
    func testRejectedNativeAuthorizationCannotReserveAnAccount() throws {
        let f = try fixture(), machine = try f.open(initialize: true), owner = try setupOwner(f, machine: machine)
        defer { try? owner.close() }
        let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() },
            authorize: { try SetupAdministratorNative.validate(externalForm: $0) }, invalidate: {})
        let hello = Reply<UInt64>(); endpoint.enrollmentHello { hello.put($0) }; XCTAssertEqual(hello.value, 2)
        let request = try AccountEnrollmentRequest(allowedTargetUIDs: [0], independentPolicyDisclosureAccepted: true), reply = Reply<Data?>()
        endpoint.beginAccountEnrollment(try request.bytes,
            authorization: Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)) { reply.put($0) }
        XCTAssertNil(reply.value ?? nil)
        XCTAssertNil(try machine.accountPreparation(ownerUID: getuid()))
        XCTAssertEqual(try f.sql("PRAGMA user_version"), 2)
    }
    func testRequestCodecRefusesImplicitDisclosureDuplicateTargetsAndUnknownVersions() throws {
        let f = try fixture()
        for fields: [UInt64: CBORValue] in [
            [0: .unsigned(1), 1: .array([.unsigned(0)]), 2: .boolean(false)],
            [0: .unsigned(1), 1: .array([.unsigned(0), .unsigned(0)]), 2: .boolean(true)],
            [0: .unsigned(1), 1: .array([.unsigned(UInt64(UInt32.max))]), 2: .boolean(true)],
            [0: .unsigned(2), 1: .array([.unsigned(0)]), 2: .boolean(true)]] {
            XCTAssertThrowsError(try AccountEnrollmentRequest.decode(DeterministicCBOR.encode(.map(fields), limits: f.limits)))
        }
        let request = try AccountEnrollmentRequest(allowedTargetUIDs: [0, getuid()], independentPolicyDisclosureAccepted: true)
        XCTAssertEqual(try AccountEnrollmentRequest.decode(request.bytes), request)
    }
    func testNativeControllerRefusesOrdinaryUserBeforeProtectedOperations() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let intent = try f.begin(machine)
        XCTAssertThrowsError(try AccountPreparationController.resume(machine: machine, expected: intent, verifyCurrent: { XCTFail() })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(try machine.accountPreparation(ownerUID: getuid()), intent)
    }
}
