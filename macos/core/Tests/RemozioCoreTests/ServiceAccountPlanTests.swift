import CryptoKit
import Foundation
import Darwin
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class ServiceAccountPlanTests: XCTestCase {
    private let mac = Data(repeating: 1, count: 16), accountID = Data(repeating: 2, count: 16)
    private let owner: UInt32 = 501
    private let directoryID = UUID()
    private func account(prepared: Bool = true) throws -> AccountPreparationIntent {
        let limits = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(mac), 2: .bytes(accountID), 3: .bytes(Data(repeating: 3, count: 16)),
            4: .unsigned(1), 5: .unsigned(AuditEpochCause.initial.rawValue), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 3)
        let code = try AuthorityCodePolicy(entries: [.init(role: .authority, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.authority",
            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 4, count: 20), active: true)])
        let initial = AuthorityJournalInitialization(descriptor: descriptor, codePolicy: code,
            capabilities: .init(contracts: [contract: []]), allowedContracts: [contract], installCommandReplay: true)
        let policy = try CommandElevationPolicy(macID: mac, accountID: accountID, callerUID: owner, allowedTargetUIDs: [0],
            independentPolicyDisclosureAccepted: true)
        // Declared fixture state only. This does not establish hardware or completed native storage.
        return try .init(setupID: Data(repeating: 5, count: 16), revision: Data(repeating: 6, count: 16), macID: mac,
            installationID: Data(repeating: 7, count: 16), releaseDigest: Data(repeating: 8, count: 32), accountID: accountID,
            ownerUID: owner, directoryID: directoryID, policyBytes: policy.canonicalBytes, initializationBytes: initial.initializationBytes,
            authorityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation, storagePrepared: prepared)
    }
    private func claims(account: Data? = nil) throws -> [ServiceAccountClaim] {
        try [.init(accountID: account ?? accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
             .init(accountID: account ?? accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())]
    }
    private func plan(_ account: AccountPreparationIntent, _ claims: [ServiceAccountClaim]? = nil) throws -> ServiceAccountPlan {
        try .init(account: account, planID: Data(repeating: 9, count: 16), claims: claims ?? self.claims(account: account.accountID))
    }
    func testFrozenPlanRoundTripsAndKeepsIdentityClaimsDistinct() throws {
        let account = try account(), plan = try plan(account)
        let decoded = try ServiceAccountPlan.decode(plan.encoded)
        XCTAssertEqual(decoded, plan); XCTAssertNoThrow(try decoded.validate(account: account))
        XCTAssertEqual(plan.claims.map(\.role), [.transport, .gateway])
        XCTAssertEqual(Set(plan.claims.map(\.number)).count, 2)
        XCTAssertEqual(Set(plan.claims.flatMap { [$0.userID, $0.groupID] }).count, 4)
        XCTAssertLessThan(try plan.encoded.count, 1024)
    }
    func testNamesAreStableAndBoundToTheAccountAndRole() throws {
        let first = try claims(), repeated = try claims(), other = try claims(account: Data(repeating: 10, count: 16))
        XCTAssertEqual(first.map(\.name), repeated.map(\.name))
        XCTAssertNotEqual(first[0].name, first[1].name); XCTAssertNotEqual(first[0].name, other[0].name)
        for claim in first {
            XCTAssertEqual(claim.name.utf8.count, 31)
            XCTAssertTrue(claim.name.utf8.allSatisfy { (48...57).contains($0) || (97...122).contains($0) || $0 == 95 })
        }
    }
    func testUnpreparedAccountCannotCreateAPlan() throws {
        XCTAssertThrowsError(try plan(account(prepared: false))) {
            XCTAssertEqual($0 as? ServiceAccountProvisioningError, .incomplete)
        }
    }
    func testRoleDuplicatesSharedUIDsAndInteractiveOwnerUIDAreRejected() throws {
        let account = try account(), originals = try claims()
        let transport = originals[0], gateway = originals[1]
        let duplicateRole = try ServiceAccountClaim(accountID: accountID, role: .transport, number: gateway.number, userID: UUID(), groupID: UUID())
        let sharedUID = try ServiceAccountClaim(accountID: accountID, role: .gateway, number: transport.number, userID: UUID(), groupID: UUID())
        let ownerUID = try ServiceAccountClaim(accountID: accountID, role: .gateway, number: owner, userID: UUID(), groupID: UUID())
        for values in [[transport], [transport, duplicateRole], [transport, sharedUID], [transport, ownerUID], originals + originals] {
            XCTAssertThrowsError(try plan(account, values)) { XCTAssertEqual($0 as? ServiceAccountProvisioningError, .invalidPlan) }
        }
    }
    func testCrossAccountAndSharedOrInteractiveDirectoryUUIDsAreRejected() throws {
        let account = try account(), originals = try claims(), transport = originals[0]
        let foreign = try ServiceAccountClaim(accountID: Data(repeating: 11, count: 16), role: .gateway, number: 20001, userID: UUID(), groupID: UUID())
        let shared = try ServiceAccountClaim(accountID: accountID, role: .gateway, number: 20001, userID: transport.groupID, groupID: UUID())
        let ownerRecord = try ServiceAccountClaim(accountID: accountID, role: .gateway, number: 20001, userID: directoryID, groupID: UUID())
        for claim in [foreign, shared, ownerRecord] { XCTAssertThrowsError(try plan(account, [transport, claim])) }
    }
    func testInvalidNumericClaimsAndEqualUserGroupUUIDsAreRejected() {
        for number in [UInt32(0), 80, UInt32.max] {
            XCTAssertThrowsError(try ServiceAccountClaim(accountID: accountID, role: .transport, number: number, userID: UUID(), groupID: UUID()))
        }
        let id = UUID()
        XCTAssertThrowsError(try ServiceAccountClaim(accountID: accountID, role: .transport, number: 20000, userID: id, groupID: id))
    }
    func testScopeValidationRefusesChangedReleaseInstallationOwnerAndKey() throws {
        let account = try account(), plan = try plan(account)
        guard case .map(let fields) = try DeterministicCBOR.decode(plan.encoded, limits: ServiceAccountPlan.limits) else { return XCTFail() }
        let changes: [(UInt64, CBORValue)] = [(1, .bytes(Data(repeating: 12, count: 16))), (2, .bytes(Data(repeating: 12, count: 16))),
            (3, .bytes(Data(repeating: 12, count: 16))), (4, .bytes(Data(repeating: 12, count: 16))),
            (5, .bytes(Data(repeating: 12, count: 32))), (6, .unsigned(502)),
            (7, .bytes(ServiceAccountPlan.bytes(UUID()))), (8, .bytes(P256.Signing.PrivateKey().publicKey.x963Representation))]
        for (key, value) in changes {
            var changed = fields; changed[key] = value
            let decoded = try ServiceAccountPlan.decode(DeterministicCBOR.encode(.map(changed), limits: ServiceAccountPlan.limits))
            XCTAssertThrowsError(try decoded.validate(account: account)) { XCTAssertEqual($0 as? ServiceAccountProvisioningError, .changedScope) }
        }
    }
    func testCodecRejectsUnknownVersionsFieldsMalformedUUIDsAndReorderedClaims() throws {
        let value = try plan(account())
        guard case .map(let fields) = try DeterministicCBOR.decode(value.encoded, limits: ServiceAccountPlan.limits),
              case .array(let rows) = fields[10] else { return XCTFail() }
        for (key, changed): (UInt64, CBORValue) in [(0, .unsigned(2)), (11, .null), (7, .bytes(Data())),
            (10, .array(rows.reversed())), (10, .array([rows[0], rows[0]])), (6, .unsigned(UInt64(UInt32.max)))] {
            var copy = fields; copy[key] = changed
            XCTAssertThrowsError(try ServiceAccountPlan.decode(DeterministicCBOR.encode(.map(copy), limits: ServiceAccountPlan.limits)))
        }
    }
    private struct Interrupted: Error {}
    private func storageFixture(_ body: (AccountPreparationFixture, AccountPreparationIntent, PreparationIntentStore, ServiceAccountPlanStorage) throws -> Void) throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner SQLite fixture") }
        let fixture = try AccountPreparationFixture(), machine = try fixture.open(initialize: true)
        defer { try? machine.close() }
        let account = try fixture.resume(machine, fixture.begin(machine))
        try body(fixture, account, machine, .init(machine: machine, account: account))
    }
    func testExplicitReservationUpgradesStorageAndCompletionPreservesThePlan() throws {
        try storageFixture { fixture, account, machine, storage in
            XCTAssertEqual(try fixture.sql("PRAGMA user_version"), 4)
            XCTAssertEqual(try storage.load(), .init(plan: nil, complete: false))
            XCTAssertTrue(try machine.reservedServiceAccountNumbers().isEmpty)
            XCTAssertEqual(try fixture.sql("PRAGMA user_version"), 4)
            let value = try plan(account)
            try storage.retain(value, verify: {})
            XCTAssertEqual(try fixture.sql("PRAGMA user_version"), 5)
            XCTAssertEqual(try storage.load(), .init(plan: value, complete: false))
            XCTAssertEqual(try machine.reservedServiceAccountNumbers(), [20000, 20001])
            try storage.complete(value, verify: {})
            try storage.retain(value, verify: {}); try storage.complete(value, verify: {})
            XCTAssertEqual(try storage.load(), .init(plan: value, complete: true))
            XCTAssertEqual(try fixture.sql("SELECT COUNT(*) FROM service_accounts_v1"), 1)
            XCTAssertEqual(try machine.reservedServiceAccountNumbers(), [20000, 20001])
        }
    }
    func testLostCommitAcknowledgmentsKeepClaimsAndCompletionOnReopen() throws {
        for completion in [false, true] {
            try storageFixture { fixture, account, original, initial in
                let value = try plan(account)
                if completion { try initial.retain(value, verify: {}) }
                try original.close()
                var armed = false
                let writer = try fixture.open(hook: { if armed { throw Interrupted() } })
                let storage = try ServiceAccountPlanStorage(machine: writer, account: account)
                armed = true
                if completion { XCTAssertThrowsError(try storage.complete(value, verify: {})) }
                else { XCTAssertThrowsError(try storage.retain(value, verify: {})) }
                XCTAssertThrowsError(try storage.load())
                try writer.close()
                let restored = try fixture.open(); defer { try? restored.close() }
                let reopened = try ServiceAccountPlanStorage(machine: restored, account: account)
                XCTAssertEqual(try reopened.load(), .init(plan: value, complete: completion))
                try reopened.retain(value, verify: {})
                if completion { try reopened.complete(value, verify: {}) }
                XCTAssertEqual(try reopened.load(), .init(plan: value, complete: completion))
            }
        }
    }
    func testScopeFailureOrDifferentClaimsCannotReplaceTheReservation() throws {
        try storageFixture { _, account, _, storage in
            let value = try plan(account), other = try plan(account)
            XCTAssertThrowsError(try storage.retain(value, verify: { throw Interrupted() }))
            XCTAssertNil(try storage.load().plan)
            try storage.retain(value, verify: {})
            XCTAssertThrowsError(try storage.retain(other, verify: {}))
            XCTAssertThrowsError(try storage.complete(other, verify: {}))
            XCTAssertThrowsError(try storage.complete(value, verify: { throw Interrupted() }))
            XCTAssertEqual(try storage.load(), .init(plan: value, complete: false))
        }
    }
    func testCompletionCannotCreateAnUnreservedPlan() throws {
        try storageFixture { fixture, account, _, storage in
            XCTAssertThrowsError(try storage.complete(plan(account), verify: {}))
            XCTAssertEqual(try fixture.sql("PRAGMA user_version"), 4)
            XCTAssertEqual(try storage.load(), .init(plan: nil, complete: false))
        }
    }
    func testAnotherAccountCannotReserveEitherNumberInEitherRole() throws {
        try storageFixture { fixture, account, machine, storage in
            let first = try plan(account)
            try storage.retain(first, verify: {})
            let other = LocalAccountIdentity(uid: account.ownerUID + 1, primaryGroupID: getgid(), directoryID: UUID())
            let second = try fixture.resume(machine, fixture.begin(machine, identity: other))
            let secondStorage = try ServiceAccountPlanStorage(machine: machine, account: second)
            for numbers: [UInt32] in [[20000, 20002], [20002, 20000], [20001, 20002], [20002, 20001]] {
                let claims = try zip(ServiceAccountPlan.roles, numbers).map { role, number in
                    try ServiceAccountClaim(accountID: second.accountID, role: role, number: number, userID: UUID(), groupID: UUID())
                }
                XCTAssertThrowsError(try secondStorage.retain(plan(second, claims), verify: {})) {
                    XCTAssertEqual($0 as? ServiceAccountProvisioningError, .conflictingRecord)
                }
                XCTAssertNil(try secondStorage.load().plan)
            }
            let unused = try zip(ServiceAccountPlan.roles, [UInt32(20002), 20003]).map { role, number in
                try ServiceAccountClaim(accountID: second.accountID, role: role, number: number, userID: UUID(), groupID: UUID())
            }
            try secondStorage.retain(plan(second, unused), verify: {})
            XCTAssertEqual(try machine.reservedServiceAccountNumbers(), [20000, 20001, 20002, 20003])
            XCTAssertEqual(try storage.load().plan, first)
        }
    }
    func testMalformedPlanOrMismatchedNumericColumnsRetireTheConnection() throws {
        for mutation in ["UPDATE service_accounts_v1 SET record=x'00'", "UPDATE service_accounts_v1 SET transport=20002"] {
            try storageFixture { fixture, account, _, storage in
                try storage.retain(plan(account), verify: {})
                _ = try fixture.sql(mutation)
                XCTAssertThrowsError(try storage.load()) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
                XCTAssertThrowsError(try storage.load()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
                XCTAssertEqual(try fixture.sql("SELECT COUNT(*) FROM service_accounts_v1"), 1)
            }
        }
    }
    func testUnpreparedOrUnretainedAccountCannotOpenServiceStorage() throws {
        try storageFixture { _, _, machine, _ in
            XCTAssertThrowsError(try ServiceAccountPlanStorage(machine: machine, account: account(prepared: false)))
            XCTAssertThrowsError(try ServiceAccountPlanStorage(machine: machine, account: account()))
        }
    }
    func testNativeStoreRequiresRootBeforeProtectedAccountAccess() throws {
        try storageFixture { _, account, machine, _ in
            XCTAssertThrowsError(try ServiceAccountPlanStorage.open(machine: machine, account: account)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
    }
    // Logical directory state only. SQLite persistence above is real; these records do not prove native OD creation or process isolation.
    private typealias Directory = ServiceAccountDirectoryFixture
    private func resume(_ account: AccountPreparationIntent, _ value: ServiceAccountPlan, _ storage: ServiceAccountPlanStorage,
                        _ directory: Directory, verify: () throws -> Void = {},
                        makePlan: (() throws -> ServiceAccountPlan)? = nil,
                        stage: (ServiceAccountPreparation.Stage) throws -> Void = { _ in }) throws -> ServiceAccountPlan {
        try ServiceAccountPreparation.resume(account: account, storage: storage, directory: directory,
            makePlan: makePlan ?? { value }, verifyCurrent: verify, didStage: stage)
    }
    func testControllerRetainsClaimsBeforeDirectoryWritesAndNeverRepeatsCompletedCreation() throws {
        try storageFixture { _, account, _, storage in
            let value = try plan(account), directory = Directory()
            XCTAssertEqual(try resume(account, value, storage, directory, stage: { stage in
                if case .planRetained = stage { XCTAssertTrue(directory.writes.isEmpty); XCTAssertEqual(try storage.load().plan, value) }
            }), value)
            XCTAssertEqual(directory.writes, ["group-4", "user-4", "group-6", "user-6"])
            XCTAssertEqual(try storage.load(), .init(plan: value, complete: true))
            XCTAssertEqual(try resume(account, value, storage, directory, makePlan: { XCTFail("Keep the retained plan"); throw Interrupted() }), value)
            XCTAssertEqual(directory.writes.count, 4)
        }
    }
    func testEachControllerInterruptionKeepsClaimsAndResumesWithoutDuplicateCreation() throws {
        let stages: [ServiceAccountPreparation.Stage] = [.planRetained, .groupCreated(.transport), .userCreated(.transport),
            .validated(.transport), .groupCreated(.gateway), .userCreated(.gateway), .validated(.gateway), .completed]
        for interrupted in stages {
            try storageFixture { _, account, _, storage in
                let value = try plan(account), directory = Directory()
                XCTAssertThrowsError(try resume(account, value, storage, directory, stage: { if $0 == interrupted { throw Interrupted() } }))
                XCTAssertEqual(try storage.load().plan, value)
                XCTAssertEqual(try resume(account, value, storage, directory, makePlan: { XCTFail(); throw Interrupted() }), value)
                XCTAssertEqual(directory.writes, ["group-4", "user-4", "group-6", "user-6"])
            }
        }
    }
    func testUnknownDirectoryWriteResultsAreReconciledInsteadOfReplayed() throws {
        for operation in ["group-4", "user-4", "group-6", "user-6"] {
            try storageFixture { _, account, _, storage in
                let value = try plan(account), directory = Directory()
                directory.lostWrite = operation
                XCTAssertThrowsError(try resume(account, value, storage, directory))
                XCTAssertFalse(try storage.load().complete)
                _ = try resume(account, value, storage, directory)
                XCTAssertEqual(directory.writes, ["group-4", "user-4", "group-6", "user-6"])
            }
        }
    }
    func testMissingPlanCannotAdoptExistingNamesEvenWithOtherwiseMatchingClaims() throws {
        try storageFixture { _, account, _, storage in
            let value = try plan(account), directory = Directory(), claim = value.claims[0]
            directory.groups = [.init(number: claim.number, id: claim.groupID, names: [claim.name])]
            XCTAssertThrowsError(try resume(account, value, storage, directory, makePlan: { XCTFail(); throw Interrupted() }))
            XCTAssertNil(try storage.load().plan); XCTAssertTrue(directory.writes.isEmpty)
        }
    }
    func testConflictInTheSecondRolePreventsAllDirectoryWrites() throws {
        try storageFixture { _, account, _, storage in
            let value = try plan(account), directory = Directory(), claim = value.claims[1]
            try storage.retain(value, verify: {})
            directory.users = [.init(number: claim.number, id: UUID(), names: ["foreign"])]
            XCTAssertThrowsError(try resume(account, value, storage, directory))
            XCTAssertTrue(directory.writes.isEmpty); XCTAssertFalse(try storage.load().complete)
        }
    }
    func testCompletedPreparationCannotRecreateMissingUsersOrGroups() throws {
        for removeGroup in [false, true] {
            try storageFixture { _, account, _, storage in
                let value = try plan(account), directory = Directory()
                _ = try resume(account, value, storage, directory)
                let writes = directory.writes
                if removeGroup { directory.groups.removeAll() } else { directory.users.removeAll() }
                XCTAssertThrowsError(try resume(account, value, storage, directory))
                XCTAssertEqual(directory.writes, writes); XCTAssertTrue(try storage.load().complete)
            }
        }
    }
    func testLateCompletionObservationPreventsRecreationBeforeTheFirstWrite() throws {
        try storageFixture { _, account, _, storage in
            let value = try plan(account), directory = Directory()
            try storage.retain(value, verify: {})
            var checks = 0
            XCTAssertThrowsError(try resume(account, value, storage, directory, verify: {
                checks += 1
                if checks == 2 { try storage.complete(value, verify: {}) }
            }))
            XCTAssertTrue(try storage.load().complete); XCTAssertTrue(directory.writes.isEmpty)
        }
    }
    func testAccountOrDirectoryPolicyFailureDoesNotPublishCompletion() throws {
        try storageFixture { _, account, _, storage in
            let value = try plan(account), directory = Directory()
            XCTAssertThrowsError(try resume(account, value, storage, directory, verify: { throw Interrupted() }))
            XCTAssertNil(try storage.load().plan); XCTAssertTrue(directory.writes.isEmpty)
            directory.invalidUser = .gateway
            XCTAssertThrowsError(try resume(account, value, storage, directory))
            XCTAssertFalse(try storage.load().complete)
            let writes = directory.writes
            directory.invalidUser = nil
            _ = try resume(account, value, storage, directory)
            XCTAssertEqual(directory.writes, writes)
        }
    }
    func testDescriptionsDoNotExposeClaimsOrIdentityPins() throws {
        let plan = try plan(account())
        XCTAssertEqual(plan.description, "ServiceAccountPlan(redacted)")
        XCTAssertEqual(plan.claims[0].description, "ServiceAccountClaim(redacted)")
    }
}
