import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Synthetic file references test durable bookkeeping. They do not prove installed files, ownership or admission.
final class UpdateAdmissionRegistrationTests: XCTestCase {
    private enum Fault: Error { case injected }
    private typealias Fixture = UpdateCandidateStorageFixture
    private func enable(_ f: Fixture) throws {
        try UpdateAdmissionRegistrationStorage.enableInLease(installedRelease: f.release, policy: f.policy, store: f.store)
    }
    private func record(_ f: Fixture, owner: Data? = nil, machine: PreparationFileIdentity = .init(device: 1, inode: 1),
        accounts: [UpdateAdmissionRegistrationRecord.Account]? = nil) throws -> UpdateAdmissionRegistrationRecord {
        let inventory = try XCTUnwrap(f.store.inventory())
        return try .init(macID: f.mac, installationID: inventory.installationID, machine: machine,
            accounts: accounts ?? [.init(accountID: f.account, identity: .init(device: 1, inode: 2))], designatedOwner: owner)
    }
    @discardableResult
    private func retain(_ f: Fixture, _ value: UpdateAdmissionRegistrationRecord,
        replacing previous: UpdateAdmissionRegistrationRecord? = nil, verify: () throws -> Void = {}) throws -> UpdateAdmissionRegistrationRecord {
        try f.store.retainUpdateAdmissionRegistration(value, replacing: previous,
            runtime: f.store.retainedRuntimeCompatibilityInputs(), verifyFiles: verify)
    }
    func testUpgradeIsExplicitAndPreservesInventoryRuntimeAndSelectedCopy() throws {
        let f = try Fixture(admission: true), selected = try f.select(f.copy()), before = try f.store.retainedRuntimeCompatibilityInputs()
        XCTAssertEqual(before.schemaVersion, 15); XCTAssertNil(try f.store.updateAdmissionRegistration())
        try enable(f)
        let after = try f.store.retainedRuntimeCompatibilityInputs()
        XCTAssertEqual(after.schemaVersion, 16); XCTAssertEqual(after.inventory, before.inventory)
        XCTAssertEqual(after.runtimes, before.runtimes); XCTAssertEqual(after.gateways, before.gateways)
        XCTAssertEqual(try f.store.updateCandidate(), selected); XCTAssertEqual(try f.store.records(), [selected.preparation])
        try enable(f); try f.reopen(); XCTAssertEqual(try f.store.retainedRuntimeCompatibilityInputs(), after)
    }
    func testMissingInstalledReadersAndWrongInstalledReleaseCannotUpgrade() throws {
        for role in [AuthorityCodeRole.authority, .setupController] {
            for missing in ["authority.installation-preparation", UpdateAdmissionRegistrationRecord.formatName, "schema16"] {
                let f = try Fixture(admission: true)
                let old = try f.editedRelease { component in
                    let formats = try component.formats.filter { component.role != role || $0.name != missing }.map { format in
                        if component.role == role, missing == "schema16", format.name == "authority.installation-preparation" {
                            return try ReleaseFormat(name: format.name, readers: format.readers.subtracting([16]),
                                writers: format.writers.subtracting([16]), migrations: format.migrations)
                        }
                        return format
                    }
                    return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                        relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                        teamID: component.teamID, formats: formats)
                }
                XCTAssertThrowsError(try UpdateAdmissionRegistrationStorage.enableInLease(installedRelease: old, policy: f.policy, store: f.store)) {
                    let expected: ReleaseCompatibilityError = missing == "schema16"
                        ? .missingReader(role, "authority.installation-preparation", 16) : .missingFormat(role, missing)
                    XCTAssertEqual($0 as? ReleaseCompatibilityError, expected)
                }
                XCTAssertEqual(try f.store.retainedRuntimeCompatibilityInputs().schemaVersion, 15)
            }
        }
        let f = try Fixture(admission: true)
        XCTAssertThrowsError(try f.store.upgradeUpdateAdmissionStorage(expectedInstalledReleaseDigest: Data(repeating: 99, count: 32)))
        XCTAssertEqual(try f.store.retainedRuntimeCompatibilityInputs().schemaVersion, 15)
    }
    func testSchemaSixteenRequiresRegistrationReadersBeforeAnyReferenceIsStored() throws {
        let f = try Fixture(admission: true); try enable(f)
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.store)
        XCTAssertNil(try f.store.updateAdmissionRegistration())
        for role in [AuthorityCodeRole.authority, .setupController] {
            let registration = try XCTUnwrap(snapshot.requirements.formats.first { $0.role == role && $0.name == UpdateAdmissionRegistrationRecord.formatName })
            XCTAssertEqual(registration.readVersions, [1]); XCTAssertEqual(registration.writeVersions, [1])
            XCTAssertTrue(try XCTUnwrap(snapshot.requirements.formats.first {
                $0.role == role && $0.name == "authority.installation-preparation"
            }).readVersions.contains(16))
        }
    }
    func testExactReferencesSurviveReopenWithoutAnImplicitOwner() throws {
        let f = try Fixture(admission: true); try enable(f); let value = try record(f)
        XCTAssertNil(value.designatedOwner)
        XCTAssertEqual(try retain(f, value), value)
        XCTAssertEqual(try retain(f, value, replacing: value), value)
        try f.reopen(); XCTAssertEqual(try f.store.updateAdmissionRegistration(), value)
        XCTAssertNil(try f.store.updateAdmissionRegistration()?.designatedOwner)
    }
    func testStaleRecordOrCompatibilitySnapshotCannotReachFileVerification() throws {
        let f = try Fixture(admission: true); try enable(f); let first = try record(f), runtime = try f.store.retainedRuntimeCompatibilityInputs()
        try retain(f, first)
        let second = try record(f, owner: f.account)
        XCTAssertThrowsError(try retain(f, second, verify: { XCTFail("Stale writer reached file verification") }))
        XCTAssertThrowsError(try f.store.retainUpdateAdmissionRegistration(second, replacing: first, runtime: runtime,
            verifyFiles: { XCTFail("Stale snapshot reached file verification") }))
        XCTAssertEqual(try f.store.updateAdmissionRegistration(), first)
    }
    func testARegistrationChangeMakesEarlierInputsStaleForSelectionAndReleaseChecks() throws {
        let f = try Fixture(admission: true); try enable(f)
        let copy = try f.copy(), runtime = try f.store.retainedRuntimeCompatibilityInputs()
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.store)
        try retain(f, record(f))
        XCTAssertNotEqual(try f.store.retainedRuntimeCompatibilityInputs(), runtime)
        XCTAssertThrowsError(try f.store.selectUpdateCandidate(preparation: copy, runtime: runtime, replacing: nil)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
        XCTAssertNil(try f.store.updateCandidate())
        XCTAssertThrowsError(try snapshot.requireCurrent(machine: f.store)) {
            XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
        }
        XCTAssertNoThrow(try f.select(copy))
    }
    func testPinnedMachineAccountAndDesignatedOwnerCannotBeReplaced() throws {
        let f = try Fixture(admission: true); try enable(f); let first = try record(f, owner: f.account); try retain(f, first)
        let changedMachine = try record(f, owner: f.account, machine: .init(device: 1, inode: 3))
        let changedAccount = try record(f, owner: f.account, accounts: [.init(accountID: f.account, identity: .init(device: 1, inode: 4))])
        let removedOwner = try record(f)
        for value in [changedMachine, changedAccount, removedOwner] {
            XCTAssertThrowsError(try retain(f, value, replacing: first)) { XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition) }
            XCTAssertEqual(try f.store.updateAdmissionRegistration(), first)
        }
    }
    func testNewAccountReferencesNeedCurrentInventoryAndPreserveAllPinnedReferences() throws {
        let f = try Fixture(admission: true); try enable(f); let first = try record(f); try retain(f, first)
        let secondID = Data(repeating: 92, count: 16), second = UpdateAdmissionRegistrationRecord.Account(accountID: secondID, identity: .init(device: 1, inode: 3))
        let extended = try record(f, owner: secondID, accounts: first.accounts + [second])
        XCTAssertThrowsError(try retain(f, extended, replacing: first))
        let inventory = try XCTUnwrap(f.store.inventory())
        let added = try InstallationAccount(accountID: secondID, ownerUID: inventory.accounts[0].ownerUID + 2000)
        let next = try InstallationInventory(macID: inventory.macID, installationID: inventory.installationID, revision: inventory.revision,
            bundlePath: inventory.bundlePath, releaseDigest: inventory.releaseDigest, accounts: inventory.accounts + [added],
            services: inventory.services, formatVersion: inventory.formatVersion)
        _ = try f.store.writeInventory(next, expectedRevision: inventory.revision)
        XCTAssertEqual(try retain(f, extended, replacing: first), extended)
        let removed = try record(f, owner: secondID, accounts: [second])
        XCTAssertThrowsError(try retain(f, removed, replacing: extended))
        try f.reopen(); XCTAssertEqual(try f.store.updateAdmissionRegistration(), extended)
    }
    func testWrongMachineAndInstallationAreRejectedBeforeFileVerification() throws {
        let f = try Fixture(admission: true); try enable(f); let value = try record(f)
        for candidate in [
            try UpdateAdmissionRegistrationRecord(macID: Data(repeating: 93, count: 16), installationID: value.installationID,
                machine: value.machine, accounts: value.accounts, designatedOwner: nil),
            try UpdateAdmissionRegistrationRecord(macID: f.mac, installationID: Data(repeating: 94, count: 16),
                machine: value.machine, accounts: value.accounts, designatedOwner: nil)
        ] {
            XCTAssertThrowsError(try retain(f, candidate, verify: { XCTFail("Wrong scope reached file verification") }))
        }
        XCTAssertNil(try f.store.updateAdmissionRegistration())
    }
    func testFileVerificationFailureBeforeOrAfterTheWriteRollsBack() throws {
        for failAt in [1, 2] {
            let f = try Fixture(admission: true); try enable(f); let value = try record(f); var checks = 0
            XCTAssertThrowsError(try retain(f, value) { checks += 1; if checks == failAt { throw Fault.injected } })
            XCTAssertEqual(checks, failAt); XCTAssertNil(try f.store.updateAdmissionRegistration())
            XCTAssertEqual(try retain(f, value), value)
        }
    }
    func testFileVerificationCannotReenterOrCloseTheMachineWriter() throws {
        let f = try Fixture(admission: true); try enable(f); let value = try record(f)
        try retain(f, value) {
            XCTAssertThrowsError(try f.store.updateAdmissionRegistration()) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
            XCTAssertThrowsError(try f.store.close()) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
        }
    }
    func testUnknownCommitRetiresTheOwnerAndReopensTheExactDurableReferences() throws {
        let f = try Fixture(admission: true); try enable(f); let value = try record(f)
        try f.reopen(hook: { throw Fault.injected })
        XCTAssertThrowsError(try retain(f, value)); XCTAssertThrowsError(try f.store.updateAdmissionRegistration())
        try f.reopen(); XCTAssertEqual(try f.store.updateAdmissionRegistration(), value)
    }
    func testUnknownMigrationCommitRequiresReopenAndDoesNotChooseAnOwner() throws {
        let f = try Fixture(admission: true); try f.reopen(hook: { throw Fault.injected })
        XCTAssertThrowsError(try enable(f)); XCTAssertThrowsError(try f.store.updateAdmissionRegistration())
        try f.reopen(); XCTAssertEqual(try f.store.retainedRuntimeCompatibilityInputs().schemaVersion, 16)
        XCTAssertNil(try f.store.updateAdmissionRegistration()); try enable(f)
    }
    func testCorruptRevisionRetiresTheStoreWithoutRepair() throws {
        let f = try Fixture(admission: true); try enable(f); let value = try record(f); try retain(f, value)
        try f.sql("UPDATE update_admission_registration_v1 SET revision=zeroblob(16) WHERE id=1")
        XCTAssertThrowsError(try f.store.updateAdmissionRegistration()) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
        XCTAssertThrowsError(try f.store.records())
    }
    func testCodecRejectsUnknownNoncanonicalDuplicateAndUnboundReferences() throws {
        let f = try Fixture(admission: true), value = try record(f), bytes = try value.encoded
        XCTAssertEqual(try UpdateAdmissionRegistrationRecord.decode(bytes), value)
        XCTAssertThrowsError(try UpdateAdmissionRegistrationRecord.decode(bytes + Data(" ".utf8)))
        XCTAssertThrowsError(try UpdateAdmissionRegistrationRecord.decode(Data(repeating: 0, count: 32769)))
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any]); fields["unknown"] = 1
        XCTAssertThrowsError(try UpdateAdmissionRegistrationRecord.decode(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])))
        XCTAssertThrowsError(try record(f, accounts: value.accounts + value.accounts))
        XCTAssertThrowsError(try record(f, machine: value.accounts[0].identity))
        XCTAssertThrowsError(try record(f, owner: Data(repeating: 95, count: 16)))
        XCTAssertEqual(value.description, "UpdateAdmissionRegistrationRecord(redacted)"); XCTAssertEqual(value.debugDescription, value.description)
    }
    func testNativeEntryRefusesAnOrdinaryAccountBeforeStorageChanges() throws {
        XCTAssertNotEqual(getuid(), 0); let f = try Fixture(admission: true)
        XCTAssertThrowsError(try UpdateAdmissionRegistrationStorage.enable(installedRelease: f.release, policy: f.policy, store: f.store)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(try f.store.retainedRuntimeCompatibilityInputs().schemaVersion, 15)
    }
}
