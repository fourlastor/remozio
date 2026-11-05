import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class MachineUpdateReplacementRecordTests: XCTestCase {
    private final class Fixture {
        let data: UpdateCandidateStorageFixture
        let installed: ReleaseDestinationLease
        let inventory: InstallationInventory
        let candidate: UpdateSchedulingCandidateRecord
        let admission: UpdateAdmissionRegistrationRecord
        let pending: MachineUpdateActivationRecord
        let started: MachineUpdateActivationRecord
        let previous: PreparationFileIdentity
        init() throws {
            data = try .init()
            let parent = data.f.f.root.appendingPathComponent("InstalledReplacementRecord")
            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
            XCTAssertEqual(chmod(parent.path, 0o755), 0)
            let app = parent.appendingPathComponent("Remozio.app")
            try FileManager.default.createDirectory(at: app, withIntermediateDirectories: false)
            XCTAssertEqual(chmod(app.path, 0o755), 0)
            installed = try .init(anchor: data.f.f.root.path, relativeDirectory: "InstalledReplacementRecord", owner: getuid())
            let old = try XCTUnwrap(data.store.inventory())
            inventory = try .init(macID: old.macID, installationID: old.installationID, revision: old.revision,
                bundlePath: app.path, releaseDigest: old.releaseDigest, accounts: old.accounts, services: old.services)
            candidate = try data.select(data.copy())
            previous = try installed.preparationCopyIdentity(name: "Remozio.app")
            admission = try .init(macID: inventory.macID, installationID: inventory.installationID,
                machine: .init(device: previous.device, inode: 1),
                accounts: [.init(accountID: data.account, identity: .init(device: previous.device, inode: 2))], designatedOwner: nil)
            pending = try .init(candidate: candidate, inventory: inventory, admission: admission)
            started = try pending.starting(policyPreflightDigest: Data(repeating: 7, count: 32))
        }
        deinit { installed.close() }
        func record(activation: MachineUpdateActivationRecord? = nil, inventory: InstallationInventory? = nil,
            candidate: UpdateSchedulingCandidateRecord? = nil, previous: PreparationFileIdentity? = nil) throws -> MachineUpdateReplacementRecord {
            try .init(activation: activation ?? started, inventory: inventory ?? self.inventory,
                candidate: candidate ?? self.candidate, policy: data.policy, installed: installed,
                prepared: data.destination, previousIdentity: previous ?? self.previous)
        }
        func changedCandidate(generation: UInt64? = nil, selected: Bool = true) throws -> UpdateSchedulingCandidateRecord {
            try .init(macID: candidate.macID, installationID: candidate.installationID,
                inventoryRevision: candidate.inventoryRevision, preparation: candidate.preparation,
                generation: generation ?? candidate.generation, revision: UUID(), selected: selected)
        }
        func changedInventory() throws -> InstallationInventory {
            try .init(macID: inventory.macID, installationID: inventory.installationID, revision: inventory.revision,
                bundlePath: inventory.bundlePath, releaseDigest: Data(repeating: 90, count: 32),
                accounts: inventory.accounts, services: inventory.services)
        }
    }
    private func object(_ record: MachineUpdateReplacementRecord) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: record.encoded) as? [String: Any])
    }
    private func bytes(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    func testRecordBindsBothOwnedParentsAndTheExactActivationOperands() throws {
        let f = try Fixture(), value = try f.record()
        XCTAssertEqual(value.phase, .prepared)
        XCTAssertEqual(value.activationAttempt, f.started.attemptID)
        XCTAssertEqual(value.candidateDigest, f.started.candidateDigest)
        XCTAssertEqual(value.inventoryDigest, f.started.inventoryDigest)
        XCTAssertEqual(value.admissionDigest, f.started.admissionDigest)
        XCTAssertEqual(value.policyDigest, try MachineUpdateActivationRecord.digest(f.data.policy.bytes))
        XCTAssertEqual(value.previousIdentity, f.previous)
        XCTAssertEqual(value.preparedIdentity, f.candidate.preparation.copyIdentity)
        try value.requireScope(activation: f.started, inventory: f.inventory, candidate: f.candidate)
        try value.requireParents(installed: f.installed, prepared: f.data.destination)
    }
    func testCodecRoundTripsCanonicalBytesWithoutPrintingTheOperands() throws {
        let f = try Fixture(), value = try f.record()
        XCTAssertEqual(try MachineUpdateReplacementRecord.decode(value.encoded), value)
        XCTAssertEqual(try MachineUpdateReplacementRecord.decode(value.encoded).encoded, try value.encoded)
        XCTAssertEqual(value.description, "MachineUpdateReplacementRecord(redacted)")
    }
    func testObservedSwapChangesOnlyItsPhaseAndRevision() throws {
        let f = try Fixture(), before = try f.record(), after = try before.observingSwap()
        XCTAssertEqual(after.phase, .observed)
        XCTAssertNotEqual(after.revision, before.revision)
        var expected = try object(before)
        expected["revision"] = after.revision.uuidString
        expected["phase"] = 2
        XCTAssertEqual(try bytes(expected), try after.encoded)
        XCTAssertThrowsError(try after.observingSwap())
        try after.requireScope(activation: f.started, inventory: f.inventory, candidate: f.candidate)
    }
    func testOnlyTheStartedPhaseCanCreateSwapOperands() throws {
        let f = try Fixture()
        for phase in try [f.pending, f.pending.advancing(to: .cancelled), f.started.advancing(to: .restartChecking)] {
            XCTAssertThrowsError(try f.record(activation: phase)) {
                XCTAssertEqual($0 as? MachineUpdateReplacementError, .wrongPhase)
            }
        }
    }
    func testConstructionRejectsAChangedCandidateRevisionOrGenerationWithTheSameCopy() throws {
        let f = try Fixture()
        for candidate in try [f.changedCandidate(), f.changedCandidate(generation: f.candidate.generation + 1)] {
            XCTAssertEqual(candidate.preparation, f.candidate.preparation)
            XCTAssertThrowsError(try f.record(candidate: candidate))
        }
    }
    func testConstructionRejectsAnUnselectedCandidateAndChangedInventoryContents() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.record(candidate: f.changedCandidate(selected: false)))
        let changed = try f.changedInventory()
        XCTAssertEqual(changed.bundlePath, f.inventory.bundlePath)
        XCTAssertEqual(changed.revision, f.inventory.revision)
        XCTAssertThrowsError(try f.record(inventory: changed))
    }
    func testASecondActivationAttemptCannotReuseTheOperands() throws {
        let f = try Fixture(), record = try f.record()
        let other = try MachineUpdateActivationRecord(candidate: f.candidate, inventory: f.inventory, admission: f.admission)
            .starting(policyPreflightDigest: Data(repeating: 7, count: 32))
        XCTAssertThrowsError(try record.requireScope(activation: other, inventory: f.inventory, candidate: f.candidate)) {
            XCTAssertEqual($0 as? MachineUpdateReplacementError, .changedBinding)
        }
    }
    func testParentValidationRejectsAnotherOwnedDirectory() throws {
        let f = try Fixture(), other = try Fixture(), record = try f.record()
        XCTAssertThrowsError(try record.requireParents(installed: other.installed, prepared: f.data.destination))
        XCTAssertThrowsError(try record.requireParents(installed: f.installed, prepared: other.data.destination))
        try record.requireParents(installed: f.installed, prepared: f.data.destination)
    }
    func testEqualOrCrossDeviceOperandsCannotCreateARecord() throws {
        let f = try Fixture(), prepared = try XCTUnwrap(f.candidate.preparation.copyIdentity)
        XCTAssertThrowsError(try f.record(previous: prepared))
        XCTAssertThrowsError(try f.record(previous: .init(device: prepared.device ^ 1, inode: f.previous.inode)))
    }
    func testCodecRejectsUnsupportedVersionsUnknownPhasesAndMalformedDigests() throws {
        let f = try Fixture(), record = try f.record()
        for change: (String, Any) in [("formatVersion", 2), ("phase", 99), ("candidateDigest", Data(repeating: 1, count: 31).base64EncodedString()),
            ("inventoryDigest", Data().base64EncodedString()), ("policyDigest", Data(repeating: 2, count: 33).base64EncodedString())] {
            var changed = try object(record); changed[change.0] = change.1
            XCTAssertThrowsError(try MachineUpdateReplacementRecord.decode(bytes(changed)))
        }
    }
    func testCodecRejectsRelativeTraversalAndOverlongBundlePaths() throws {
        let f = try Fixture(), record = try f.record()
        for path in ["relative", "/tmp/../bad", "/tmp//bad", "/tmp/./bad", "/" + String(repeating: "a", count: Int(PATH_MAX))] {
            var changed = try object(record); changed["installedParent"] = path
            XCTAssertThrowsError(try MachineUpdateReplacementRecord.decode(bytes(changed)))
        }
        for name in ["Bad", "../Other.app", "Bad/Other.app", String(repeating: "a", count: 256) + ".app"] {
            var changed = try object(record); changed["preparedName"] = name
            XCTAssertThrowsError(try MachineUpdateReplacementRecord.decode(bytes(changed)))
        }
    }
    func testCodecRejectsEmptyAncestryAndReusedFileIdentities() throws {
        let f = try Fixture(), record = try f.record()
        var changed = try object(record); changed["installedAncestry"] = []
        XCTAssertThrowsError(try MachineUpdateReplacementRecord.decode(bytes(changed)))
        changed = try object(record); changed["previousIdentity"] = changed["preparedIdentity"]
        XCTAssertThrowsError(try MachineUpdateReplacementRecord.decode(bytes(changed)))
    }
    func testCodecRejectsUnknownMissingNoncanonicalAndOversizedInputs() throws {
        let f = try Fixture(), record = try f.record()
        var changed = try object(record); changed["unknown"] = 1
        XCTAssertThrowsError(try MachineUpdateReplacementRecord.decode(bytes(changed)))
        changed = try object(record); changed.removeValue(forKey: "admissionDigest")
        XCTAssertThrowsError(try MachineUpdateReplacementRecord.decode(bytes(changed)))
        XCTAssertThrowsError(try MachineUpdateReplacementRecord.decode(record.encoded + Data([0x20])))
        XCTAssertThrowsError(try MachineUpdateReplacementRecord.decode(Data()))
        XCTAssertThrowsError(try MachineUpdateReplacementRecord.decode(Data(repeating: 0, count: MachineUpdateReplacementRecord.maximumBytes + 1)))
    }
    func testValueRequirementsBindBothReadersToTheReplacementSchema() throws {
        let requirements = try MachineUpdateReplacementRecord.requirements
        XCTAssertEqual(requirements.count, 4)
        for role in [AuthorityCodeRole.authority, .setupController] {
            XCTAssertEqual(requirements.first { $0.role == role && $0.name == "authority.installation-preparation" }?.readVersions, [18])
            XCTAssertEqual(requirements.first { $0.role == role && $0.name == MachineUpdateReplacementRecord.formatName }?.readVersions, [1])
        }
    }
}
