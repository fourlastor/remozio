import Foundation
import XCTest
@testable import RemozioCore

final class MachineUpdateActivationRecordTests: XCTestCase {
    private struct Scope {
        let candidate: UpdateSchedulingCandidateRecord
        let inventory: InstallationInventory
        let admission: UpdateAdmissionRegistrationRecord
        let record: MachineUpdateActivationRecord
    }

    private func scope() throws -> Scope {
        let mac = Data(repeating: 1, count: 16)
        let installation = Data(repeating: 2, count: 16)
        let account = Data(repeating: 3, count: 16)
        let service = try InstallationService(role: .authority, kind: .daemon, domainUID: nil,
            executionUID: 0, label: "dev.sebastiano.remozio.macos.authority", plistName: "dev.sebastiano.remozio.macos.authority.plist", accountID: account)
        let inventory = try InstallationInventory(macID: mac, installationID: installation,
            revision: Data(repeating: 4, count: 16), bundlePath: "/Applications/Remozio.app",
            releaseDigest: Data(repeating: 5, count: 32),
            accounts: [InstallationAccount(accountID: account, ownerUID: 501)], services: [service])
        let preparation = try PreparationIntentRecord(id: UUID(), revision: UUID(),
            parent: "/Library/Application Support/Remozio/Prepared", ancestry: [.init(device: 1, inode: 10)],
            phase: .copyRecorded, copyIdentity: .init(device: 1, inode: 11), copyDigest: Data(repeating: 6, count: 32))
        let candidate = try UpdateSchedulingCandidateRecord(macID: mac, installationID: installation,
            inventoryRevision: inventory.revision, preparation: preparation, generation: 7)
        let admission = try UpdateAdmissionRegistrationRecord(macID: mac, installationID: installation,
            machine: .init(device: 1, inode: 12), accounts: [.init(accountID: account, identity: .init(device: 1, inode: 13))],
            designatedOwner: account)
        let record = try MachineUpdateActivationRecord(candidate: candidate, inventory: inventory, admission: admission)
        return Scope(candidate: candidate, inventory: inventory, admission: admission, record: record)
    }

    private func candidate(_ scope: Scope, macID: Data? = nil, installationID: Data? = nil,
        inventoryRevision: Data? = nil, revision: UUID? = nil, selected: Bool = true) throws -> UpdateSchedulingCandidateRecord {
        try .init(macID: macID ?? scope.candidate.macID, installationID: installationID ?? scope.candidate.installationID,
            inventoryRevision: inventoryRevision ?? scope.candidate.inventoryRevision, preparation: scope.candidate.preparation,
            generation: scope.candidate.generation, revision: revision ?? scope.candidate.revision, selected: selected)
    }

    /// A JSON value re-encoded with JSONEncoder, so its key order matches the record's canonical encoding.
    /// JSONSerialization sorts keys differently, so its output is never canonical.
    private enum JSONValue: Encodable {
        case string(String), number(Int64), bool(Bool), object([String: JSONValue])

        init(_ value: Any) throws {
            switch value {
            case let value as String: self = .string(value)
            case let value as NSNumber where CFGetTypeID(value) == CFBooleanGetTypeID(): self = .bool(value.boolValue)
            case let value as NSNumber: self = .number(value.int64Value)
            case let value as [String: Any]: self = .object(try value.mapValues(JSONValue.init))
            default: throw PreparationStoreError.corruptRecord
            }
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .string(let value): try container.encode(value)
            case .number(let value): try container.encode(value)
            case .bool(let value): try container.encode(value)
            case .object(let value): try container.encode(value)
            }
        }
    }

    private func canonicalJSON(_ object: [String: Any]) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(object.mapValues(JSONValue.init))
    }

    /// Replaces one field and keeps every other byte canonical, so a rejection comes from the replaced field.
    private func replaceJSON(_ record: MachineUpdateActivationRecord, key: String, value: Any) throws -> Data {
        let canonical = try record.encoded
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: canonical) as? [String: Any])
        XCTAssertEqual(try canonicalJSON(object), canonical)
        object[key] = value
        return try canonicalJSON(object)
    }

    func testInitialRecordBindsTheSelectedCandidateInventoryAndAdmission() throws {
        let s = try scope()
        XCTAssertEqual(s.record.phase, .draining)
        XCTAssertEqual(s.record.formatVersion, 1)
        XCTAssertEqual(s.record.macID, s.inventory.macID)
        XCTAssertEqual(s.record.installationID, s.inventory.installationID)
        XCTAssertEqual(s.record.updateID, s.candidate.updateID)
        XCTAssertEqual(s.record.generation, s.candidate.generation)
        XCTAssertEqual(s.record.machineAdmission, s.admission.machine)
        XCTAssertEqual(s.record.candidateDigest, try MachineUpdateActivationRecord.digest(s.candidate.encoded))
        XCTAssertEqual(s.record.inventoryDigest, MachineUpdateActivationRecord.digest(s.inventory.canonicalBytes))
        XCTAssertEqual(s.record.admissionDigest, try MachineUpdateActivationRecord.digest(s.admission.encoded))
        try s.record.requireScope(candidate: s.candidate, inventory: s.inventory, admission: s.admission)
    }

    func testUnselectedCandidateCannotCreateAnActivationRecord() throws {
        let s = try scope()
        XCTAssertThrowsError(try MachineUpdateActivationRecord(candidate: candidate(s, selected: false), inventory: s.inventory,
            admission: s.admission)) { XCTAssertEqual($0 as? MachineUpdateActivationError, .changedScope) }
    }

    func testForeignCandidateMacInstallationAndInventoryRevisionAreRejected() throws {
        let s = try scope()
        for c in try [candidate(s, macID: Data(repeating: 20, count: 16)),
            candidate(s, installationID: Data(repeating: 21, count: 16)),
            candidate(s, inventoryRevision: Data(repeating: 22, count: 16))] {
            XCTAssertThrowsError(try MachineUpdateActivationRecord(candidate: c, inventory: s.inventory, admission: s.admission)) {
                XCTAssertEqual($0 as? MachineUpdateActivationError, .changedScope)
            }
        }
    }

    func testForeignAdmissionMacAndInstallationAreRejected() throws {
        let s = try scope()
        for identity in [(Data(repeating: 20, count: 16), s.admission.installationID),
            (s.admission.macID, Data(repeating: 21, count: 16))] {
            let admission = try UpdateAdmissionRegistrationRecord(macID: identity.0, installationID: identity.1,
                machine: s.admission.machine, accounts: s.admission.accounts, designatedOwner: s.admission.designatedOwner)
            XCTAssertThrowsError(try MachineUpdateActivationRecord(candidate: s.candidate, inventory: s.inventory, admission: admission)) {
                XCTAssertEqual($0 as? MachineUpdateActivationError, .changedScope)
            }
        }
    }

    func testScopeRejectsAChangedCandidateRevisionWithTheSameUpdateID() throws {
        let s = try scope()
        let changed = try candidate(s, revision: UUID())
        XCTAssertEqual(changed.updateID, s.candidate.updateID)
        XCTAssertThrowsError(try s.record.requireScope(candidate: changed, inventory: s.inventory, admission: s.admission)) {
            XCTAssertEqual($0 as? MachineUpdateActivationError, .changedScope)
        }
    }

    func testScopeRejectsChangedInventoryContentsWithTheSameRevision() throws {
        let s = try scope()
        let changed = try InstallationInventory(macID: s.inventory.macID, installationID: s.inventory.installationID,
            revision: s.inventory.revision, bundlePath: "/Applications/Other.app", releaseDigest: s.inventory.releaseDigest,
            accounts: s.inventory.accounts, services: s.inventory.services)
        XCTAssertThrowsError(try s.record.requireScope(candidate: s.candidate, inventory: changed, admission: s.admission)) {
            XCTAssertEqual($0 as? MachineUpdateActivationError, .changedScope)
        }
    }

    func testScopeRejectsAReplacedAdmissionFileWithTheSameRevision() throws {
        let s = try scope()
        let changed = try UpdateAdmissionRegistrationRecord(macID: s.admission.macID, installationID: s.admission.installationID,
            machine: .init(device: s.admission.machine.device, inode: s.admission.machine.inode + 100),
            accounts: s.admission.accounts, designatedOwner: s.admission.designatedOwner, revision: s.admission.revision)
        XCTAssertThrowsError(try s.record.requireScope(candidate: s.candidate, inventory: s.inventory, admission: changed)) {
            XCTAssertEqual($0 as? MachineUpdateActivationError, .changedScope)
        }
    }

    func testPreflightDigestIsBoundBeforeTheIrreversibleTransition() throws {
        let s = try scope()
        let digest = Data(repeating: 40, count: 32)
        let started = try s.record.starting(policyPreflightDigest: digest)
        XCTAssertEqual(started.phase, .activationStarted)
        XCTAssertEqual(started.formatVersion, 2)
        XCTAssertEqual(started.policyPreflightDigest, digest)
        XCTAssertEqual(started.attemptID, s.record.attemptID)
        XCTAssertNotEqual(started.revision, s.record.revision)
        for count in [0, 1, 31, 33] {
            XCTAssertThrowsError(try s.record.starting(policyPreflightDigest: Data(repeating: 40, count: count)))
        }
        XCTAssertThrowsError(try started.starting(policyPreflightDigest: digest))
    }

    func testCancellationStopsAtTheIrreversibleBoundary() throws {
        let s = try scope()
        let cancelled = try s.record.advancing(to: .cancelled)
        XCTAssertEqual(cancelled.phase, .cancelled)
        let started = try s.record.starting(policyPreflightDigest: Data(repeating: 40, count: 32))
        let checking = try started.advancing(to: .restartChecking)
        let finishing = try checking.finalizing()
        let completed = try finishing.completing()
        for record in [started, checking, finishing, completed] {
            XCTAssertThrowsError(try record.advancing(to: .cancelled)) {
                XCTAssertEqual($0 as? MachineUpdateActivationError, .tooLate)
            }
        }
        XCTAssertThrowsError(try cancelled.advancing(to: .activationStarted))
    }

    func testARecordCannotSkipRestartCheckingOrFinishing() throws {
        let s = try scope()
        let started = try s.record.starting(policyPreflightDigest: Data(repeating: 40, count: 32))
        for record in [s.record, started] {
            XCTAssertThrowsError(try record.finalizing())
            XCTAssertThrowsError(try record.completing())
            XCTAssertThrowsError(try record.advancing(to: .finishing))
            XCTAssertThrowsError(try record.advancing(to: .completed))
        }
        let checking = try started.advancing(to: .restartChecking)
        XCTAssertThrowsError(try checking.completing())
        XCTAssertThrowsError(try checking.advancing(to: .completed))
    }

    func testANewAttemptCannotStartWithoutAPreflightDigest() throws {
        let s = try scope()
        XCTAssertThrowsError(try s.record.advancing(to: .activationStarted)) {
            XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
        }
        XCTAssertEqual(s.record.phase, .draining)
    }

    func testLegacyRestartRecordCannotCreateAFinalizationProposal() throws {
        let s = try scope()
        // Canonical version 1 bytes written before the preflight digest existed.
        let started = try MachineUpdateActivationRecord.decode(replaceJSON(s.record, key: "phase", value: 2))
        XCTAssertEqual(started.phase, .activationStarted)
        XCTAssertEqual(started.formatVersion, 1)
        XCTAssertNil(started.policyPreflightDigest)
        let legacy = try started.advancing(to: .restartChecking)
        XCTAssertEqual(legacy.formatVersion, 1)
        XCTAssertNil(legacy.policyPreflightDigest)
        XCTAssertThrowsError(try legacy.finalizing())
        XCTAssertEqual(try MachineUpdateActivationRecord.decode(legacy.encoded), legacy)
        let decoded = try MachineUpdateActivationRecord.decode(replaceJSON(s.record, key: "phase", value: 3))
        XCTAssertEqual(decoded.phase, .restartChecking)
        XCTAssertThrowsError(try decoded.finalizing())
    }

    func testFinalizationRequiresTheExactRestartRecord() throws {
        let s = try scope()
        let started = try s.record.starting(policyPreflightDigest: Data(repeating: 40, count: 32))
        let checking = try started.advancing(to: .restartChecking)
        let finishing = try checking.finalizing()
        try finishing.requireFinalizationSource(checking)
        XCTAssertEqual(finishing.formatVersion, 3)
        XCTAssertEqual(finishing.policyPreflightDigest, checking.policyPreflightDigest)
        XCTAssertThrowsError(try finishing.requireFinalizationSource(started))
        let other = try scope().record.starting(policyPreflightDigest: Data(repeating: 40, count: 32)).advancing(to: .restartChecking)
        XCTAssertThrowsError(try finishing.requireFinalizationSource(other))
        let changed = try MachineUpdateActivationRecord.decode(replaceJSON(checking, key: "candidateDigest", value: Data(repeating: 41, count: 32).base64EncodedString()))
        XCTAssertThrowsError(try finishing.requireFinalizationSource(changed))
    }

    func testCompletionRequiresTheExactFinishingRecord() throws {
        let s = try scope()
        let checking = try s.record.starting(policyPreflightDigest: Data(repeating: 40, count: 32)).advancing(to: .restartChecking)
        let finishing = try checking.finalizing()
        let completed = try finishing.completing()
        try completed.requireCompletionSource(finishing)
        XCTAssertEqual(completed.formatVersion, 4)
        XCTAssertEqual(completed.attemptID, finishing.attemptID)
        XCTAssertNotEqual(completed.revision, finishing.revision)
        XCTAssertThrowsError(try completed.requireCompletionSource(checking))
        let changed = try MachineUpdateActivationRecord.decode(replaceJSON(finishing, key: "admissionDigest", value: Data(repeating: 42, count: 32).base64EncodedString()))
        XCTAssertThrowsError(try completed.requireCompletionSource(changed))
        XCTAssertThrowsError(try completed.completing())
    }

    func testEveryRetainedPhaseHasACanonicalRoundTripAndRedactedDescription() throws {
        let s = try scope()
        let started = try s.record.starting(policyPreflightDigest: Data(repeating: 40, count: 32))
        let checking = try started.advancing(to: .restartChecking)
        let finishing = try checking.finalizing()
        for record in try [s.record, s.record.advancing(to: .cancelled), started, checking, finishing, finishing.completing()] {
            let bytes = try record.encoded
            XCTAssertEqual(try MachineUpdateActivationRecord.decode(bytes), record)
            XCTAssertEqual(try MachineUpdateActivationRecord.decode(bytes).encoded, bytes)
            XCTAssertEqual(record.description, "MachineUpdateActivationRecord(redacted)")
            XCTAssertEqual(record.debugDescription, record.description)
        }
    }

    func testPhaseFlagsKeepAdmissionClosedUntilCancellationOrCompletion() throws {
        for phase in [MachineUpdateActivationRecord.Phase.draining, .activationStarted, .restartChecking, .finishing] {
            XCTAssertTrue(phase.blocksMachineWrites)
        }
        XCTAssertFalse(MachineUpdateActivationRecord.Phase.cancelled.blocksMachineWrites)
        XCTAssertFalse(MachineUpdateActivationRecord.Phase.completed.blocksMachineWrites)
        XCTAssertFalse(MachineUpdateActivationRecord.Phase.draining.irreversible)
        XCTAssertFalse(MachineUpdateActivationRecord.Phase.cancelled.irreversible)
        for phase in [MachineUpdateActivationRecord.Phase.activationStarted, .restartChecking, .finishing, .completed] {
            XCTAssertTrue(phase.irreversible)
        }
    }

    func testDecoderRejectsUnknownFieldsNoncanonicalBytesAndOversizedInput() throws {
        let s = try scope()
        let bytes = try s.record.encoded
        for invalid in [Data(), bytes + Data([0x20]), Data(bytes.dropLast()), Data(repeating: 0x20, count: MachineUpdateActivationRecord.maximumBytes + 1),
            try replaceJSON(s.record, key: "unexpected", value: true)] {
            XCTAssertThrowsError(try MachineUpdateActivationRecord.decode(invalid)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    func testDecoderRejectsInvalidScopeLengthsZeroGenerationAndFileIdentity() throws {
        let s = try scope()
        for key in ["macID", "installationID", "updateID", "candidateDigest", "inventoryDigest", "admissionDigest"] {
            XCTAssertThrowsError(try MachineUpdateActivationRecord.decode(replaceJSON(s.record, key: key, value: Data([1]).base64EncodedString())))
        }
        XCTAssertThrowsError(try MachineUpdateActivationRecord.decode(replaceJSON(s.record, key: "generation", value: 0)))
        XCTAssertThrowsError(try MachineUpdateActivationRecord.decode(replaceJSON(s.record, key: "machineAdmission", value: ["device": 1, "inode": 0])))
    }

    func testDecoderRejectsVersionPhaseAndPreflightMismatches() throws {
        let s = try scope()
        for version in [0, 2, 3, 4, 5] {
            XCTAssertThrowsError(try MachineUpdateActivationRecord.decode(replaceJSON(s.record, key: "formatVersion", value: version)))
        }
        for phase in [0, 5, 6, 7] {
            XCTAssertThrowsError(try MachineUpdateActivationRecord.decode(replaceJSON(s.record, key: "phase", value: phase)))
        }
        let started = try s.record.starting(policyPreflightDigest: Data(repeating: 40, count: 32))
        XCTAssertThrowsError(try MachineUpdateActivationRecord.decode(replaceJSON(started, key: "policyPreflightDigest", value: Data([1]).base64EncodedString())))
        XCTAssertThrowsError(try MachineUpdateActivationRecord.decode(replaceJSON(started, key: "phase", value: 1)))
    }

    func testFormatRequirementsPreserveAllRetainedActivationVersions() throws {
        let completion = try MachineUpdateActivationRecord.completionRequirements
        XCTAssertEqual(completion.count, 2)
        XCTAssertEqual(Set(completion.map(\.role)), [.authority, .setupController])
        for requirement in completion {
            XCTAssertEqual(requirement.name, MachineUpdateActivationRecord.formatName)
            XCTAssertEqual(requirement.readVersions, [1, 2, 3, 4])
            XCTAssertEqual(requirement.writeVersions, [4])
        }
        for requirement in try MachineUpdateActivationRecord.finalizationRequirements {
            XCTAssertEqual(requirement.readVersions, [1, 2, 3])
            XCTAssertEqual(requirement.writeVersions, [3])
        }
    }
}
