import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Real owned plan files and SQLite. Runtime publication and registration fixtures prove no native Root or service behavior.
final class SharedSetupImportRelayPlanTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Harness {
        let f: SharedSetupImportFixture
        let intent: SharedSetupImportIntent
        let services: ServiceAccountPlan
        init() throws {
            let roles: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway, .commandFrontend, .commandMonitor, .commandChild, .setupController]
            let policy = try AuthorityCodePolicy(entries: roles.map { role in
                try .init(role: role, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.role-\(role.rawValue)",
                    installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: UInt8(role.rawValue), count: 20), active: true)
            })
            f = try .init(relativeDirectory: "machine/SharedSetupImport", policy: policy)
            intent = try f.intent()
            services = try .init(account: f.account, planID: AccountPreparationIntent.randomID(), claims: [
                .init(accountID: f.account.accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
                .init(accountID: f.account.accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())])
            let machine = try f.accountFixture.open(); defer { try? machine.close() }
            try machine.retainServiceAccountPlan(services); try machine.completeServiceAccountPlan(services)
            let journal = try f.open(initialize: true); try journal.begin(intent); try journal.close()
        }
        func machine<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            let value = try f.accountFixture.open(); defer { try? value.close() }; return try body(value)
        }
        func directory<Value>(_ body: (ProtectedSetupDirectory) throws -> Value) throws -> Value {
            let directory = try ProtectedSetupDirectory(anchor: f.accountFixture.root.path, relativePath: f.relativeDirectory, owner: getuid(), createIfMissing: false)
            defer { directory.close() }; return try body(directory)
        }
        var path: String { f.accountFixture.root.path + "/" + f.relativeDirectory + "/" + AdministrativeSetupPublication.File.importRelayPlan(accountID: f.account.accountID).name }
        func prepare(_ expected: SharedSetupImportIntent? = nil, records: [SharedSetupImportIntent]? = nil,
                     published: Bool = false, select: (Set<UInt16>) throws -> UInt16 = { _ in 51001 },
                     verify: () throws -> Void = {}) throws -> SharedSetupImportRelayPlan {
            try directory { try SharedSetupImportRelayStorage.prepare(expected: expected ?? intent, records: records ?? [intent],
                runtimePublished: published, directory: $0, owner: getuid(), select: select, verifyCurrent: verify) }
        }
        func read(_ expected: SharedSetupImportIntent? = nil) throws -> SharedSetupImportRelayPlan? {
            try directory { try SharedSetupImportRelayStorage.read(expected: expected ?? intent, directory: $0, owner: getuid()) }
        }
        func owner(operations: RuntimeActivationOperations = .native) throws -> SetupAccountOwner {
            try .init(openMachine: { try self.f.accountFixture.open() }, expectedReleaseDigest: f.accountFixture.release,
                resume: { _, _ in throw Interrupted() }, accountCodePolicy: f.accountFixture.policy,
                lookupAccount: { uid in guard uid == self.f.accountFixture.identity.uid else { throw AdministrativeSetupError.wrongAccount }; return self.f.accountFixture.identity },
                activationOperations: operations)
        }
        func progress(_ owner: SetupAccountOwner) throws -> SetupPortableImportProgress { try XCTUnwrap(owner.portableImportProgress(callerUID: getuid())) }
        func publishRuntime() throws -> (RuntimePreparationMaterial, SharedSetupImportIntent) {
            try machine { machine in
                let now = Date(), material = try RuntimePreparationMaterial.create(services: services, notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
                try machine.retainRuntimeMaterial(material.reference); try machine.completeRuntimePublication(material.reference)
                return try machine.withSharedImportJournal { journal in
                    (material, try XCTUnwrap(journal).advance(intent, to: .runtimePublished))
                }
            }
        }
        func evidence(relay: Bool = true, writable: Bool = true) throws -> SignedReleaseEvidence {
            try NativeHostReleaseFixture.make(policy: f.account.initialAuthority.codePolicy) { component in
                guard component.role == .setupController else { return component }
                var formats = component.formats
                formats.append(try .init(name: SharedSetupImportJournal.formatName, readers: [2], writers: [2]))
                formats.append(try .init(name: PortableSetup.formatName, readers: [1, 2, 3, 4], writers: [1, 2, 3, 4]))
                if relay { formats.append(try .init(name: SharedSetupImportRelayPlan.formatName, readers: [1], writers: writable ? [1] : [])) }
                return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                    relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                    build: component.build, teamID: component.teamID, formats: formats)
            }
        }
    }
    func testCanonicalPlanBindsTheLocalOperationAndContainsNoProviderCredential() throws {
        let h = try Harness(), plan = try SharedSetupImportRelayPlan(expected: h.intent, port: 51001)
        XCTAssertEqual(try SharedSetupImportRelayPlan.decode(plan.bytes, expected: h.intent), plan)
        XCTAssertNil(plan.bytes.range(of: Data("synthetic-provider-token-only".utf8)))
        XCTAssertEqual(String(reflecting: plan), "SharedSetupImportRelayPlan(redacted)")
        XCTAssertEqual(plan.hostname, "m-" + h.intent.operationID.map { String(format: "%02x", $0) }.joined() + ".remozio.example.invalid")
        XCTAssertTrue(plan.tunnelName.hasPrefix("remozio-")); XCTAssertLessThan(plan.tunnelName.count, 100)
    }
    func testPhaseChangesPreserveTheSamePlanButAnotherOperationCannotAdoptIt() throws {
        let h = try Harness(), plan = try SharedSetupImportRelayPlan(expected: h.intent, port: 51001)
        let later = try h.intent.advanced(to: .runtimePublished)
        XCTAssertEqual(try SharedSetupImportRelayPlan.decode(plan.bytes, expected: later), plan)
        XCTAssertThrowsError(try SharedSetupImportRelayPlan.decode(plan.bytes, expected: h.f.intent()))
        XCTAssertThrowsError(try SharedSetupImportRelayPlan.decode(plan.bytes, expected: h.f.another(h.intent, account: 33)))
    }
    func testThePlanRefusesUnknownFieldsVersionsPurposeAndInvalidPorts() throws {
        let h = try Harness(), plan = try SharedSetupImportRelayPlan(expected: h.intent, port: 51001)
        let limits = try CBORLimits(maxBytes: 2048, maxDepth: 1, maxItems: 32)
        guard case let .map(fields) = try DeterministicCBOR.decode(plan.bytes, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("wrong")), (10, .unsigned(0)), (10, .unsigned(443)), (10, .unsigned(65536)), (14, .null)] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try SharedSetupImportRelayPlan.decode(DeterministicCBOR.encode(.map(changed), limits: limits), expected: h.intent))
        }
        XCTAssertThrowsError(try SharedSetupImportRelayPlan.decode(plan.bytes.dropLast(), expected: h.intent))
    }
    func testProviderFreeImportsCannotInventARelayPlan() throws {
        let h = try Harness(), proposal = PortableSetup(defaults: try h.f.proposal().defaults)
        let intent = try SharedSetupImportIntent(scope: h.f.scope, proposal: proposal)
        XCTAssertThrowsError(try SharedSetupImportRelayPlan(expected: intent, port: 51001))
    }
    func testGeneratedHostnamesRespectTheFullDnsLengthLimit() throws {
        let h = try Harness(), suffix = [String(repeating: "a", count: 63), String(repeating: "b", count: 63), String(repeating: "c", count: 63), String(repeating: "d", count: 63)].joined(separator: ".")
        // A shorter suffix is valid by itself but leaves no room for the local generated label.
        let cloud = try SetupCloudflareConfiguration(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32), dnsSuffix: String(suffix.dropLast(2)), apiToken: "synthetic-only")
        let intent = try SharedSetupImportIntent(scope: h.f.scope, proposal: .init(defaults: h.f.proposal().defaults, cloudflare: cloud))
        XCTAssertThrowsError(try SharedSetupImportRelayPlan(expected: intent, port: 51001))
    }
    func testOwnedPublicationAndExplicitRetryPreserveThePortAndInode() throws {
        let h = try Harness(); var selections = 0
        let first = try h.prepare(select: { ports in XCTAssertTrue(ports.isEmpty); selections += 1; return 51001 })
        var before = stat(); XCTAssertEqual(lstat(h.path, &before), 0); XCTAssertEqual(before.st_mode & 0o7777, 0o600)
        XCTAssertEqual(try h.prepare(select: { _ in XCTFail("Selected a new port on retry"); return 51002 }), first)
        var after = stat(); XCTAssertEqual(lstat(h.path, &after), 0); XCTAssertEqual(after.st_ino, before.st_ino); XCTAssertEqual(selections, 1)
        XCTAssertEqual(try h.read(), first)
    }
    func testAnUnknownPublicationReplyRecoversTheRetainedPlanWithoutReselection() throws {
        let h = try Harness(); var selections = 0
        XCTAssertThrowsError(try h.prepare(select: { _ in selections += 1; return 51001 }, verify: {
            if FileManager.default.fileExists(atPath: h.path) { throw Interrupted() }
        }))
        XCTAssertEqual(try h.prepare(select: { _ in XCTFail("Repeated selection"); return 51002 }).port, 51001)
        XCTAssertEqual(selections, 1)
    }
    func testMissingAdvancedOrPartiallyPublishedPlanIsNeverRecreated() throws {
        let h = try Harness(), advanced = try h.intent.advanced(to: .runtimePublished)
        for (record, published) in [(advanced, false), (h.intent, true)] {
            XCTAssertThrowsError(try h.prepare(record, records: [record], published: published, select: { _ in XCTFail(); return 51001 }))
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: h.path))
    }
    func testCorruptOrLinkedAcceptedPlansCannotBeOverwritten() throws {
        for link in [false, true] {
            let h = try Harness()
            if link { try FileManager.default.createSymbolicLink(atPath: h.path, withDestinationPath: "/dev/null") }
            else { try Data("conflict".utf8).write(to: URL(fileURLWithPath: h.path)); XCTAssertEqual(chmod(h.path, 0o600), 0) }
            XCTAssertThrowsError(try h.prepare(select: { _ in XCTFail(); return 51001 }))
        }
    }
    func testReservedPortsAreComparedAcrossRetainedAccounts() throws {
        let h = try Harness(), other = try h.f.another(h.intent, account: 31)
        let first = try h.prepare(), records = [h.intent, other]
        let second = try h.prepare(other, records: records, select: { ports in XCTAssertEqual(ports, [first.port]); return 51002 })
        XCTAssertEqual(second.port, 51002)
        XCTAssertEqual(try h.prepare(records: records), first)
    }
    func testAReservedPortFromTheSelectorCannotBePublishedForAnotherAccount() throws {
        let h = try Harness(), other = try h.f.another(h.intent, account: 31); _ = try h.prepare()
        XCTAssertThrowsError(try h.prepare(other, records: [h.intent, other], select: { _ in 51001 }))
    }
    func testUntrackedAcceptedPlanFilesInvalidateTheUpdateSnapshot() throws {
        let h = try Harness(), other = try h.f.another(h.intent, account: 31)
        _ = try h.prepare(other, records: [other])
        XCTAssertThrowsError(try h.machine { try RuntimeReleaseCompatibilitySnapshot.capture(machine: $0) }) {
            XCTAssertEqual($0 as? SharedSetupImportError, .corruptRecord)
        }
    }
    func testUpdateSnapshotsRequireRelayReadersAndWritersOnlyWhenAPlanExists() throws {
        let h = try Harness(), before = try h.machine { try RuntimeReleaseCompatibilitySnapshot.capture(machine: $0) }
        XCTAssertFalse(before.requirements.formats.contains { $0.name == SharedSetupImportRelayPlan.formatName })
        _ = try h.prepare()
        let snapshot = try h.machine { machine -> RuntimeReleaseCompatibilitySnapshot in
            XCTAssertThrowsError(try before.requireCurrent(machine: machine))
            return try .capture(machine: machine)
        }
        let requirement = try XCTUnwrap(snapshot.requirements.formats.first { $0.name == SharedSetupImportRelayPlan.formatName })
        XCTAssertEqual(requirement.role, .setupController); XCTAssertEqual(requirement.readVersions, [1]); XCTAssertEqual(requirement.writeVersions, [1])
        try h.machine { machine in
            try snapshot.validate(h.evidence(), policy: h.f.account.initialAuthority.codePolicy, machine: machine)
            XCTAssertThrowsError(try snapshot.validate(h.evidence(relay: false), policy: h.f.account.initialAuthority.codePolicy, machine: machine))
            XCTAssertThrowsError(try snapshot.validate(h.evidence(writable: false), policy: h.f.account.initialAuthority.codePolicy, machine: machine))
        }
    }
    func testReplacingIdenticalPlanBytesInvalidatesTheCapturedFileIdentity() throws {
        let h = try Harness(); _ = try h.prepare()
        let snapshot = try h.machine { try RuntimeReleaseCompatibilitySnapshot.capture(machine: $0) }
        let bytes = try Data(contentsOf: URL(fileURLWithPath: h.path)), replacement = h.path + ".replacement"
        try bytes.write(to: URL(fileURLWithPath: replacement)); XCTAssertEqual(chmod(replacement, 0o600), 0)
        XCTAssertEqual(rename(replacement, h.path), 0)
        XCTAssertThrowsError(try h.machine { try snapshot.requireCurrent(machine: $0) })
    }
    func testNativePortSelectionIsBoundedAndNeverReusesAReservedChoice() throws {
        var calls = 0
        XCTAssertEqual(try SharedSetupRelayPortSelection.choose(reserved: [51001], candidate: { calls += 1; return calls == 1 ? 51001 : 51002 }), 51002)
        XCTAssertEqual(calls, 2); calls = 0
        XCTAssertThrowsError(try SharedSetupRelayPortSelection.choose(reserved: [51001], candidate: { calls += 1; return 51001 }))
        XCTAssertEqual(calls, 64)
        XCTAssertGreaterThanOrEqual(try SharedSetupRelayPortSelection.choose(reserved: []), 1024)
    }
    func testTheOwnerRetainsLocalChoicesWithoutChangingImportProgressOrRuntime() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }; let before = try h.progress(owner)
        let plan = try owner.prepareImportedRelayPlan(callerUID: getuid(), expected: before, proposal: h.f.proposal(), selectPort: { _ in 51001 })
        XCTAssertEqual(plan.port, 51001); XCTAssertEqual(try h.progress(owner), before)
        XCTAssertNil(before.runtime.materialID)
        XCTAssertEqual(try owner.prepareImportedRelayPlan(callerUID: getuid(), expected: before, proposal: h.f.proposal(), selectPort: { _ in XCTFail(); return 51002 }), plan)
    }
    func testWrongCallerOrProposalCannotSelectALocalPort() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }; let before = try h.progress(owner)
        for (uid, proposal) in [(getuid() + 1, try h.f.proposal()), (getuid(), PortableSetup(defaults: try h.f.proposal().defaults))] {
            XCTAssertThrowsError(try owner.prepareImportedRelayPlan(callerUID: uid, expected: before, proposal: proposal, selectPort: { _ in XCTFail(); return 51001 }))
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: h.path))
    }
    func testTheOwnerNeverRepairsALostPlanAfterRuntimeIdentityWasRetained() throws {
        let h = try Harness(); _ = try h.publishRuntime()
        let owner = try h.owner(); defer { try? owner.close() }
        XCTAssertThrowsError(try owner.prepareImportedRelayPlan(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), selectPort: { _ in XCTFail(); return 51001 }))
        XCTAssertFalse(FileManager.default.fileExists(atPath: h.path))
    }
    func testRuntimeAndActivationReconstructionKeepTheSameLocalPort() throws {
        let h = try Harness(), local = try h.prepare(), (material, retained) = try h.publishRuntime()
        try h.machine { machine in
            let initial = try XCTUnwrap(machine.initialization(accountID: h.f.account.accountID)), inventory = try XCTUnwrap(machine.inventory())
            let bundle = try RuntimeConfigurationBundle.initial(account: h.f.account, initialization: initial, reference: material.reference,
                inventory: inventory, importIntent: retained, relayPlan: local)
            XCTAssertEqual(bundle.transport.relayPort, 51001)
            let plan = try RuntimeActivationPlan(account: h.f.account, initialization: initial, runtime: machine.runtimePreparation(accountID: h.f.account.accountID),
                inventory: inventory, importIntent: retained, relayPlan: local)
            let decoded = try RuntimeActivationPlan.decode(plan.encoded)
            XCTAssertEqual(try decoded.configurationBundle(account: h.f.account, initialization: initial, inventory: inventory).transport.canonicalBytes, bundle.transport.canonicalBytes)
            XCTAssertThrowsError(try RuntimeConfigurationBundle.initial(account: h.f.account, initialization: initial, reference: material.reference, inventory: inventory, importIntent: retained))
        }
    }
    func testMissingRelayPlanRefusesBeforeAnyRuntimeMaterialEffect() throws {
        let h = try Harness(), (_, retained) = try h.publishRuntime(); var effects = 0
        try h.machine { machine in
            let runtime = try machine.runtimePreparation(accountID: h.f.account.accountID)
            XCTAssertThrowsError(try RuntimePublicationController.prepare(machine: machine, account: h.f.account, expected: runtime, importIntent: retained,
                verifyCurrent: {}, verifyServices: { _ in effects += 1 }, verifyAuthority: { _ in effects += 1 },
                restoreMaterial: { _, _, _ in effects += 1; throw Interrupted() }, publish: { _, _, _ in effects += 1 }))
        }
        XCTAssertEqual(effects, 0)
    }
    func testActivationOwnerUsesTheRetainedRelayPlanBeforeRegistration() throws {
        let h = try Harness(); _ = try h.prepare(); _ = try h.publishRuntime(); var ports: [UInt16?] = [], registrations = 0
        let operations = RuntimeActivationOperations(prepare: { plan, _, _, _, verify in ports.append(plan.transport.relayPort); try verify() },
            validate: { plan, _, _, _, verify in XCTAssertEqual(plan.transport.relayPort, 51001); try verify() },
            register: { _, verify in registrations += 1; try verify() }, didStage: { _ in })
        let owner = try h.owner(operations: operations); defer { try? owner.close() }
        let result = try owner.resumeActivation(callerUID: getuid(), expected: XCTUnwrap(owner.activationProgress(callerUID: getuid())))
        XCTAssertTrue(result.jobsRegistered); XCTAssertEqual(ports, [51001]); XCTAssertEqual(registrations, 2)
    }
}
