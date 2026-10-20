import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned protected files and injected provider reads only. No provider request, Root process or installed service is exercised.
final class SharedSetupImportRelayInspectionOwnerTests: XCTestCase, @unchecked Sendable {
    private struct Interrupted: Error {}
    private actor Counter { private(set) var calls = 0; func record() { calls += 1 } }
    private final class Harness: @unchecked Sendable {
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
        func readPlan(_ expected: SharedSetupImportIntent? = nil) throws -> SharedSetupImportRelayPlan? {
            try directory { try SharedSetupImportRelayStorage.read(expected: expected ?? intent, directory: $0, owner: getuid()) }
        }
        func owner(operations: RuntimeActivationOperations = .native) throws -> SetupAccountOwner {
            try .init(openMachine: { try self.f.accountFixture.open() }, expectedReleaseDigest: f.accountFixture.release,
                resume: { _, _ in throw Interrupted() }, accountCodePolicy: f.accountFixture.policy,
                lookupAccount: { uid in guard uid == self.f.accountFixture.identity.uid else { throw AdministrativeSetupError.wrongAccount }; return self.f.accountFixture.identity },
                activationOperations: operations)
        }
        func progress(_ owner: SetupAccountOwner) throws -> SetupPortableImportProgress { try XCTUnwrap(owner.portableImportProgress(callerUID: getuid())) }
    }

    private func result(_ h: Harness, plan: SharedSetupImportRelayPlan, present: Bool = true) throws -> CloudflareImportedRelayInspection {
        let config = try XCTUnwrap(h.f.proposal().cloudflare)
        let tunnel: CloudflareTunnelObservation? = present ? .init(accountID: config.accountID,
            tunnelID: "11111111-1111-4111-8111-111111111111", name: plan.tunnelName) : nil
        return .init(scope: .init(accountID: config.accountID, zoneID: config.zoneID, zoneName: "example.invalid", dnsSuffix: config.dnsSuffix),
            tunnel: tunnel, configuration: tunnel.map { .init(accountID: $0.accountID, tunnelID: $0.tunnelID,
                providerVersion: 1, planDigest: Data(SHA256.hash(data: plan.bytes))) })
    }
    func testOwnerReleasesBothDatabaseLeasesAndReturnsNoNewImportState() async throws {
        let h = try Harness(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal(), count = Counter()
        let observed = try await owner.inspectImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { config, retained, local in
            await count.record(); XCTAssertEqual(local, plan); XCTAssertEqual(retained, h.intent)
            XCTAssertEqual(config.accountID, try XCTUnwrap(proposal.cloudflare).accountID)
            try h.machine { machine in try machine.withSharedImportJournal { journal in XCTAssertEqual(try journal?.records(), [h.intent]) } }
            return try self.result(h, plan: local)
        })
        XCTAssertEqual(observed, try result(h, plan: plan)); XCTAssertEqual(try h.progress(owner), expected)
        XCTAssertEqual(String(reflecting: observed), "CloudflareImportedRelayInspection(redacted)")
        let calls = await count.calls; XCTAssertEqual(calls, 1)
    }
    func testObservedAbsenceNeitherAdoptsAResourceNorAdvancesTheImport() async throws {
        let h = try Harness(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal()
        let observed = try await owner.inspectImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
            try self.result(h, plan: plan, present: false)
        })
        XCTAssertNil(observed.tunnel); XCTAssertEqual(try h.progress(owner), expected)
    }
    func testAPlanMustAlreadyExistBeforeAnyProviderRead() async throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal(), count = Counter()
        do { _ = try await owner.inspectImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
            await count.record(); throw Interrupted()
        }); XCTFail() } catch { XCTAssertEqual(error as? SharedSetupImportCompletionValidation.Failure, .incomplete) }
        let calls = await count.calls; XCTAssertEqual(calls, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: h.path)); XCTAssertEqual(try h.progress(owner), expected)
    }
    func testWrongCallerAndChangedProposalStopBeforeSendingCredentials() async throws {
        let h = try Harness(), _ = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal(), count = Counter()
        for (uid, selected) in [(getuid() + 1, proposal), (getuid(), PortableSetup(defaults: proposal.defaults))] {
            do { _ = try await owner.inspectImportedRelayTunnel(callerUID: uid, expected: expected, proposal: selected, inspect: { _, _, _ in
                await count.record(); throw Interrupted()
            }); XCTFail() } catch {}
        }
        let calls = await count.calls; XCTAssertEqual(calls, 0)
    }
    func testCrossedTunnelAndZoneEvidenceCannotEscapeTheOwner() async throws {
        let h = try Harness(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal(), valid = try result(h, plan: plan)
        let tunnel = try XCTUnwrap(valid.tunnel)
        let crossed = [
            CloudflareImportedRelayInspection(scope: valid.scope, tunnel: .init(accountID: String(repeating: "c", count: 32), tunnelID: tunnel.tunnelID, name: tunnel.name)),
            .init(scope: valid.scope, tunnel: .init(accountID: tunnel.accountID, tunnelID: "not-a-uuid", name: tunnel.name)),
            .init(scope: valid.scope, tunnel: .init(accountID: tunnel.accountID, tunnelID: tunnel.tunnelID, name: tunnel.name + "-other")),
            .init(scope: .init(accountID: valid.scope.accountID, zoneID: String(repeating: "c", count: 32), zoneName: valid.scope.zoneName, dnsSuffix: valid.scope.dnsSuffix), tunnel: tunnel)]
        for value in crossed {
            do { _ = try await owner.inspectImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in value }); XCTFail() }
            catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        }
        XCTAssertEqual(try h.progress(owner), expected)
    }
    func testAnImportRevisionChangedDuringTheReadRejectsTheObservation() async throws {
        let h = try Harness(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal()
        do { _ = try await owner.inspectImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
            try h.machine { machine in
                let now = Date(), material = try RuntimePreparationMaterial.create(services: h.services,
                    notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
                try machine.retainRuntimeMaterial(material.reference); try machine.completeRuntimePublication(material.reference)
                try machine.withSharedImportJournal { journal in _ = try XCTUnwrap(journal).advance(h.intent, to: .runtimePublished) }
            }
            return try self.result(h, plan: plan)
        }); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
    }
    func testAnInventoryRevisionChangedDuringTheReadRejectsTheObservation() async throws {
        let h = try Harness(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal()
        do { _ = try await owner.inspectImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
            try h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
            return try self.result(h, plan: plan)
        }); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        XCTAssertEqual(try h.progress(owner), expected)
    }
    func testAnIdenticalPlanReplacedWithAnotherInodeRejectsLateEvidence() async throws {
        let h = try Harness(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal()
        do { _ = try await owner.inspectImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
            let temporary = h.path + ".replacement"
            try plan.bytes.write(to: URL(fileURLWithPath: temporary)); XCTAssertEqual(chmod(temporary, 0o600), 0)
            XCTAssertEqual(rename(temporary, h.path), 0)
            return try self.result(h, plan: plan)
        }); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        XCTAssertEqual(try h.readPlan(), plan)
    }
    func testAMissingPlanAfterTheReadIsNeverRecreated() async throws {
        let h = try Harness(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal()
        do { _ = try await owner.inspectImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
            XCTAssertEqual(unlink(h.path), 0); return try self.result(h, plan: plan)
        }); XCTFail() } catch { XCTAssertEqual(error as? SharedSetupImportCompletionValidation.Failure, .incomplete) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: h.path))
    }
    func testCancellationDuringTheReadRejectsLateEvidenceAndReleasesAdmission() async throws {
        let h = try Harness(), plan = try h.prepare(), owner = try h.owner()
        let expected = try h.progress(owner), proposal = try h.f.proposal()
        let task = Task { @Sendable in
            try await owner.inspectImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
                withUnsafeCurrentTask { $0?.cancel() }; return try self.result(h, plan: plan)
            })
        }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(try h.progress(owner), expected); XCTAssertNoThrow(try owner.close())
    }
    func testOwnerShutdownRejectsLateEvidenceWithoutLeakingAnAdmission() async throws {
        let h = try Harness(), plan = try h.prepare(), owner = try h.owner()
        let expected = try h.progress(owner), proposal = try h.f.proposal()
        do { _ = try await owner.inspectImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
            XCTAssertThrowsError(try owner.close()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
            return try self.result(h, plan: plan)
        }); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
        XCTAssertNoThrow(try owner.close())
    }
    func testProviderFailureIsNotRetriedAndAdvancesNoMarker() async throws {
        let h = try Harness(), _ = try h.prepare(), owner = try h.owner()
        let expected = try h.progress(owner), proposal = try h.f.proposal(), count = Counter()
        do { _ = try await owner.inspectImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
            await count.record(); throw CloudflareProvisioningError.unauthorized
        }); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .unauthorized) }
        let calls = await count.calls; XCTAssertEqual(calls, 1); XCTAssertEqual(try h.progress(owner), expected)
        XCTAssertNoThrow(try owner.close())
    }
    func testAlreadyCancelledInspectionNeverReachesProviderCode() async throws {
        let h = try Harness(), _ = try h.prepare(), owner = try h.owner()
        let expected = try h.progress(owner), proposal = try h.f.proposal(), count = Counter()
        let task = Task { @Sendable in
            withUnsafeCurrentTask { $0?.cancel() }
            return try await owner.inspectImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
                await count.record(); throw Interrupted()
            })
        }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let calls = await count.calls; XCTAssertEqual(calls, 0); XCTAssertNoThrow(try owner.close())
    }
}
