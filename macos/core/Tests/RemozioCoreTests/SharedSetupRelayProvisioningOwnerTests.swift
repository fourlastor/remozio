import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned files and injected provider operations only. No Root process or installed service runs here.
final class SharedSetupRelayProvisioningOwnerTests: XCTestCase, @unchecked Sendable {
    private struct Interrupted: Error {}
    private actor Counter { private(set) var calls = 0; func record() { calls += 1 } }
    private func observation(_ h: RelayProvisioningFixture, plan: SharedSetupImportRelayPlan) throws -> CloudflareTunnelObservation {
        let config = try XCTUnwrap(h.f.proposal().cloudflare)
        return .init(accountID: config.accountID, tunnelID: "11111111-1111-4111-8111-111111111111", name: plan.tunnelName)
    }
    private func inspection(_ h: RelayProvisioningFixture, plan: SharedSetupImportRelayPlan, present: Bool = false) throws -> CloudflareImportedRelayInspection {
        let config = try XCTUnwrap(h.f.proposal().cloudflare), tunnel = present ? try observation(h, plan: plan) : nil
        return .init(scope: .init(accountID: config.accountID, zoneID: config.zoneID, zoneName: "example.invalid", dnsSuffix: config.dnsSuffix),
            tunnel: tunnel, configuration: tunnel.map { .init(accountID: $0.accountID, tunnelID: $0.tunnelID,
                providerVersion: 1, planDigest: Data(SHA256.hash(data: plan.bytes))) })
    }
    private func read(_ h: RelayProvisioningFixture, plan: SharedSetupImportRelayPlan) throws -> SharedSetupRelayProvisioningRecord? {
        try h.directory { try SharedSetupRelayProvisioningStorage.read(expected: h.intent, plan: plan, directory: $0, owner: getuid()) }
    }
    func testDispatchIsDurableBeforePostAndSuccessIsIdempotent() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal(), reads = Counter(), posts = Counter()
        let created = try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
            await reads.record(); return try self.inspection(h, plan: plan)
        }, create: { _, _, _, dispatched in
            await posts.record(); XCTAssertEqual(dispatched.phase, .dispatched)
            XCTAssertEqual(try self.read(h, plan: plan), dispatched)
            try h.machine { machine in try machine.withSharedImportJournal { journal in XCTAssertEqual(try journal?.records(), [h.intent]) } }
            return try .created(self.observation(h, plan: plan))
        })
        XCTAssertEqual(created.phase, .created); XCTAssertEqual(try read(h, plan: plan), created)
        XCTAssertEqual(try h.progress(owner), expected)
        let repeated = try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
            await reads.record(); throw Interrupted()
        }, create: { _, _, _, _ in await posts.record(); throw Interrupted() })
        XCTAssertEqual(repeated, created)
        let readCount = await reads.calls, postCount = await posts.calls; XCTAssertEqual(readCount, 1); XCTAssertEqual(postCount, 1)
    }
    func testUnknownAndThrownPostOutcomesAreRetainedWithoutAutomaticRetry() async throws {
        for throwing in [false, true] {
            let h = try RelayProvisioningFixture(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
            let expected = try h.progress(owner), proposal = try h.f.proposal(), posts = Counter()
            let result = try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal,
                inspect: { _, _, _ in try self.inspection(h, plan: plan) }, create: { _, _, _, _ in
                    await posts.record(); if throwing { throw Interrupted() }; return .unknown
                })
            XCTAssertEqual(result.phase, .unknown)
            do { _ = try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal,
                inspect: { _, _, _ in XCTFail("No automatic retry inspection"); throw Interrupted() },
                create: { _, _, _, _ in await posts.record(); throw Interrupted() }); XCTFail() }
            catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
            let count = await posts.calls; XCTAssertEqual(count, 1); XCTAssertEqual(try read(h, plan: plan), result)
        }
    }
    func testCancellationDuringPreflightKeepsPreparedStateAndSendsNoPost() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal(), posts = Counter()
        let task = Task { @Sendable in
            try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
                withUnsafeCurrentTask { $0?.cancel() }; return try self.inspection(h, plan: plan)
            }, create: { _, _, _, _ in await posts.record(); throw Interrupted() })
        }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(try read(h, plan: plan)?.phase, .prepared)
        let count = await posts.calls; XCTAssertEqual(count, 0)
    }
    func testCancellationDuringPostRetainsUnknownBeforeReportingCancellation() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal()
        let task = Task { @Sendable in
            try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal,
                inspect: { _, _, _ in try self.inspection(h, plan: plan) }, create: { _, _, _, _ in
                    withUnsafeCurrentTask { $0?.cancel() }; throw CancellationError()
                })
        }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(try read(h, plan: plan)?.phase, .unknown)
    }
    func testCancellationAtAcknowledgementRetainsTheCreatedResource() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal()
        let task = Task { @Sendable in
            try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal,
                inspect: { _, _, _ in try self.inspection(h, plan: plan) }, create: { _, _, _, _ in
                    withUnsafeCurrentTask { $0?.cancel() }; return try .created(self.observation(h, plan: plan))
                })
        }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let retained = try XCTUnwrap(read(h, plan: plan)); XCTAssertEqual(retained.phase, .created)
        XCTAssertEqual(retained.tunnelID, try observation(h, plan: plan).tunnelID)
    }
    func testWrongCallerAndChangedProposalHaveNoProvisioningEffects() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal(), calls = Counter()
        for (uid, selected) in [(getuid() + 1, proposal), (getuid(), PortableSetup(defaults: proposal.defaults))] {
            do { _ = try await owner.createImportedRelayTunnel(callerUID: uid, expected: expected, proposal: selected,
                inspect: { _, _, _ in await calls.record(); throw Interrupted() },
                create: { _, _, _, _ in await calls.record(); throw Interrupted() }); XCTFail() } catch {}
        }
        let count = await calls.calls; XCTAssertEqual(count, 0); XCTAssertNil(try read(h, plan: plan))
    }
    func testInventoryChangeDuringPreflightStopsBeforeDispatch() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal(), posts = Counter()
        do { _ = try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
            try h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
            return try self.inspection(h, plan: plan)
        }, create: { _, _, _, _ in await posts.record(); throw Interrupted() }); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        XCTAssertEqual(try read(h, plan: plan)?.phase, .prepared); let count = await posts.calls; XCTAssertEqual(count, 0)
    }
    func testIdenticalPlanReplacementDuringPreflightStopsBeforeDispatch() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal(), posts = Counter()
        do { _ = try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
            let replacement = h.path + ".replacement"; try plan.bytes.write(to: URL(fileURLWithPath: replacement))
            XCTAssertEqual(chmod(replacement, 0o600), 0); XCTAssertEqual(rename(replacement, h.path), 0)
            return try self.inspection(h, plan: plan)
        }, create: { _, _, _, _ in await posts.record(); throw Interrupted() }); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        XCTAssertEqual(try read(h, plan: plan)?.phase, .prepared); let count = await posts.calls; XCTAssertEqual(count, 0)
    }
    func testImportPhaseChangeDuringPreflightStopsBeforeDispatch() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal(), posts = Counter()
        do { _ = try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal, inspect: { _, _, _ in
            try h.machine { machine in
                let now = Date(), material = try RuntimePreparationMaterial.create(services: h.services,
                    notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
                try machine.retainRuntimeMaterial(material.reference); try machine.completeRuntimePublication(material.reference)
                try machine.withSharedImportJournal { journal in _ = try XCTUnwrap(journal).advance(h.intent, to: .runtimePublished) }
            }
            return try self.inspection(h, plan: plan)
        }, create: { _, _, _, _ in await posts.record(); throw Interrupted() }); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        XCTAssertEqual(try read(h, plan: plan)?.phase, .prepared); let count = await posts.calls; XCTAssertEqual(count, 0)
    }
    func testShutdownDuringPostLeavesUnresolvedDispatchAndNeverResends() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), owner = try h.owner()
        let expected = try h.progress(owner), proposal = try h.f.proposal(), posts = Counter()
        do { _ = try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal,
            inspect: { _, _, _ in try self.inspection(h, plan: plan) }, create: { _, _, _, _ in
                await posts.record()
                XCTAssertThrowsError(try owner.close()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
                return try .created(self.observation(h, plan: plan))
            }); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
        XCTAssertNoThrow(try owner.close()); XCTAssertEqual(try read(h, plan: plan)?.phase, .dispatched)
        let reopened = try h.owner(); defer { try? reopened.close() }
        do { _ = try await reopened.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal,
            inspect: { _, _, _ in XCTFail("Unresolved dispatch must not retry"); throw Interrupted() },
            create: { _, _, _, _ in await posts.record(); throw Interrupted() }); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
        let count = await posts.calls; XCTAssertEqual(count, 1)
    }
    func testPreexistingTunnelIsNeverAdoptedByName() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal(), posts = Counter()
        do { _ = try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal,
            inspect: { _, _, _ in try self.inspection(h, plan: plan, present: true) },
            create: { _, _, _, _ in await posts.record(); throw Interrupted() }); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .wrongScope) }
        XCTAssertEqual(try read(h, plan: plan)?.phase, .prepared); let count = await posts.calls; XCTAssertEqual(count, 0)
    }
    func testProviderRefusalIsDurableAndDoesNotAutomaticallyRetry() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal(), posts = Counter()
        let result = try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal,
            inspect: { _, _, _ in try self.inspection(h, plan: plan) }, create: { _, _, _, _ in await posts.record(); return .rejected(.rateLimited) })
        XCTAssertEqual(result.phase, .rejected); XCTAssertEqual(result.refusal, .rateLimited)
        do { _ = try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal,
            inspect: { _, _, _ in throw Interrupted() }, create: { _, _, _, _ in await posts.record(); throw Interrupted() }); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
        let count = await posts.calls; XCTAssertEqual(count, 1); XCTAssertEqual(try read(h, plan: plan), result)
    }
    func testChangedInventoryAfterPostCannotCommitAcrossTheChangedScope() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal()
        do { _ = try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal,
            inspect: { _, _, _ in try self.inspection(h, plan: plan) }, create: { _, _, _, _ in
                try h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
                return try .created(self.observation(h, plan: plan))
            }); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        XCTAssertEqual(try read(h, plan: plan)?.phase, .dispatched)
    }
    func testCrossedInjectedCreationResultCannotBecomeOwnedState() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal()
        let result = try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal,
            inspect: { _, _, _ in try self.inspection(h, plan: plan) }, create: { _, _, _, _ in
                .created(.init(accountID: String(repeating: "c", count: 32), tunnelID: "11111111-1111-4111-8111-111111111111", name: plan.tunnelName))
            })
        XCTAssertEqual(result.phase, .unknown); XCTAssertNil(result.tunnelID)
    }
}
