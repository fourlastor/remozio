import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned protected fixtures only. No provider account,Root service or device is used.
final class SharedSetupRelayPrivateRouteOwnerTests: XCTestCase, @unchecked Sendable {
    private func retain(_ h: RelayProvisioningFixture, plan: SharedSetupImportRelayPlan) throws -> SharedSetupRelayProvisioningRecord {
        try h.directory { directory in
            let prepared = try SharedSetupRelayProvisioningStorage.begin(expected: h.intent, plan: plan, directory: directory, owner: getuid(), verifyCurrent: {})
            let sent = try prepared.transition(to: .dispatched), created = try sent.transition(to: .created, tunnelID: "11111111-1111-4111-8111-111111111111")
            for (next, old) in [(sent, prepared), (created, sent)] {
                try SharedSetupRelayProvisioningStorage.replace(next, previous: old, expected: h.intent, plan: plan, directory: directory, owner: getuid(), verifyCurrent: {})
            }
            return created
        }
    }
    private func metadata(_ h: RelayProvisioningFixture, plan: SharedSetupImportRelayPlan) throws -> RelayIngressProbe.Step {
        RelayIngressProbe.reply(try RelayIngressProviderFixture.metadata(configuration: XCTUnwrap(h.f.proposal().cloudflare), plan: plan))
    }
    private func empty() throws -> RelayIngressProbe.Step { RelayIngressProbe.reply(try RelayPrivateRouteReplies.page()) }
    private func route() throws -> RelayIngressProbe.Step {
        RelayIngressProbe.reply(try RelayPrivateRouteReplies.page(results: [["tunnel_id": "11111111-1111-4111-8111-111111111111", "hostname": "private.invalid"]]))
    }
    func testOwnerReadsExactIdentityAndBothRouteTypesWithoutAdvancingImport() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), created = try retain(h, plan: plan), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal()
        let probe = try RelayIngressProbe([metadata(h, plan: plan), empty(), empty()], hook: { _, _ in
            try h.machine { machine in try machine.withSharedImportJournal { journal in XCTAssertEqual(try journal?.records(), [h.intent]) } }
        })
        let result = try await owner.inspectImportedRelayPrivateRoutes(callerUID: getuid(), expected: expected, proposal: proposal, send: { try await probe.send($0) })
        XCTAssertNoThrow(try result.validate(expected: h.intent, plan: plan, created: created))
        XCTAssertEqual(try h.progress(owner), expected); let requests = await probe.all(); XCTAssertEqual(requests.count, 3)
        XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
    }
    func testPrivateIpRoutePreventsIngressMutationWithoutDeletingTheRoute() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), _ = try retain(h, plan: plan), owner = try h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe([metadata(h, plan: plan), route()])
        do { _ = try await owner.applyImportedRelayIngress(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
    }
    func testPrivateHostnameRoutePreventsIngressMutationWithoutDeletingTheRoute() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), _ = try retain(h, plan: plan), owner = try h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe([metadata(h, plan: plan), empty(), route()])
        do { _ = try await owner.applyImportedRelayIngress(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 3); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
    }
    func testARouteAddedAfterIngressWritePreventsSuccessfulReadiness() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), created = try retain(h, plan: plan), owner = try h.owner(); defer { try? owner.close() }
        let config = try XCTUnwrap(h.f.proposal().cloudflare)
        let probe = try RelayIngressProbe([metadata(h, plan: plan), empty(), empty(), RelayIngressProbe.reply(Data()),
            RelayIngressProbe.reply(RelayIngressProviderFixture.ingress(configuration: config, plan: plan)), empty(), route()])
        do { _ = try await owner.applyImportedRelayIngress(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 7); XCTAssertEqual(requests.filter { $0.httpMethod == "PUT" }.count, 1)
        let retained = try h.directory { try SharedSetupRelayProvisioningStorage.read(expected: h.intent, plan: plan, directory: $0, owner: getuid()) }
        XCTAssertEqual(retained, created)
    }
    func testInventoryChangeBetweenRouteReadsStopsFurtherCredentialTransmission() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), _ = try retain(h, plan: plan), owner = try h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe([metadata(h, plan: plan), empty(), empty()], hook: { count, _ in if count == 2 {
            try h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
        } })
        do { _ = try await owner.inspectImportedRelayPrivateRoutes(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), send: { try await probe.send($0) }); XCTFail() } catch {}
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testLateInventoryChangeCannotReturnRouteAbsenceEvidence() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), _ = try retain(h, plan: plan), owner = try h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe([metadata(h, plan: plan), empty(), empty()], hook: { count, _ in if count == 3 {
            try h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
        } })
        do { _ = try await owner.inspectImportedRelayPrivateRoutes(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 3)
    }
    func testShutdownDuringRouteReadPreventsTheNextRequest() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), _ = try retain(h, plan: plan), owner = try h.owner()
        let probe = try RelayIngressProbe([metadata(h, plan: plan), empty(), empty()], hook: { count, _ in if count == 2 {
            XCTAssertThrowsError(try owner.close()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
        } })
        do { _ = try await owner.inspectImportedRelayPrivateRoutes(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), send: { try await probe.send($0) }); XCTFail() } catch {}
        XCTAssertNoThrow(try owner.close()); let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testWrongCallerAndUnresolvedCreationNeverTransmitCredentials() async throws {
        let h = try RelayProvisioningFixture(), _ = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), proposal = try h.f.proposal(), probe = RelayIngressProbe([])
        for uid in [getuid(), getuid() + 1] {
            do { _ = try await owner.inspectImportedRelayPrivateRoutes(callerUID: uid, expected: expected, proposal: proposal, send: { try await probe.send($0) }); XCTFail() } catch {}
        }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
}
