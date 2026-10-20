import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned protected fixtures only. No provider, administrator or installed-service activity is used.
final class SharedSetupAccessHostnameOwnerTests: XCTestCase, @unchecked Sendable {
    private func steps(_ f: AccessApplicationFixture) throws -> [RelayIngressProbe.Step] {
        try [RelayIngressProbe.reply(RelayIngressProviderFixture.metadata(configuration: XCTUnwrap(f.h.f.proposal().cloudflare), plan: f.plan)),
            RelayIngressProbe.reply(AccessHostnameReplies.page([AccessHostnameReplies.own(f)], size: 1, total: 2)),
            RelayIngressProbe.reply(AccessHostnameReplies.page([AccessHostnameReplies.row(1, uri: "unrelated.invalid")], number: 2, size: 1, total: 2))]
    }
    private func inspect(_ owner: SetupAccountOwner, f: AccessApplicationFixture, expected: SetupPortableImportProgress,
                         probe: RelayIngressProbe) async throws -> CloudflareAccessHostnameInventory {
        try await owner.inspectImportedAccessHostnameInventory(callerUID: getuid(), expected: expected, proposal: f.h.f.proposal(), send: { try await probe.send($0) })
    }
    func testAccountInventoryReleasesDatabaseLeasesAndPreservesImportProgress() async throws {
        let f = try AccessApplicationFixture(), application = try f.retainCreated(), owner = try f.h.owner(); defer { try? owner.close() }
        let expected = try f.h.progress(owner), probe = try RelayIngressProbe(steps(f), hook: { _, _ in
            try f.h.machine { machine in try machine.withSharedImportJournal { journal in XCTAssertEqual(try journal?.records(), [f.h.intent]) } }
        })
        let observed = try await inspect(owner, f: f, expected: expected, probe: probe)
        XCTAssertNoThrow(try observed.validate(expected: f.h.intent, plan: f.plan, createdTunnel: f.tunnel, application: application))
        XCTAssertEqual(observed.applicationCount, 2); XCTAssertEqual(try f.h.progress(owner), expected); XCTAssertEqual(try f.read(), application)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 3); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
    }
    func testIdenticalApplicationReplacementStopsBeforeTheNextPage() async throws {
        let f = try AccessApplicationFixture(), application = try f.retainCreated(), owner = try f.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == 2 {
            let temp = f.path + ".replacement"; try application.bytes.write(to: URL(fileURLWithPath: temp))
            XCTAssertEqual(chmod(temp, 0o600), 0); XCTAssertEqual(rename(temp, f.path), 0)
        } })
        do { _ = try await inspect(owner, f: f, expected: f.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testInventoryChangeAtTheLastPageCannotReturnACompleteObservation() async throws {
        let f = try AccessApplicationFixture(); _ = try f.retainCreated(); let owner = try f.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == 3 {
            try f.h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
        } })
        do { _ = try await inspect(owner, f: f, expected: f.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 3)
    }
    func testChangedTunnelRecordStopsBeforeTheNextPage() async throws {
        let f = try AccessApplicationFixture(); _ = try f.retainCreated(); let owner = try f.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == 2 {
            let path = URL(fileURLWithPath: f.path).deletingLastPathComponent().appendingPathComponent(AdministrativeSetupPublication.File.importRelayProvisioning(accountID: f.h.intent.scope.accountID).name).path
            let temp = path + ".replacement"; try f.tunnel.bytes.write(to: URL(fileURLWithPath: temp))
            XCTAssertEqual(chmod(temp, 0o600), 0); XCTAssertEqual(rename(temp, path), 0)
        } })
        do { _ = try await inspect(owner, f: f, expected: f.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testLateProviderFailureDoesNotHideALocalScopeChange() async throws {
        let f = try AccessApplicationFixture(); _ = try f.retainCreated(); let owner = try f.h.owner(); defer { try? owner.close() }
        var replies = try steps(f); replies[2] = .lost
        let probe = RelayIngressProbe(replies, hook: { count, _ in if count == 3 {
            try f.h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
        } })
        do { _ = try await inspect(owner, f: f, expected: f.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
    }
    func testShutdownDuringPaginationStopsFurtherReads() async throws {
        let f = try AccessApplicationFixture(); _ = try f.retainCreated(); let owner = try f.h.owner()
        let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == 2 {
            XCTAssertThrowsError(try owner.close()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
        } })
        do { _ = try await inspect(owner, f: f, expected: f.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
        XCTAssertNoThrow(try owner.close()); let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testMissingApplicationDoesNotQueryTheAccessInventory() async throws {
        let f = try AccessApplicationFixture(), owner = try f.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe([steps(f)[0]])
        do { _ = try await inspect(owner, f: f, expected: f.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1); XCTAssertNil(try f.read())
    }
    func testWrongCallerSendsNoRequests() async throws {
        let f = try AccessApplicationFixture(); _ = try f.retainCreated(); let owner = try f.h.owner(); defer { try? owner.close() }
        let probe = RelayIngressProbe([])
        do { _ = try await owner.inspectImportedAccessHostnameInventory(callerUID: getuid() + 1, expected: f.h.progress(owner),
            proposal: f.h.f.proposal(), send: { try await probe.send($0) }); XCTFail() } catch {}
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
}
