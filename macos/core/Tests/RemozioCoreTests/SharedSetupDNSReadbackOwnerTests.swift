import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned fixtures and synthetic HTTP only. No provider resource or installed service is touched.
final class SharedSetupDNSReadbackOwnerTests: XCTestCase, @unchecked Sendable {
    private func steps(_ f: DNSRecordFixture) throws -> [RelayIngressProbe.Step] {
        try [RelayIngressProbe.reply(RelayIngressProviderFixture.metadata(configuration: XCTUnwrap(f.base.h.f.proposal().cloudflare), plan: f.base.plan)),
            RelayIngressProbe.reply(f.dnsReply())]
    }
    private func inspect(_ owner: SetupAccountOwner, f: DNSRecordFixture, expected: SetupPortableImportProgress,
                         probe: RelayIngressProbe) async throws -> CloudflareDNSRecordObservation {
        try await owner.inspectImportedDNSRecord(callerUID: getuid(), expected: expected, proposal: f.base.h.f.proposal(), send: { try await probe.send($0) })
    }
    private func replaceFile(_ path: String, bytes: Data) throws {
        let temp = path + ".replacement"; try bytes.write(to: URL(fileURLWithPath: temp))
        XCTAssertEqual(chmod(temp, 0o600), 0); XCTAssertEqual(rename(temp, path), 0)
    }
    func testExactRecordReadReleasesDatabaseLeasesAndPreservesProgress() async throws {
        let f = try DNSRecordFixture(), record = try f.retainCreated(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let expected = try f.base.h.progress(owner), probe = try RelayIngressProbe(steps(f), hook: { _, _ in
            try f.base.h.machine { machine in try machine.withSharedImportJournal { journal in XCTAssertEqual(try journal?.records(), [f.base.h.intent]) } }
        })
        let observed = try await inspect(owner, f: f, expected: expected, probe: probe)
        XCTAssertNoThrow(try observed.validate(expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel, application: f.access, record: record))
        XCTAssertEqual(try f.base.h.progress(owner), expected); XCTAssertEqual(try f.read(), record)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
        XCTAssertTrue(requests[1].url?.path.hasSuffix("/dns_records/" + DNSRecordFixture.providerID) == true)
    }
    func testIdenticalDNSRecordReplacementCannotReturnAnObservation() async throws {
        let f = try DNSRecordFixture(), record = try f.retainCreated(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == 2 { try self.replaceFile(f.path, bytes: record.bytes) } })
        do { _ = try await inspect(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testIdenticalAccessRecordReplacementCannotReturnDNSReadback() async throws {
        let f = try DNSRecordFixture(); _ = try f.retainCreated(); let owner = try f.base.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == 2 { try self.replaceFile(f.base.path, bytes: f.access.bytes) } })
        do { _ = try await inspect(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
    }
    func testIdenticalTunnelRecordReplacementCannotReturnDNSReadback() async throws {
        let f = try DNSRecordFixture(); _ = try f.retainCreated(); let owner = try f.base.h.owner(); defer { try? owner.close() }
        let path = URL(fileURLWithPath: f.path).deletingLastPathComponent().appendingPathComponent(AdministrativeSetupPublication.File.importRelayProvisioning(accountID: f.base.h.intent.scope.accountID).name).path
        let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == 2 { try self.replaceFile(path, bytes: f.base.tunnel.bytes) } })
        do { _ = try await inspect(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
    }
    func testScopeChangeDuringMetadataReadStopsBeforeDNSCredentialsAreSent() async throws {
        let f = try DNSRecordFixture(); _ = try f.retainCreated(); let owner = try f.base.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == 1 {
            try f.base.h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
        } })
        do { _ = try await inspect(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
    func testLateInventoryChangeCannotReturnDNSReadback() async throws {
        let f = try DNSRecordFixture(); _ = try f.retainCreated(); let owner = try f.base.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == 2 {
            try f.base.h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
        } })
        do { _ = try await inspect(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
    }
    func testProviderFailureDoesNotHideALateLocalDNSReplacement() async throws {
        let f = try DNSRecordFixture(), record = try f.retainCreated(), owner = try f.base.h.owner(); defer { try? owner.close() }
        var replies = try steps(f); replies[1] = .lost
        let probe = RelayIngressProbe(replies, hook: { count, _ in if count == 2 { try self.replaceFile(f.path, bytes: record.bytes) } })
        do { _ = try await inspect(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
    }
    func testMissingDNSRecordDoesNotCreateStateOrQueryDNS() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe([steps(f)[0]])
        do { _ = try await inspect(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
        XCTAssertNil(try f.read()); let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
    func testPreparedDispatchedAndUnknownStatesCannotTriggerAdoptionOrRetry() async throws {
        for selected in 0..<3 {
            let f = try DNSRecordFixture(), prepared = try f.begin()
            var retained = prepared
            if selected >= 1 { let sent = try prepared.transition(to: .dispatched); try f.replace(sent, previous: prepared); retained = sent }
            if selected == 2 { let unknown = try retained.transition(to: .unknown); try f.replace(unknown, previous: retained); retained = unknown }
            let owner = try f.base.h.owner(); defer { try? owner.close() }; let probe = try RelayIngressProbe([steps(f)[0]])
            do { _ = try await inspect(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
            catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
            XCTAssertEqual(try f.read(), retained); let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
    }
    func testShutdownDuringReadCannotReturnEvidenceAndDrainsTheWork() async throws {
        let f = try DNSRecordFixture(); _ = try f.retainCreated(); let owner = try f.base.h.owner()
        let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == 2 {
            XCTAssertThrowsError(try owner.close()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
        } })
        do { _ = try await inspect(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
        XCTAssertNoThrow(try owner.close())
    }
    func testWrongCallerAndChangedProposalSendNoRequests() async throws {
        let f = try DNSRecordFixture(); _ = try f.retainCreated(); let owner = try f.base.h.owner(); defer { try? owner.close() }
        let proposal = try f.base.h.f.proposal(), expected = try f.base.h.progress(owner), probe = RelayIngressProbe([])
        for (uid, selected) in [(getuid() + 1, proposal), (getuid(), PortableSetup(defaults: proposal.defaults))] {
            do { _ = try await owner.inspectImportedDNSRecord(callerUID: uid, expected: expected, proposal: selected, send: { try await probe.send($0) }); XCTFail() } catch {}
        }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
}
