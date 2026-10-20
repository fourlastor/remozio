import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// One protected scope spans all read-only checks. Native admission and real provider behavior remain separate gates.
final class SharedSetupRelayPublicationPreflightOwnerTests: XCTestCase, @unchecked Sendable {
    private func inspect(_ owner: SetupAccountOwner, f: DNSRecordFixture, expected: SetupPortableImportProgress,
                         probe: RelayIngressProbe) async throws -> CloudflareRelayPublicationPreflight {
        try await owner.inspectImportedRelayPublicationPreflight(callerUID: getuid(), expected: expected, proposal: f.base.h.f.proposal(), send: { try await probe.send($0) })
    }
    private func replaceFile(_ path: String, bytes: Data) throws {
        let temp = path + ".replacement"; try bytes.write(to: URL(fileURLWithPath: temp))
        XCTAssertEqual(chmod(temp, 0o600), 0); XCTAssertEqual(rename(temp, path), 0)
    }
    func testAllChecksReleaseDatabaseLeasesAndAdvanceNoImportOrDNSState() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let expected = try f.base.h.progress(owner), probe = try RelayIngressProbe(RelayPublicationReplies.ownerSteps(f), hook: { _, _ in
            try f.base.h.machine { machine in try machine.withSharedImportJournal { journal in XCTAssertEqual(try journal?.records(), [f.base.h.intent]) } }
        })
        let result = try await inspect(owner, f: f, expected: expected, probe: probe)
        XCTAssertEqual(result.hostnameAssessment, .noOtherMatchObserved); XCTAssertEqual(try f.base.h.progress(owner), expected)
        XCTAssertEqual(try f.base.read(), f.access); XCTAssertNil(try f.read())
        let requests = await probe.all(); XCTAssertEqual(requests.count, 11); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
    }
    func testLocalScopeChangeAtEveryReceiptStopsBeforeTheNextRequestOrResult() async throws {
        for index in 1...11 {
            let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
            let probe = try RelayIngressProbe(RelayPublicationReplies.ownerSteps(f), hook: { count, _ in if count == index {
                try f.base.h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
            } })
            do { _ = try await inspect(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail(String(index)) }
            catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, index)
        }
    }
    func testAccessReplacementStopsBeforeDNSCredentialsAreSent() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(RelayPublicationReplies.ownerSteps(f), hook: { count, _ in if count == 5 {
            try self.replaceFile(f.base.path, bytes: f.access.bytes)
        } })
        do { _ = try await inspect(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 5)
    }
    func testPlanReplacementDuringDNSReadStopsBeforeTheNextRequest() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(RelayPublicationReplies.ownerSteps(f), hook: { count, _ in if count == 8 {
            try self.replaceFile(f.base.h.path, bytes: f.base.plan.bytes)
        } })
        do { _ = try await inspect(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() } catch {}
        let requests = await probe.all(); XCTAssertEqual(requests.count, 8)
    }
    func testFinalProviderFailureDoesNotHideALocalScopeChange() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }; var replies = try RelayPublicationReplies.ownerSteps(f); replies[10] = .lost
        let probe = RelayIngressProbe(replies, hook: { count, _ in if count == 11 {
            try f.base.h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
        } })
        do { _ = try await inspect(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
    }
    func testShutdownStopsBeforeDNSAndDrainsAllOutstandingWork() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner()
        let probe = try RelayIngressProbe(RelayPublicationReplies.ownerSteps(f), hook: { count, _ in if count == 7 {
            XCTAssertThrowsError(try owner.close()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
        } })
        do { _ = try await inspect(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
        XCTAssertNoThrow(try owner.close()); let requests = await probe.all(); XCTAssertEqual(requests.count, 7)
    }
    func testWrongCallerAndChangedProposalHaveNoNetworkEffects() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let proposal = try f.base.h.f.proposal(), expected = try f.base.h.progress(owner), probe = RelayIngressProbe([])
        for (uid, selected) in [(getuid() + 1, proposal), (getuid(), PortableSetup(defaults: proposal.defaults))] {
            do { _ = try await owner.inspectImportedRelayPublicationPreflight(callerUID: uid, expected: expected, proposal: selected, send: { try await probe.send($0) }); XCTFail() } catch {}
        }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
    func testBroaderWildcardPrecedenceIsReportedWithoutChangingTheApprovedSetup() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let wildcard = "*." + f.base.plan.hostname.split(separator: ".").dropFirst().joined(separator: ".")
        let expected = try f.base.h.progress(owner), probe = try RelayIngressProbe(RelayPublicationReplies.ownerSteps(f, extraApplications: [AccessHostnameReplies.row(1, uri: wildcard)]))
        let result = try await inspect(owner, f: f, expected: expected, probe: probe)
        XCTAssertEqual(result.hostnameAssessment, .exactHostnamePrecedesBroaderWildcardRoots); XCTAssertEqual(try f.base.h.progress(owner), expected)
        XCTAssertEqual(try f.base.read(), f.access); XCTAssertNil(try f.read())
    }
}
