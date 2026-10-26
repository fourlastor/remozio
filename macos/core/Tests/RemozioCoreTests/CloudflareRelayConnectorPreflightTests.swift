import Foundation
import XCTest
@testable import RemozioCore

enum RelayConnectorPreflightReplies {
    static func steps(_ f: DNSRecordFixture, extraApplications: [[String: Any]] = []) throws -> [RelayIngressProbe.Step] {
        var replies = try RelayPublicationReplies.steps(f, extraApplications: extraApplications)
        replies.replaceSubrange(7...8, with: [RelayIngressProbe.reply(try f.dnsReply())])
        return replies
    }
    static func ownerSteps(_ f: DNSRecordFixture, extraApplications: [[String: Any]] = []) throws -> [RelayIngressProbe.Step] {
        try [RelayIngressProbe.reply(RelayIngressProviderFixture.metadata(configuration: XCTUnwrap(f.base.h.f.proposal().cloudflare),
            plan: f.base.plan))] + steps(f, extraApplications: extraApplications)
    }
}

/// Synthetic provider replies do not prove propagation, native authorization or approval delivery.
final class CloudflareRelayConnectorPreflightTests: XCTestCase, @unchecked Sendable {
    private func inspect(_ f: DNSRecordFixture, record: SharedSetupDNSRecord,
                         probe: RelayIngressProbe) async throws -> CloudflareRelayConnectorPreflight {
        try await CloudflareRelayConnectorPreflightClient(send: { try await probe.send($0) }).inspect(XCTUnwrap(f.base.h.f.proposal().cloudflare),
            expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel, application: f.access, record: record)
    }
    func testCreatedDNSUsesExactReadbackAndAllProviderChecksWithoutMutations() async throws {
        let f = try DNSRecordFixture(), record = try f.retainCreated(), probe = try RelayIngressProbe(RelayConnectorPreflightReplies.steps(f))
        let result = try await inspect(f, record: record, probe: probe)
        XCTAssertNoThrow(try result.validate(expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel,
            application: f.access, record: record))
        let requests = await probe.all(); XCTAssertEqual(requests.count, 10)
        XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" && $0.httpBody == nil })
        XCTAssertTrue(requests[7].url?.path.hasSuffix("/dns_records/" + DNSRecordFixture.providerID) == true)
        XCTAssertFalse(requests.contains { $0.url?.query?.contains("name.exact=") == true })
        XCTAssertEqual(try f.read(), record); XCTAssertEqual(String(reflecting: result), "CloudflareRelayConnectorPreflight(redacted)")
    }
    func testDenialAtEveryReceiptCannotReturnPartialEvidence() async throws {
        let f = try DNSRecordFixture(), record = try f.retainCreated()
        for index in 0..<10 {
            var replies = try RelayConnectorPreflightReplies.steps(f); replies[index] = RelayIngressProbe.reply(Data(), status: 403)
            let probe = RelayIngressProbe(replies)
            do { _ = try await inspect(f, record: record, probe: probe); XCTFail(String(index)) }
            catch { XCTAssertEqual(error as? CloudflareProvisioningError, .unauthorized) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, index + 1)
        }
    }
    func testCancellationAtEveryReceiptStopsBeforeTheNextRequest() async throws {
        let f = try DNSRecordFixture(), record = try f.retainCreated()
        for index in 1...10 {
            let probe = try RelayIngressProbe(RelayConnectorPreflightReplies.steps(f), hook: { count, _ in
                if count == index { withUnsafeCurrentTask { $0?.cancel() } }
            })
            let task = Task { @Sendable in try await self.inspect(f, record: record, probe: probe) }
            do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, index)
        }
    }
    func testMissingDNSAcceptanceSendsNothingAndWrongDNSReadbackStopsBeforeFinalRoutes() async throws {
        let f = try DNSRecordFixture(), unresolved = try f.begin(), probe = RelayIngressProbe([])
        do { _ = try await inspect(f, record: unresolved, probe: probe); XCTFail() } catch {}
        let empty = await probe.all(); XCTAssertTrue(empty.isEmpty)
        let sent = try unresolved.transition(to: .dispatched); try f.replace(sent, previous: unresolved)
        let record = try sent.transition(to: .created, dnsRecordID: DNSRecordFixture.providerID); try f.replace(record, previous: sent)
        for changes: [String: Any] in [["content": "wrong.invalid"], ["meta": ["shadowed_by": ["other"]]], ["meta": NSNull()]] {
            var replies = try RelayConnectorPreflightReplies.steps(f); replies[7] = RelayIngressProbe.reply(try f.dnsReply(changes: changes))
            let selected = RelayIngressProbe(replies)
            do { _ = try await inspect(f, record: record, probe: selected); XCTFail() } catch {}
            let requests = await selected.all(); XCTAssertEqual(requests.count, 8)
        }
    }
    func testExistingWildcardContractIsPreservedAndUnresolvedMatchesCannotPublish() async throws {
        let f = try DNSRecordFixture(), record = try f.retainCreated()
        let wildcard = "*." + f.base.plan.hostname.split(separator: ".").dropFirst().joined(separator: ".")
        let allowed = try RelayIngressProbe(RelayConnectorPreflightReplies.steps(f, extraApplications: [AccessHostnameReplies.row(1, uri: wildcard)]))
        let result = try await inspect(f, record: record, probe: allowed)
        XCTAssertEqual(result.prerequisites.hostnameAssessment, .exactHostnamePrecedesBroaderWildcardRoots)
        for uri in [f.base.plan.hostname, wildcard + "/private"] {
            let denied = try RelayIngressProbe(RelayConnectorPreflightReplies.steps(f, extraApplications: [AccessHostnameReplies.row(1, uri: uri)]))
            do { _ = try await inspect(f, record: record, probe: denied); XCTFail() }
            catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
        }
    }
    func testReadbackCannotValidateAnotherAcceptedDNSCreationAttempt() async throws {
        let f = try DNSRecordFixture(), record = try f.retainCreated(), probe = try RelayIngressProbe(RelayConnectorPreflightReplies.steps(f))
        let observed = try await inspect(f, record: record, probe: probe)
        let other = try SharedSetupDNSRecord(expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel, application: f.access)
            .transition(to: .dispatched).transition(to: .created, dnsRecordID: DNSRecordFixture.providerID)
        XCTAssertThrowsError(try observed.validate(expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel,
            application: f.access, record: other))
    }
}
