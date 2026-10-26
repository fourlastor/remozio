import CryptoKit
import Foundation
import XCTest
@testable import RemozioCore

/// Synthetic provider replies only. Live DNS, Access coverage and installed services remain separate gates.
final class CloudflareDNSRecordClientTests: XCTestCase, @unchecked Sendable {
    private func create(_ f: DNSRecordFixture, probe: RelayIngressProbe, record: SharedSetupDNSRecord? = nil) async throws -> CloudflareDNSCreationOutcome {
        try await CloudflareDNSRecordClient(send: { try await probe.send($0) }).create(XCTUnwrap(f.base.h.f.proposal().cloudflare), expected: f.base.h.intent,
            plan: f.base.plan, createdTunnel: f.base.tunnel, application: f.access, dispatched: record ?? f.begin().transition(to: .dispatched))
    }
    private func inspect(_ f: DNSRecordFixture, probe: RelayIngressProbe, record: SharedSetupDNSRecord? = nil) async throws -> CloudflareDNSRecordObservation {
        try await CloudflareDNSRecordClient(send: { try await probe.send($0) }).inspect(XCTUnwrap(f.base.h.f.proposal().cloudflare), expected: f.base.h.intent,
            plan: f.base.plan, createdTunnel: f.base.tunnel, application: f.access, record: record ?? f.read() ?? f.retainCreated())
    }
    private func absent(_ f: DNSRecordFixture, probe: RelayIngressProbe) async throws {
        try await CloudflareDNSRecordClient(send: { try await probe.send($0) }).inspectAbsent(XCTUnwrap(f.base.h.f.proposal().cloudflare),
            expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel, application: f.access)
    }
    private func empty(info: [String: Any] = [:]) throws -> RelayIngressProbe.Step { RelayIngressProbe.reply(try RelayPrivateRouteReplies.page(info: info)) }
    func testCreationIsOneFixedProxiedCnameForTheCreatedTunnel() async throws {
        let f = try DNSRecordFixture(), probe = try RelayIngressProbe([RelayIngressProbe.reply(f.dnsReply())])
        guard case let .created(identity) = try await create(f, probe: probe) else { return XCTFail() }
        let requests = await probe.all(), request = try XCTUnwrap(requests.first)
        XCTAssertEqual(requests.count, 1); XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.url?.absoluteString, "https://api.cloudflare.com/client/v4/zones/" + identity.zoneID + "/dns_records?include_shadow_metadata=true")
        let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as? [String: Any])
        XCTAssertEqual(Set(fields.keys), ["name", "type", "content", "proxied", "ttl"])
        XCTAssertEqual(fields["name"] as? String, f.base.plan.hostname); XCTAssertEqual(fields["type"] as? String, "CNAME")
        XCTAssertEqual(fields["content"] as? String, f.base.tunnel.tunnelID! + ".cfargotunnel.com")
        XCTAssertEqual(fields["proxied"] as? Bool, true); XCTAssertEqual(fields["ttl"] as? Int, 1)
        XCTAssertEqual(request.httpBody, try SharedSetupDNSRecord.requestBody(plan: f.base.plan, tunnelID: XCTUnwrap(f.base.tunnel.tunnelID)))
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
        XCTAssertTrue(request.value(forHTTPHeaderField: "Authorization")?.hasPrefix("Bearer ") == true)
        XCTAssertEqual(String(reflecting: identity), "CloudflareDNSRecordIdentity(redacted)")
    }
    func testCreationAcknowledgementRequiresTheExactRecordConfiguration() async throws {
        let f = try DNSRecordFixture()
        let variants: [(String, Any)] = [("id", "wrong"), ("name", "other.invalid"), ("type", "A"), ("content", "other.cfargotunnel.com"),
            ("proxied", false), ("proxiable", false), ("ttl", 300), ("zone_id", String(repeating: "c", count: 32)),
            ("meta", ["shadowed_by": [String(repeating: "a", count: 32)]])]
        for (key, value) in variants {
            let probe = try RelayIngressProbe([RelayIngressProbe.reply(f.dnsReply(changes: [key: value]))])
            guard case .unknown = try await create(f, probe: probe) else { return XCTFail(key) }
        }
    }
    func testAmbiguousCreationRepliesAreNeverRetried() async throws {
        let f = try DNSRecordFixture()
        for step in [RelayIngressProbe.Step.lost, .cancelled, RelayIngressProbe.reply(Data("not-json".utf8)),
            RelayIngressProbe.reply(Data(repeating: 32, count: FCMHTTPTransport.maximumResponseBytes + 1))] {
            let probe = RelayIngressProbe([step])
            guard case .unknown = try await create(f, probe: probe) else { return XCTFail() }
            let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
    }
    func testDefiniteCreationRefusalsAreTypedAndConflictsStayUnknown() async throws {
        let f = try DNSRecordFixture()
        for (status, expected): (Int, SharedSetupDNSRecord.Refusal) in [(401, .unauthorized), (403, .unauthorized), (429, .rateLimited), (400, .providerRejected)] {
            let probe = RelayIngressProbe([RelayIngressProbe.reply(Data(), status: status)])
            guard case let .rejected(actual) = try await create(f, probe: probe) else { return XCTFail() }; XCTAssertEqual(actual, expected)
        }
        for status in [201, 302, 408, 409, 425, 500] {
            let probe = try RelayIngressProbe([RelayIngressProbe.reply(f.dnsReply(), status: status)])
            guard case .unknown = try await create(f, probe: probe) else { return XCTFail() }
        }
    }
    func testValidCreationReceiptSurvivesCancellationForDurableRetention() async throws {
        let f = try DNSRecordFixture(), probe = try RelayIngressProbe([RelayIngressProbe.reply(f.dnsReply())], hook: { _, _ in withUnsafeCurrentTask { $0?.cancel() } })
        let task = Task { @Sendable in try await self.create(f, probe: probe) }
        guard case .created = try await task.value else { return XCTFail() }
    }
    func testAbsencePreflightChecksExactNamesAndParentDelegationsInTheBoundZone() async throws {
        let f = try DNSRecordFixture(), probe = try RelayIngressProbe([empty(), empty()])
        try await absent(f, probe: probe); let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
        for (index, request) in requests.enumerated() {
            XCTAssertEqual(request.httpMethod, "GET"); XCTAssertNil(request.httpBody)
            let url = try XCTUnwrap(URLComponents(url: XCTUnwrap(request.url), resolvingAgainstBaseURL: false))
            XCTAssertEqual(url.host, "api.cloudflare.com")
            XCTAssertEqual(url.path, "/client/v4/zones/" + (try XCTUnwrap(f.base.h.f.proposal().cloudflare)).zoneID + "/dns_records")
            XCTAssertEqual(Dictionary(uniqueKeysWithValues: (url.queryItems ?? []).map { ($0.name, $0.value ?? "") }),
                [index == 0 ? "name.exact" : "shadowing_name": f.base.plan.hostname, "include_shadow_metadata": "true", "page": "1", "per_page": "100"])
        }
    }
    func testExistingRecordsAndParentNSDelegationsStopWithoutAdoptionOrDeletion() async throws {
        for delegation in [false, true] {
            let f = try DNSRecordFixture(), occupied = RelayIngressProbe.reply(try RelayPrivateRouteReplies.page(results: [["type": delegation ? "NS" : "CNAME"]]))
            let probe = try RelayIngressProbe(delegation ? [empty(), occupied] : [occupied])
            do { try await absent(f, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, delegation ? 2 : 1)
            XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
        }
    }
    func testFilteredAbsenceDoesNotRequireTheWholeZoneToHaveNoRecords() async throws {
        let f = try DNSRecordFixture(), probe = try RelayIngressProbe([empty(info: ["total_count": 500]), empty(info: ["total_count": 500])])
        try await absent(f, probe: probe)
    }
    func testMalformedOrDeniedDelegationReadCannotProveAbsence() async throws {
        let f = try DNSRecordFixture()
        for step in [RelayIngressProbe.Step.lost, RelayIngressProbe.reply(Data(), status: 403), RelayIngressProbe.reply(Data("not-json".utf8)),
            RelayIngressProbe.reply(try RelayPrivateRouteReplies.page(info: ["count": 1]))] {
            let probe = try RelayIngressProbe([empty(), step])
            do { try await absent(f, probe: probe); XCTFail() } catch {}
            let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
        }
    }
    func testReadbackUsesOnlyTheRetainedProviderIdentifier() async throws {
        let f = try DNSRecordFixture(), record = try f.retainCreated(), probe = try RelayIngressProbe([RelayIngressProbe.reply(f.dnsReply())])
        let observed = try await inspect(f, probe: probe, record: record)
        XCTAssertNoThrow(try observed.validate(expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel, application: f.access, record: record))
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1); XCTAssertEqual(requests[0].httpMethod, "GET")
        XCTAssertEqual(requests[0].url?.path, "/client/v4/zones/" + observed.identity.zoneID + "/dns_records/" + DNSRecordFixture.providerID)
        XCTAssertEqual(requests[0].url?.query, "include_shadow_metadata=true")
        XCTAssertEqual(String(reflecting: observed), "CloudflareDNSRecordObservation(redacted)")
    }
    func testReadbackRejectsCrossedIdentityTargetProxyAndShadowMetadata() async throws {
        let f = try DNSRecordFixture(); _ = try f.retainCreated()
        let variants: [(String, Any)] = [("id", String(repeating: "a", count: 32)), ("name", "other.invalid"), ("type", "AAAA"),
            ("content", "other.cfargotunnel.com"), ("proxied", false), ("proxiable", false), ("ttl", 300),
            ("zone_id", String(repeating: "c", count: 32)), ("meta", ["shadowed_by": ["parent-ns"]]),
            ("meta", ["dead_glue": true]), ("meta", ["is_glue": true])]
        for (key, value) in variants {
            let probe = try RelayIngressProbe([RelayIngressProbe.reply(f.dnsReply(changes: [key: value]))])
            do { _ = try await inspect(f, probe: probe); XCTFail(key) } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        }
    }
    func testReadbackCanUseCurrentResponsesWithoutLegacyZoneId() async throws {
        let f = try DNSRecordFixture(), probe = try RelayIngressProbe([RelayIngressProbe.reply(f.dnsReply(changes: ["zone_id": NSNull()]))])
        let result = try await inspect(f, probe: probe); XCTAssertEqual(result.identity.hostname, f.base.plan.hostname)
    }
    func testMalformedAndFailedReadbackEnvelopesNeverReturnEvidence() async throws {
        let f = try DNSRecordFixture(); _ = try f.retainCreated()
        let replies = try [f.dnsReply(envelope: ["success": false]), f.dnsReply(envelope: ["result": NSNull()]),
            f.dnsReply(envelope: ["errors": [["code": 1000]]])]
        for body in replies {
            let probe = RelayIngressProbe([RelayIngressProbe.reply(body)])
            do { _ = try await inspect(f, probe: probe); XCTFail() } catch {}
        }
    }
    func testUnresolvedRecordAndCrossedZoneStopBeforeSendingCredentials() async throws {
        let f = try DNSRecordFixture(), prepared = try f.begin(), probe = RelayIngressProbe([])
        do { _ = try await create(f, probe: probe, record: prepared); XCTFail() } catch {}
        do { _ = try await inspect(f, probe: probe, record: prepared); XCTFail() } catch {}
        let configuration = try XCTUnwrap(f.base.h.f.proposal().cloudflare)
        let wrong = try SetupCloudflareConfiguration(accountID: configuration.accountID, zoneID: String(repeating: "c", count: 32),
            dnsSuffix: configuration.dnsSuffix, apiToken: "synthetic-only")
        do { try await CloudflareDNSRecordClient(send: { try await probe.send($0) }).inspectAbsent(wrong, expected: f.base.h.intent,
            plan: f.base.plan, createdTunnel: f.base.tunnel, application: f.access); XCTFail() } catch {}
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
    func testAlreadyCancelledCreationSendsNoRequest() async throws {
        let f = try DNSRecordFixture(), probe = RelayIngressProbe([])
        let task = Task { @Sendable in withUnsafeCurrentTask { $0?.cancel() }; return try await self.create(f, probe: probe) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
    func testCancellationDuringExactReadDoesNotReturnAnObservation() async throws {
        let f = try DNSRecordFixture(), probe = try RelayIngressProbe([RelayIngressProbe.reply(f.dnsReply())], hook: { _, _ in withUnsafeCurrentTask { $0?.cancel() } })
        let task = Task { @Sendable in try await self.inspect(f, probe: probe) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
    func testCreationWithoutShadowMetadataStaysUnknown() async throws {
        let f = try DNSRecordFixture()
        let replies = try [f.dnsReply(omitting: ["meta"]), f.dnsReply(changes: ["meta": NSNull()])]
        for body in replies {
            let probe = RelayIngressProbe([RelayIngressProbe.reply(body)])
            guard case .unknown = try await create(f, probe: probe) else { XCTFail("Missing metadata cannot acknowledge creation"); continue }
            let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
            XCTAssertEqual(requests.first?.httpMethod, "POST")
        }
    }
    func testReadbackWithoutShadowMetadataReturnsNoEvidence() async throws {
        let f = try DNSRecordFixture(); _ = try f.retainCreated()
        let replies = try [f.dnsReply(omitting: ["meta"]), f.dnsReply(changes: ["meta": NSNull()])]
        for body in replies {
            let probe = RelayIngressProbe([RelayIngressProbe.reply(body)])
            do { _ = try await inspect(f, probe: probe); XCTFail("Missing metadata cannot prove readback") }
            catch { XCTAssertEqual(error as? CloudflareProvisioningError, .invalidResponse) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
            XCTAssertEqual(requests.first?.httpMethod, "GET")
        }
    }

}
