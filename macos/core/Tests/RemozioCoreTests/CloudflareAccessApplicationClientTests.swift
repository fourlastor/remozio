import CryptoKit
import Foundation
import XCTest
@testable import RemozioCore

/// Synthetic replies only. Real provider defaults and hostname precedence remain integration gates.
final class CloudflareAccessApplicationClientTests: XCTestCase, @unchecked Sendable {
    private func create(_ f: AccessApplicationFixture, record: SharedSetupAccessApplicationRecord, probe: RelayIngressProbe) async throws -> CloudflareAccessApplicationCreationOutcome {
        try await CloudflareAccessApplicationClient(send: { try await probe.send($0) }).create(XCTUnwrap(f.h.f.proposal().cloudflare),
            expected: f.h.intent, plan: f.plan, createdTunnel: f.tunnel, dispatched: record)
    }
    private func inspect(_ f: AccessApplicationFixture, application: SharedSetupAccessApplicationRecord, probe: RelayIngressProbe) async throws -> CloudflareInitialAccessObservation {
        try await CloudflareAccessApplicationClient(send: { try await probe.send($0) }).inspectInitial(XCTUnwrap(f.h.f.proposal().cloudflare),
            expected: f.h.intent, plan: f.plan, createdTunnel: f.tunnel, application: application)
    }
    private func empty() throws -> RelayIngressProbe.Step { RelayIngressProbe.reply(try RelayPrivateRouteReplies.page()) }
    func testCreationPostContainsOnlyThePlannedApplicationAndNoAllowingPolicy() async throws {
        let f = try AccessApplicationFixture(), sent = try f.begin().transition(to: .dispatched)
        let probe = try RelayIngressProbe([RelayIngressProbe.reply(f.applicationReply())])
        let result = try await create(f, record: sent, probe: probe), requests = await probe.all(), request = try XCTUnwrap(requests.first)
        guard case let .created(identity) = result else { return XCTFail() }
        XCTAssertEqual(identity.hostname, f.plan.hostname); XCTAssertEqual(identity.name, f.plan.accessApplicationName)
        XCTAssertEqual(identity.applicationID, "22222222-2222-4222-8222-222222222222")
        XCTAssertEqual(requests.count, 1); XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.url?.absoluteString, "https://api.cloudflare.com/client/v4/accounts/\(identity.accountID)/access/apps")
        let bytes = try XCTUnwrap(request.httpBody); XCTAssertEqual(bytes, try SharedSetupAccessApplicationRecord.requestBody(plan: f.plan))
        XCTAssertEqual(Data(SHA256.hash(data: bytes)), sent.requestDigest)
        let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        XCTAssertEqual(Set(fields.keys), ["name", "type", "domain", "destinations", "policies", "service_auth_401_redirect", "auto_redirect_to_identity", "app_launcher_visible", "allow_authenticate_via_warp"])
        XCTAssertEqual((fields["policies"] as? [Any])?.count, 0)
        XCTAssertEqual(fields["service_auth_401_redirect"] as? Bool, true)
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
        XCTAssertTrue(request.value(forHTTPHeaderField: "Authorization")?.hasPrefix("Bearer ") == true)
        XCTAssertEqual(String(reflecting: result), "CloudflareAccessApplicationCreationOutcome(redacted)")
    }
    func testCreationAcknowledgementMustMatchNameDomainTypeUuidAndAudience() async throws {
        let f = try AccessApplicationFixture(), sent = try f.begin().transition(to: .dispatched)
        let changes: [(String, Any)] = [("name", "other-name"), ("domain", "other.invalid"), ("type", "saas"),
            ("id", "not-a-uuid"), ("aud", ""), ("aud", "contains space"), ("aud", String(repeating: "a", count: 257))]
        for (key, value) in changes {
            let probe = try RelayIngressProbe([RelayIngressProbe.reply(f.applicationReply(changes: [key: value]))])
            guard case .unknown = try await create(f, record: sent, probe: probe) else { return XCTFail() }
        }
    }
    func testLostOversizedAndMalformedCreationRepliesRemainUnknown() async throws {
        let f = try AccessApplicationFixture(), sent = try f.begin().transition(to: .dispatched)
        for step in [RelayIngressProbe.Step.lost, .cancelled, RelayIngressProbe.reply(Data("not-json".utf8)),
            RelayIngressProbe.reply(Data(repeating: 32, count: FCMHTTPTransport.maximumResponseBytes + 1))] {
            let probe = RelayIngressProbe([step])
            guard case .unknown = try await create(f, record: sent, probe: probe) else { return XCTFail() }
            let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
    }
    func testCreationRefusalIsTypedAndAmbiguousStatusesAreNotRetried() async throws {
        let f = try AccessApplicationFixture(), sent = try f.begin().transition(to: .dispatched)
        for (status, expected): (Int, SharedSetupAccessApplicationRecord.Refusal) in [(401, .unauthorized), (403, .unauthorized), (429, .rateLimited), (400, .providerRejected)] {
            let probe = RelayIngressProbe([RelayIngressProbe.reply(Data(), status: status)])
            guard case let .rejected(actual) = try await create(f, record: sent, probe: probe) else { return XCTFail() }
            XCTAssertEqual(actual, expected); let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
        for status in [201, 302, 408, 409, 425, 500] {
            let probe = try RelayIngressProbe([RelayIngressProbe.reply(f.applicationReply(), status: status)])
            guard case .unknown = try await create(f, record: sent, probe: probe) else { return XCTFail() }
            let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
    }
    func testValidCreationAcknowledgementSurvivesCancellationAtReceipt() async throws {
        let f = try AccessApplicationFixture(), sent = try f.begin().transition(to: .dispatched)
        let probe = try RelayIngressProbe([RelayIngressProbe.reply(f.applicationReply())], hook: { _, _ in withUnsafeCurrentTask { $0?.cancel() } })
        let task = Task { @Sendable in try await self.create(f, record: sent, probe: probe) }
        guard case .created = try await task.value else { return XCTFail() }
    }
    func testPreflightUsesOnlyExactDomainSelectionAndDoesNotAdoptMatches() async throws {
        let f = try AccessApplicationFixture(), config = try XCTUnwrap(f.h.f.proposal().cloudflare), probe = try RelayIngressProbe([empty()])
        try await CloudflareAccessApplicationClient(send: { try await probe.send($0) }).inspectAbsent(config, expected: f.h.intent, plan: f.plan, createdTunnel: f.tunnel)
        let requests = await probe.all(), request = try XCTUnwrap(requests.first), url = try XCTUnwrap(URLComponents(url: XCTUnwrap(request.url), resolvingAgainstBaseURL: false))
        XCTAssertEqual(request.httpMethod, "GET"); XCTAssertNil(request.httpBody)
        XCTAssertEqual(Dictionary(uniqueKeysWithValues: (url.queryItems ?? []).map { ($0.name, $0.value ?? "") }),
            ["domain": f.plan.hostname, "exact": "true", "page": "1", "per_page": "100"])
        let collision = RelayIngressProbe([RelayIngressProbe.reply(try RelayPrivateRouteReplies.page(results: [["domain": f.plan.hostname]]))])
        do { try await CloudflareAccessApplicationClient(send: { try await collision.send($0) }).inspectAbsent(config,
            expected: f.h.intent, plan: f.plan, createdTunnel: f.tunnel); XCTFail() }
        catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
    }
    func testInitialReadbackChecksExactApplicationAndItsOwnEmptyPolicyList() async throws {
        let f = try AccessApplicationFixture(), application = try f.retainCreated()
        let probe = try RelayIngressProbe([RelayIngressProbe.reply(f.applicationReply()), empty()])
        let result = try await inspect(f, application: application, probe: probe), requests = await probe.all()
        XCTAssertNoThrow(try result.validate(expected: f.h.intent, plan: f.plan, createdTunnel: f.tunnel, application: application))
        XCTAssertEqual(requests.count, 2); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" && $0.httpBody == nil })
        XCTAssertTrue(requests[0].url?.path.hasSuffix("/access/apps/22222222-2222-4222-8222-222222222222") == true)
        XCTAssertTrue(requests[1].url?.path.hasSuffix("/access/apps/22222222-2222-4222-8222-222222222222/policies") == true)
        XCTAssertEqual(String(reflecting: result), "CloudflareInitialAccessObservation(redacted)")
    }
    func testReadbackRejectsCrossedIdentityAndInteractiveOrAlternativeAuthentication() async throws {
        let f = try AccessApplicationFixture(), application = try f.retainCreated()
        let changes: [(String, Any)] = [("id", "33333333-3333-4333-8333-333333333333"), ("name", "other-name"),
            ("domain", "*.example.invalid"), ("type", "saas"), ("aud", "other-audience"), ("service_auth_401_redirect", false),
            ("auto_redirect_to_identity", true), ("app_launcher_visible", true), ("allow_authenticate_via_warp", true),
            ("skip_interstitial", true), ("read_service_tokens_from_header", "Authorization"), ("custom_deny_url", "https://other.invalid"),
            ("custom_non_identity_deny_url", "https://other.invalid"), ("cors_headers", ["bypass_options": true]), ("scim_config", [:])]
        for (key, value) in changes {
            let probe = try RelayIngressProbe([RelayIngressProbe.reply(f.applicationReply(changes: [key: value])), empty()])
            do { _ = try await inspect(f, application: application, probe: probe); XCTFail() } catch {}
            let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
    }
    func testDestinationReadbackRejectsPublicOverridesWildcardsExtraPathsAndPrivateTargets() async throws {
        let f = try AccessApplicationFixture(), application = try f.retainCreated()
        let destinations: [Any] = [[], [["type": "public", "uri": "*.example.invalid"]], [["type": "public", "uri": f.plan.hostname + "/admin"]],
            [["type": "private", "uri": f.plan.hostname]], [["type": "public", "uri": f.plan.hostname, "overrides": [["behavior": "public", "path_pattern": "/*"]]]],
            [["type": "public", "uri": f.plan.hostname, "unknown_routing_option": true]],
            [["type": "public", "uri": f.plan.hostname], ["type": "public", "uri": "other.invalid"]]]
        for selected in destinations {
            let probe = try RelayIngressProbe([RelayIngressProbe.reply(f.applicationReply(changes: ["destinations": selected])), empty()])
            do { _ = try await inspect(f, application: application, probe: probe); XCTFail() } catch {}
            let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
    }
    func testInitialApplicationCannotHaveAnyAllowBypassOrServicePolicyYet() async throws {
        let f = try AccessApplicationFixture(), application = try f.retainCreated()
        for decision in ["allow", "bypass", "non_identity", "deny"] {
            let probe = try RelayIngressProbe([RelayIngressProbe.reply(f.applicationReply()),
                RelayIngressProbe.reply(RelayPrivateRouteReplies.page(results: [["decision": decision]]))])
            do { _ = try await inspect(f, application: application, probe: probe); XCTFail() }
            catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        }
    }
    func testPolicyPermissionMalformedAndTransportFailuresNeverProveDefaultDeny() async throws {
        let f = try AccessApplicationFixture(), application = try f.retainCreated()
        for step in [RelayIngressProbe.Step.lost, RelayIngressProbe.reply(Data(), status: 403), RelayIngressProbe.reply(Data("not-json".utf8)),
            RelayIngressProbe.reply(try RelayPrivateRouteReplies.page(info: ["count": 1]))] {
            let probe = try RelayIngressProbe([RelayIngressProbe.reply(f.applicationReply()), step])
            do { _ = try await inspect(f, application: application, probe: probe); XCTFail() } catch {}
            let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
        }
    }
    func testUnresolvedRecordOrCrossedConfigurationStopsBeforeCredentialsAreSent() async throws {
        let f = try AccessApplicationFixture(), prepared = try f.begin(), probe = RelayIngressProbe([])
        do { _ = try await create(f, record: prepared, probe: probe); XCTFail() } catch {}
        do { _ = try await inspect(f, application: prepared, probe: probe); XCTFail() } catch {}
        let wrong = try SetupCloudflareConfiguration(accountID: String(repeating: "c", count: 32), zoneID: XCTUnwrap(f.h.f.proposal().cloudflare).zoneID,
            dnsSuffix: XCTUnwrap(f.h.f.proposal().cloudflare).dnsSuffix, apiToken: "synthetic-only")
        do { try await CloudflareAccessApplicationClient(send: { try await probe.send($0) }).inspectAbsent(wrong,
            expected: f.h.intent, plan: f.plan, createdTunnel: f.tunnel); XCTFail() } catch {}
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
    func testAlreadyCancelledCreationAndReadbackSendNoCredentials() async throws {
        let f = try AccessApplicationFixture(), application = try f.retainCreated(), probe = RelayIngressProbe([])
        let task = Task { @Sendable in withUnsafeCurrentTask { $0?.cancel() }; return try await self.inspect(f, application: application, probe: probe) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
    func testCancellationAfterApplicationReadDoesNotFetchPolicies() async throws {
        let f = try AccessApplicationFixture(), application = try f.retainCreated()
        let probe = try RelayIngressProbe([RelayIngressProbe.reply(f.applicationReply()), empty()], hook: { _, _ in withUnsafeCurrentTask { $0?.cancel() } })
        let task = Task { @Sendable in try await self.inspect(f, application: application, probe: probe) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
}
