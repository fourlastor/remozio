import CryptoKit
import Foundation
import XCTest
@testable import RemozioCore

/// Synthetic replies only. These checks send no provider request.
final class CloudflareTunnelCreationClientTests: XCTestCase, @unchecked Sendable {
    private struct Input: Sendable {
        let configuration: SetupCloudflareConfiguration
        let expected: SharedSetupImportIntent
        let plan: SharedSetupImportRelayPlan
        let dispatched: SharedSetupRelayProvisioningRecord
    }
    private actor Probe {
        private var requests: [URLRequest] = []
        let reply: FCMHTTPReply
        init(_ body: Data, status: Int = 200) { reply = .init(status: status, retryAfter: nil, body: body) }
        func send(_ request: URLRequest) -> FCMHTTPReply { requests.append(request); return reply }
        func all() -> [URLRequest] { requests }
    }
    private func input() throws -> Input {
        let f = try SharedSetupImportFixture(), proposal = try f.proposal(), expected = try f.intent()
        let plan = try SharedSetupImportRelayPlan(expected: expected, port: 51001)
        return try .init(configuration: XCTUnwrap(proposal.cloudflare), expected: expected, plan: plan,
            dispatched: SharedSetupRelayProvisioningRecord(expected: expected, plan: plan).transition(to: .dispatched))
    }
    private func tunnel(_ i: Input) -> [String: Any] {
        ["id": "11111111-1111-4111-8111-111111111111", "account_tag": i.configuration.accountID,
         "name": i.plan.tunnelName, "config_src": "cloudflare", "remote_config": true,
         "tun_type": "cfd_tunnel", "deleted_at": NSNull()]
    }
    private func body(_ result: Any, changes: [String: Any] = [:]) throws -> Data {
        var envelope: [String: Any] = ["success": true, "errors": [], "result": result]
        for (key, value) in changes { envelope[key] = value }
        return try JSONSerialization.data(withJSONObject: envelope)
    }
    private func create(_ i: Input, probe: Probe) async throws -> CloudflareTunnelCreationOutcome {
        try await CloudflareTunnelCreationClient(send: { await probe.send($0) }).create(i.configuration,
            expected: i.expected, plan: i.plan, dispatched: i.dispatched)
    }
    private func assertUnknown(_ outcome: CloudflareTunnelCreationOutcome, file: StaticString = #filePath, line: UInt = #line) {
        guard case .unknown = outcome else { return XCTFail("Expected an unresolved outcome", file: file, line: line) }
    }
    func testTheFixedPostContainsOnlyTheLocalNameAndRemoteConfigurationMode() async throws {
        let i = try input(), probe = try Probe(body(tunnel(i)))
        let result = try await create(i, probe: probe)
        guard case let .created(observation) = result else { return XCTFail() }
        XCTAssertEqual(observation.accountID, i.configuration.accountID); XCTAssertEqual(observation.name, i.plan.tunnelName)
        let requests = await probe.all(), request = try XCTUnwrap(requests.first)
        XCTAssertEqual(requests.count, 1); XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.url?.absoluteString, "https://api.cloudflare.com/client/v4/accounts/\(i.configuration.accountID)/cfd_tunnel")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
        XCTAssertTrue(request.value(forHTTPHeaderField: "Authorization")?.hasPrefix("Bearer ") == true)
        let bytes = try XCTUnwrap(request.httpBody)
        XCTAssertEqual(bytes, try SharedSetupRelayProvisioningRecord.requestBody(plan: i.plan))
        XCTAssertEqual(Data(SHA256.hash(data: bytes)), i.dispatched.requestDigest)
        let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: String])
        XCTAssertEqual(fields, ["name": i.plan.tunnelName, "config_src": "cloudflare"])
        XCTAssertEqual(String(reflecting: result), "CloudflareTunnelCreationOutcome(redacted)")
    }
    func testDeprecatedRemoteFlagAndTunnelTypeCanBeAbsent() async throws {
        let i = try input(); var value = tunnel(i); value.removeValue(forKey: "remote_config"); value.removeValue(forKey: "tun_type")
        let result = try await create(i, probe: Probe(body(value)))
        guard case .created = result else { return XCTFail() }
    }
    func testCrossedOrMalformedTunnelAcknowledgementsRemainUnresolved() async throws {
        let i = try input()
        let changes: [(String, Any)] = [("account_tag", String(repeating: "c", count: 32)), ("name", i.plan.tunnelName + "-other"),
            ("config_src", "local"), ("remote_config", false), ("remote_config", "true"), ("tun_type", "warp_connector"),
            ("id", "not-a-uuid"), ("id", "11111111111141118111111111111111"), ("deleted_at", "2026-01-01T00:00:00Z")]
        for (key, change) in changes {
            var value = tunnel(i); value[key] = change
            assertUnknown(try await create(i, probe: Probe(body(value))))
        }
    }
    func testUppercaseUuidIsRetainedInCanonicalForm() async throws {
        let i = try input(); var value = tunnel(i); value["id"] = "ABCDEF01-ABCD-4BCD-8BCD-ABCDEF012345"
        let result = try await create(i, probe: Probe(body(value)))
        guard case let .created(observation) = result else { return XCTFail() }
        XCTAssertEqual(observation.tunnelID, "abcdef01-abcd-4bcd-8bcd-abcdef012345")
    }
    func testExplicitHttpRefusalsAreTypedAndNeverRetried() async throws {
        let i = try input()
        let statuses: [(Int, SharedSetupRelayProvisioningRecord.Refusal)] = [(401, .unauthorized), (403, .unauthorized),
            (429, .rateLimited), (400, .providerRejected), (404, .providerRejected), (422, .providerRejected)]
        for (status, expected) in statuses {
            let probe = Probe(Data("synthetic-sensitive-provider-body".utf8), status: status)
            let result = try await create(i, probe: probe)
            guard case let .rejected(actual) = result else { return XCTFail() }
            XCTAssertEqual(actual, expected); let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
    }
    func testAmbiguousStatusesRemainUnresolvedWithoutRetry() async throws {
        let i = try input()
        for status in [201, 202, 301, 302, 408, 409, 425, 500, 503] {
            let probe = try Probe(body(tunnel(i)), status: status)
            assertUnknown(try await create(i, probe: probe))
            let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
    }
    func testMalformedOrPartialSuccessEnvelopesRemainUnresolved() async throws {
        let i = try input()
        let bodies = try [body(tunnel(i), changes: ["success": false]), body(tunnel(i), changes: ["errors": [["code": 1000]]]),
            body(NSNull()), body([tunnel(i)]), body(["id": "11111111-1111-4111-8111-111111111111"]), Data("not-json".utf8)]
        for bytes in bodies { assertUnknown(try await create(i, probe: Probe(bytes))) }
    }
    func testOversizedSuccessResponseRemainsUnresolved() async throws {
        let i = try input(), probe = Probe(Data(repeating: 32, count: FCMHTTPTransport.maximumResponseBytes + 1))
        assertUnknown(try await create(i, probe: probe))
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
    func testTransportErrorsAreReducedToUnresolvedOutcomes() async throws {
        let i = try input()
        for cancel in [false, true] {
            let client = CloudflareTunnelCreationClient(send: { _ in
                if cancel { throw CancellationError() }
                throw URLError(.cannotConnectToHost, userInfo: [NSLocalizedDescriptionKey: "synthetic-sensitive-diagnostic"])
            })
            assertUnknown(try await client.create(i.configuration, expected: i.expected, plan: i.plan, dispatched: i.dispatched))
        }
    }
    func testAlreadyCancelledCreationSendsNoCredential() async throws {
        let i = try input(), probe = try Probe(body(tunnel(i)))
        let task = Task { @Sendable in
            withUnsafeCurrentTask { $0?.cancel() }; return try await self.create(i, probe: probe)
        }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
    func testAValidAcknowledgementSurvivesCancellationAtReceipt() async throws {
        let i = try input(), bytes = try body(tunnel(i))
        let task = Task { @Sendable in
            try await CloudflareTunnelCreationClient(send: { _ in
                withUnsafeCurrentTask { $0?.cancel() }; return .init(status: 200, retryAfter: nil, body: bytes)
            }).create(i.configuration, expected: i.expected, plan: i.plan, dispatched: i.dispatched)
        }
        let result = try await task.value
        guard case .created = result else { return XCTFail() }
    }
    func testWrongPhasePlanOrConfigurationStopsBeforeSendingCredentials() async throws {
        let i = try input(), probe = try Probe(body(tunnel(i)))
        let client = CloudflareTunnelCreationClient(send: { await probe.send($0) })
        let prepared = try SharedSetupRelayProvisioningRecord(expected: i.expected, plan: i.plan)
        let wrongPlan = try SharedSetupImportRelayPlan(expected: i.expected, port: 51002)
        let wrongConfig = try SetupCloudflareConfiguration(accountID: String(repeating: "c", count: 32), zoneID: i.configuration.zoneID,
            dnsSuffix: i.configuration.dnsSuffix, apiToken: "synthetic-only")
        for (config, plan, record) in [(i.configuration, i.plan, prepared), (i.configuration, wrongPlan, i.dispatched), (wrongConfig, i.plan, i.dispatched)] {
            do { _ = try await client.create(config, expected: i.expected, plan: plan, dispatched: record); XCTFail() } catch {}
        }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
}
