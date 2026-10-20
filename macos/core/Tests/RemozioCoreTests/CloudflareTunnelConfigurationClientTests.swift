import CryptoKit
import Foundation
import XCTest
@testable import RemozioCore

/// Synthetic provider data. These checks prove neither provider ownership nor Access or installed connector behavior.
final class CloudflareTunnelConfigurationClientTests: XCTestCase, @unchecked Sendable {
    private struct Input: Sendable {
        let configuration: SetupCloudflareConfiguration
        let expected: SharedSetupImportIntent
        let plan: SharedSetupImportRelayPlan
        let tunnel: CloudflareTunnelObservation
    }
    private actor Probe {
        var requests: [URLRequest] = []
        let reply: FCMHTTPReply
        init(_ bytes: Data, status: Int = 200) { reply = .init(status: status, retryAfter: nil, body: bytes) }
        func send(_ request: URLRequest) -> FCMHTTPReply { requests.append(request); return reply }
        func all() -> [URLRequest] { requests }
    }
    private func input() throws -> Input {
        let f = try SharedSetupImportFixture(), proposal = try f.proposal(), expected = try f.intent(), plan = try SharedSetupImportRelayPlan(expected: expected, port: 51001)
        let config = try XCTUnwrap(proposal.cloudflare)
        return .init(configuration: config, expected: expected, plan: plan,
            tunnel: .init(accountID: config.accountID, tunnelID: "11111111-1111-4111-8111-111111111111", name: plan.tunnelName))
    }
    private func routing(_ selected: Input) -> [String: Any] {
        ["ingress": [["hostname": selected.plan.hostname, "path": "^/$", "service": "http://127.0.0.1:51001"], ["service": "http_status:404"]]]
    }
    private func body(_ selected: Input, config: [String: Any]? = nil, result changes: [String: Any] = [:],
                      envelope updates: [String: Any] = [:]) throws -> Data {
        var result: [String: Any] = ["account_id": selected.configuration.accountID, "tunnel_id": selected.tunnel.tunnelID,
            "source": "cloudflare", "version": 1, "config": config ?? routing(selected)]
        for (key, value) in changes { result[key] = value }
        var envelope: [String: Any] = ["success": true, "errors": [], "result": result]
        for (key, value) in updates { envelope[key] = value }
        return try JSONSerialization.data(withJSONObject: envelope)
    }
    private func inspect(_ selected: Input, probe: Probe) async throws -> CloudflareTunnelConfigurationObservation {
        try await CloudflareTunnelConfigurationClient(send: { await probe.send($0) }).inspect(selected.configuration,
            expected: selected.expected, plan: selected.plan, tunnel: selected.tunnel)
    }
    private func failure(_ expected: CloudflareProvisioningError, selected: Input, bytes: Data) async throws {
        do { _ = try await inspect(selected, probe: Probe(bytes)); XCTFail("Expected exact-ingress refusal") }
        catch { XCTAssertEqual(error as? CloudflareProvisioningError, expected) }
    }
    private func changedRule(_ selected: Input, index: Int = 0, key: String, value: Any?) -> [String: Any] {
        var config = routing(selected), rules = config["ingress"] as! [[String: Any]]
        rules[index][key] = value; config["ingress"] = rules; return config
    }
    func testOnlyTheFixedReadEndpointReceivesTheImportedCredential() async throws {
        let selected = try input(), probe = try Probe(body(selected))
        let observed = try await inspect(selected, probe: probe), requests = await probe.all(), request = try XCTUnwrap(requests.first)
        XCTAssertEqual(requests.count, 1); XCTAssertEqual(request.httpMethod, "GET"); XCTAssertNil(request.httpBody)
        XCTAssertEqual(request.url?.absoluteString, "https://api.cloudflare.com/client/v4/accounts/" + selected.configuration.accountID + "/cfd_tunnel/" + selected.tunnel.tunnelID + "/configurations")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer synthetic-provider-token-only")
        XCTAssertEqual(observed.accountID, selected.configuration.accountID); XCTAssertEqual(observed.tunnelID, selected.tunnel.tunnelID)
        XCTAssertEqual(observed.providerVersion, 1); XCTAssertEqual(observed.planDigest, Data(SHA256.hash(data: selected.plan.bytes)))
        XCTAssertEqual(String(reflecting: observed), "CloudflareTunnelConfigurationObservation(redacted)")
    }
    func testPlannedConfigurationContainsExactlyTheExpectedPublicRoutesAndNoCredential() throws {
        let selected = try input(), bytes = try CloudflareTunnelConfigurationClient.plannedConfiguration(selected.plan)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? NSDictionary)
        XCTAssertEqual(object, ["config": routing(selected)] as NSDictionary)
        XCTAssertNil(bytes.range(of: Data("synthetic-provider-token-only".utf8)))
        XCTAssertNil((object["config"] as? NSDictionary)?["warp-routing"])
    }
    func testAlternateOriginsPortsAndProxyProtocolsAreRejected() async throws {
        let selected = try input()
        for origin in ["http://localhost:51001", "http://127.0.0.1:51002", "http://0.0.0.0:51001", "http://attacker.example:51001",
            "tcp://127.0.0.1:51001", "unix:///tmp/anything", "https://127.0.0.1:51001", "http://127.0.0.1:51001/other", "http://127.0.0.1:51001@attacker.example"] {
            try await failure(.wrongScope, selected: selected, bytes: body(selected, config: changedRule(selected, key: "service", value: origin)))
        }
    }
    func testOnlyTheExactLocalHostnameIsAccepted() async throws {
        let selected = try input()
        for hostname: Any? in [nil, "*", "*.example.invalid", selected.plan.hostname + ".attacker.example", "another.example.invalid"] {
            try await failure(.wrongScope, selected: selected, bytes: body(selected, config: changedRule(selected, key: "hostname", value: hostname)))
        }
    }
    func testTheApprovalPathMustMatchOnlyTheRootPath() async throws {
        let selected = try input()
        for path: Any? in [nil, "/", ".*", "^/.*", "^/admin$"] {
            try await failure(.wrongScope, selected: selected, bytes: body(selected, config: changedRule(selected, key: "path", value: path)))
        }
    }
    func testTheFinalRuleMustRejectAllOtherTraffic() async throws {
        let selected = try input()
        for (key, value): (String, Any?) in [("service", "http://127.0.0.1:51001"), ("service", "http_status:200"), ("hostname", selected.plan.hostname), ("path", "^/$")] {
            try await failure(.wrongScope, selected: selected, bytes: body(selected, config: changedRule(selected, index: 1, key: key, value: value)))
        }
    }
    func testMissingExtraAndReorderedIngressRulesAreRejected() async throws {
        let selected = try input(), rules = routing(selected)["ingress"] as! [[String: Any]]
        for changed in [[], [rules[0]], [rules[1], rules[0]], rules + [rules[1]]] {
            try await failure(.wrongScope, selected: selected, bytes: body(selected, config: ["ingress": changed]))
        }
    }
    func testOriginOverridesAndUnknownRoutingFieldsCannotBeIgnored() async throws {
        let selected = try input()
        for field in ["httpHostHeader", "proxyType", "access", "noTLSVerify"] {
            var config = routing(selected); config["originRequest"] = [field: "unexpected"]
            try await failure(.wrongScope, selected: selected, bytes: body(selected, config: config))
            let changed = changedRule(selected, key: "originRequest", value: [field: "unexpected"])
            try await failure(.wrongScope, selected: selected, bytes: body(selected, config: changed))
        }
        var config = routing(selected); config["unrecognized-routing"] = true
        try await failure(.wrongScope, selected: selected, bytes: body(selected, config: config))
    }
    func testEmptyOriginDefaultsAreCompatibleWithoutAuthorizingOverrides() async throws {
        let selected = try input(); var config = changedRule(selected, key: "originRequest", value: [String: String]())
        config["originRequest"] = [String: String]()
        _ = try await inspect(selected, probe: Probe(body(selected, config: config)))
    }
    func testWarpFieldsNeverEnableAnAdditionalRoute() async throws {
        let selected = try input()
        for warp: [String: Any] in [["enabled": true], ["enabled": false, "other": true]] {
            var config = routing(selected); config["warp-routing"] = warp
            try await failure(.wrongScope, selected: selected, bytes: body(selected, config: config))
        }
        var numeric = routing(selected); numeric["warp-routing"] = ["enabled": 0]
        try await failure(.invalidResponse, selected: selected, bytes: body(selected, config: numeric))
        var legacy = routing(selected); legacy["warp-routing"] = ["enabled": false]
        _ = try await inspect(selected, probe: Probe(body(selected, config: legacy)))
        // A legacy false flag proves no private-route state. The observation covers public ingress only.
    }
    func testCrossedProviderIdentityCannotBeAccepted() async throws {
        let selected = try input()
        for fields in [["account_id": String(repeating: "c", count: 32)], ["tunnel_id": "22222222-2222-4222-8222-222222222222"], ["source": "local"]] {
            try await failure(.wrongScope, selected: selected, bytes: body(selected, result: fields))
        }
    }
    func testVersionsMustBeUnsignedIntegersAndRequiredFieldsCannotBeMissing() async throws {
        let selected = try input()
        for version: Any in [-1, true, "1", 1.5] {
            try await failure(.invalidResponse, selected: selected, bytes: body(selected, result: ["version": version]))
        }
        for key in ["account_id", "tunnel_id", "source", "version", "config"] {
            try await failure(.invalidResponse, selected: selected, bytes: body(selected, result: [key: NSNull()]))
        }
        let zero = try await inspect(selected, probe: Probe(body(selected, result: ["version": 0])))
        XCTAssertEqual(zero.providerVersion, 0)
    }
    func testMalformedAndUnsuccessfulEnvelopesProduceTypedFailures() async throws {
        let selected = try input()
        for changes: [String: Any] in [["success": false], ["errors": [["message": "synthetic-diagnostic"]]]] {
            try await failure(.providerRejected, selected: selected, bytes: body(selected, envelope: changes))
        }
        for bytes in [Data("not-json".utf8), try body(selected, envelope: ["success": 1]), try body(selected, envelope: ["result": NSNull()])] {
            try await failure(.invalidResponse, selected: selected, bytes: bytes)
        }
    }
    func testOversizedRepliesCannotReachTheDecoder() async throws {
        let selected = try input()
        try await failure(.responseTooLarge, selected: selected, bytes: Data(repeating: 32, count: FCMHTTPTransport.maximumResponseBytes + 1))
    }
    func testStatusesDoNotRetryOrExposeProviderBodies() async throws {
        let selected = try input()
        for (status, expected): (Int, CloudflareProvisioningError) in [(401, .unauthorized), (403, .unauthorized), (429, .rateLimited), (404, .providerRejected), (500, .unavailable), (302, .unavailable)] {
            let probe = Probe(Data("synthetic-sensitive-diagnostic".utf8), status: status)
            do { _ = try await inspect(selected, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, expected) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
    }
    func testTransportErrorsRemainTypedAndCredentialFree() async throws {
        let selected = try input()
        for large in [false, true] {
            let client = CloudflareTunnelConfigurationClient(send: { _ in
                if large { throw FCMError.responseTooLarge }
                throw URLError(.cannotConnectToHost, userInfo: [NSLocalizedDescriptionKey: "synthetic-sensitive-diagnostic"])
            })
            do { _ = try await client.inspect(selected.configuration, expected: selected.expected, plan: selected.plan, tunnel: selected.tunnel); XCTFail() }
            catch { XCTAssertEqual(error as? CloudflareProvisioningError, large ? .responseTooLarge : .unavailable) }
        }
    }
    func testCrossedOrMalformedResourceScopeStopsBeforeCredentialTransmission() async throws {
        let selected = try input(), probe = try Probe(body(selected)), client = CloudflareTunnelConfigurationClient(send: { await probe.send($0) })
        for tunnel in [CloudflareTunnelObservation(accountID: String(repeating: "c", count: 32), tunnelID: selected.tunnel.tunnelID, name: selected.tunnel.name),
            .init(accountID: selected.tunnel.accountID, tunnelID: "../other", name: selected.tunnel.name),
            .init(accountID: selected.tunnel.accountID, tunnelID: selected.tunnel.tunnelID, name: "unrelated")] {
            do { _ = try await client.inspect(selected.configuration, expected: selected.expected, plan: selected.plan, tunnel: tunnel); XCTFail() }
            catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 0)
    }
    func testAlreadyCancelledInspectionNeverSendsCredentials() async throws {
        let selected = try input(), probe = try Probe(body(selected))
        let task = Task { @Sendable in withUnsafeCurrentTask { $0?.cancel() }; return try await self.inspect(selected, probe: probe) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 0)
    }
    func testCancellationAfterTheReplyCannotReturnConfigurationEvidence() async throws {
        let selected = try input(), bytes = try body(selected)
        let task = Task { @Sendable in
            try await CloudflareTunnelConfigurationClient(send: { _ in
                withUnsafeCurrentTask { $0?.cancel() }; return .init(status: 200, retryAfter: nil, body: bytes)
            }).inspect(selected.configuration, expected: selected.expected, plan: selected.plan, tunnel: selected.tunnel)
        }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
    }
}
