import CryptoKit
import Foundation
import XCTest
@testable import RemozioCore

/// The full provider read sequence uses synthetic HTTP replies. No real account or provisioning permission is exercised.
final class CloudflareImportedRelayInspectionTests: XCTestCase, @unchecked Sendable {
    private struct Input: Sendable {
        let configuration: SetupCloudflareConfiguration
        let expected: SharedSetupImportIntent
        let plan: SharedSetupImportRelayPlan
    }
    private actor Probe {
        var requests: [URLRequest] = []
        let replies: [Data]
        let cancelAt: Int?
        init(_ replies: [Data], cancelAt: Int? = nil) { self.replies = replies; self.cancelAt = cancelAt }
        func send(_ request: URLRequest) throws -> FCMHTTPReply {
            requests.append(request)
            guard requests.count <= replies.count else { throw URLError(.cannotConnectToHost) }
            if requests.count == cancelAt { withUnsafeCurrentTask { $0?.cancel() } }
            return .init(status: 200, retryAfter: nil, body: replies[requests.count - 1])
        }
        func all() -> [URLRequest] { requests }
    }
    private func input() throws -> Input {
        let f = try SharedSetupImportFixture(), proposal = try f.proposal(), expected = try f.intent()
        return try .init(configuration: XCTUnwrap(proposal.cloudflare), expected: expected, plan: .init(expected: expected, port: 51001))
    }
    private func envelope(_ result: Any, info: [String: Any]? = nil) throws -> Data {
        var object: [String: Any] = ["success": true, "errors": [], "result": result]
        if let info { object["result_info"] = info }; return try JSONSerialization.data(withJSONObject: object)
    }
    private func zone(_ selected: Input, account: String? = nil) throws -> Data {
        try envelope(["id": selected.configuration.zoneID, "account": ["id": account ?? selected.configuration.accountID],
            "name": "example.invalid", "status": "active", "paused": false])
    }
    private func inventory(_ selected: Input, present: Bool = true, account: String? = nil, page: Int = 1) throws -> Data {
        let result: [[String: Any]] = present ? [["id": "11111111-1111-4111-8111-111111111111", "account_tag": account ?? selected.configuration.accountID,
            "name": selected.plan.tunnelName, "config_src": "cloudflare", "remote_config": true, "tun_type": "cfd_tunnel", "deleted_at": NSNull()]] : []
        return try envelope(result, info: ["count": result.count, "page": page, "per_page": 100, "total_count": result.count])
    }
    private func configuration(_ selected: Input, service: String = "http://127.0.0.1:51001") throws -> Data {
        try envelope(["account_id": selected.configuration.accountID, "tunnel_id": "11111111-1111-4111-8111-111111111111", "source": "cloudflare", "version": 3,
            "config": ["ingress": [["hostname": selected.plan.hostname, "path": "^/$", "service": service], ["service": "http_status:404"]]]])
    }
    private func inspect(_ selected: Input, probe: Probe) async throws -> CloudflareImportedRelayInspection {
        try await CloudflareImportedRelayInspection.inspect(configuration: selected.configuration, expected: selected.expected,
            plan: selected.plan, send: { try await probe.send($0) })
    }
    func testNativeReadSequenceChecksZoneThenCompleteInventoryThenExactIngress() async throws {
        let selected = try input(), probe = try Probe([zone(selected), inventory(selected), inventory(selected, present: false, page: 2), configuration(selected)])
        let result = try await inspect(selected, probe: probe), requests = await probe.all()
        XCTAssertEqual(requests.count, 4); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" && $0.httpBody == nil })
        XCTAssertEqual(requests.map { $0.url?.path }, ["/client/v4/zones/" + selected.configuration.zoneID,
            "/client/v4/accounts/" + selected.configuration.accountID + "/cfd_tunnel",
            "/client/v4/accounts/" + selected.configuration.accountID + "/cfd_tunnel",
            "/client/v4/accounts/" + selected.configuration.accountID + "/cfd_tunnel/11111111-1111-4111-8111-111111111111/configurations"])
        XCTAssertEqual(result.configuration?.providerVersion, 3)
        XCTAssertEqual(result.configuration?.planDigest, Data(SHA256.hash(data: selected.plan.bytes)))
        XCTAssertEqual(result.configuration?.tunnelID, result.tunnel?.tunnelID)
        XCTAssertEqual(String(reflecting: result), "CloudflareImportedRelayInspection(redacted)")
    }
    func testCompleteAbsencePerformsNoConfigurationReadOrMutation() async throws {
        let selected = try input(), probe = try Probe([zone(selected), inventory(selected, present: false)])
        let result = try await inspect(selected, probe: probe), requests = await probe.all()
        XCTAssertNil(result.tunnel); XCTAssertNil(result.configuration); XCTAssertEqual(requests.count, 2)
    }
    func testCrossedZoneAccountStopsBeforeInventoryOrConfiguration() async throws {
        let selected = try input(), probe = try Probe([zone(selected, account: String(repeating: "c", count: 32))])
        do { _ = try await inspect(selected, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
    func testCrossedTunnelAccountStopsBeforeConfiguration() async throws {
        let selected = try input(), probe = try Probe([zone(selected), inventory(selected, account: String(repeating: "c", count: 32))])
        do { _ = try await inspect(selected, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testUnsafeIngressCannotBeReplacedByAnInventoryOnlySuccess() async throws {
        let selected = try input(), probe = try Probe([zone(selected), inventory(selected), inventory(selected, present: false, page: 2), configuration(selected, service: "tcp://127.0.0.1:22")])
        do { _ = try await inspect(selected, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 4)
    }
    func testConfigurationFailureDoesNotRetryOrReturnTheEarlierTunnelMatch() async throws {
        let selected = try input(), probe = try Probe([zone(selected), inventory(selected), inventory(selected, present: false, page: 2)])
        do { _ = try await inspect(selected, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .unavailable) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 4)
    }
    func testMalformedInventoryDoesNotTriggerAConfigurationRead() async throws {
        let selected = try input(), probe = try Probe([zone(selected), Data("not-json".utf8)])
        do { _ = try await inspect(selected, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .invalidResponse) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testCrossedLocalSelectionStopsBeforeTheFirstCredentialTransmission() async throws {
        let selected = try input(), probe = try Probe([zone(selected)])
        let wrong = try SetupCloudflareConfiguration(accountID: String(repeating: "c", count: 32), zoneID: selected.configuration.zoneID,
            dnsSuffix: selected.configuration.dnsSuffix, apiToken: "synthetic-only")
        do { _ = try await CloudflareImportedRelayInspection.inspect(configuration: wrong, expected: selected.expected,
            plan: selected.plan, send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 0)
    }
    func testCancellationBetweenStagesSendsNoLaterRequest() async throws {
        let selected = try input(), probe = try Probe([zone(selected), inventory(selected), inventory(selected, present: false, page: 2), configuration(selected)], cancelAt: 1)
        let task = Task { @Sendable in try await self.inspect(selected, probe: probe) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
    func testReadbackMustBindConfigurationPresenceAndScopeToTheExactTunnelAndPlan() throws {
        let selected = try input(), scope = CloudflareProvisioningScope(accountID: selected.configuration.accountID,
            zoneID: selected.configuration.zoneID, zoneName: "example.invalid", dnsSuffix: selected.configuration.dnsSuffix)
        let tunnel = CloudflareTunnelObservation(accountID: selected.configuration.accountID,
            tunnelID: "11111111-1111-4111-8111-111111111111", name: selected.plan.tunnelName)
        let valid = CloudflareTunnelConfigurationObservation(accountID: tunnel.accountID, tunnelID: tunnel.tunnelID,
            providerVersion: 3, planDigest: Data(SHA256.hash(data: selected.plan.bytes)))
        let crossed = [
            CloudflareImportedRelayInspection(scope: scope, tunnel: tunnel), .init(scope: scope, tunnel: nil, configuration: valid),
            .init(scope: scope, tunnel: tunnel, configuration: .init(accountID: String(repeating: "c", count: 32), tunnelID: tunnel.tunnelID, providerVersion: 3, planDigest: valid.planDigest)),
            .init(scope: scope, tunnel: tunnel, configuration: .init(accountID: tunnel.accountID, tunnelID: "22222222-2222-4222-8222-222222222222", providerVersion: 3, planDigest: valid.planDigest)),
            .init(scope: scope, tunnel: tunnel, configuration: .init(accountID: tunnel.accountID, tunnelID: tunnel.tunnelID, providerVersion: 3, planDigest: Data(repeating: 0, count: 32)))]
        for result in crossed { XCTAssertThrowsError(try result.validate(configuration: selected.configuration, expected: selected.expected, plan: selected.plan)) }
        XCTAssertNoThrow(try CloudflareImportedRelayInspection(scope: scope, tunnel: tunnel, configuration: valid)
            .validate(configuration: selected.configuration, expected: selected.expected, plan: selected.plan))
    }
}
