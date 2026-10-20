import CryptoKit
import Foundation
import XCTest
@testable import RemozioCore

struct RelayIngressProviderFixture: Sendable {
    let configuration: SetupCloudflareConfiguration
    let expected: SharedSetupImportIntent
    let plan: SharedSetupImportRelayPlan
    let created: SharedSetupRelayProvisioningRecord
    init() throws {
        let f = try SharedSetupImportFixture(); expected = try f.intent()
        configuration = try XCTUnwrap(f.proposal().cloudflare)
        plan = try .init(expected: expected, port: 51001)
        created = try SharedSetupRelayProvisioningRecord(expected: expected, plan: plan).transition(to: .dispatched)
            .transition(to: .created, tunnelID: "11111111-1111-4111-8111-111111111111")
    }
    static func metadata(configuration: SetupCloudflareConfiguration, plan: SharedSetupImportRelayPlan,
                         id: String = "11111111-1111-4111-8111-111111111111", changes: [String: Any] = [:]) throws -> Data {
        var result: [String: Any] = ["id": id, "account_tag": configuration.accountID, "name": plan.tunnelName,
            "config_src": "cloudflare", "remote_config": true, "tun_type": "cfd_tunnel", "deleted_at": NSNull()]
        for (key, value) in changes { result[key] = value }
        return try JSONSerialization.data(withJSONObject: ["success": true, "errors": [], "result": result])
    }
    static func ingress(configuration: SetupCloudflareConfiguration, plan: SharedSetupImportRelayPlan,
                        id: String = "11111111-1111-4111-8111-111111111111", changes: [String: Any] = [:]) throws -> Data {
        let desired = try XCTUnwrap(JSONSerialization.jsonObject(with: CloudflareTunnelConfigurationClient.plannedConfiguration(plan)) as? [String: Any])
        var result: [String: Any] = ["account_id": configuration.accountID, "tunnel_id": id, "source": "cloudflare", "version": 3,
                                   "config": try XCTUnwrap(desired["config"])]
        for (key, value) in changes { result[key] = value }
        return try JSONSerialization.data(withJSONObject: ["success": true, "errors": [], "result": result])
    }
}
actor RelayIngressProbe {
    enum Step: Sendable { case reply(FCMHTTPReply), lost, cancelled }
    private let steps: [Step]
    private let hook: @Sendable (Int, URLRequest) throws -> Void
    private var requests: [URLRequest] = []
    init(_ steps: [Step], hook: @escaping @Sendable (Int, URLRequest) throws -> Void = { _, _ in }) { self.steps = steps; self.hook = hook }
    func send(_ request: URLRequest) throws -> FCMHTTPReply {
        requests.append(request); try hook(requests.count, request)
        guard requests.count <= steps.count else { throw URLError(.cannotConnectToHost) }
        switch steps[requests.count - 1] {
        case .reply(let value): return value
        case .lost: throw URLError(.networkConnectionLost, userInfo: [NSLocalizedDescriptionKey: "synthetic-sensitive-diagnostic"])
        case .cancelled: throw CancellationError()
        }
    }
    func all() -> [URLRequest] { requests }
    static func reply(_ bytes: Data, status: Int = 200) -> Step { .reply(.init(status: status, retryAfter: nil, body: bytes)) }
}

/// Synthetic provider replies only. These checks make no provider call.
final class CloudflareCreatedTunnelClientTests: XCTestCase, @unchecked Sendable {
    private func metadata(_ i: RelayIngressProviderFixture, probe: RelayIngressProbe) async throws -> CloudflareTunnelObservation {
        try await CloudflareCreatedTunnelClient(send: { try await probe.send($0) }).inspect(i.configuration,
            expected: i.expected, plan: i.plan, created: i.created)
    }
    private func apply(_ i: RelayIngressProviderFixture, probe: RelayIngressProbe) async throws -> CloudflareTunnelConfigurationObservation {
        try await CloudflareTunnelConfigurationClient(send: { try await probe.send($0) }).apply(i.configuration,
            expected: i.expected, plan: i.plan, created: i.created)
    }
    private func validRead(_ i: RelayIngressProviderFixture) throws -> RelayIngressProbe.Step {
        try .reply(.init(status: 200, retryAfter: nil, body: RelayIngressProviderFixture.ingress(configuration: i.configuration, plan: i.plan)))
    }
    func testMetadataGetUsesOnlyTheRetainedCreatedUuid() async throws {
        let i = try RelayIngressProviderFixture()
        let bytes = try RelayIngressProviderFixture.metadata(configuration: i.configuration, plan: i.plan)
        let probe = RelayIngressProbe([.reply(.init(status: 200, retryAfter: nil, body: bytes))])
        let value = try await metadata(i, probe: probe), requests = await probe.all(), request = try XCTUnwrap(requests.first)
        XCTAssertEqual(value, try i.created.createdTunnel(expected: i.expected, plan: i.plan))
        XCTAssertEqual(requests.count, 1); XCTAssertEqual(request.httpMethod, "GET"); XCTAssertNil(request.httpBody)
        XCTAssertEqual(request.url?.absoluteString, "https://api.cloudflare.com/client/v4/accounts/\(i.configuration.accountID)/cfd_tunnel/11111111-1111-4111-8111-111111111111")
        XCTAssertTrue(request.value(forHTTPHeaderField: "Authorization")?.hasPrefix("Bearer ") == true)
    }
    func testMetadataCannotCrossTheRetainedIdentityOrManagementMode() async throws {
        let i = try RelayIngressProviderFixture()
        let changes: [(String, Any)] = [("id", "22222222-2222-4222-8222-222222222222"), ("account_tag", String(repeating: "c", count: 32)),
            ("name", i.plan.tunnelName + "-other"), ("config_src", "local"), ("remote_config", false),
            ("remote_config", "true"), ("tun_type", "warp_connector"), ("deleted_at", "2026-01-01T00:00:00Z")]
        for (key, value) in changes {
            let bytes = try RelayIngressProviderFixture.metadata(configuration: i.configuration, plan: i.plan, changes: [key: value])
            let probe = RelayIngressProbe([RelayIngressProbe.reply(bytes)])
            do { _ = try await metadata(i, probe: probe); XCTFail() } catch {}
            let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
    }
    func testMissingOrRefusedMetadataNeverProvidesAResourceIdentity() async throws {
        let i = try RelayIngressProviderFixture()
        for (status, expected): (Int, CloudflareProvisioningError) in [(401, .unauthorized), (403, .unauthorized), (429, .rateLimited),
            (404, .providerRejected), (500, .unavailable), (302, .unavailable)] {
            let probe = RelayIngressProbe([RelayIngressProbe.reply(Data(), status: status)])
            do { _ = try await metadata(i, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, expected) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
    }
    func testMalformedAndOversizedMetadataAreRejected() async throws {
        let i = try RelayIngressProviderFixture()
        for bytes in [Data("not-json".utf8), Data(repeating: 32, count: FCMHTTPTransport.maximumResponseBytes + 1)] {
            do { _ = try await metadata(i, probe: RelayIngressProbe([RelayIngressProbe.reply(bytes)])); XCTFail() } catch {}
        }
    }
    func testIngressPutContainsOnlyThePlannedOriginAndRequiresIndependentReadback() async throws {
        let i = try RelayIngressProviderFixture(), probe = try RelayIngressProbe([RelayIngressProbe.reply(Data("untrusted-write-reply".utf8)), validRead(i)])
        let result = try await apply(i, probe: probe), requests = await probe.all()
        XCTAssertEqual(requests.count, 2); XCTAssertEqual(requests.map(\.httpMethod), ["PUT", "GET"])
        XCTAssertEqual(requests[0].url, requests[1].url); XCTAssertEqual(requests[0].httpBody, try CloudflareTunnelConfigurationClient.plannedConfiguration(i.plan))
        XCTAssertNil(requests[1].httpBody); XCTAssertEqual(requests[0].value(forHTTPHeaderField: "Content-Type"), "application/json")
        XCTAssertEqual(result.providerVersion, 3); XCTAssertEqual(result.planDigest, Data(SHA256.hash(data: i.plan.bytes)))
    }
    func testLostWriteReplyCanBeReconciledByTheExactReadWithoutAnotherPut() async throws {
        let i = try RelayIngressProviderFixture(), probe = try RelayIngressProbe([.lost, validRead(i)])
        _ = try await apply(i, probe: probe)
        let requests = await probe.all(); XCTAssertEqual(requests.map(\.httpMethod), ["PUT", "GET"])
    }
    func testAmbiguousWriteStatusesRequireReadbackWithoutFollowingRedirects() async throws {
        let i = try RelayIngressProviderFixture()
        for status in [201, 302, 408, 409, 425, 500, 503] {
            let probe = try RelayIngressProbe([RelayIngressProbe.reply(Data(), status: status), validRead(i)])
            _ = try await apply(i, probe: probe)
            let requests = await probe.all(); XCTAssertEqual(requests.count, 2); XCTAssertEqual(requests[0].url, requests[1].url)
        }
    }
    func testConcreteWriteRefusalStopsWithoutRetryOrReadback() async throws {
        let i = try RelayIngressProviderFixture()
        for (status, expected): (Int, CloudflareProvisioningError) in [(400, .providerRejected), (401, .unauthorized),
            (403, .unauthorized), (404, .providerRejected), (429, .rateLimited)] {
            let probe = try RelayIngressProbe([RelayIngressProbe.reply(Data(), status: status), validRead(i)])
            do { _ = try await apply(i, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, expected) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
    }
    func testSuccessfulWriteAloneCannotHideMissingOrWrongConfiguration() async throws {
        let i = try RelayIngressProviderFixture()
        for bytes in [Data("malformed".utf8), try RelayIngressProviderFixture.ingress(configuration: i.configuration, plan: i.plan,
            id: "22222222-2222-4222-8222-222222222222"), try RelayIngressProviderFixture.ingress(configuration: i.configuration,
                plan: i.plan, changes: ["config": ["ingress": [["service": "http_status:200"]]]])] {
            let probe = RelayIngressProbe([RelayIngressProbe.reply(Data()), RelayIngressProbe.reply(bytes)])
            do { _ = try await apply(i, probe: probe); XCTFail() } catch {}
            let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
        }
    }
    func testReadbackTransportFailureDoesNotRetryTheWrite() async throws {
        let i = try RelayIngressProviderFixture(), probe = RelayIngressProbe([RelayIngressProbe.reply(Data()), .lost])
        do { _ = try await apply(i, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .unavailable) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testCancellationAfterWriteNeverStartsReadback() async throws {
        let i = try RelayIngressProviderFixture(), probe = try RelayIngressProbe([RelayIngressProbe.reply(Data()), validRead(i)], hook: { count, _ in
            if count == 1 { withUnsafeCurrentTask { $0?.cancel() } }
        })
        let task = Task { @Sendable in try await self.apply(i, probe: probe) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
    func testAlreadyCancelledWorkSendsNoCredential() async throws {
        let i = try RelayIngressProviderFixture(), probe = RelayIngressProbe([])
        let task = Task { @Sendable in withUnsafeCurrentTask { $0?.cancel() }; return try await self.metadata(i, probe: probe) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
    func testUnresolvedCreationAndCrossedSelectionStopBeforeSendingCredentials() async throws {
        let i = try RelayIngressProviderFixture(), probe = RelayIngressProbe([])
        let prepared = try SharedSetupRelayProvisioningRecord(expected: i.expected, plan: i.plan), sent = try prepared.transition(to: .dispatched)
        let states = [prepared, sent, try sent.transition(to: .unknown), try sent.transition(to: .rejected, refusal: .unauthorized)]
        for record in states {
            XCTAssertThrowsError(try i.configuration.createdTunnelRequest(expected: i.expected, plan: i.plan, created: record))
            do { _ = try await CloudflareTunnelConfigurationClient(send: { try await probe.send($0) }).apply(i.configuration,
                expected: i.expected, plan: i.plan, created: record); XCTFail() } catch {}
        }
        let crossed = try SharedSetupImportRelayPlan(expected: i.expected, port: 51002)
        XCTAssertThrowsError(try i.configuration.createdTunnelRequest(expected: i.expected, plan: crossed, created: i.created))
        let wrong = try SetupCloudflareConfiguration(accountID: String(repeating: "c", count: 32), zoneID: i.configuration.zoneID,
            dnsSuffix: i.configuration.dnsSuffix, apiToken: "synthetic-only")
        XCTAssertThrowsError(try wrong.tunnelIngressUpdateRequest(expected: i.expected, plan: i.plan, created: i.created))
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
}
