import Foundation
import XCTest
@testable import RemozioCore

/// Synthetic replies only. Inventory evidence proves no resource ownership, provisioning permission or native Root admission.
final class CloudflareTunnelInspectionClientTests: XCTestCase, @unchecked Sendable {
    private struct Input: Sendable {
        let configuration: SetupCloudflareConfiguration
        let expected: SharedSetupImportIntent
        let plan: SharedSetupImportRelayPlan
    }
    private actor Probe {
        var requests: [URLRequest] = []
        let replies: [FCMHTTPReply]
        init(_ bodies: [Data], status: Int = 200) { replies = bodies.map { .init(status: status, retryAfter: nil, body: $0) } }
        func send(_ request: URLRequest) throws -> FCMHTTPReply {
            requests.append(request)
            guard requests.count <= replies.count else { throw URLError(.cannotConnectToHost) }
            return replies[requests.count - 1]
        }
        func all() -> [URLRequest] { requests }
    }
    private func input() throws -> Input {
        let f = try SharedSetupImportFixture(), proposal = try f.proposal(), expected = try f.intent()
        return try .init(configuration: XCTUnwrap(proposal.cloudflare), expected: expected, plan: .init(expected: expected, port: 51001))
    }
    private func tunnel(_ selected: Input, id: String = "11111111-1111-4111-8111-111111111111", name: String? = nil) -> [String: Any] {
        ["id": id, "account_tag": selected.configuration.accountID, "name": name ?? selected.plan.tunnelName,
         "config_src": "cloudflare", "remote_config": true, "tun_type": "cfd_tunnel", "deleted_at": NSNull()]
    }
    private func body(_ tunnels: [[String: Any]] = [], page: Int = 1, size: Int = 100, total: Int? = nil,
                      info extra: [String: Any] = [:], envelope changes: [String: Any] = [:], padding: Int = 0) throws -> Data {
        var info: [String: Any] = ["page": page, "per_page": size, "count": tunnels.count, "total_count": total ?? tunnels.count]
        for (key, value) in extra { info[key] = value }
        var value: [String: Any] = ["success": true, "errors": [], "result": tunnels, "result_info": info]
        for (key, change) in changes { value[key] = change }
        return try JSONSerialization.data(withJSONObject: value) + Data(repeating: 32, count: padding)
    }
    private func inspect(_ selected: Input, probe: Probe) async throws -> CloudflareTunnelObservation? {
        try await CloudflareTunnelInspectionClient(send: { try await probe.send($0) }).inspect(selected.configuration, expected: selected.expected, plan: selected.plan)
    }
    private func failure(_ error: CloudflareProvisioningError, selected: Input, probe: Probe) async throws {
        do { _ = try await inspect(selected, probe: probe); XCTFail("Expected bounded inspection failure") }
        catch let actual { XCTAssertEqual(actual as? CloudflareProvisioningError, error) }
    }
    func testTheOnlyRequestIsReadOnlyAndUsesTheFixedOriginAndLocalOperationName() async throws {
        let selected = try input(), probe = try Probe([body()])
        let result = try await inspect(selected, probe: probe); XCTAssertNil(result)
        let requests = await probe.all(), request = try XCTUnwrap(requests.first)
        XCTAssertEqual(requests.count, 1); XCTAssertEqual(request.httpMethod, "GET"); XCTAssertNil(request.httpBody)
        let url = try XCTUnwrap(request.url), components = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        XCTAssertEqual(url.scheme, "https"); XCTAssertEqual(url.host, "api.cloudflare.com")
        XCTAssertEqual(url.path, "/client/v4/accounts/" + selected.configuration.accountID + "/cfd_tunnel")
        XCTAssertEqual(Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).map { ($0.name, $0.value) }),
            ["name": selected.plan.tunnelName, "is_deleted": "false", "page": "1", "per_page": "100"])
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer synthetic-provider-token-only")
    }
    func testAnExactRemoteTunnelProducesOnlyRedactedInventoryEvidence() async throws {
        let selected = try input(), probe = try Probe([body([tunnel(selected)])])
        let result = try await inspect(selected, probe: probe)
        let observed = try XCTUnwrap(result)
        XCTAssertEqual(observed.accountID, selected.configuration.accountID)
        XCTAssertEqual(observed.tunnelID, "11111111-1111-4111-8111-111111111111"); XCTAssertEqual(observed.name, selected.plan.tunnelName)
        XCTAssertEqual(String(reflecting: observed), "CloudflareTunnelObservation(redacted)")
    }
    func testDeprecatedRemoteFlagMayBeAbsentWhenTheConfigurationSourceIsExplicit() async throws {
        let selected = try input(); var value = tunnel(selected); value.removeValue(forKey: "remote_config")
        let observed = try await inspect(selected, probe: Probe([body([value])]))
        XCTAssertNotNil(observed)
    }
    func testANamePrefixIsNotAnExactCandidate() async throws {
        let selected = try input(), probe = try Probe([body([tunnel(selected, name: selected.plan.tunnelName + "-other")])])
        let observed = try await inspect(selected, probe: probe); XCTAssertNil(observed)
    }
    func testEveryPageIsReadEvenWhenTheFirstPageMatches() async throws {
        let selected = try input(), probe = try Probe([
            body([tunnel(selected)], size: 1, total: 2),
            body([tunnel(selected, id: "22222222-2222-4222-8222-222222222222", name: "unrelated")], page: 2, size: 1, total: 2)])
        let observed = try await inspect(selected, probe: probe); XCTAssertNotNil(observed)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
        XCTAssertTrue(try XCTUnwrap(requests.last?.url?.query).contains("page=2"))
    }
    func testTwoMatchingNamesOnDifferentPagesAreAmbiguous() async throws {
        let selected = try input(), probe = try Probe([
            body([tunnel(selected)], size: 1, total: 2),
            body([tunnel(selected, id: "22222222-2222-4222-8222-222222222222")], page: 2, size: 1, total: 2)])
        try await failure(.wrongScope, selected: selected, probe: probe)
    }
    func testRepeatedResourceIDsAcrossPagesAreNotACompleteInventory() async throws {
        let selected = try input(), probe = try Probe([
            body([tunnel(selected)], size: 1, total: 2), body([tunnel(selected)], page: 2, size: 1, total: 2)])
        try await failure(.invalidResponse, selected: selected, probe: probe)
    }
    func testCrossedAccountEvidenceIsRejectedEvenForAnUnrelatedName() async throws {
        let selected = try input(); var crossed = tunnel(selected, name: "unrelated"); crossed["account_tag"] = String(repeating: "c", count: 32)
        try await failure(.wrongScope, selected: selected, probe: Probe([body([crossed])]))
    }
    func testDeletedLocalAndOtherTunnelTypesCannotBecomeCandidates() async throws {
        let selected = try input()
        for (key, value): (String, Any) in [("deleted_at", "2026-10-19T00:00:00Z"), ("config_src", "local"), ("remote_config", false), ("tun_type", "warp_connector")] {
            var changed = tunnel(selected); changed[key] = value
            try await failure(.wrongScope, selected: selected, probe: Probe([body([changed])]))
        }
    }
    func testMalformedMissingAndCoercedResourceFieldsCannotProduceEvidence() async throws {
        let selected = try input()
        for (key, value): (String, Any?) in [("id", "not-a-uuid"), ("account_tag", nil), ("remote_config", 1), ("tun_type", nil), ("deleted_at", 0)] {
            var changed = tunnel(selected); changed[key] = value
            try await failure(.invalidResponse, selected: selected, probe: Probe([body([changed])]))
        }
    }
    func testPaginationMetadataMustBeCompleteConsistentAndBounded() async throws {
        let selected = try input()
        for info: [String: Any] in [["page": 2], ["per_page": 0], ["per_page": 101], ["count": 1], ["total_count": -1],
            ["total_count": 1001], ["total_pages": 2], ["page": true], ["total_count": "0"]] {
            try await failure(.invalidResponse, selected: selected, probe: Probe([body(info: info)]))
        }
        try await failure(.invalidResponse, selected: selected, probe: Probe([body(envelope: ["result_info": NSNull()])]))
    }
    func testZeroTotalPagesIsAcceptedOnlyForTheEmptyResult() async throws {
        let selected = try input()
        let empty = try await inspect(selected, probe: Probe([body(info: ["total_pages": 0])]))
        XCTAssertNil(empty)
        try await failure(.invalidResponse, selected: selected, probe: Probe([body([tunnel(selected)], info: ["total_pages": 0])]))
    }
    func testChangingTotalsOrPageSizeNeverReturnPartialEvidence() async throws {
        let selected = try input(), first = try body([tunnel(selected)], size: 1, total: 2)
        for second in [try body([], page: 2, size: 1, total: 1), try body([tunnel(selected)], page: 2, size: 2, total: 2),
                       try body([], page: 2, size: 1, total: 2)] {
            try await failure(.invalidResponse, selected: selected, probe: Probe([first, second]))
        }
    }
    func testResponseAndAggregateByteLimitsDoNotReturnAFalseAbsence() async throws {
        let selected = try input()
        try await failure(.responseTooLarge, selected: selected, probe: Probe([Data(repeating: 32, count: FCMHTTPTransport.maximumResponseBytes + 1)]))
        var pages: [Data] = []
        for page in 1...10 {
            let id = String(format: "%08x-1111-4111-8111-111111111111", page)
            let raw = try body([tunnel(selected, id: id, name: "unrelated")], page: page, size: 1, total: 10)
            pages.append(raw + Data(repeating: 32, count: 60_000 - raw.count))
        }
        let probe = Probe(pages); try await failure(.responseTooLarge, selected: selected, probe: probe)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 9)
    }
    func testProviderStatusesNeverRetryAndDoNotExposeTheirBodies() async throws {
        let selected = try input()
        for (status, error): (Int, CloudflareProvisioningError) in [(401, .unauthorized), (403, .unauthorized), (429, .rateLimited),
            (404, .providerRejected), (500, .unavailable), (302, .unavailable)] {
            let probe = Probe([Data("synthetic-sensitive-diagnostic".utf8)], status: status)
            try await failure(error, selected: selected, probe: probe)
            let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
    }
    func testProviderEnvelopeFailuresAndMalformedJsonCannotReportAbsence() async throws {
        let selected = try input()
        for bytes in [try body(envelope: ["success": false]), try body(envelope: ["errors": [["message": "synthetic"]]])] {
            try await failure(.providerRejected, selected: selected, probe: Probe([bytes]))
        }
        for bytes in [Data("not-json".utf8), try body(envelope: ["success": 1]), try body(envelope: ["result": NSNull()])] {
            try await failure(.invalidResponse, selected: selected, probe: Probe([bytes]))
        }
    }
    func testTransportFailureOnALaterPageCannotReturnTheFirstMatch() async throws {
        let selected = try input(), probe = try Probe([body([tunnel(selected)], size: 1, total: 2)])
        try await failure(.unavailable, selected: selected, probe: probe)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testTransportDiagnosticsAreReducedToTypedErrors() async throws {
        let selected = try input()
        for large in [false, true] {
            let client = CloudflareTunnelInspectionClient(send: { _ in
                if large { throw FCMError.responseTooLarge }
                throw URLError(.cannotConnectToHost, userInfo: [NSLocalizedDescriptionKey: "synthetic-sensitive-diagnostic"])
            })
            do { _ = try await client.inspect(selected.configuration, expected: selected.expected, plan: selected.plan); XCTFail() }
            catch { XCTAssertEqual(error as? CloudflareProvisioningError, large ? .responseTooLarge : .unavailable) }
        }
    }
    func testAlreadyCancelledInspectionSendsNoCredential() async throws {
        let selected = try input(), probe = try Probe([body()])
        let task = Task { @Sendable in
            withUnsafeCurrentTask { $0?.cancel() }
            return try await self.inspect(selected, probe: probe)
        }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 0)
    }
    func testCancellationAfterAReplyCannotReturnInventoryEvidence() async throws {
        let selected = try input(), bytes = try body([tunnel(selected)])
        let task = Task { @Sendable in
            try await CloudflareTunnelInspectionClient(send: { _ in
                withUnsafeCurrentTask { $0?.cancel() }; return .init(status: 200, retryAfter: nil, body: bytes)
            }).inspect(selected.configuration, expected: selected.expected, plan: selected.plan)
        }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
    }
    func testCrossedConfigurationOrLocalOperationStopsBeforeSendingCredentials() async throws {
        let selected = try input(), other = try SharedSetupImportFixture().intent(), probe = try Probe([body()])
        let wrong = try SetupCloudflareConfiguration(accountID: String(repeating: "c", count: 32), zoneID: selected.configuration.zoneID,
            dnsSuffix: selected.configuration.dnsSuffix, apiToken: "synthetic-only")
        let client = CloudflareTunnelInspectionClient(send: { try await probe.send($0) })
        do { _ = try await client.inspect(wrong, expected: selected.expected, plan: selected.plan); XCTFail() }
        catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        do { _ = try await client.inspect(selected.configuration, expected: other, plan: selected.plan); XCTFail() } catch {}
        let requests = await probe.all(); XCTAssertEqual(requests.count, 0)
        for page in [0, CloudflareTunnelInspectionClient.maximumPages + 1] {
            XCTAssertThrowsError(try selected.configuration.tunnelInspectionRequest(expected: selected.expected, plan: selected.plan, page: page))
        }
    }
}
