import CryptoKit
import Foundation
import XCTest
@testable import RemozioCore

enum RelayPrivateRouteReplies {
    static func page(results: [[String: Any]] = [], info changes: [String: Any] = [:], envelope extra: [String: Any] = [:]) throws -> Data {
        var info: [String: Any] = ["page": 1, "count": results.count, "per_page": 100, "total_count": results.count]
        for (key, value) in changes { info[key] = value }
        var envelope: [String: Any] = ["success": true, "errors": [], "result": results, "result_info": info]
        for (key, value) in extra { envelope[key] = value }
        return try JSONSerialization.data(withJSONObject: envelope)
    }
}

/// Synthetic route lists only. Empty filtered results are observations,not an atomic provider policy lock.
final class CloudflarePrivateRouteClientTests: XCTestCase, @unchecked Sendable {
    private func inspect(_ i: RelayIngressProviderFixture, probe: RelayIngressProbe) async throws -> CloudflarePrivateRouteObservation {
        try await CloudflarePrivateRouteClient(send: { try await probe.send($0) }).inspect(i.configuration, expected: i.expected, plan: i.plan, created: i.created)
    }
    private func empty() throws -> RelayIngressProbe.Step { RelayIngressProbe.reply(try RelayPrivateRouteReplies.page()) }
    func testBothFixedListsUseTheRetainedUuidAndExcludeDeletedRoutes() async throws {
        let i = try RelayIngressProviderFixture(), probe = try RelayIngressProbe([empty(), empty()])
        let observed = try await inspect(i, probe: probe), requests = await probe.all()
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(requests.map { $0.url?.path }, ["/client/v4/accounts/\(i.configuration.accountID)/teamnet/routes", "/client/v4/accounts/\(i.configuration.accountID)/zerotrust/routes/hostname"])
        for request in requests {
            XCTAssertEqual(request.httpMethod, "GET"); XCTAssertNil(request.httpBody)
            let url = try XCTUnwrap(URLComponents(url: XCTUnwrap(request.url), resolvingAgainstBaseURL: false))
            XCTAssertEqual(url.scheme, "https"); XCTAssertEqual(url.host, "api.cloudflare.com")
            XCTAssertEqual(Dictionary(uniqueKeysWithValues: (url.queryItems ?? []).map { ($0.name, $0.value ?? "") }),
                ["tunnel_id": "11111111-1111-4111-8111-111111111111", "is_deleted": "false", "page": "1", "per_page": "100"])
            XCTAssertTrue(request.value(forHTTPHeaderField: "Authorization")?.hasPrefix("Bearer ") == true)
        }
        XCTAssertNoThrow(try observed.validate(expected: i.expected, plan: i.plan, created: i.created))
        XCTAssertEqual(String(reflecting: observed), "CloudflarePrivateRouteObservation(redacted)")
    }
    func testOtherMacsGlobalTotalsDoNotInvalidateEmptyTunnelFilteredResults() async throws {
        let i = try RelayIngressProviderFixture(), bytes = try RelayPrivateRouteReplies.page(info: ["total_count": 2000, "total_pages": 20])
        let probe = RelayIngressProbe([RelayIngressProbe.reply(bytes), RelayIngressProbe.reply(bytes)])
        _ = try await inspect(i, probe: probe); let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testAnIpRouteStopsWithoutAnyMutationOrHostnameQuery() async throws {
        let i = try RelayIngressProviderFixture(), bytes = try RelayPrivateRouteReplies.page(results: [["id": "22222222-2222-4222-8222-222222222222",
            "tunnel_id": "11111111-1111-4111-8111-111111111111", "network": "10.0.0.0/8", "deleted_at": NSNull()]])
        let probe = RelayIngressProbe([RelayIngressProbe.reply(bytes)])
        do { _ = try await inspect(i, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
    }
    func testAHostnameRouteCannotHideBehindAnEmptyIpList() async throws {
        let i = try RelayIngressProviderFixture(), bytes = try RelayPrivateRouteReplies.page(results: [["hostname": "internal.invalid", "tunnel_id": "11111111-1111-4111-8111-111111111111"]])
        let probe = try RelayIngressProbe([empty(), RelayIngressProbe.reply(bytes)])
        do { _ = try await inspect(i, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testMalformedOrCrossedFilterResultsCannotProveAbsence() async throws {
        let i = try RelayIngressProviderFixture()
        let bodies = try [RelayPrivateRouteReplies.page(results: [["tunnel_id": "22222222-2222-4222-8222-222222222222"]]),
            RelayPrivateRouteReplies.page(envelope: ["result": NSNull()]), RelayPrivateRouteReplies.page(envelope: ["result_info": NSNull()]),
            RelayPrivateRouteReplies.page(envelope: ["success": false]), RelayPrivateRouteReplies.page(envelope: ["errors": [["code": 1000]]]), Data("not-json".utf8)]
        for bytes in bodies {
            do { _ = try await inspect(i, probe: RelayIngressProbe([RelayIngressProbe.reply(bytes)])); XCTFail() } catch {}
        }
    }
    func testMalformedPageMetadataCannotClaimAnEmptyFirstPage() async throws {
        let i = try RelayIngressProviderFixture()
        let changes: [[String: Any]] = [["page": 0], ["page": 2], ["count": 1], ["count": -1], ["per_page": 0],
            ["per_page": 101], ["total_count": -1], ["total_pages": -1], ["page": "1"]]
        for change in changes {
            let probe = RelayIngressProbe([RelayIngressProbe.reply(try RelayPrivateRouteReplies.page(info: change))])
            do { _ = try await inspect(i, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .invalidResponse) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
    }
    func testPermissionAndHttpFailuresAreNeverTreatedAsNoRoutes() async throws {
        let i = try RelayIngressProviderFixture()
        for (status, expected): (Int, CloudflareProvisioningError) in [(401, .unauthorized), (403, .unauthorized), (404, .providerRejected),
            (429, .rateLimited), (302, .unavailable), (503, .unavailable)] {
            let probe = try RelayIngressProbe([empty(), RelayIngressProbe.reply(Data(), status: status)])
            do { _ = try await inspect(i, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, expected) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
        }
    }
    func testTransportFailureAfterTheIpListDoesNotReturnPartialEvidence() async throws {
        let i = try RelayIngressProviderFixture(), probe = try RelayIngressProbe([empty(), .lost])
        do { _ = try await inspect(i, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .unavailable) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testOversizedReplyIsBoundedWithoutRetry() async throws {
        let i = try RelayIngressProviderFixture(), probe = RelayIngressProbe([RelayIngressProbe.reply(Data(repeating: 32, count: FCMHTTPTransport.maximumResponseBytes + 1))])
        do { _ = try await inspect(i, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .responseTooLarge) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
    func testCancellationAfterIpReplySendsNoHostnameRequest() async throws {
        let i = try RelayIngressProviderFixture(), probe = try RelayIngressProbe([empty(), empty()], hook: { _, _ in withUnsafeCurrentTask { $0?.cancel() } })
        let task = Task { @Sendable in try await self.inspect(i, probe: probe) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
    func testAlreadyCancelledInspectionSendsNoCredential() async throws {
        let i = try RelayIngressProviderFixture(), probe = RelayIngressProbe([])
        let task = Task { @Sendable in withUnsafeCurrentTask { $0?.cancel() }; return try await self.inspect(i, probe: probe) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
    func testUnresolvedOrCrossedSelectionStopsBeforeSendingCredentials() async throws {
        let i = try RelayIngressProviderFixture(), probe = RelayIngressProbe([])
        let prepared = try SharedSetupRelayProvisioningRecord(expected: i.expected, plan: i.plan)
        do { _ = try await CloudflarePrivateRouteClient(send: { try await probe.send($0) }).inspect(i.configuration,
            expected: i.expected, plan: i.plan, created: prepared); XCTFail() } catch {}
        let wrong = try SetupCloudflareConfiguration(accountID: String(repeating: "c", count: 32), zoneID: i.configuration.zoneID,
            dnsSuffix: i.configuration.dnsSuffix, apiToken: "synthetic-only")
        do { _ = try await CloudflarePrivateRouteClient(send: { try await probe.send($0) }).inspect(wrong,
            expected: i.expected, plan: i.plan, created: i.created); XCTFail() } catch {}
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
    func testObservationIsBoundToTheCreatedTunnelAndPlanDigest() throws {
        let i = try RelayIngressProviderFixture()
        let valid = CloudflarePrivateRouteObservation(accountID: i.configuration.accountID,
            tunnelID: "11111111-1111-4111-8111-111111111111", planDigest: Data(SHA256.hash(data: i.plan.bytes)))
        XCTAssertNoThrow(try valid.validate(expected: i.expected, plan: i.plan, created: i.created))
        let crossed = CloudflarePrivateRouteObservation(accountID: valid.accountID, tunnelID: "22222222-2222-4222-8222-222222222222", planDigest: valid.planDigest)
        XCTAssertThrowsError(try crossed.validate(expected: i.expected, plan: i.plan, created: i.created))
        let changed = try SharedSetupImportRelayPlan(expected: i.expected, port: 51002)
        XCTAssertThrowsError(try valid.validate(expected: i.expected, plan: changed, created: i.created))
    }
}
