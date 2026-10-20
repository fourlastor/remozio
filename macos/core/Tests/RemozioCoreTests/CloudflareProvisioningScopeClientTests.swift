import Foundation
import XCTest
@testable import RemozioCore

/// Synthetic provider replies only. These tests perform no network request and prove no provider permission.
final class CloudflareProvisioningScopeClientTests: XCTestCase, @unchecked Sendable {
    private static let account = String(repeating: "a", count: 32), zone = String(repeating: "b", count: 32)
    private actor Probe {
        var requests: [URLRequest] = []
        func record(_ request: URLRequest) { requests.append(request) }
        func count() -> Int { requests.count }
        func first() -> URLRequest? { requests.first }
    }
    private func configuration(suffix: String = "relay.fixture.example") throws -> SetupCloudflareConfiguration {
        try .init(accountID: Self.account, zoneID: Self.zone, dnsSuffix: suffix, apiToken: "synthetic-not-a-secret")
    }
    private func body(account: String = CloudflareProvisioningScopeClientTests.account, zone: String = CloudflareProvisioningScopeClientTests.zone, name: String = "fixture.example",
                      status: String = "active", paused: Bool = false) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["success": true, "errors": [], "result": [
            "id": zone, "account": ["id": account], "name": name, "status": status, "paused": paused]])
    }
    private func client(_ reply: FCMHTTPReply, probe: Probe? = nil) -> CloudflareProvisioningScopeClient {
        .init(send: { request in await probe?.record(request); return reply })
    }
    private func failure(_ expected: CloudflareProvisioningError, client: CloudflareProvisioningScopeClient,
                         configuration selected: SetupCloudflareConfiguration? = nil) async throws {
        do { _ = try await client.inspect(selected ?? configuration()); XCTFail("Expected a scoped failure") }
        catch { XCTAssertEqual(error as? CloudflareProvisioningError, expected) }
    }
    func testTheOnlyRequestUsesTheFixedOriginAndConfiguredZone() async throws {
        let probe = Probe(), value = try await client(.init(status: 200, retryAfter: nil, body: body()), probe: probe).inspect(configuration())
        let first = await probe.first(), request = try XCTUnwrap(first)
        XCTAssertEqual(request.url?.absoluteString, "https://api.cloudflare.com/client/v4/zones/" + Self.zone)
        XCTAssertEqual(request.httpMethod, "GET"); XCTAssertNil(request.httpBody)
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer synthetic-not-a-secret")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
        XCTAssertEqual(value.accountID, Self.account); XCTAssertEqual(value.zoneID, Self.zone)
        XCTAssertEqual(value.zoneName, "fixture.example"); XCTAssertEqual(value.dnsSuffix, "relay.fixture.example")
        XCTAssertEqual(String(reflecting: value), "CloudflareProvisioningScope(redacted)")
        let count = await probe.count(); XCTAssertEqual(count, 1)
    }
    func testTheZoneApexAndDeeperSuffixesAreAccepted() async throws {
        for suffix in ["fixture.example", "relay.fixture.example", "a.b.fixture.example"] {
            let result = try await client(.init(status: 200, retryAfter: nil, body: body())).inspect(configuration(suffix: suffix))
            XCTAssertEqual(result.dnsSuffix, suffix)
        }
    }
    func testProviderZoneCaseIsNormalizedBeforeTheLabelCheck() async throws {
        let result = try await client(.init(status: 200, retryAfter: nil, body: body(name: "Fixture.EXAMPLE"))).inspect(configuration())
        XCTAssertEqual(result.zoneName, "fixture.example")
    }
    func testSuffixMatchingUsesTheDnsLabelBoundary() async throws {
        for suffix in ["evilfixture.example", "fixture.example.attacker.example", "other.example"] {
            try await failure(.wrongScope, client: client(.init(status: 200, retryAfter: nil, body: body())), configuration: configuration(suffix: suffix))
        }
    }
    func testAProviderReplyForAnotherAccountOrZoneCannotAuthorizeTheScope() async throws {
        for bytes in [try body(account: String(repeating: "c", count: 32)), try body(zone: String(repeating: "c", count: 32))] {
            try await failure(.wrongScope, client: client(.init(status: 200, retryAfter: nil, body: bytes)))
        }
    }
    func testPausedAndInactiveZonesRemainUnavailable() async throws {
        for bytes in [try body(paused: true), try body(status: "pending"), try body(status: "moved")] {
            try await failure(.unavailable, client: client(.init(status: 200, retryAfter: nil, body: bytes)))
        }
    }
    func testProviderFailureStatusesNeverRetryOrExposeTheBody() async throws {
        for (status, expected): (Int, CloudflareProvisioningError) in [
            (401, .unauthorized), (403, .unauthorized), (429, .rateLimited), (400, .providerRejected),
            (404, .providerRejected), (500, .unavailable), (301, .unavailable)] {
            let probe = Probe()
            try await failure(expected, client: client(.init(status: status, retryAfter: "1", body: Data("synthetic-sensitive-diagnostic".utf8)), probe: probe))
            let count = await probe.count(); XCTAssertEqual(count, 1)
        }
    }
    func testProviderErrorsAndFalseSuccessNeverCreateAValidScope() async throws {
        for json in ["{\"success\":false,\"errors\":[],\"result\":null}", "{\"success\":true,\"errors\":[{}],\"result\":null}"] {
            try await failure(.providerRejected, client: client(.init(status: 200, retryAfter: nil, body: Data(json.utf8))))
        }
    }
    func testMissingMalformedAndCoercedProviderFieldsAreRejected() async throws {
        let valid = try XCTUnwrap(JSONSerialization.jsonObject(with: body()) as? [String: Any])
        var wrongBoolean = valid; wrongBoolean["success"] = 1
        var missingResult = valid; missingResult.removeValue(forKey: "result")
        var wrongZone = valid; var result = try XCTUnwrap(wrongZone["result"] as? [String: Any]); result["paused"] = 0; wrongZone["result"] = result
        for bytes in [Data("not json".utf8), try JSONSerialization.data(withJSONObject: wrongBoolean),
                      try JSONSerialization.data(withJSONObject: missingResult), try JSONSerialization.data(withJSONObject: wrongZone), try body(name: "fixture..example")] {
            try await failure(.invalidResponse, client: client(.init(status: 200, retryAfter: nil, body: bytes)))
        }
    }
    func testOversizedProviderResponsesCannotReachTheDecoder() async throws {
        try await failure(.responseTooLarge, client: client(.init(status: 200, retryAfter: nil,
            body: Data(repeating: 32, count: FCMHTTPTransport.maximumResponseBytes + 1))))
    }
    func testTransportDiagnosticsAreReducedToTypedErrors() async throws {
        try await failure(.unavailable, client: .init(send: { _ in throw URLError(.cannotConnectToHost, userInfo: [NSLocalizedDescriptionKey: "synthetic-sensitive-diagnostic"]) }))
        try await failure(.responseTooLarge, client: .init(send: { _ in throw FCMError.responseTooLarge }))
    }
    func testAnAlreadyCancelledAttemptNeverSendsCredentials() async throws {
        let probe = Probe(), bytes = try body(), selected = try configuration()
        let task = Task { @Sendable in
            withUnsafeCurrentTask { $0?.cancel() }
            return try await self.client(.init(status: 200, retryAfter: nil, body: bytes), probe: probe).inspect(selected)
        }
        do { _ = try await task.value; XCTFail("Expected cancellation") } catch { XCTAssertTrue(error is CancellationError) }
        let count = await probe.count(); XCTAssertEqual(count, 0)
    }
    func testCancellationDuringTransportCannotReturnAnInspectedScope() async throws {
        let bytes = try body(), selected = try configuration()
        let task = Task { @Sendable in
            try await CloudflareProvisioningScopeClient(send: { _ in
                withUnsafeCurrentTask { $0?.cancel() }; return .init(status: 200, retryAfter: nil, body: bytes)
            }).inspect(selected)
        }
        do { _ = try await task.value; XCTFail("Expected cancellation") } catch { XCTAssertTrue(error is CancellationError) }
    }
}
