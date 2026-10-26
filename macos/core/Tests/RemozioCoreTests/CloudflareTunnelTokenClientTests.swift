import Foundation
import XCTest
@testable import RemozioCore

/// Synthetic credentials only. No provider or native credential store is accessed.
final class CloudflareTunnelTokenClientTests: XCTestCase, @unchecked Sendable {
    private let tunnelID = "11111111-1111-4111-8111-111111111111"
    private func token(_ i: RelayIngressProviderFixture, changes: [String: Any] = [:]) throws -> String {
        var fields: [String: Any] = ["a": i.configuration.accountID, "t": tunnelID,
            "s": Data(repeating: 0x71, count: 32).base64EncodedString()]
        for (key, value) in changes { fields[key] = value }
        return try JSONSerialization.data(withJSONObject: fields).base64EncodedString()
    }
    private func envelope(_ token: String) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["success": true, "errors": [], "result": token])
    }
    private func metadata(_ i: RelayIngressProviderFixture, changes: [String: Any] = [:]) throws -> RelayIngressProbe.Step {
        .reply(.init(status: 200, retryAfter: nil, body: try RelayIngressProviderFixture.metadata(
            configuration: i.configuration, plan: i.plan, changes: changes)))
    }
    private func read(_ i: RelayIngressProviderFixture, _ probe: RelayIngressProbe,
                      created: SharedSetupRelayProvisioningRecord? = nil) async throws -> CloudflareTunnelRunCredential {
        try await CloudflareTunnelTokenClient(send: { try await probe.send($0) }).read(i.configuration,
            expected: i.expected, plan: i.plan, created: created ?? i.created)
    }

    func testReadBindsTheCredentialAndEveryRequestToTheRetainedTunnel() async throws {
        let i = try RelayIngressProviderFixture()
        let probe = try RelayIngressProbe([metadata(i), .reply(.init(status: 200, retryAfter: nil, body: envelope(token(i)))), metadata(i)])
        let credential = try await read(i, probe), requests = await probe.all()
        XCTAssertEqual(credential.tunnel, try i.created.createdTunnel(expected: i.expected, plan: i.plan))
        XCTAssertEqual(requests.count, 3)
        XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" && $0.httpBody == nil })
        let base = "https://api.cloudflare.com/client/v4/accounts/" + i.configuration.accountID + "/cfd_tunnel/" + tunnelID
        XCTAssertEqual(requests.map { $0.url?.absoluteString }, [base, base + "/token", base])
        try credential.withFileBytes { bytes in
            let data = try XCTUnwrap(Data(base64Encoded: bytes))
            let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: String])
            XCTAssertEqual(Set(fields.keys), ["a", "s", "t"])
            XCTAssertEqual(fields["a"], i.configuration.accountID); XCTAssertEqual(fields["t"], tunnelID)
        }
        XCTAssertEqual(String(describing: credential), "CloudflareTunnelRunCredential(redacted)")
        XCTAssertEqual(String(reflecting: credential), "CloudflareTunnelRunCredential(redacted)")
        var diagnostic = ""
        dump(credential, to: &diagnostic)
        XCTAssertLessThan(diagnostic.utf8.count, 128)
        XCTAssertTrue(diagnostic.contains("redacted"))
    }

    func testCrossedCredentialIdentityOrEndpointNeverEscapesTheClient() async throws {
        let i = try RelayIngressProviderFixture()
        for change: [String: Any] in [["a": String(repeating: "c", count: 32)],
            ["t": "22222222-2222-4222-8222-222222222222"], ["e": "untrusted.invalid"]] {
            let probe = try RelayIngressProbe([metadata(i), .reply(.init(status: 200, retryAfter: nil, body: envelope(token(i, changes: change))))])
            do { _ = try await read(i, probe); XCTFail("A crossed credential was accepted") }
            catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
        }
    }

    func testMalformedCredentialNeverProducesAFileValue() async throws {
        let i = try RelayIngressProviderFixture()
        let malformed = try ["", "not-base64", token(i) + "\n", String(repeating: "a", count: 8193),
            token(i, changes: ["s": "not-base64"]), token(i, changes: ["s": ""]),
            token(i, changes: ["s": 4]), token(i, changes: ["a": NSNull()])]
        for value in malformed {
            let probe = try RelayIngressProbe([metadata(i), .reply(.init(status: 200, retryAfter: nil, body: envelope(value)))])
            do { _ = try await read(i, probe); XCTFail("A malformed credential was accepted") }
            catch { XCTAssertEqual(error as? CloudflareProvisioningError, .invalidResponse) }
        }
    }

    func testChangedTunnelAfterTheReadPreventsCredentialPublication() async throws {
        let i = try RelayIngressProviderFixture()
        let probe = try RelayIngressProbe([metadata(i), .reply(.init(status: 200, retryAfter: nil, body: envelope(token(i)))),
            metadata(i, changes: ["deleted_at": "2026-10-20T00:00:00Z"])])
        do { _ = try await read(i, probe); XCTFail("A deleted tunnel produced a credential") }
        catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 3)
    }

    func testUnresolvedCreationSendsNothing() async throws {
        let i = try RelayIngressProviderFixture(), probe = RelayIngressProbe([])
        let prepared = try SharedSetupRelayProvisioningRecord(expected: i.expected, plan: i.plan)
        let dispatched = try prepared.transition(to: .dispatched)
        for state in [prepared, dispatched, try dispatched.transition(to: .unknown)] {
            do { _ = try await read(i, probe, created: state); XCTFail("An unresolved creation sent a request") } catch {}
        }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }

    func testProviderRefusalAndLostReplyDoNotRetryOrLeakDiagnostics() async throws {
        let i = try RelayIngressProviderFixture()
        let failures: [(RelayIngressProbe.Step, CloudflareProvisioningError)] = [
            (.lost, .unavailable), (.reply(.init(status: 401, retryAfter: nil, body: Data())), .unauthorized),
            (.reply(.init(status: 429, retryAfter: nil, body: Data())), .rateLimited),
            (.reply(.init(status: 302, retryAfter: nil, body: Data())), .unavailable)]
        for (step, expected) in failures {
            let probe = try RelayIngressProbe([metadata(i), step])
            do { _ = try await read(i, probe); XCTFail("A failed read returned a credential") }
            catch { XCTAssertEqual(error as? CloudflareProvisioningError, expected) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
        }
    }

    func testCancellationAfterTokenReplyDoesNotReturnTheCredential() async throws {
        let i = try RelayIngressProviderFixture()
        let probe = try RelayIngressProbe([metadata(i), .reply(.init(status: 200, retryAfter: nil, body: envelope(token(i))))], hook: { count, _ in
            if count == 2 { withUnsafeCurrentTask { $0?.cancel() } }
        })
        let task = Task { @Sendable in try await self.read(i, probe) }
        do { _ = try await task.value; XCTFail("Cancelled work returned a credential") }
        catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
}
