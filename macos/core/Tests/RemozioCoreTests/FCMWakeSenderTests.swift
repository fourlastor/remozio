import Foundation
import CryptoKit
import RemozioProtocol
@testable import RemozioCore
import XCTest

final class FCMWakeSenderTests: XCTestCase, @unchecked Sendable {
    private let probeEpoch = UUID()
    private func verifiedProbeCandidate() throws -> VerifiedGatewayCandidate {
        let key = P256.Signing.PrivateKey(), limits = try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128)
        func id(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
        let binding = try GatewayTokenBinding(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4), lifecycleEpoch: id(5),
            phoneID: id(6), enrollmentEpoch: id(7), candidateID: id(8), tokenDigest: Data(SHA256.hash(data: Data("synthetic-registration".utf8))),
            challenge: id(9, 32), enrollmentTag: id(10, 32))
        let candidate = try GatewayTokenCandidate(binding: binding, revision: 1, operationID: id(11), issuedAtUnixMillis: 1_000_000, expiresAtUnixMillis: 1_060_000)
        let payload = try candidate.encode(limits: limits)
        let input = try GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
        let trust = try GatewayCandidateTrust(ownerID: binding.ownerID, macID: binding.macID, accountID: binding.accountID,
            gatewayID: binding.gatewayID, lifecycleEpoch: binding.lifecycleEpoch, rootPublicKey: key.publicKey.x963Representation,
            active: true, revision: UUID(), appliedControlRevision: 0,
            enrollment: GatewayPhoneEnrollment(phoneID: binding.phoneID, epoch: binding.enrollmentEpoch, tag: binding.enrollmentTag, active: true))
        return try GatewayCandidateVerifier.verify(canonicalCandidate: payload, signature: key.signature(for: input).rawRepresentation,
            wireVersion: 1, registrationToken: "synthetic-registration", trust: trust, nowUnixMillis: 1_000_000,
            now: AuthorityMoment(epoch: probeEpoch, milliseconds: 100), maximumLifetimeMillis: 60_000, payloadLimits: limits, signingLimits: limits)
    }
    private func probe(_ candidate: VerifiedGatewayCandidate? = nil, wall: UInt64 = 1_000_000,
                       moment: UInt64 = 100, maximumTTL: UInt32 = 300, epoch: UUID? = nil) throws -> FCMTokenProbe {
        try FCMTokenProbe(candidate: candidate ?? verifiedProbeCandidate(), nowUnixMillis: wall,
            now: AuthorityMoment(epoch: epoch ?? probeEpoch, milliseconds: moment), maximumTTLSeconds: maximumTTL)
    }

    func testProbeContainsOnlyBoundOpaqueChallengeAtNormalPriority() throws {
        let candidate = try verifiedProbeCandidate(), probe = try probe(candidate)
        let request = try sender("fixture-probe").request(probe, accessToken: token(), validateOnly: false)
        let root = try body(request), message = try XCTUnwrap(root["message"] as? [String: Any])
        XCTAssertEqual(Set(root.keys), ["message", "validate_only"])
        XCTAssertEqual(Set(message.keys), ["token", "data", "android"])
        XCTAssertEqual(message["token"] as? String, "synthetic-registration")
        let data = try XCTUnwrap(message["data"] as? [String: String])
        XCTAssertEqual(Set(data.keys), ["candidate_v1", "token_challenge_v1", "enrollment_v1"])
        guard case let .tokenChallenge(parsed) = try PushData.decode(data) else { return XCTFail() }
        XCTAssertEqual(parsed.candidateID, candidate.candidate.binding.candidateID)
        XCTAssertEqual(parsed.challenge, candidate.candidate.binding.challenge)
        XCTAssertEqual(parsed.enrollmentTag, candidate.candidate.binding.enrollmentTag)
        XCTAssertEqual(message["android"] as? [String: String], ["ttl": "60s", "priority": "NORMAL", "restricted_package_name": "dev.sebastiano.remozio.android"])
        XCTAssertEqual(String(reflecting: probe), "FCMTokenProbe(redacted)")
    }

    func testProbeTTLUsesTheShorterRemainingDeadlineAndRoundsDown() throws {
        let candidate = try verifiedProbeCandidate()
        XCTAssertEqual(try probe(candidate, maximumTTL: 5).ttlSeconds, 5)
        XCTAssertEqual(try probe(candidate, maximumTTL: 0).ttlSeconds, 0)
        XCTAssertEqual(try probe(candidate, moment: 5_100).ttlSeconds, 55)
        XCTAssertEqual(try probe(candidate, wall: 1_059_000).ttlSeconds, 1)
        XCTAssertEqual(try probe(candidate, moment: 60_099).ttlSeconds, 0)
        XCTAssertEqual(try probe(candidate, wall: 1_059_999).ttlSeconds, 0)
    }

    func testProbeRejectsExpiredCandidatesAndClockChanges() throws {
        let candidate = try verifiedProbeCandidate()
        XCTAssertThrowsError(try probe(candidate, moment: 60_100))
        XCTAssertThrowsError(try probe(candidate, wall: 1_060_000))
        XCTAssertThrowsError(try probe(candidate, wall: 999_999))
        XCTAssertThrowsError(try probe(candidate, moment: 99))
        XCTAssertThrowsError(try probe(candidate, epoch: UUID()))
        XCTAssertThrowsError(try probe(candidate, maximumTTL: 2_419_201))
    }

    func testProbeSendUsesBoundedTransportAndReportsOnlyProviderAcceptance() async throws {
        let probe = try probe(), client = try sender("fixture-probe-send")
        let accepted = try await client.send(probe, accessToken: token())
        let validated = try await client.send(probe, accessToken: token(), validateOnly: true)
        XCTAssertEqual(accepted, .accepted); XCTAssertEqual(validated, .validated)
        let request = try XCTUnwrap(FCMFixtureProtocol.requests.last("fixture-probe-send"))
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer synthetic-oauth-token")
        XCTAssertEqual(FCMFixtureProtocol.requests.count("fixture-probe-send"), 2)
        do { _ = try await sender("fixture-network-error").send(probe, accessToken: token()); XCTFail("Expected network failure") }
        catch { XCTAssertEqual(error as? FCMError, .network) }
    }

    private func sender(_ project: String = "fixture-success") throws -> FCMWakeSender {
        try FCMWakeSender(project: project, packageName: "dev.sebastiano.remozio.android",
            transport: FCMHTTPTransport(timeoutSeconds: 5, protocolClasses: [FCMFixtureProtocol.self]))
    }
    private func wake(ttl: UInt32 = 300, priority: FCMPriority = .high) throws -> FCMWake {
        try FCMWake(registrationToken: "synthetic-registration", identifier: Data(repeating: 7, count: 32), enrollmentTag: Data(repeating: 9, count: 32), ttlSeconds: ttl, priority: priority)
    }
    private func token() throws -> FCMAccessToken { try FCMAccessToken("synthetic-oauth-token") }
    private func body(_ request: URLRequest) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as? [String: Any])
    }
    private func reply(_ status: Int, code: String? = nil, type: String = "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                       retryAfter: String? = nil, outerCode: Int? = nil) throws -> FCMHTTPReply {
        let detail: [[String: String]] = code.map { [["@type": type, "errorCode": $0]] } ?? []
        let data = try JSONSerialization.data(withJSONObject: ["error": ["code": outerCode ?? status, "details": detail,
            "message": "synthetic secret must not escape"]])
        return FCMHTTPReply(status: status, retryAfter: retryAfter, body: data)
    }

    func testBuildsOnlyOpaqueWakeAndExplicitAndroidDeliveryOptions() throws {
        let request = try sender().request(wake(), accessToken: token(), validateOnly: false)
        XCTAssertEqual(request.url?.absoluteString, "https://fcm.googleapis.com/v1/projects/fixture-success/messages:send")
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer synthetic-oauth-token")
        let root = try body(request), message = try XCTUnwrap(root["message"] as? [String: Any])
        XCTAssertEqual(Set(root.keys), ["message", "validate_only"])
        XCTAssertEqual(Set(message.keys), ["token", "data", "android"])
        XCTAssertEqual(message["token"] as? String, "synthetic-registration")
        XCTAssertEqual(message["data"] as? [String: String], ["wake_v1": Data(repeating: 7, count: 32).base64EncodedString(), "enrollment_v1": Data(repeating: 9, count: 32).base64EncodedString()])
        XCTAssertEqual(message["android"] as? [String: String], ["ttl": "300s", "priority": "HIGH", "restricted_package_name": "dev.sebastiano.remozio.android"])
        let normal = try body(sender().request(wake(ttl: 0, priority: .normal), accessToken: token(), validateOnly: true))
        XCTAssertEqual(normal["validate_only"] as? Bool, true)
        let android = (normal["message"] as? [String: Any])?["android"] as? [String: String]
        XCTAssertEqual(android?["ttl"], "0s"); XCTAssertEqual(android?["priority"], "NORMAL")
        XCTAssertFalse(String(describing: try token()).contains("synthetic"))
        XCTAssertFalse(String(reflecting: try wake()).contains("synthetic"))
    }

    func testSharedRegistrationPreservesDistinctEnrollmentRoutes() throws {
        let first = try wake()
        let second = try FCMWake(registrationToken: "synthetic-registration", identifier: first.identifier,
            enrollmentTag: Data(repeating: 10, count: 32), ttlSeconds: 300, priority: .high)
        let one = try XCTUnwrap(body(sender().request(first, accessToken: token(), validateOnly: false))["message"] as? [String: Any])
        let two = try XCTUnwrap(body(sender().request(second, accessToken: token(), validateOnly: false))["message"] as? [String: Any])
        XCTAssertEqual(one["token"] as? String, two["token"] as? String)
        let dataOne = try XCTUnwrap(one["data"] as? [String: String])
        let dataTwo = try XCTUnwrap(two["data"] as? [String: String])
        XCTAssertEqual(dataOne["wake_v1"], dataTwo["wake_v1"])
        XCTAssertNotEqual(dataOne["enrollment_v1"], dataTwo["enrollment_v1"])
        XCTAssertEqual(dataTwo["enrollment_v1"], second.enrollmentTag.base64EncodedString())
    }

    func testRejectsInvalidConfigurationTokensAndWakeBounds() throws {
        for project in ["", ".", "..", "a/b", "../outside", "evil?key=1", "evil#fragment", "https://evil.test", String(repeating: "a", count: 129)] {
            XCTAssertThrowsError(try sender(project))
        }
        for timeout in [0.0, -1, .infinity, .nan, 121] {
            XCTAssertThrowsError(try FCMWakeSender(project: "fixture", packageName: "dev.sebastiano.remozio.android", timeoutSeconds: timeout))
        }
        XCTAssertThrowsError(try FCMWakeSender(project: "fixture", packageName: "bad\npackage"))
        for text in ["", "token\r\nInjected: x", "space token", String(repeating: "x", count: 16385)] {
            XCTAssertThrowsError(try FCMAccessToken(text))
            XCTAssertThrowsError(try FCMWake(registrationToken: text, identifier: Data(repeating: 0, count: 32), enrollmentTag: Data(repeating: 9, count: 32), ttlSeconds: 1, priority: .normal))
        }
        XCTAssertThrowsError(try FCMWake(registrationToken: "test", identifier: Data(), enrollmentTag: Data(repeating: 9, count: 32), ttlSeconds: 1, priority: .normal))
        for count in [0, 31, 33] {
            XCTAssertThrowsError(try FCMWake(registrationToken: "test", identifier: Data(repeating: 7, count: 32),
                enrollmentTag: Data(repeating: 9, count: count), ttlSeconds: 1, priority: .normal))
        }
        XCTAssertThrowsError(try wake(ttl: 2_419_201))
        XCTAssertNoThrow(try wake(ttl: 2_419_200))
    }

    func testClassifiesProviderAcceptanceSeparatelyFromValidationAndDelivery() async throws {
        let accepted = try await sender().send(wake(), accessToken: token())
        let validated = try await sender().send(wake(), accessToken: token(), validateOnly: true)
        XCTAssertEqual(accepted, .accepted); XCTAssertEqual(validated, .validated)
        let request = try XCTUnwrap(FCMFixtureProtocol.requests.last("fixture-success"))
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer synthetic-oauth-token")
        for text in ["{}", "not JSON", #"{"name":"projects/other/messages/123"}"#, #"{"name":"projects/fixture-success/messages/"}"#] {
            XCTAssertThrowsError(try sender().classify(FCMHTTPReply(status: 200, retryAfter: nil, body: Data(text.utf8)), validateOnly: false, now: Date()))
        }
    }

    func testOnlyTypedUnregisteredResponseInvalidatesRegistration() throws {
        let client = try sender(), now = Date()
        XCTAssertEqual(try client.classify(reply(404, code: "UNREGISTERED"), validateOnly: false, now: now), .registrationInvalid)
        for response in [try reply(404), try reply(404, code: "UNREGISTERED", type: "unexpected"),
                         try reply(404, code: "UNREGISTERED", outerCode: 400), try reply(400, code: "UNREGISTERED")] {
            XCTAssertEqual(try client.classify(response, validateOnly: false, now: now), .rejected(httpStatus: response.status))
        }
        XCTAssertEqual(try client.classify(reply(403, code: "SENDER_ID_MISMATCH"), validateOnly: false, now: now), .senderMismatch)
        XCTAssertEqual(try client.classify(reply(403), validateOnly: false, now: now), .rejected(httpStatus: 403))
        XCTAssertEqual(try client.classify(reply(401), validateOnly: false, now: now), .authenticationRequired)
        XCTAssertEqual(try client.classify(reply(418), validateOnly: false, now: now), .rejected(httpStatus: 418))
    }

    func testRetryFloorsPreserveQuotaAndLongRetryAfterWithoutSendingAgain() throws {
        let client = try sender(), now = Date(timeIntervalSince1970: 0)
        XCTAssertEqual(try client.classify(reply(429, retryAfter: "2"), validateOnly: false, now: now), .retryable(minimumDelaySeconds: 60))
        XCTAssertEqual(try client.classify(reply(503, retryAfter: "120"), validateOnly: false, now: now), .retryable(minimumDelaySeconds: 120))
        XCTAssertEqual(try client.classify(reply(500), validateOnly: false, now: now), .retryable(minimumDelaySeconds: 1))
        XCTAssertEqual(try client.classify(reply(503, retryAfter: "Thu, 01 Jan 1970 00:03:00 GMT"), validateOnly: false, now: now), .retryable(minimumDelaySeconds: 180))
        XCTAssertEqual(try client.classify(reply(503, retryAfter: "9999999999999999999999999"), validateOnly: false, now: now), .retryable(minimumDelaySeconds: .greatestFiniteMagnitude))
        XCTAssertEqual(try client.classify(reply(503, retryAfter: "invalid"), validateOnly: false, now: now), .retryable(minimumDelaySeconds: 1))
    }

    func testTransportRejectsDeclaredAndStreamedOversizedResponses() async throws {
        for project in ["fixture-declared-large", "fixture-stream-large"] {
            do { _ = try await sender(project).send(wake(), accessToken: token()); XCTFail("Expected response bound") }
            catch { XCTAssertEqual(error as? FCMError, .responseTooLarge) }
        }
    }

    func testExactResponseByteLimitIsAccepted() async throws {
        let result = try await sender("fixture-boundary").send(wake(), accessToken: token())
        XCTAssertEqual(result, .accepted)
    }

    func testNetworkDiagnosticsAreRedacted() async throws {
        do { _ = try await sender("fixture-network-error").send(wake(), accessToken: token()); XCTFail("Expected network error") }
        catch {
            XCTAssertEqual(error as? FCMError, .network)
            XCTAssertFalse(String(describing: error).contains("synthetic-secret"))
        }
    }

    func testRedirectNeverForwardsAuthorizationToAnotherEndpoint() async throws {
        let result = try await sender("fixture-redirect").send(wake(), accessToken: token())
        XCTAssertEqual(result, .rejected(httpStatus: 307))
        XCTAssertNil(FCMFixtureProtocol.requests.last("redirect-target"))
    }

    func testCancellationStopsActiveRequestWithoutRetry() async throws {
        let client = try sender("fixture-hang"), wake = try wake(), token = try token()
        let before = FCMFixtureProtocol.requests.count("fixture-hang")
        let task = Task { try await client.send(wake, accessToken: token) }
        defer { task.cancel() }
        for _ in 0..<100 {
            if FCMFixtureProtocol.requests.count("fixture-hang") > before { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertNotNil(FCMFixtureProtocol.requests.last("fixture-hang"))
        task.cancel()
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(FCMFixtureProtocol.requests.count("fixture-hang"), before + 1)
    }
}

private final class FCMFixtureProtocol: URLProtocol, @unchecked Sendable {
    static let requests = Requests()
    final class Requests: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [String: [URLRequest]] = [:]
        func append(_ request: URLRequest, key: String) { lock.withLock { values[key, default: []].append(request) } }
        func last(_ key: String) -> URLRequest? { lock.withLock { values[key]?.last } }
        func count(_ key: String) -> Int { lock.withLock { values[key]?.count ?? 0 } }
    }
    override class func canInit(with request: URLRequest) -> Bool { true } // No fixture request can reach a network.
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let url = request.url!
        let project = url.pathComponents.dropFirst(3).first ?? "redirect-target"
        Self.requests.append(request, key: project)
        if project == "fixture-hang" { return }
        if project == "fixture-network-error" {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "synthetic-secret", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "synthetic-secret"])); return
        }
        if project == "fixture-redirect" {
            let response = HTTPURLResponse(url: url, statusCode: 307, httpVersion: "HTTP/1.1", headerFields: ["Location": "https://redirect-target.invalid/"])!
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: URL(string: "https://redirect-target.invalid/")!), redirectResponse: response)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocolDidFinishLoading(self)
            return
        }
        let large = project == "fixture-stream-large" || project == "fixture-declared-large"
        let headers = project == "fixture-declared-large" ? ["Content-Length": "65537"] : [:]
        let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        var data = large ? Data(repeating: 65, count: 65537) : Data("{\"name\":\"projects/\(project)/messages/fixture\"}".utf8)
        if project == "fixture-boundary" { data.append(Data(repeating: 32, count: 65536 - data.count)) }
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
