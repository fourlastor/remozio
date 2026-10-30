import Foundation
import XCTest
@testable import RemozioCore

final class RelayConnectorReadinessTests: XCTestCase, @unchecked Sendable {
    private let id = UUID(uuidString: "12345678-1234-4234-9234-123456789012")!
    private func body(status: Int = 200, connections: Any = 1, identifier: String? = nil) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["status": status, "readyConnections": connections,
            "connectorId": identifier ?? id.uuidString])
    }
    private func probe(_ fixture: ReadinessFixtureProtocol.Reply) async throws -> RelayConnectorReadiness.State {
        let port = ReadinessFixtureProtocol.store.register(fixture)
        return try await RelayConnectorReadiness(protocolClasses: [ReadinessFixtureProtocol.self])
            .probe(.init(port: port, connectorID: id))
    }
    func testIdentityBoundConnectedAndDisconnectedResponses() async throws {
        let connected = try await probe(.init(body: body(connections: 4)))
        XCTAssertEqual(connected, .connected)
        let disconnected = try await probe(.init(status: 503, body: body(status: 503, connections: 0)))
        XCTAssertEqual(disconnected, .disconnected)
    }
    func testCrossedIdentityStatusAndConnectionCountsAreRejected() async throws {
        for reply in try [ReadinessFixtureProtocol.Reply(body: body(identifier: UUID().uuidString)),
            .init(body: body(status: 503, connections: 0)), .init(status: 503, body: body()),
            .init(body: body(connections: 0)), .init(status: 503, body: body(status: 503, connections: 1)),
            .init(body: body(connections: -1)), .init(body: body(connections: true)),
            .init(status: 500, body: body(status: 500, connections: 0)),
            .init(body: Data("{}".utf8)), .init(body: Data("invalid-json".utf8))] {
            do { _ = try await probe(reply); XCTFail("Invalid readiness response was accepted") }
            catch { XCTAssertEqual(error as? RelayConnectorReadiness.Failure, .invalidResponse) }
        }
    }
    func testDeclaredAndStreamingResponseLimitsAreEnforced() async throws {
        for reply in [ReadinessFixtureProtocol.Reply(headers: ["Content-Length": "8193"], body: Data()),
                      .init(body: Data(repeating: 32, count: 8193))] {
            do { _ = try await probe(reply); XCTFail("Oversized response was accepted") }
            catch { XCTAssertEqual(error as? RelayConnectorReadiness.Failure, .responseTooLarge) }
        }
        var boundary = try body()
        boundary.append(Data(repeating: 32, count: 8192 - boundary.count))
        let result = try await probe(.init(body: boundary))
        XCTAssertEqual(result, .connected)
    }
    func testRequestUsesOnlyTheFixedLoopbackPathWithoutCredentials() async throws {
        let port = ReadinessFixtureProtocol.store.register(.init(body: try body()))
        let client = try RelayConnectorReadiness(protocolClasses: [ReadinessFixtureProtocol.self])
        _ = try await client.probe(.init(port: port, connectorID: id))
        let request = try XCTUnwrap(ReadinessFixtureProtocol.store.request(port))
        XCTAssertEqual(request.url?.absoluteString, "http://127.0.0.1:\(port)/ready")
        XCTAssertEqual(request.httpMethod, "GET"); XCTAssertNil(request.httpBody)
        XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
        XCTAssertNil(request.value(forHTTPHeaderField: "Proxy-Authorization"))
        XCTAssertNil(request.value(forHTTPHeaderField: "Cookie"))
    }
    func testRedirectCannotSelectAnotherDestination() async throws {
        let before = ReadinessFixtureProtocol.store.redirectTargetCount
        do { _ = try await probe(.init(status: 307, body: Data(), redirect: true)); XCTFail("Redirect was accepted") }
        catch { XCTAssertEqual(error as? RelayConnectorReadiness.Failure, .invalidResponse) }
        XCTAssertEqual(ReadinessFixtureProtocol.store.redirectTargetCount, before)
    }
    func testCancellationStopsOnlyItsOwnAttempt() async throws {
        let slow = ReadinessFixtureProtocol.store.register(.init(body: Data(), hang: true))
        let fast = ReadinessFixtureProtocol.store.register(.init(body: try body()))
        let client = try RelayConnectorReadiness(protocolClasses: [ReadinessFixtureProtocol.self])
        let identifier = id
        let task = Task { try await client.probe(.init(port: slow, connectorID: identifier)) }
        defer { task.cancel() }
        for _ in 0..<100 {
            if ReadinessFixtureProtocol.store.request(slow) != nil { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertNotNil(ReadinessFixtureProtocol.store.request(slow))
        task.cancel()
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch { XCTAssertTrue(error is CancellationError) }
        let other = try await client.probe(.init(port: fast, connectorID: id))
        XCTAssertEqual(other, .connected)
        XCTAssertEqual(ReadinessFixtureProtocol.store.requestCount(slow), 1)
    }
    func testInvalidConfigurationAndNetworkErrorsExposeNoDiagnosticBody() async throws {
        for timeout in [0, -1, .infinity, .nan, 11] { XCTAssertThrowsError(try RelayConnectorReadiness(timeoutSeconds: timeout)) }
        let client = try RelayConnectorReadiness(protocolClasses: [ReadinessFixtureProtocol.self])
        do { _ = try await client.probe(.init(port: 0, connectorID: id)); XCTFail("Zero port was accepted") }
        catch { XCTAssertEqual(error as? RelayConnectorReadiness.Failure, .invalidConfiguration) }
        do { _ = try await probe(.init(body: Data(), fail: true)); XCTFail("Network failure was accepted") }
        catch {
            XCTAssertEqual(error as? RelayConnectorReadiness.Failure, .network)
            XCTAssertFalse(String(describing: error).contains("disposable-diagnostic"))
        }
    }
}

private final class ReadinessFixtureProtocol: URLProtocol, @unchecked Sendable {
    struct Reply: Sendable {
        let status: Int
        let headers: [String: String]
        let body: Data
        let redirect: Bool
        let hang: Bool
        let fail: Bool
        init(status: Int = 200, headers: [String: String] = [:], body: Data,
             redirect: Bool = false, hang: Bool = false, fail: Bool = false) {
            self.status = status; self.headers = headers; self.body = body
            self.redirect = redirect; self.hang = hang; self.fail = fail
        }
    }
    final class Store: @unchecked Sendable {
        private let lock = NSLock()
        private var next: UInt16 = 40_000
        private var replies: [UInt16: Reply] = [:]
        private var requests: [UInt16: [URLRequest]] = [:]
        private var redirected = 0
        func register(_ reply: Reply) -> UInt16 {
            lock.withLock { let port = next; next += 1; replies[port] = reply; return port }
        }
        func receive(_ request: URLRequest) -> Reply? {
            lock.withLock {
                guard request.url?.host == "127.0.0.1", let value = request.url?.port, let port = UInt16(exactly: value) else {
                    redirected += 1; return nil
                }
                requests[port, default: []].append(request); return replies[port]
            }
        }
        func request(_ port: UInt16) -> URLRequest? { lock.withLock { requests[port]?.last } }
        func requestCount(_ port: UInt16) -> Int { lock.withLock { requests[port]?.count ?? 0 } }
        var redirectTargetCount: Int { lock.withLock { redirected } }
    }
    static let store = Store()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        guard let reply = Self.store.receive(request) else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL)); return
        }
        if reply.hang { return }
        if reply.fail {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "disposable-diagnostic", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "disposable-diagnostic"])); return
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: "HTTP/1.1", headerFields: reply.headers)!
        if reply.redirect {
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: URL(string: "http://redirect-target.invalid/")!), redirectResponse: response)
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if !reply.body.isEmpty { client?.urlProtocol(self, didLoad: reply.body) }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
