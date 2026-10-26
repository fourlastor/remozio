import Foundation

/// Checks one discovered loopback endpoint. A connected edge does not prove Access policy or approval delivery.
struct RelayConnectorReadiness: Sendable {
    enum Failure: Error, Equatable { case invalidConfiguration, invalidResponse, responseTooLarge, network }
    enum State: Equatable, Sendable { case connected, disconnected }
    static let maximumResponseBytes = 8192
    private let timeoutSeconds: TimeInterval
    private let protocolClasses: [AnyClass]?
    init(timeoutSeconds: TimeInterval = 2, protocolClasses: [AnyClass]? = nil) throws {
        guard timeoutSeconds.isFinite, (0.05...10).contains(timeoutSeconds) else { throw Failure.invalidConfiguration }
        self.timeoutSeconds = timeoutSeconds; self.protocolClasses = protocolClasses
    }
    func probe(_ discovery: RelayConnectorDiscovery) async throws -> State {
        try Task.checkCancellation()
        guard discovery.port > 0 else { throw Failure.invalidConfiguration }
        var parts = URLComponents()
        parts.scheme = "http"; parts.host = "127.0.0.1"; parts.port = Int(discovery.port); parts.path = "/ready"
        guard let url = parts.url else { throw Failure.invalidConfiguration }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        configuration.urlCache = nil; configuration.urlCredentialStorage = nil; configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false; configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = timeoutSeconds; configuration.timeoutIntervalForResource = timeoutSeconds
        configuration.waitsForConnectivity = false
        if let protocolClasses { configuration.protocolClasses = protocolClasses }
        let session = URLSession(configuration: configuration, delegate: FixedEndpoint(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"; request.httpShouldHandleCookies = false
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        do {
            return try await withTaskCancellationHandler {
                try Task.checkCancellation()
                let (bytes, response) = try await session.bytes(for: request)
                guard let response = response as? HTTPURLResponse, response.url == url else { throw Failure.invalidResponse }
                guard response.expectedContentLength <= Int64(Self.maximumResponseBytes) else { throw Failure.responseTooLarge }
                var body = Data()
                for try await byte in bytes {
                    try Task.checkCancellation()
                    guard body.count < Self.maximumResponseBytes else { throw Failure.responseTooLarge }
                    body.append(byte)
                }
                try Task.checkCancellation()
                return try Self.interpret(status: response.statusCode, body: body, expected: discovery.connectorID)
            } onCancel: { session.invalidateAndCancel() }
        } catch {
            if Task.isCancelled || (error as? URLError)?.code == .cancelled { throw CancellationError() }
            if let known = error as? Failure { throw known }
            throw Failure.network
        }
    }
    private static func interpret(status: Int, body: Data, expected: UUID) throws -> State {
        struct Reply: Decodable { let status: Int; let readyConnections: UInt; let connectorId: UUID }
        guard let value = try? JSONDecoder().decode(Reply.self, from: body), value.connectorId == expected,
              value.status == status else { throw Failure.invalidResponse }
        switch status {
        case 200 where value.readyConnections > 0: return .connected
        case 503 where value.readyConnections == 0: return .disconnected
        default: throw Failure.invalidResponse
        }
    }
    private final class FixedEndpoint: NSObject, URLSessionTaskDelegate, Sendable {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
            completionHandler(nil)
        }
        func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
