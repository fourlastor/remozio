import Foundation
import XCTest
@testable import RemozioCore

final class RelayConnectorDiagnosticsTests: XCTestCase {
    private let id = UUID(uuidString: "12345678-1234-4234-9234-123456789012")!
    private func line(_ message: String) throws -> [UInt8] {
        Array(try JSONSerialization.data(withJSONObject: ["message": message])) + [10]
    }
    func testFragmentedMessagesRequireBothStartupFieldsAndPublishOnce() throws {
        var parser = RelayConnectorDiagnostics()
        let port = try line("Starting metrics server on 127.0.0.1:12345/metrics")
        for byte in port { XCTAssertNil(parser.consume([byte][...])) }
        let identity = try line("Generated Connector ID: " + id.uuidString)
        var observed: RelayConnectorDiscovery?
        for byte in identity { observed = parser.consume([byte][...]) ?? observed }
        XCTAssertEqual(observed, .init(port: 12345, connectorID: id))
        XCTAssertNil(parser.consume(try line("Starting metrics server on 127.0.0.1:54321/metrics")[...]))
        XCTAssertEqual(parser.discovery, observed)
    }
    func testOversizedAndMalformedLinesCannotSmuggleAValidSuffix() throws {
        var parser = RelayConnectorDiagnostics()
        XCTAssertNil(parser.consume(try line("Generated Connector ID: " + id.uuidString)[...]))
        var oversized = [UInt8](repeating: 120, count: RelayConnectorDiagnostics.maximumLineBytes + 1)
        oversized += try line("Starting metrics server on 127.0.0.1:12345/metrics")
        XCTAssertNil(parser.consume(oversized[...]))
        XCTAssertLessThanOrEqual(parser.bufferedByteCount, RelayConnectorDiagnostics.maximumLineBytes)
        XCTAssertNil(parser.consume(Array("not-json\n{\"message\":42}\n".utf8)[...]))
        XCTAssertEqual(parser.consume(try line("Starting metrics server on 127.0.0.1:12345/metrics")[...]),
            .init(port: 12345, connectorID: id))
    }
    func testOnlyAnExactNumericIPv4LoopbackEndpointCanBeDiscovered() throws {
        for endpoint in ["0.0.0.0:12345", "localhost:12345", "[::1]:12345", "127.0.0.1:0", "127.0.0.1:65536",
                         "127.0.0.1:0123", "127.0.0.1:+123", "127.0.0.1:123/other"] {
            var parser = RelayConnectorDiagnostics()
            XCTAssertNil(parser.consume(try line("Generated Connector ID: " + id.uuidString)[...]))
            XCTAssertNil(parser.consume(try line("Starting metrics server on " + endpoint + "/metrics")[...]), endpoint)
        }
        var parser = RelayConnectorDiagnostics()
        XCTAssertNil(parser.consume(try line("Generated Connector ID: invalid")[...]))
        XCTAssertNil(parser.consume(try line("Starting metrics server on 127.0.0.1:12345/metrics")[...]))
        XCTAssertNil(parser.discovery)
    }
}
