import Foundation

/// Operational endpoint discovery only. This value does not authenticate a process or authorize an approval.
struct RelayConnectorDiscovery: Equatable, Sendable {
    let port: UInt16
    let connectorID: UUID
}

/// Reads only bounded JSON startup messages from the owned child's pipe. Other diagnostic content is discarded.
struct RelayConnectorDiagnostics {
    static let maximumLineBytes = 4096
    private var line = Data()
    private var dropping = false
    private var port: UInt16?
    private var identifier: UUID?
    private(set) var discovery: RelayConnectorDiscovery?
    var bufferedByteCount: Int { line.count }

    mutating func consume(_ bytes: ArraySlice<UInt8>) -> RelayConnectorDiscovery? {
        var observed: RelayConnectorDiscovery?
        for byte in bytes {
            if byte == 10 {
                if !dropping, discovery == nil { observed = parse() ?? observed }
                line.removeAll(keepingCapacity: true); dropping = false
            } else if !dropping {
                if line.count == Self.maximumLineBytes { line.removeAll(keepingCapacity: true); dropping = true }
                else { line.append(byte) }
            }
        }
        return observed
    }
    private mutating func parse() -> RelayConnectorDiscovery? {
        struct Message: Decodable { let message: String }
        guard let message = try? JSONDecoder().decode(Message.self, from: line).message else { return nil }
        let identifierPrefix = "Generated Connector ID: "
        let portPrefix = "Starting metrics server on 127.0.0.1:", portSuffix = "/metrics"
        if identifier == nil, message.hasPrefix(identifierPrefix) {
            let value = String(message.dropFirst(identifierPrefix.count))
            if let parsed = UUID(uuidString: value), parsed.uuidString.lowercased() == value.lowercased() { identifier = parsed }
        }
        if port == nil, message.hasPrefix(portPrefix), message.hasSuffix(portSuffix) {
            let value = String(message.dropFirst(portPrefix.count).dropLast(portSuffix.count))
            if let parsed = UInt16(value), parsed > 0, String(parsed) == value { port = parsed }
        }
        guard let port, let identifier else { return nil }
        let value = RelayConnectorDiscovery(port: port, connectorID: identifier)
        discovery = value; return value
    }
}
