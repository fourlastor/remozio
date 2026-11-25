import Network

/// Normalize transport addresses before applying source quotas. This key grants no pairing authority.
enum PairingSetupV2Source: Hashable, Sendable {
    case ipv4(UInt32)
    case ipv6(high: UInt64, low: UInt64)

    init?(_ endpoint: NWEndpoint) {
        guard case .hostPort(let host, _) = endpoint else { return nil }
        switch host {
        case .ipv4(let address):
            self = .ipv4(address.rawValue.reduce(0) { ($0 << 8) | UInt32($1) })
        case .ipv6(let address):
            let bytes = address.rawValue
            guard bytes.count == 16 else { return nil }
            let marker = bytes.index(bytes.startIndex, offsetBy: 10)
            if bytes.prefix(10).allSatisfy({ $0 == 0 }), bytes[marker] == 0xff, bytes[bytes.index(after: marker)] == 0xff {
                self = .ipv4(bytes.suffix(4).reduce(0) { ($0 << 8) | UInt32($1) })
            } else {
                self = .ipv6(high: bytes.prefix(8).reduce(0) { ($0 << 8) | UInt64($1) },
                             low: bytes.suffix(8).reduce(0) { ($0 << 8) | UInt64($1) })
            }
        case .name:
            return nil
        @unknown default:
            return nil
        }
    }
}
