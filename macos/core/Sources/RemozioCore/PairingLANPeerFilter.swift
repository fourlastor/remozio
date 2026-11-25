import Darwin
import Foundation
import RemozioMach

struct PairingLANSubnet: Equatable, Sendable {
    private let bound: [UInt8]
    private let mask: [UInt8]

    /// Read only the bytes covered by Darwin's sa_len. Omitted trailing mask bytes are zero.
    init?(bound: PairingLANRoute.Address, netmask: [UInt8]) {
        guard let layout = PairingLANAddressLayout(bound), netmask.count >= 2 else { return nil }
        let length = Int(netmask[0])
        guard length > layout.offset, length <= layout.size, length <= netmask.count else { return nil }
        let family = Int32(netmask[1])
        guard family == AF_UNSPEC || family == layout.family else { return nil }

        let end = min(length, layout.offset + layout.bytes.count)
        var mask = Array(netmask[layout.offset..<end])
        mask += Array(repeating: 0, count: layout.bytes.count - mask.count)
        let minimumBytes = layout.family == AF_INET ? 1 : 2
        guard mask.prefix(minimumBytes).allSatisfy({ $0 == .max }) else { return nil }

        var prefixEnded = false
        for byte in mask {
            let prefixBits = (~byte).leadingZeroBitCount
            guard byte == UInt8.max << (8 - prefixBits), !prefixEnded || prefixBits == 0 else { return nil }
            prefixEnded = prefixBits < 8
        }
        self.bound = layout.bytes
        self.mask = mask
    }

    func contains(_ peer: PairingSetupV2Source) -> Bool {
        let bytes: [UInt8]
        switch peer {
        case .ipv4(let address):
            let first = address >> 24
            guard bound.count == 4, (1...223).contains(first), first != 127, address >> 16 != 0xa9fe else { return false }
            bytes = withUnsafeBytes(of: address.bigEndian) { Array($0) }
        case .ipv6(let high, let low):
            let first = high >> 56
            guard bound.count == 16, first & 0xe0 == 0x20 || first & 0xfe == 0xfc else { return false }
            bytes = withUnsafeBytes(of: high.bigEndian) { Array($0) } + withUnsafeBytes(of: low.bigEndian) { Array($0) }
        }
        return mask.indices.allSatisfy { (bytes[$0] ^ bound[$0]) & mask[$0] == 0 }
    }
}

private struct PairingLANAddressLayout {
    let family: Int32
    let size: Int
    let offset: Int
    let bytes: [UInt8]

    init?(_ address: PairingLANRoute.Address) {
        switch address {
        case .ipv4(let address):
            guard let offset = MemoryLayout<sockaddr_in>.offset(of: \.sin_addr) else { return nil }
            (family, size, self.offset, bytes) = (AF_INET, MemoryLayout<sockaddr_in>.size, offset, Array(address.rawValue))
        case .ipv6(let address):
            guard let offset = MemoryLayout<sockaddr_in6>.offset(of: \.sin6_addr) else { return nil }
            (family, size, self.offset, bytes) = (AF_INET6, MemoryLayout<sockaddr_in6>.size, offset, Array(address.rawValue))
        }
    }
}

extension PairingLANRoute {
    struct InterfaceRow {
        let flags: UInt32
        let address: [UInt8]
        let netmask: [UInt8]?
    }

    var liveSubnet: PairingLANSubnet? {
        Self.readSubnet(bound: address, index: index, liveIndex: { if_nametoindex(scope.interfaceName) },
                        rows: { Self.readInterfaceRows(scope.interfaceName) }, ipv6Flags: { bytes in
            var flags: UInt32 = 0
            let status = bytes.withUnsafeBufferPointer {
                remozio_pairing_ipv6_flags(scope.interfaceName, $0.baseAddress, &flags)
            }
            return status == 0 ? flags : nil
        })
    }

    static func readSubnet(bound: Address, index: UInt32, liveIndex: () -> UInt32, rows: () -> [InterfaceRow]?,
                           ipv6Flags: ([UInt8]) -> UInt32?) -> PairingLANSubnet? {
        guard index != 0, liveIndex() == index, let layout = PairingLANAddressLayout(bound), let rows = rows() else { return nil }
        let active = UInt32(IFF_UP | IFF_RUNNING)
        var subnet: PairingLANSubnet?
        for row in rows {
            guard row.address.count >= layout.size, Int(row.address[0]) >= layout.size, Int(row.address[0]) <= row.address.count,
                  Int32(row.address[1]) == layout.family,
                  row.address[layout.offset..<(layout.offset + layout.bytes.count)].elementsEqual(layout.bytes) else { continue }
            guard subnet == nil, row.flags & active == active, row.flags & UInt32(IFF_LOOPBACK) == 0,
                  let mask = row.netmask, let exact = PairingLANSubnet(bound: bound, netmask: mask) else { return nil }
            subnet = exact
        }

        guard let subnet else { return nil }
        if layout.family == AF_INET6 {
            guard let flags = ipv6Flags(layout.bytes), flags & UInt32(RemozioPairingIPv6Unusable) == 0 else { return nil }
        }
        return liveIndex() == index ? subnet : nil
    }

    private static func readInterfaceRows(_ interface: String) -> [InterfaceRow]? {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return nil }
        defer { freeifaddrs(first) }

        func bytes(_ address: UnsafePointer<sockaddr>) -> [UInt8] {
            Array(UnsafeRawBufferPointer(start: UnsafeRawPointer(address), count: Int(address.pointee.sa_len)))
        }

        var rows: [InterfaceRow] = []
        var cursor = list
        while let entry = cursor {
            let info = entry.pointee
            cursor = info.ifa_next
            guard String(cString: info.ifa_name) == interface, let address = info.ifa_addr else { continue }
            let family = Int32(address.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            rows.append(.init(flags: info.ifa_flags, address: bytes(UnsafePointer(address)),
                              netmask: info.ifa_netmask.map { bytes(UnsafePointer($0)) }))
        }
        return rows
    }
}
