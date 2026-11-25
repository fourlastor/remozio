import Darwin
import Foundation
import Network
import RemozioMach

struct PairingLANAddressSelection {
    private static func usableIPv4(_ address: Data) -> Bool {
        guard address.count == 4, let first = address.first else { return false }
        return (1...223).contains(first) && first != 127 && !address.starts(with: [169, 254])
    }

    static func ipv4(_ addresses: [Data], primary: Data?) -> Data? {
        let usable = Set(addresses.filter(usableIPv4))
        if usable.count == 1 { return usable.first }
        guard let primary, usable.contains(primary) else { return nil }
        return primary
    }

    struct IPv6Candidate {
        let address: Data
        let flags: UInt32?

        var isUsable: Bool {
            guard address.count == 16, let first = address.first, let flags else { return false }
            let isGlobal = first & 0xe0 == 0x20
            let isUniqueLocal = first & 0xfe == 0xfc
            return (isGlobal || isUniqueLocal) && flags & UInt32(RemozioPairingIPv6Unusable) == 0
        }
    }

    static func ipv6(_ addresses: [IPv6Candidate]) -> Data? {
        // The global range sorts before the unique-local range.
        addresses.filter(\.isUsable).map(\.address).min { $0.lexicographicallyPrecedes($1) }
    }

    static func contains(_ bound: PairingLANRoute.Address, ipv4: [Data], ipv6: [IPv6Candidate]) -> Bool {
        switch bound {
        case .ipv4(let address):
            return usableIPv4(address.rawValue) && ipv4.contains(address.rawValue)
        case .ipv6(let address):
            return ipv6.contains { $0.address == address.rawValue && $0.isUsable }
        }
    }
}

/// A window keeps its selected interface and address for as long as both are usable.
struct PairingLANRoute: Sendable {
    enum Address: Equatable, Sendable {
        case ipv4(IPv4Address)
        case ipv6(IPv6Address)

        init?(family: PairingLANScope.AddressFamily, bytes: Data) {
            switch family {
            case .ipv4:
                guard let address = IPv4Address(bytes) else { return nil }
                self = .ipv4(address)
            case .ipv6:
                guard let address = IPv6Address(bytes) else { return nil }
                self = .ipv6(address)
            }
        }

        var host: NWEndpoint.Host {
            switch self {
            case .ipv4(let address): .ipv4(address)
            case .ipv6(let address): .ipv6(address)
            }
        }
    }

    let scope: PairingLANScope
    let interface: NWInterface
    let index: UInt32
    let address: Address

    static func resolve(_ scope: PairingLANScope, timeoutMilliseconds: UInt64) async throws -> Self {
        let index = if_nametoindex(scope.interfaceName)
        guard index != 0 else { throw TransportPairingControlError.unavailableInterface }
        let monitor = NWPathMonitor()
        defer { monitor.cancel() }
        let paths = AsyncStream<NWPath>(bufferingPolicy: .bufferingNewest(1)) { continuation in
            monitor.pathUpdateHandler = { _ = continuation.yield($0) }
        }
        monitor.start(queue: DispatchQueue(label: "dev.remozio.pairing-lan-path"))
        let path = try await withThrowingTaskGroup(of: NWPath.self) { tasks in
            tasks.addTask {
                for await path in paths { return path }
                throw TransportPairingControlError.closed
            }
            tasks.addTask {
                try await Task.sleep(for: .milliseconds(Int64(timeoutMilliseconds)))
                throw TransportPairingControlError.timedOut
            }
            defer { tasks.cancelAll() }
            guard let result = try await tasks.next() else { throw TransportPairingControlError.closed }
            return result
        }
        try Task.checkCancellation()
        let matches = path.availableInterfaces.filter { $0.name == scope.interfaceName && $0.index == Int(index) && $0.type != .loopback }
        guard matches.count == 1, let interface = matches.first, let address = selectAddress(scope) else {
            throw TransportPairingControlError.unavailableInterface
        }
        let route = Self(scope: scope, interface: interface, index: index, address: address)
        guard route.isCurrent else { throw TransportPairingControlError.unavailableInterface }
        return route
    }

    var isCurrent: Bool {
        guard if_nametoindex(scope.interfaceName) == index, let addresses = Self.readAddresses(scope),
              if_nametoindex(scope.interfaceName) == index else { return false }
        return PairingLANAddressSelection.contains(address, ipv4: addresses.ipv4, ipv6: addresses.ipv6)
    }

    private static func selectAddress(_ scope: PairingLANScope) -> Address? {
        guard let addresses = readAddresses(scope) else { return nil }
        let selected: Data?
        switch scope.family {
        case .ipv4:
            var primary: Data?
            if Set(addresses.ipv4).count > 1 {
                var bytes = [UInt8](repeating: 0, count: 4)
                if remozio_pairing_ipv4_primary(scope.interfaceName, &bytes) == 0 { primary = Data(bytes) }
            }
            selected = PairingLANAddressSelection.ipv4(addresses.ipv4, primary: primary)
        case .ipv6:
            selected = PairingLANAddressSelection.ipv6(addresses.ipv6)
        }
        return selected.flatMap { Address(family: scope.family, bytes: $0) }
    }

    private static func readAddresses(_ scope: PairingLANScope)
        -> (ipv4: [Data], ipv6: [PairingLANAddressSelection.IPv6Candidate])? {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return nil }
        defer { freeifaddrs(first) }
        var cursor = list
        var ipv4: [Data] = [], ipv6: [PairingLANAddressSelection.IPv6Candidate] = []
        while let entry = cursor {
            let info = entry.pointee
            cursor = info.ifa_next
            guard String(cString: info.ifa_name) == scope.interfaceName,
                  info.ifa_flags & UInt32(IFF_UP | IFF_RUNNING) == UInt32(IFF_UP | IFF_RUNNING),
                  info.ifa_flags & UInt32(IFF_LOOPBACK) == 0, let address = info.ifa_addr else { continue }
            switch (scope.family, Int32(address.pointee.sa_family)) {
            case (.ipv4, AF_INET):
                guard Int(address.pointee.sa_len) >= MemoryLayout<sockaddr_in>.size else { continue }
                let bytes = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                ipv4.append(withUnsafeBytes(of: bytes) { Data($0) })
            case (.ipv6, AF_INET6):
                guard Int(address.pointee.sa_len) >= MemoryLayout<sockaddr_in6>.size else { continue }
                let bytes = address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
                let data = withUnsafeBytes(of: bytes) { Data($0) }
                var flags: UInt32 = 0
                let status = data.withUnsafeBytes {
                    remozio_pairing_ipv6_flags(scope.interfaceName, $0.bindMemory(to: UInt8.self).baseAddress, &flags)
                }
                ipv6.append(.init(address: data, flags: status == 0 ? flags : nil))
            default: break
            }
        }
        return (ipv4, ipv6)
    }
}
