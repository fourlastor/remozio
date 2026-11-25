import Darwin
import dnssd
import Foundation
import Network
import RemozioMach
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class PairingLANPolicyTests: XCTestCase {
    private final class AdvertisementEvents: Sendable {
        let callback = Mutex<(@Sendable (Bool) -> Void)?>(nil)
        let stopped = Mutex(0)
        let reports = Mutex<[Bool]>([])
    }

    private func bytes(_ hex: String) -> Data {
        let digits = Array(hex.filter { !$0.isWhitespace })
        return Data(stride(from: 0, to: digits.count, by: 2).map { UInt8(String(digits[$0...($0 + 1)]), radix: 16)! })
    }

    private func subnet(_ address: PairingLANRoute.Address, mask: [UInt8], family: Int32 = AF_UNSPEC,
                        offset: Int, reportedLength: UInt8? = nil) -> PairingLANSubnet? {
        let length = offset + mask.count
        let header = [reportedLength ?? UInt8(length), UInt8(family)] + Array(repeating: 0, count: offset - 2)
        return PairingLANSubnet(bound: address, netmask: header + mask)
    }

    private func source(_ host: String) throws -> PairingSetupV2Source {
        try XCTUnwrap(PairingSetupV2Source(.hostPort(host: NWEndpoint.Host(host), port: 1)))
    }

    func testIPv4SubnetUsesTheExactMaskAndNormalizesMappedPeers() throws {
        let bound = PairingLANRoute.Address.ipv4(try XCTUnwrap(IPv4Address("198.51.100.130")))
        let offset = try XCTUnwrap(MemoryLayout<sockaddr_in>.offset(of: \.sin_addr))
        let subnet25 = try XCTUnwrap(subnet(bound, mask: [255, 255, 255, 128], family: AF_INET, offset: offset))
        let subnet24 = try XCTUnwrap(subnet(bound, mask: [255, 255, 255], offset: offset))
        XCTAssertTrue(subnet25.contains(try source("198.51.100.200")))
        XCTAssertTrue(subnet25.contains(try source("::ffff:198.51.100.200")))
        XCTAssertFalse(subnet25.contains(try source("198.51.100.40")))
        XCTAssertTrue(subnet24.contains(try source("198.51.100.40")))
        XCTAssertFalse(subnet24.contains(try source("198.51.101.40")))
        XCTAssertFalse(subnet24.contains(try source("2001:db8::1")))
        XCTAssertNil(PairingSetupV2Source(.hostPort(host: .name("peer.local", nil), port: 1)))
    }

    func testIPv6SubnetMatchesNonByteAlignedGlobalAndUniqueLocalPrefixes() throws {
        let offset = try XCTUnwrap(MemoryLayout<sockaddr_in6>.offset(of: \.sin6_addr))
        for block in ["2001:db8", "fc00:db8", "fd00:db8"] {
            let bound = PairingLANRoute.Address.ipv6(try XCTUnwrap(IPv6Address("\(block):0:0:8000::1")))
            let mask = Array(repeating: UInt8.max, count: 8) + [128]
            let link = try XCTUnwrap(subnet(bound, mask: mask, family: AF_INET6, offset: offset))
            XCTAssertTrue(link.contains(try source("\(block):0:0:ffff::2")))
            XCTAssertFalse(link.contains(try source("\(block):0:0:7fff::2")))
            XCTAssertFalse(link.contains(try source("::ffff:198.51.100.200")))
        }
    }

    func testSubnetRejectsUnusablePeersAndOverbroadMasks() throws {
        let v4 = PairingLANRoute.Address.ipv4(try XCTUnwrap(IPv4Address("169.1.1.1")))
        let offset4 = try XCTUnwrap(MemoryLayout<sockaddr_in>.offset(of: \.sin_addr))
        let v6 = PairingLANRoute.Address.ipv6(try XCTUnwrap(IPv6Address("fd00::1")))
        let offset6 = try XCTUnwrap(MemoryLayout<sockaddr_in6>.offset(of: \.sin6_addr))
        XCTAssertNil(subnet(v4, mask: [254], offset: offset4))
        XCTAssertNil(subnet(v6, mask: [255, 254], offset: offset6))
        let link4 = try XCTUnwrap(subnet(v4, mask: [255], offset: offset4))
        let link6 = try XCTUnwrap(subnet(v6, mask: [255, 255], offset: offset6))
        XCTAssertTrue(link4.contains(try source("169.1.2.3")))
        XCTAssertFalse(link4.contains(try source("169.254.1.2")))
        XCTAssertTrue(link6.contains(try source("fd00::2")))
        XCTAssertFalse(link6.contains(try source("fe80::2")))
        XCTAssertFalse(link6.contains(try source("ff02::1")))
    }

    func testSubnetSnapshotUsesOnlyTheExactUsableBoundRow() throws {
        let ip = try XCTUnwrap(IPv6Address("2001:db8::7"))
        let bound = PairingLANRoute.Address.ipv6(ip)
        let offset = try XCTUnwrap(MemoryLayout<sockaddr_in6>.offset(of: \.sin6_addr))
        let length = MemoryLayout<sockaddr_in6>.size
        let flags = UInt32(IFF_UP | IFF_RUNNING)
        func row(_ ip: IPv6Address, mask: [UInt8]?, claimedLength: Int = 28) -> PairingLANRoute.InterfaceRow {
            var bytes = [UInt8](repeating: 0, count: length)
            bytes[0] = UInt8(claimedLength)
            bytes[1] = UInt8(AF_INET6)
            bytes.replaceSubrange(offset..<(offset + 16), with: ip.rawValue)
            return .init(flags: flags, address: bytes, netmask: mask)
        }
        let mask = [UInt8(offset + 8), 0] + Array(repeating: 0, count: offset - 2) + Array(repeating: 255, count: 8)
        let exact = row(ip, mask: mask), alias = row(try XCTUnwrap(IPv6Address("2001:db8:1::7")), mask: nil)
        func snapshot(_ rows: [PairingLANRoute.InterfaceRow],
                      ipv6: UInt32? = 0) -> PairingLANSubnet? {
            PairingLANRoute.readSubnet(bound: bound, index: 7, liveIndex: { 7 }, rows: { rows }, ipv6Flags: { _ in ipv6 })
        }
        XCTAssertNotNil(snapshot([alias, exact]))
        XCTAssertNil(snapshot([alias]))
        XCTAssertNil(snapshot([exact, exact]))
        XCTAssertNil(snapshot([row(ip, mask: nil)]))
        XCTAssertNil(snapshot([row(ip, mask: mask, claimedLength: offset + 2)]))
        XCTAssertNil(snapshot([exact], ipv6: UInt32(RemozioPairingIPv6Unusable)))
        XCTAssertNil(snapshot([exact], ipv6: nil))

        var index: UInt32 = 7
        XCTAssertNil(PairingLANRoute.readSubnet(bound: bound, index: 7, liveIndex: { index }, rows: {
            index = 8
            return [exact]
        }, ipv6Flags: { _ in 0 }))

        let newMask = [UInt8(offset + 9), 0] + Array(repeating: 0, count: offset - 2) + Array(repeating: 255, count: 9)
        XCTAssertNotEqual(snapshot([exact]), snapshot([row(ip, mask: newMask)]))
    }

    func testNetmaskRejectsInvalidLengthFamilyAndNoncontiguousPrefixes() throws {
        let bound = PairingLANRoute.Address.ipv4(try XCTUnwrap(IPv4Address("192.0.2.10")))
        let offset = try XCTUnwrap(MemoryLayout<sockaddr_in>.offset(of: \.sin_addr))
        XCTAssertNil(subnet(bound, mask: [], offset: offset))
        XCTAssertNil(subnet(bound, mask: [0], offset: offset))
        XCTAssertNil(subnet(bound, mask: [255, 0, 255], offset: offset))
        XCTAssertNil(subnet(bound, mask: [255, 255, 127], offset: offset))
        XCTAssertNil(subnet(bound, mask: [255], family: AF_INET6, offset: offset))
        XCTAssertNil(subnet(bound, mask: [], offset: offset, reportedLength: 1))
        XCTAssertNil(subnet(bound, mask: [], offset: offset, reportedLength: 255))
    }

    private let point = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"

    func testPairingSchemaPreservesLegacyBytesAndMatchesLANVectors() throws {
        for (flag, suffix, prefix) in [(nil as Bool?, "", "a30001"), (false, "03f4", "a40002"), (true, "03f5", "a40002")] {
            let expected = bytes(prefix + "015841" + point + "021a0001d4c0" + suffix)
            let configuration = try AuthorityPairingSetupConfiguration(transportPublicKey: bytes(point), v2ActivationEnabled: flag)
            XCTAssertEqual(configuration.canonicalBytes, expected)
            XCTAssertEqual(try AuthorityPairingSetupConfiguration.decode(expected).v2ActivationEnabled, flag)
        }
        for family in [PairingLANScope.AddressFamily.ipv4, .ipv6] {
            let scope = try PairingLANScope(interfaceName: "en0", family: family)
            let expected = bytes("a50003015841" + point + "021a0001d4c003f5048263656e300" + String(family.rawValue))
            let configuration = try AuthorityPairingSetupConfiguration(transportPublicKey: bytes(point), v2ActivationEnabled: true,
                                                                        lanScope: scope)
            XCTAssertEqual(configuration.canonicalBytes, expected)
            XCTAssertEqual(try AuthorityPairingSetupConfiguration.decode(expected).lanScope, scope)
        }
        let maxScope = try PairingLANScope(interfaceName: "a12345678901234", family: .ipv6)
        let largest = try AuthorityPairingSetupConfiguration(transportPublicKey: bytes(point), lifetimeMilliseconds: 300_000,
                                                              v2ActivationEnabled: true, lanScope: maxScope)
        XCTAssertEqual(largest.canonicalBytes.count, 98)
        XCTAssertEqual(try AuthorityPairingSetupConfiguration.decode(largest.canonicalBytes).lanScope, maxScope)
    }

    func testPairingSchemaRejectsFalseScopeAndMalformedScopeFields() throws {
        let prefix = "a50003015841" + point + "021a0001d4c0"
        for suffix in ["03f4048263656e3004", "03f5048263656e3005", "03f5048263456e3004", "03f504826004",
                       "03f5048363656e300400", "03f5048263656e301804", "03f5048263656e300400"] {
            XCTAssertThrowsError(try AuthorityPairingSetupConfiguration.decode(bytes(prefix + suffix)))
        }
        XCTAssertThrowsError(try AuthorityPairingSetupConfiguration.decode(bytes("a40003015841" + point + "021a0001d4c003f5")))
        XCTAssertThrowsError(try AuthorityPairingSetupConfiguration.decode(bytes("a50002015841" + point + "021a0001d4c003f5048263656e3004")))
        let lan = try PairingLANScope(interfaceName: "en0", family: .ipv4)
        XCTAssertThrowsError(try AuthorityPairingSetupConfiguration(transportPublicKey: bytes(point), v2ActivationEnabled: false, lanScope: lan))
    }

    func testLANBindingRequiresTheExactWindowAndCanonicalProtectedScope() throws {
        let windowID = Data(repeating: 7, count: 16)
        let binding = PairingLANBinding(windowID: windowID, revision: .init(authorityEpoch: UUID(), configurationDigest: Data(count: 32)),
                                        scope: try .init(interfaceName: "en0", family: .ipv4), expiresAtMilliseconds: 1_200)
        let encoded = try binding.encode()
        XCTAssertEqual(try PairingLANBinding.decode(encoded, windowID: windowID), binding)
        XCTAssertThrowsError(try PairingLANBinding.decode(encoded, windowID: Data(count: 16)))
        XCTAssertThrowsError(try PairingLANBinding.decode(encoded + Data([0]), windowID: windowID))
    }

    func testLANBindingUsesTheOriginalDeadlineAfterTransportStartsLate() throws {
        let binding = PairingLANBinding(windowID: Data(count: 16),
            revision: .init(authorityEpoch: UUID(), configurationDigest: Data(count: 32)),
            scope: try .init(interfaceName: "en0", family: .ipv4), expiresAtMilliseconds: 1_200)
        XCTAssertEqual(binding.remainingMilliseconds(at: 1_150, windowLifetime: 200), 50)
        XCTAssertEqual(binding.remainingMilliseconds(at: 1_199, windowLifetime: 200), 1)
        XCTAssertNil(binding.remainingMilliseconds(at: 1_200, windowLifetime: 200))
        XCTAssertNil(binding.remainingMilliseconds(at: 1_201, windowLifetime: 200))
        XCTAssertNil(binding.remainingMilliseconds(at: 999, windowLifetime: 200))
    }

    func testIPv4RequiresAnObservedPrimaryWhenSeveralAddressesAreUsable() {
        let primary = Data([192, 168, 1, 7]), other = Data([192, 168, 2, 8]), replacement = Data([192, 168, 1, 41])
        XCTAssertEqual(PairingLANAddressSelection.ipv4([other, primary], primary: primary), primary)
        XCTAssertEqual(PairingLANAddressSelection.ipv4([primary, other], primary: primary), primary)
        XCTAssertNil(PairingLANAddressSelection.ipv4([other, primary], primary: nil))
        XCTAssertNil(PairingLANAddressSelection.ipv4([other, replacement], primary: primary))
        XCTAssertEqual(PairingLANAddressSelection.ipv4([replacement, other], primary: replacement), replacement)
        let linkLocal = Data([169, 254, 1, 9])
        XCTAssertNil(PairingLANAddressSelection.ipv4([Data([127, 0, 0, 1]), Data(count: 4), linkLocal], primary: nil))
        XCTAssertEqual(PairingLANAddressSelection.ipv4([linkLocal, primary], primary: linkLocal), primary)
    }

    func testIPv6SelectsAStableGlobalAddressRegardlessOfEnumerationOrder() {
        let flags = UInt32(RemozioPairingIPv6Unusable)
        let earlier = bytes("20010db8000000000000000000000001"), later = bytes("20010db8000000000000000000000002")
        let candidates: [PairingLANAddressSelection.IPv6Candidate] = [
            .init(address: later, flags: 0), .init(address: earlier, flags: 0),
            .init(address: bytes("20010db8000000000000000000000000"), flags: flags),
            .init(address: bytes("fe800000000000000000000000000001"), flags: 0),
            .init(address: bytes("fd000000000000000000000000000001"), flags: 0)
        ]
        XCTAssertEqual(PairingLANAddressSelection.ipv6(candidates), earlier)
        XCTAssertEqual(PairingLANAddressSelection.ipv6(Array(candidates.reversed())), earlier)
        XCTAssertNil(PairingLANAddressSelection.ipv6(Array(candidates.dropFirst(2))))
        for flag in [UInt32(0x01), 0x10, 0x80, 0x0200, 0x1000] {
            XCTAssertNil(PairingLANAddressSelection.ipv6([.init(address: earlier, flags: flag)]))
        }
    }

    func testIPv6IsUnavailableWhenTheSDKCannotReadAddressFlags() {
        let address = bytes("20010db8000000000000000000000001")
        let unavailable = PairingLANAddressSelection.IPv6Candidate(address: address, flags: nil)
        let readable = PairingLANAddressSelection.IPv6Candidate(address: address, flags: 0)
        XCTAssertNil(PairingLANAddressSelection.ipv6([unavailable]))
        XCTAssertEqual(PairingLANAddressSelection.ipv6([readable]), address)
    }

    func testBonjourTargetHasOnlyTheSelectedAddressAndChangesForEachWindow() throws {
        let ipv4 = Data([192, 168, 5, 11])
        let ipv6 = bytes("20010db8000000000000000000000001")
        let address4 = try XCTUnwrap(PairingLANRoute.Address(family: .ipv4, bytes: ipv4))
        let address6 = try XCTUnwrap(PairingLANRoute.Address(family: .ipv6, bytes: ipv6))
        XCTAssertNil(PairingLANRoute.Address(family: .ipv6, bytes: ipv4))
        XCTAssertNil(PairingLANRoute.Address(family: .ipv4, bytes: ipv6))

        let host4 = PairingLANAdvertisement.HostRecord(address: address4)
        let host6 = PairingLANAdvertisement.HostRecord(address: address6)
        XCTAssertEqual(host4.recordType, UInt16(kDNSServiceType_A))
        XCTAssertEqual(host4.data, ipv4)
        XCTAssertEqual(host6.recordType, UInt16(kDNSServiceType_AAAA))
        XCTAssertEqual(host6.data, ipv6)
        XCTAssertTrue(host4.name.hasSuffix(".local."))
        XCTAssertTrue(host6.name.hasSuffix(".local."))
        XCTAssertNotEqual(host4.name, host6.name)
    }

    func testBonjourWithdrawalDiscardsLateRegistrationForTheClosedWindow() throws {
        let queue = DispatchQueue(label: "pairing-lan-advertisement-fixture")
        let events = AdvertisementEvents()
        let address = try XCTUnwrap(PairingLANRoute.Address(family: .ipv4, bytes: Data([192, 168, 5, 11])))
        let registration = PairingLANAdvertisement(queue: queue, register: { name, index, port, host, _, report in
            XCTAssertEqual(name, "R-public-scope")
            XCTAssertEqual(index, 7)
            XCTAssertEqual(port, 4321)
            XCTAssertEqual(host.recordType, UInt16(kDNSServiceType_A))
            XCTAssertEqual(host.data, Data([192, 168, 5, 11]))
            events.callback.withLock { $0 = report }
            return { events.stopped.withLock { $0 += 1 } }
        })
        queue.sync {
            registration.start(name: "R-public-scope", index: 7, port: 4321, address: address, isCurrent: { true }) { event in
                switch event {
                case .ready: events.reports.withLock { $0.append(true) }
                case .failed, .stopped: events.reports.withLock { $0.append(false) }
                }
            }
            XCTAssertTrue(events.reports.withLock { $0.isEmpty })
            let deliver = events.callback.withLock { $0 }
            deliver?(true)
            registration.withdraw()
            XCTAssertEqual(events.stopped.withLock { $0 }, 1)
            deliver?(true)
            deliver?(false)
            registration.close()
        }
        XCTAssertEqual(events.stopped.withLock { $0 }, 1)
        XCTAssertEqual(events.reports.withLock { $0 }, [true])
    }
}
