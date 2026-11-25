import dnssd
import Foundation
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
