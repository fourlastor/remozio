import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityPairingReceiptTests: XCTestCase, @unchecked Sendable {
    private let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
    private let setupID = Data(repeating: 7, count: 16)
    private final class Driver: AuthorityXPCDriver, @unchecked Sendable {
        let version: UInt64, response: Data, hold: Bool
        private let lock = NSLock()
        private var versions = 0, receipts = 0
        private var callback: (@Sendable (AuthorityXPCReply) -> Void)?
        private var last: (Data, Data)?
        let sent = XCTestExpectation(description: "receipt sent")
        var counts: (Int, Int) { lock.withLock { (versions, receipts) } }
        var received: (Data, Data)? { lock.withLock { last } }
        init(version: UInt64 = 1, response: Data = Data(), hold: Bool = false) {
            self.version = version; self.response = response; self.hold = hold
        }
        func start(invalidated: @escaping @Sendable () -> Void) {}
        func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.hello(1)) }
        func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.snapshot(Data([1]))) }
        func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.validation(true)) }
        func receiptVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { versions += 1 }; reply(.receiptVersion(version))
        }
        func receipt(_ binding: Data, setupID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { receipts += 1; last = (binding, setupID); if hold { callback = reply } }
            if hold { sent.fulfill() } else { reply(.receipt(response)) }
        }
        func finish() { lock.withLock { callback }?(.receipt(response)) }
        func close() {}
    }
    private func binding(accountID: Data? = nil) throws -> AuthorityPeerBinding {
        try AuthorityPeerBinding(scope: ChannelScope(macID: mac, accountID: accountID ?? account,
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16)),
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, revision: UUID())
    }
    func testClientNegotiatesBeforeBindingAndCachesVersion() async throws {
        let proof = Data(repeating: 9, count: 64), driver = Driver(response: proof)
        let channel = AuthorityXPCChannel(driver: driver), peer = try binding()
        try await channel.start()
        let first = try await channel.pairingReceipt(binding: peer, setupID: setupID)
        let second = try await channel.pairingReceipt(binding: peer, setupID: setupID)
        XCTAssertEqual(first, proof); XCTAssertEqual(second, proof)
        XCTAssertEqual(driver.counts.0, 1); XCTAssertEqual(driver.counts.1, 2)
        XCTAssertEqual(driver.received?.0, try AuthorityTrustCodec.encodeBinding(peer))
        XCTAssertEqual(driver.received?.1, setupID)
        await channel.close()
    }
    func testUnsupportedVersionSendsNoBindingAndPreservesCommonOperations() async throws {
        for version: UInt64 in [0, 2, UInt64.max] {
            let driver = Driver(version: version), channel = AuthorityXPCChannel(driver: driver)
            try await channel.start()
            do { _ = try await channel.pairingReceipt(binding: binding(), setupID: setupID); XCTFail() }
            catch { guard case AuthorityXPCError.unsupportedPairingReceipt = error else { return XCTFail("wrong error") } }
            XCTAssertEqual(driver.counts.1, 0); XCTAssertNil(driver.received)
            let snapshot = try await channel.trustSnapshot(); XCTAssertEqual(snapshot, Data([1]))
            await channel.close()
        }
    }
    func testMissingReceiptPreservesChannelButMalformedRepliesRetireIt() async throws {
        let empty = AuthorityXPCChannel(driver: Driver())
        try await empty.start()
        let absent = try await empty.pairingReceipt(binding: binding(), setupID: setupID)
        XCTAssertNil(absent)
        _ = try await empty.trustSnapshot(); await empty.close()
        for count in [1, 63, 65] {
            let channel = AuthorityXPCChannel(driver: Driver(response: Data(count: count)))
            try await channel.start()
            do { _ = try await channel.pairingReceipt(binding: binding(), setupID: setupID); XCTFail() } catch {}
            do { _ = try await channel.trustSnapshot(); XCTFail("malformed response kept channel") } catch {}
        }
    }
    func testCancellationAndTimeoutCannotAcceptALateReceiptOrRetry() async throws {
        for cancel in [false, true] {
            let driver = Driver(response: Data(count: 64), hold: true)
            let channel = AuthorityXPCChannel(driver: driver, timeoutMilliseconds: cancel ? 5000 : 100)
            let peer = try binding(), setupID = setupID
            try await channel.start()
            let operation = Task { try await channel.pairingReceipt(binding: peer, setupID: setupID) }
            await fulfillment(of: [driver.sent], timeout: 2)
            if cancel { operation.cancel() }
            do { _ = try await operation.value; XCTFail("late receipt accepted") } catch {}
            driver.finish()
            do { _ = try await channel.trustSnapshot(); XCTFail("retired channel reopened") } catch {}
            XCTAssertEqual(driver.counts.1, 1)
        }
    }
    func testEndpointRequiresCommonHelloAndSeparateReceiptNegotiation() throws {
        let trust = DirectApprovalTrust(macID: mac, accountID: account, revision: UUID(), peers: [])
        for hello in [false, true] {
            let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
                verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in true },
                pairingReceipt: { _, _ in XCTFail("unnegotiated receipt"); return nil })
            if hello { endpoint.hello { XCTAssertEqual($0, 1) } }
            endpoint.pairingReceipt(try AuthorityTrustCodec.encodeBinding(binding()), setupID: setupID) { XCTAssertNil($0) }
        }
        let disabled = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
            verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in true })
        disabled.hello { XCTAssertEqual($0, 1) }; disabled.pairingReceiptVersion { XCTAssertEqual($0, 0) }
        disabled.trustSnapshot { XCTAssertNotNil($0) }; disabled.close()
    }
    func testEndpointBoundsProofAndSetupAndRejectsWrongScope() throws {
        let trust = DirectApprovalTrust(macID: mac, accountID: account, revision: UUID(), peers: [])
        for proof: Data? in [nil, Data(count: 64), Data(count: 63), Data(count: 65)] {
            let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
                verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in true },
                pairingReceipt: { _, id in XCTAssertEqual(id, Data(repeating: 7, count: 16)); return proof })
            endpoint.hello { XCTAssertEqual($0, 1) }; endpoint.pairingReceiptVersion { XCTAssertEqual($0, 1) }
            endpoint.pairingReceipt(try AuthorityTrustCodec.encodeBinding(binding()), setupID: setupID) {
                XCTAssertEqual($0, proof == nil || proof?.count == 64 ? proof ?? Data() : nil)
            }
            endpoint.close()
        }
        for wrongScope in [false, true] {
            let calls = Mutex(0)
            let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
                verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in true },
                pairingReceipt: { _, _ in calls.withLock { $0 += 1 }; return nil })
            endpoint.hello { XCTAssertEqual($0, 1) }; endpoint.pairingReceiptVersion { XCTAssertEqual($0, 1) }
            let peer = try binding(accountID: wrongScope ? Data(repeating: 9, count: 16) : nil)
            endpoint.pairingReceipt(try AuthorityTrustCodec.encodeBinding(peer), setupID: wrongScope ? setupID : Data(count: 15)) { XCTAssertNil($0) }
            XCTAssertEqual(calls.withLock { $0 }, 0)
        }
    }
    func testOnlyDeclaredEnrolledChannelPurposesAreAccepted() {
        XCTAssertEqual(EnrolledChannelPurpose(applicationProtocol: "remozio/1"), .approvals)
        XCTAssertEqual(EnrolledChannelPurpose(applicationProtocol: PairingReceiptFrame.applicationProtocol), .pairingReceipt)
        XCTAssertNil(EnrolledChannelPurpose(applicationProtocol: "remozio-receipt/2"))
        XCTAssertNil(EnrolledChannelPurpose(applicationProtocol: "remozio-pairing/1"))
    }
}
