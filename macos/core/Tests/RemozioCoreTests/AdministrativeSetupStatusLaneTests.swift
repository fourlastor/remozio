import Darwin
import Foundation
import ObjectiveC
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AdministrativeSetupStatusLaneTests: XCTestCase, @unchecked Sendable {
    private typealias Facade = AdministrativeSetupConnectionFacade
    private typealias Status = SetupRetainedInvocationStatus
    private typealias Wire = SetupRetainedStatusWire

    /// Records every forwarded selector. Hellos answer 1 and data selectors answer one byte, so a forward is visible.
    private final class Recorder: NSObject, SetupNormalEndpoint, @unchecked Sendable {
        let calls = Mutex<[String]>([]), closes = Mutex(0)
        private func record(_ name: String) { calls.withLock { $0.append(name) } }
        func close() { closes.withLock { $0 += 1 } }
        func auditUpgradeHello(reply: @escaping @Sendable (UInt64) -> Void) { record("auditUpgradeHelloWithReply:"); reply(1) }
        func auditUpgradeProgress(reply: @escaping @Sendable (Data?) -> Void) { record("auditUpgradeProgressWithReply:"); reply(Data([1])) }
        func performAuditUpgrade(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
            record("performAuditUpgrade:authorization:reply:"); reply(Data([1]))
        }
        func portableImportRecoveryHello(reply: @escaping @Sendable (UInt64) -> Void) { record("portableImportRecoveryHelloWithReply:"); reply(1) }
        func portableImportRecovery(reply: @escaping @Sendable (Data?) -> Void) { record("portableImportRecoveryWithReply:"); reply(Data([1])) }
        func portableImportHello(reply: @escaping @Sendable (UInt64) -> Void) { record("portableImportHelloWithReply:"); reply(1) }
        func portableImportProgress(reply: @escaping @Sendable (Data?) -> Void) { record("portableImportProgressWithReply:"); reply(Data([1])) }
        func performPortableImport(_ request: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
            record("performPortableImport:authorization:reply:"); reply(Data([1]))
        }
        func gatewaySettingsHello(reply: @escaping @Sendable (UInt64) -> Void) { record("gatewaySettingsHelloWithReply:"); reply(1) }
        func gatewaySettingsProgress(reply: @escaping @Sendable (Data?) -> Void) { record("gatewaySettingsProgressWithReply:"); reply(Data([1])) }
        func retainGatewaySettings(_ expected: Data, selection: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
            record("retainGatewaySettings:selection:authorization:reply:"); reply(Data([1]))
        }
        func resumeGatewaySettings(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
            record("resumeGatewaySettings:authorization:reply:"); reply(Data([1]))
        }
        func gatewayActivationHello(reply: @escaping @Sendable (UInt64) -> Void) { record("gatewayActivationHelloWithReply:"); reply(1) }
        func gatewayActivationProgress(reply: @escaping @Sendable (Data?) -> Void) { record("gatewayActivationProgressWithReply:"); reply(Data([1])) }
        func activateGateway(_ expected: Data, settings: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
            record("activateGateway:settings:authorization:reply:"); reply(Data([1]))
        }
        func gatewayHello(reply: @escaping @Sendable (UInt64) -> Void) { record("gatewayHelloWithReply:"); reply(1) }
        func gatewayProgress(reply: @escaping @Sendable (Data?) -> Void) { record("gatewayProgressWithReply:"); reply(Data([1])) }
        func prepareGateway(_ expected: Data, choices: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
            record("prepareGateway:choices:authorization:reply:"); reply(Data([1]))
        }
        func resumeGatewayJournal(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
            record("resumeGatewayJournal:authorization:reply:"); reply(Data([1]))
        }
        func activationHello(reply: @escaping @Sendable (UInt64) -> Void) { record("activationHelloWithReply:"); reply(1) }
        func activationProgress(reply: @escaping @Sendable (Data?) -> Void) { record("activationProgressWithReply:"); reply(Data([1])) }
        func activateRuntime(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
            record("activateRuntime:authorization:reply:"); reply(Data([1]))
        }
        func runtimeHello(reply: @escaping @Sendable (UInt64) -> Void) { record("runtimeHelloWithReply:"); reply(1) }
        func runtimeProgress(reply: @escaping @Sendable (Data?) -> Void) { record("runtimeProgressWithReply:"); reply(Data([1])) }
        func prepareRuntime(_ expected: Data, fileCustodyAccepted: Bool, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
            record("prepareRuntime:fileCustodyAccepted:authorization:reply:"); reply(Data([1]))
        }
        func hello(reply: @escaping @Sendable (UInt64) -> Void) { record("helloWithReply:"); reply(1) }
        func serviceAccountsHello(reply: @escaping @Sendable (UInt64) -> Void) { record("serviceAccountsHelloWithReply:"); reply(1) }
        func serviceAccountsProgress(reply: @escaping @Sendable (Data?) -> Void) { record("serviceAccountsProgressWithReply:"); reply(Data([1])) }
        func prepareServiceAccounts(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
            record("prepareServiceAccounts:authorization:reply:"); reply(Data([1]))
        }
        func enrollmentHello(reply: @escaping @Sendable (UInt64) -> Void) { record("enrollmentHelloWithReply:"); reply(1) }
        func accountEnrollmentProgress(reply: @escaping @Sendable (Data?) -> Void) { record("accountEnrollmentProgressWithReply:"); reply(Data([1])) }
        func beginAccountEnrollment(_ request: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
            record("beginAccountEnrollment:authorization:reply:"); reply(Data([1]))
        }
        func resumeAccountEnrollment(_ setupID: Data, expectedRevision: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
            record("resumeAccountEnrollment:expectedRevision:authorization:reply:"); reply(Data([1]))
        }
        func accountStorageProgress(_ accountID: Data, reply: @escaping @Sendable (Data?) -> Void) {
            record("accountStorageProgress:reply:"); reply(Data([1]))
        }
        func resumeAccountStorage(_ accountID: Data, setupID: Data, expectedRevision: Data, authorization: Data,
                                  reply: @escaping @Sendable (Data?) -> Void) {
            record("resumeAccountStorage:setupID:expectedRevision:authorization:reply:"); reply(Data([1]))
        }
    }

    /// One harness per connection: injected peer proof, slot selection, normal construction and status source.
    private final class Harness: @unchecked Sendable {
        let peer = XPCPeerCredentials(processID: getpid(), userID: getuid(), auditSessionID: 1)
        let verified = Mutex(true), statusAllowed = Mutex(true), normalAllowed = Mutex(true)
        let selections = Mutex<[SetupConnectionSlots.Mode]>([]), opens = Mutex(0), invalidations = Mutex(0), statusReads = Mutex(0)
        let recorder = Recorder()
        let source = Mutex<Status>(.unavailable)
        let checks = Mutex(SetupAccountOwner.StatusLaneCheck.verified), touches = Mutex(0)
        lazy var facade = Facade(
            verify: { [unowned self] in
                guard self.verified.withLock({ $0 }) else { throw XPCPeerPolicyError.wrongConnection }
                return self.peer
            },
            select: { [unowned self] mode in
                self.selections.withLock { $0.append(mode) }
                return mode == .statusOnly ? self.statusAllowed.withLock { $0 } : self.normalAllowed.withLock { $0 }
            },
            openNormal: { [unowned self] _ in self.opens.withLock { $0 += 1 }; return self.recorder },
            status: { [unowned self] value in
                self.statusReads.withLock { $0 += 1 }
                XCTAssertEqual(value, self.peer)
                return self.source.withLock { $0 }
            },
            check: { [unowned self] in self.checks.withLock { $0 } },
            touch: { [unowned self] in self.touches.withLock { $0 += 1 } },
            invalidate: { [unowned self] in self.invalidations.withLock { $0 += 1 } })
    }

    private final class Reply<Value: Sendable>: @unchecked Sendable {
        let values = Mutex<[Value]>([])
        var callback: @Sendable (Value) -> Void { { [self] value in values.withLock { $0.append(value) } } }
        var only: Value? { values.withLock { $0.count == 1 ? $0[0] : nil } }
    }

    /// Every exported normal selector, keyed by its Objective-C name. Hello selectors are the only ones that may open the lane.
    private static let hellos: Set<String> = ["auditUpgradeHelloWithReply:", "portableImportRecoveryHelloWithReply:", "portableImportHelloWithReply:",
        "gatewaySettingsHelloWithReply:", "gatewayActivationHelloWithReply:", "gatewayHelloWithReply:", "activationHelloWithReply:", "runtimeHelloWithReply:", "helloWithReply:",
        "serviceAccountsHelloWithReply:", "enrollmentHelloWithReply:"]
    /// Returns (forwarded, repliedOnce): a nonzero hello or non-nil data reply means the recorder answered.
    nonisolated(unsafe) private static let selectors: [String: (Facade) -> (Bool, Bool)] = {
        let bytes = Data(repeating: 0, count: 16)
        func hello(_ call: @escaping (Facade, @escaping @Sendable (UInt64) -> Void) -> Void) -> (Facade) -> (Bool, Bool) {
            { facade in let reply = Reply<UInt64>(); call(facade, reply.callback); return (reply.only.map { $0 != 0 } ?? false, reply.only != nil) }
        }
        func data(_ call: @escaping (Facade, @escaping @Sendable (Data?) -> Void) -> Void) -> (Facade) -> (Bool, Bool) {
            { facade in let reply = Reply<Data?>(); call(facade, reply.callback); return (reply.only.map { $0 != nil } ?? false, reply.only != nil) }
        }
        return [
            "auditUpgradeHelloWithReply:": hello { $0.auditUpgradeHello(reply: $1) },
            "auditUpgradeProgressWithReply:": data { $0.auditUpgradeProgress(reply: $1) },
            "performAuditUpgrade:authorization:reply:": data { $0.performAuditUpgrade(bytes, authorization: bytes, reply: $1) },
            "portableImportRecoveryHelloWithReply:": hello { $0.portableImportRecoveryHello(reply: $1) },
            "portableImportRecoveryWithReply:": data { $0.portableImportRecovery(reply: $1) },
            "portableImportHelloWithReply:": hello { $0.portableImportHello(reply: $1) },
            "portableImportProgressWithReply:": data { $0.portableImportProgress(reply: $1) },
            "performPortableImport:authorization:reply:": data { $0.performPortableImport(bytes, authorization: bytes, reply: $1) },
            "gatewaySettingsHelloWithReply:": hello { $0.gatewaySettingsHello(reply: $1) },
            "gatewaySettingsProgressWithReply:": data { $0.gatewaySettingsProgress(reply: $1) },
            "retainGatewaySettings:selection:authorization:reply:": data {
                $0.retainGatewaySettings(bytes, selection: bytes, authorization: bytes, reply: $1)
            },
            "resumeGatewaySettings:authorization:reply:": data { $0.resumeGatewaySettings(bytes, authorization: bytes, reply: $1) },
            "gatewayActivationHelloWithReply:": hello { $0.gatewayActivationHello(reply: $1) },
            "gatewayActivationProgressWithReply:": data { $0.gatewayActivationProgress(reply: $1) },
            "activateGateway:settings:authorization:reply:": data {
                $0.activateGateway(bytes, settings: bytes, authorization: bytes, reply: $1)
            },
            "gatewayHelloWithReply:": hello { $0.gatewayHello(reply: $1) },
            "gatewayProgressWithReply:": data { $0.gatewayProgress(reply: $1) },
            "prepareGateway:choices:authorization:reply:": data {
                $0.prepareGateway(bytes, choices: bytes, authorization: bytes, reply: $1)
            },
            "resumeGatewayJournal:authorization:reply:": data { $0.resumeGatewayJournal(bytes, authorization: bytes, reply: $1) },
            "activationHelloWithReply:": hello { $0.activationHello(reply: $1) },
            "activationProgressWithReply:": data { $0.activationProgress(reply: $1) },
            "activateRuntime:authorization:reply:": data { $0.activateRuntime(bytes, authorization: bytes, reply: $1) },
            "runtimeHelloWithReply:": hello { $0.runtimeHello(reply: $1) },
            "runtimeProgressWithReply:": data { $0.runtimeProgress(reply: $1) },
            "prepareRuntime:fileCustodyAccepted:authorization:reply:": data {
                $0.prepareRuntime(bytes, fileCustodyAccepted: true, authorization: bytes, reply: $1)
            },
            "helloWithReply:": hello { $0.hello(reply: $1) },
            "serviceAccountsHelloWithReply:": hello { $0.serviceAccountsHello(reply: $1) },
            "serviceAccountsProgressWithReply:": data { $0.serviceAccountsProgress(reply: $1) },
            "prepareServiceAccounts:authorization:reply:": data { $0.prepareServiceAccounts(bytes, authorization: bytes, reply: $1) },
            "enrollmentHelloWithReply:": hello { $0.enrollmentHello(reply: $1) },
            "accountEnrollmentProgressWithReply:": data { $0.accountEnrollmentProgress(reply: $1) },
            "beginAccountEnrollment:authorization:reply:": data { $0.beginAccountEnrollment(bytes, authorization: bytes, reply: $1) },
            "resumeAccountEnrollment:expectedRevision:authorization:reply:": data {
                $0.resumeAccountEnrollment(bytes, expectedRevision: bytes, authorization: bytes, reply: $1)
            },
            "accountStorageProgress:reply:": data { $0.accountStorageProgress(bytes, reply: $1) },
            "resumeAccountStorage:setupID:expectedRevision:authorization:reply:": data {
                $0.resumeAccountStorage(bytes, setupID: bytes, expectedRevision: bytes, authorization: bytes, reply: $1)
            },
        ]
    }()
    private static let statusSelector = "retainedInvocationStatus:reply:"

    /// Every selector the exported interface declares, including inherited protocols.
    private static func exportedSelectors() -> Set<String> {
        var result = Set<String>()
        func visit(_ value: Protocol) {
            for required in [true, false] {
                var count: UInt32 = 0
                if let list = protocol_copyMethodDescriptionList(value, required, true, &count) {
                    for index in 0..<Int(count) { if let name = list[index].name { result.insert(NSStringFromSelector(name)) } }
                    free(list)
                }
            }
            var inherited: UInt32 = 0
            if let list = protocol_copyProtocolList(value, &inherited) {
                for index in 0..<Int(inherited) { visit(list[index]) }
            }
        }
        visit(AdministrativeSetupServiceXPCProtocol.self)
        return result
    }
    private func request(_ id: Data = Data(repeating: 7, count: 16)) throws -> Data { try Wire.Request(requestID: id).bytes }
    private func status(_ facade: Facade, _ bytes: Data) -> Data?? {
        let reply = Reply<Data?>(); facade.retainedInvocationStatus(bytes, reply: reply.callback); return reply.only
    }

    // MARK: Selector routing

    func testEverySelectorOfTheExportedInterfaceHasARouteInThisTest() {
        let routed = Set(Self.selectors.keys).union([Self.statusSelector])
        XCTAssertEqual(Self.exportedSelectors(), routed)
        XCTAssertTrue(Self.hellos.isSubset(of: Set(Self.selectors.keys)))
        XCTAssertTrue(Facade.self.instancesRespond(to: NSSelectorFromString(Self.statusSelector)))
        for name in Self.selectors.keys { XCTAssertTrue(Facade.self.instancesRespond(to: NSSelectorFromString(name)), name) }
    }
    func testNoNonHelloSelectorOpensTheNormalLaneOnAnUndecidedConnection() {
        for (name, call) in Self.selectors where !Self.hellos.contains(name) {
            let h = Harness()
            let result = call(h.facade)
            XCTAssertFalse(result.0, name); XCTAssertTrue(result.1, name)
            XCTAssertEqual(h.opens.withLock { $0 }, 0, name); XCTAssertEqual(h.selections.withLock { $0 }, [], name)
            XCTAssertEqual(h.facade.state, .closed, name); XCTAssertEqual(h.invalidations.withLock { $0 }, 1, name)
            XCTAssertEqual(h.recorder.calls.withLock { $0 }, [], name)
        }
    }
    func testEveryNormalSelectorIsRefusedAfterStatusWasSelected() throws {
        for (name, call) in Self.selectors {
            let h = Harness()
            XCTAssertNotNil(status(h.facade, try request()) ?? nil, name)
            XCTAssertEqual(h.facade.state, .statusOnly, name)
            let result = call(h.facade)
            XCTAssertFalse(result.0, name); XCTAssertTrue(result.1, name)
            XCTAssertEqual(h.opens.withLock { $0 }, 0, name); XCTAssertEqual(h.selections.withLock { $0 }, [.statusOnly], name)
            XCTAssertEqual(h.facade.state, .closed, name); XCTAssertEqual(h.recorder.calls.withLock { $0 }, [], name)
        }
    }
    func testEachHelloOpensTheNormalLaneOnceAndEveryNormalSelectorThenForwards() {
        for helloName in Self.hellos.sorted() {
            let h = Harness()
            let opened = Self.selectors[helloName]!(h.facade)
            XCTAssertTrue(opened.0, helloName); XCTAssertEqual(h.facade.state, .normal, helloName)
            XCTAssertEqual(h.selections.withLock { $0 }, [.normal], helloName); XCTAssertEqual(h.opens.withLock { $0 }, 1, helloName)
            for (name, call) in Self.selectors.sorted(by: { $0.key < $1.key }) {
                let result = call(h.facade)
                XCTAssertTrue(result.0, "\(helloName) then \(name)"); XCTAssertTrue(result.1, name)
            }
            XCTAssertEqual(h.opens.withLock { $0 }, 1, helloName)
            // Each selector reached the endpoint method of the same name, in call order.
            XCTAssertEqual(h.recorder.calls.withLock { $0 }, [helloName] + Self.selectors.keys.sorted(), helloName)
        }
    }
    func testStatusOnANormalConnectionRefusesOnlyThatCall() throws {
        let h = Harness()
        XCTAssertTrue(Self.selectors["helloWithReply:"]!(h.facade).0)
        XCTAssertEqual(status(h.facade, try request()), .some(nil))
        XCTAssertEqual(h.statusReads.withLock { $0 }, 0); XCTAssertEqual(h.selections.withLock { $0 }, [.normal])
        XCTAssertEqual(h.facade.state, .normal); XCTAssertEqual(h.recorder.closes.withLock { $0 }, 0)
        XCTAssertEqual(h.invalidations.withLock { $0 }, 0)
        XCTAssertTrue(Self.selectors["runtimeProgressWithReply:"]!(h.facade).0, "normal work continues on the same connection")
    }
    func testFullNormalLaneRefusesTheHelloWithoutOpeningAnEndpoint() {
        let h = Harness(); h.normalAllowed.withLock { $0 = false }
        let result = Self.selectors["runtimeHelloWithReply:"]!(h.facade)
        XCTAssertFalse(result.0); XCTAssertTrue(result.1)
        XCTAssertEqual(h.opens.withLock { $0 }, 0); XCTAssertEqual(h.facade.state, .closed)
    }
    func testFailedNormalConstructionClosesInsteadOfFallingBackToStatus() throws {
        let h = Harness(), failing = Facade(verify: { h.peer }, select: { _ in true },
            openNormal: { _ in throw AdministrativeSetupError.unavailable }, status: { _ in .unavailable },
            invalidate: { h.invalidations.withLock { $0 += 1 } })
        let reply = Reply<UInt64>(); failing.hello(reply: reply.callback)
        XCTAssertEqual(reply.only, 0); XCTAssertEqual(failing.state, .closed); XCTAssertEqual(h.invalidations.withLock { $0 }, 1)
        XCTAssertEqual(status(failing, try request()), .some(nil))
    }
    func testUnverifiedHelloNeverReachesTheOwner() {
        let h = Harness(); h.verified.withLock { $0 = false }
        XCTAssertFalse(Self.selectors["enrollmentHelloWithReply:"]!(h.facade).0)
        XCTAssertEqual(h.opens.withLock { $0 }, 0); XCTAssertEqual(h.selections.withLock { $0 }, []); XCTAssertEqual(h.facade.state, .closed)
    }
    func testEndpointSelfCloseClosesTheFacadeOnce() {
        let h = Harness(), captured = Mutex<(@Sendable () -> Void)?>(nil)
        let facade = Facade(verify: { h.peer }, select: { _ in true },
            openNormal: { close in captured.withLock { $0 = close }; return h.recorder }, status: { _ in .unavailable },
            invalidate: { h.invalidations.withLock { $0 += 1 } })
        let reply = Reply<UInt64>(); facade.hello(reply: reply.callback); XCTAssertEqual(reply.only, 1)
        captured.withLock { $0 }?(); captured.withLock { $0 }?()
        XCTAssertEqual(facade.state, .closed); XCTAssertEqual(h.invalidations.withLock { $0 }, 1)
        XCTAssertEqual(h.recorder.closes.withLock { $0 }, 1)
    }

    // MARK: Status lane

    func testStatusSelectsStatusOnlyAndRepliesWithTheBoundedProjection() throws {
        let h = Harness()
        let bytes = try XCTUnwrap(status(h.facade, try request()) ?? nil)
        XCTAssertEqual(h.facade.state, .statusOnly); XCTAssertEqual(h.selections.withLock { $0 }, [.statusOnly])
        XCTAssertEqual(h.statusReads.withLock { $0 }, 1); XCTAssertEqual(h.opens.withLock { $0 }, 0)
        XCTAssertLessThanOrEqual(bytes.count, Wire.maximumReplyBytes)
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: .init(maxBytes: 16384, maxDepth: 4, maxItems: 64)) else {
            return XCTFail("reply is not a map")
        }
        XCTAssertEqual(Set(fields.keys), Set(UInt64(0)...10))
        XCTAssertEqual(fields[0], .unsigned(1)); XCTAssertEqual(fields[1], .text(Wire.replyName))
        XCTAssertEqual(fields[2], .bytes(Data(repeating: 7, count: 16)))
        // Every fact of an unavailable projection stays null. Nothing is inferred.
        for key in UInt64(3)...10 { XCTAssertEqual(fields[key], .null, "field \(key)") }
        // A second read on the same status connection is allowed and still never opens the normal lane.
        XCTAssertNotNil(status(h.facade, try request(Data(repeating: 8, count: 16))) ?? nil)
        XCTAssertEqual(h.statusReads.withLock { $0 }, 2); XCTAssertEqual(h.selections.withLock { $0 }, [.statusOnly])
    }
    func testFullStatusLaneMalformedOversizedAndUnverifiedRequestsCloseWithoutReading() throws {
        let full = Harness(); full.statusAllowed.withLock { $0 = false }
        XCTAssertEqual(status(full.facade, try request()), .some(nil)); XCTAssertEqual(full.facade.state, .closed)
        let malformed = Harness()
        XCTAssertEqual(status(malformed.facade, Data([0xa0])), .some(nil)); XCTAssertEqual(malformed.facade.state, .closed)
        let oversized = Harness()
        XCTAssertEqual(status(oversized.facade, Data(repeating: 0, count: Wire.maximumRequestBytes + 1)), .some(nil))
        XCTAssertEqual(oversized.selections.withLock { $0 }, [])
        let unverified = Harness(); unverified.verified.withLock { $0 = false }
        XCTAssertEqual(status(unverified.facade, try request()), .some(nil)); XCTAssertEqual(unverified.selections.withLock { $0 }, [])
        for h in [full, malformed, oversized, unverified] { XCTAssertEqual(h.statusReads.withLock { $0 }, 0); XCTAssertEqual(h.opens.withLock { $0 }, 0) }
    }
    func testRefusedInstallationCheckClosesWithoutSelectingOrReading() throws {
        let h = Harness(); h.checks.withLock { $0 = .refused }
        XCTAssertEqual(status(h.facade, try request()), .some(nil))
        XCTAssertEqual(h.selections.withLock { $0 }, []); XCTAssertEqual(h.statusReads.withLock { $0 }, 0)
        XCTAssertEqual(h.facade.state, .closed)
        // Drift found on a later call of an existing status connection also closes it.
        let later = Harness()
        XCTAssertNotNil(status(later.facade, try request()) ?? nil)
        later.checks.withLock { $0 = .refused }
        XCTAssertEqual(status(later.facade, try request()), .some(nil)); XCTAssertEqual(later.facade.state, .closed)
        XCTAssertEqual(later.statusReads.withLock { $0 }, 1)
    }
    func testBusyOwnerAnswersUnavailableWithoutReadingAndPinnedReadsTheProjection() throws {
        let busy = Harness(); busy.checks.withLock { $0 = .busy }
        busy.source.withLock { $0 = Status.reservation(.reserved, identity: .init(reservationID: UUID(), incarnation: UUID()),
            binding: nil, expectedWindow: nil, worker: .observed(.idle), cleanup: .observed(.noneRegistered)) }
        let bytes = try XCTUnwrap(status(busy.facade, try request()) ?? nil)
        XCTAssertEqual(busy.statusReads.withLock { $0 }, 0); XCTAssertEqual(busy.facade.state, .statusOnly)
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: .init(maxBytes: 16384, maxDepth: 4, maxItems: 64)) else {
            return XCTFail("reply is not a map")
        }
        for key in UInt64(3)...10 { XCTAssertEqual(fields[key], .null, "field \(key)") }
        let pinned = Harness(); pinned.checks.withLock { $0 = .pinned }
        pinned.source.withLock { $0 = busy.source.withLock { $0 } }
        let observed = try XCTUnwrap(status(pinned.facade, try request()) ?? nil)
        XCTAssertEqual(pinned.statusReads.withLock { $0 }, 1)
        guard case .map(let read) = try DeterministicCBOR.decode(observed, limits: .init(maxBytes: 16384, maxDepth: 4, maxItems: 64)) else {
            return XCTFail("reply is not a map")
        }
        XCTAssertEqual(read[3], .unsigned(Wire.code(Status.Reservation.reserved)))
        XCTAssertEqual(read[8], .unsigned(Wire.code(Status.Worker.idle)))
        XCTAssertEqual(pinned.touches.withLock { $0 }, 2, "a status call restarts the idle limit when it starts and ends")
    }
    func testRequestCodecIsCanonicalAndBounded() throws {
        let id = Data(repeating: 3, count: 16), bytes = try Wire.Request(requestID: id).bytes
        XCTAssertEqual(try Wire.Request.decode(bytes).requestID, id)
        XCTAssertThrowsError(try Wire.Request(requestID: Data(repeating: 1, count: 15)))
        let limits = try CBORLimits(maxBytes: 1024, maxDepth: 2, maxItems: 8)
        for fields: [UInt64: CBORValue] in [
            [0: .unsigned(2), 1: .text(Wire.requestName), 2: .bytes(id)],
            [0: .unsigned(1), 1: .text(Wire.replyName), 2: .bytes(id)],
            [0: .unsigned(1), 1: .text(Wire.requestName), 2: .bytes(id), 3: .null],
            [0: .unsigned(1), 1: .text(Wire.requestName)],
        ] {
            XCTAssertThrowsError(try Wire.Request.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        }
    }
    func testSupervisorAndEnumCodesAreDistinct() {
        let reservations: [Status.Reservation] = [.absent, .reserved, .attached, .orphan, .recovering, .settled]
        XCTAssertEqual(Set(reservations.map { Wire.code($0) }).count, reservations.count)
        let workers: [Status.Worker] = [.idle, .running, .registered]
        XCTAssertEqual(Set(workers.map { Wire.code($0) }).count, workers.count)
        let cleanups: [Status.Cleanup] = [.noneRegistered, .pending, .joining, .joinFailed, .joined, .settled]
        XCTAssertEqual(Set(cleanups.map { Wire.code($0) }).count, cleanups.count)
        let supervisors: [Status.Supervisor] = [.recovering, .joining, .busy, .cancelled, .retired, .noWindow, .phase(.restoring), .failed(.busy)]
        XCTAssertEqual(Set(supervisors.map { Wire.supervisor($0) }.map { "\($0)" }).count, supervisors.count)
    }
    func testSecondStatusOnTheSameConnectionIsRefusedInsteadOfQueued() throws {
        let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
        let peer = XPCPeerCredentials(processID: getpid(), userID: getuid(), auditSessionID: 1), invalidations = Mutex(0)
        let facade = Facade(verify: { peer }, select: { _ in true }, openNormal: { _ in throw AdministrativeSetupError.unavailable },
            status: { _ in entered.signal(); _ = resume.wait(timeout: .now() + 3); return .unavailable },
            invalidate: { invalidations.withLock { $0 += 1 } })
        let first = Reply<Data?>(), bytes = try request()
        DispatchQueue.global().async { facade.retainedInvocationStatus(bytes, reply: first.callback); done.signal() }
        XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
        // One call in flight per status connection: the second is refused at once instead of queueing.
        XCTAssertEqual(status(facade, bytes), .some(nil))
        resume.signal(); XCTAssertEqual(done.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(invalidations.withLock { $0 }, 1)
    }

    // MARK: Slots

    func testSlotsKeepOneStatusSlotAndLetUndecidedConnectionsHoldNormalSlots() throws {
        let slots = try SetupConnectionSlots(maximumConnections: 8, timeoutMilliseconds: 60_000); try slots.start()
        defer { slots.close() }
        XCTAssertEqual([slots.maximumNormal, slots.maximumStatus], [7, 1])
        // Two connections opened at the same moment are both accepted while undecided.
        let first = try XCTUnwrap(slots.reserve()), second = try XCTUnwrap(slots.reserve())
        XCTAssertEqual(slots.mode(first), .undecided); XCTAssertEqual(slots.mode(second), .undecided)
        XCTAssertTrue(slots.select(.statusOnly, id: first))
        XCTAssertFalse(slots.select(.statusOnly, id: second), "one status slot")
        XCTAssertEqual(slots.mode(second), .undecided)
        XCTAssertTrue(slots.select(.normal, id: second))
        var normal = [second]
        for _ in 0..<6 { let id = try XCTUnwrap(slots.reserve()); XCTAssertTrue(slots.select(.normal, id: id)); normal.append(id) }
        XCTAssertNil(slots.reserve(), "seven normal slots and one status slot fill the total of eight")
        XCTAssertFalse(slots.select(.normal, id: first), "status-only never becomes normal")
        slots.remove(first)
        XCTAssertNil(slots.reserve(), "the freed status slot does not add normal capacity")
        slots.remove(normal[0])
        let next = try XCTUnwrap(slots.reserve())
        XCTAssertTrue(slots.select(.statusOnly, id: next), "an undecided connection moves its slot to the free status slot")
        XCTAssertNotNil(slots.reserve(), "and frees its provisional normal slot")
    }
    func testTotalsOneAndTwoBehaveLikeTheSharedRegistryAndThreeAddsTheStatusSlot() throws {
        for total in [1, 2, 3, 8] {
            let slots = try SetupConnectionSlots(maximumConnections: total, timeoutMilliseconds: 60_000); try slots.start()
            defer { slots.close() }
            let status = total >= 3 ? 1 : 0
            XCTAssertEqual([slots.maximumNormal, slots.maximumStatus], [total - status, status], "\(total)")
            // Below 3, as on main: every slot is normal, status is refused at once and the connection can still go normal.
            var ids: [UUID] = []
            for _ in 0..<(total - status) { ids.append(try XCTUnwrap(slots.reserve(), "\(total)")) }
            XCTAssertNil(slots.reserve(), "\(total)")
            if status == 0 {
                XCTAssertFalse(slots.select(.statusOnly, id: ids[0]), "\(total)")
                XCTAssertEqual(slots.mode(ids[0]), .undecided, "\(total)")
            } else {
                XCTAssertTrue(slots.select(.statusOnly, id: ids[0]), "\(total)")
                XCTAssertNotNil(slots.reserve(), "\(total)")
            }
            for id in ids.dropFirst() { XCTAssertTrue(slots.select(.normal, id: id), "\(total)") }
        }
        for total in [0, 65] { XCTAssertThrowsError(try SetupConnectionSlots(maximumConnections: total, timeoutMilliseconds: 1000)) }
    }
    func testUndecidedAndUnreadyNormalExpireAndStatusOnlyExpiresWhenIdle() async throws {
        let slots = try SetupConnectionSlots(maximumConnections: 8, timeoutMilliseconds: 200); try slots.start()
        defer { slots.close() }
        let undecided = try XCTUnwrap(slots.reserve())
        let opening = try XCTUnwrap(slots.reserve()); XCTAssertTrue(slots.select(.normal, id: opening))
        let ready = try XCTUnwrap(slots.reserve()); XCTAssertTrue(slots.select(.normal, id: ready)); slots.handshake(ready)
        let status = try XCTUnwrap(slots.reserve()); XCTAssertTrue(slots.select(.statusOnly, id: status))
        // Touching the status connection keeps it while it is in use.
        for _ in 0..<4 { try await Task.sleep(for: .milliseconds(100)); slots.touch(status) }
        XCTAssertNil(slots.mode(undecided)); XCTAssertNil(slots.mode(opening)); XCTAssertEqual(slots.mode(ready), .normal)
        XCTAssertEqual(slots.mode(status), .statusOnly)
        try await Task.sleep(for: .milliseconds(600))
        XCTAssertNil(slots.mode(status), "an idle status-only connection frees the status slot")
        XCTAssertEqual(slots.mode(ready), .normal)
    }
}
