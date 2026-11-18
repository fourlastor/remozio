import Darwin
import Foundation
import ObjectiveC
import Synchronization
import XCTest
@testable import RemozioCore

/// Test-only protocol. The Root service neither inherits nor exports it.
@objc private protocol OwnedOrphanRecoveryTestProtocol {
    func recoveryHello(reply: @escaping @Sendable (UInt64) -> Void)
    func startRecovery(_ request: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
    func recoveryProgress(_ request: Data, reply: @escaping @Sendable (Data?) -> Void)
    func normalCall(reply: @escaping @Sendable (Data?) -> Void)
    func statusCall(reply: @escaping @Sendable (Data?) -> Void)
}

final class SetupOrphanRecoveryAnonymousXPCTests: XCTestCase, @unchecked Sendable {
    private typealias E = SetupOrphanRecoveryEndpointTests
    private final class ManualTimer: @unchecked Sendable {
        let deadlines = Mutex<[UInt64]>([])
        private let callbacks = Mutex<[UUID: @Sendable () -> Void]>([:])
        var timer: SetupConnectionSlots.Timer {
            { [self] milliseconds, fire in
                let id = UUID(); deadlines.withLock { $0.append(milliseconds) }; callbacks.withLock { $0[id] = fire }
                return { [self] in callbacks.withLock { $0[id] = nil } }
            }
        }
    }
    private final class Adapter: NSObject, OwnedOrphanRecoveryTestProtocol, @unchecked Sendable {
        let harness: E.Harness, slots: SetupConnectionSlots, id: UUID, connection: NSXPCConnection
        let lock = NSLock(), closed = Mutex(false)
        var session: SetupOrphanRecoveryEndpoint?
        init(_ harness: E.Harness, slots: SetupConnectionSlots, id: UUID, connection: NSXPCConnection) {
            self.harness = harness; self.slots = slots; self.id = id; self.connection = connection
        }
        func recoveryHello(reply: @escaping @Sendable (UInt64) -> Void) {
            if lock.withLock({ session != nil }) { reply(1); return }
            guard slots.select(.recoveryOnly, id: id) else { reply(0); return }
            do {
                let value = try harness.session(verify: { [weak self] in
                    guard let self, NSXPCConnection.current() === connection,
                          connection.effectiveUserIdentifier == getuid(), connection.processIdentifier == getpid() else {
                        throw E.Failure.expected
                    }
                    return self.harness.peer
                })
                lock.withLock { session = value }; slots.recoveryHandshake(id); reply(1)
            } catch { reply(0) }
        }
        func startRecovery(_ request: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
            guard let value = lock.withLock({ session }) else { reply(nil); return }
            value.start(request, authorization: authorization, reply: reply)
        }
        func recoveryProgress(_ request: Data, reply: @escaping @Sendable (Data?) -> Void) {
            reply(lock.withLock { session }?.progress(request))
        }
        func normalCall(reply: @escaping @Sendable (Data?) -> Void) { reply(lock.withLock { session }?.refuseForeignSelector()) }
        func statusCall(reply: @escaping @Sendable (Data?) -> Void) { reply(lock.withLock { session }?.refuseForeignSelector()) }
        func close() {
            guard closed.withLock({ value in if value { return false }; value = true; return true }) else { return }
            lock.withLock { session }?.close(); slots.remove(id)
        }
    }
    private final class Host: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
        let harness: E.Harness, slots: SetupConnectionSlots
        let adapters = Mutex<[Adapter]>([]), importedOnStack = Mutex(true)
        let manual = ManualTimer(), invalidations = Mutex(0)
        let onInvalidated = Mutex<(@Sendable () -> Void)?>(nil)
        init(_ harness: E.Harness) throws {
            self.harness = harness
            slots = try .init(maximumConnections: 3, timeoutMilliseconds: 5000, timer: manual.timer); try slots.start()
        }
        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            guard connection.effectiveUserIdentifier == getuid(), connection.processIdentifier == getpid(), let id = slots.reserve() else {
                connection.invalidate(); return false
            }
            let adapter = Adapter(harness, slots: slots, id: id, connection: connection)
            harness.onImport = { [weak adapter, weak self] in
                let onStack = adapter.map { NSXPCConnection.current() === $0.connection } ?? false
                self?.importedOnStack.withLock { $0 = $0 && onStack }
            }
            connection.exportedInterface = NSXPCInterface(with: OwnedOrphanRecoveryTestProtocol.self)
            connection.exportedObject = adapter
            connection.interruptionHandler = { [weak adapter] in adapter?.close() }
            connection.invalidationHandler = { [weak adapter, weak self] in
                adapter?.close()
                guard let self else { return }
                invalidations.withLock { $0 += 1 }
                let notify = onInvalidated.withLock { value in let old = value; value = nil; return old }; notify?()
            }
            adapters.withLock { $0.append(adapter) }; connection.activate(); return true
        }
        func close() {
            for adapter in adapters.withLock({ $0 }) { adapter.close(); adapter.connection.invalidate() }
            slots.close(); harness.onImport = nil
        }
    }
    private static let operationBound: Duration = .seconds(120)
    private static let transportMargin: Duration = .seconds(20)
    private static func remaining(_ deadline: ContinuousClock.Instant) -> TimeInterval {
        let parts = ContinuousClock.now.duration(to: deadline).components
        return max(0, Double(parts.seconds) + Double(parts.attoseconds) / 1e18)
    }
    private func withHost(_ body: (any OwnedOrphanRecoveryTestProtocol, Host, NSXPCConnection, ContinuousClock.Instant) throws -> Void) throws {
        let harness = try E.Harness(), host = try Host(harness), listener = NSXPCListener.anonymous()
        listener.delegate = host; listener.activate()
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: OwnedOrphanRecoveryTestProtocol.self); connection.activate()
        defer { connection.invalidate(); host.close(); listener.invalidate() }
        let proxy = try XCTUnwrap(connection.remoteObjectProxyWithErrorHandler { error in XCTFail("Private XPC failed: \(error)") }
            as? any OwnedOrphanRecoveryTestProtocol)
        try body(proxy, host, connection, .now.advanced(by: Self.operationBound + Self.transportMargin))
    }
    private func data(until deadline: ContinuousClock.Instant, _ call: (@escaping @Sendable (Data?) -> Void) -> Void) throws -> Data? {
        let done = expectation(description: "Private recovery reply"), result = Mutex<Data?>(nil)
        call { bytes in result.withLock { $0 = bytes }; done.fulfill() }
        wait(for: [done], timeout: Self.remaining(deadline)); return result.withLock { $0 }
    }
    private func hello(_ proxy: any OwnedOrphanRecoveryTestProtocol, until deadline: ContinuousClock.Instant) {
        let done = expectation(description: "Private recovery lane")
        proxy.recoveryHello { version in XCTAssertEqual(version, 1); done.fulfill() }; wait(for: [done], timeout: Self.remaining(deadline))
    }
    func testPrivateTransportUsesOneSharedSessionAndImportsOnTheExportedStack() throws {
        try withHost { proxy, host, _, deadline in
            let r = try E.request(), bytes = try r.bytes
            XCTAssertNil(try data(until: deadline) { proxy.startRecovery(bytes, authorization: Data(), reply: $0) })
            hello(proxy, until: deadline)
            let first = try XCTUnwrap(data(until: deadline) { proxy.startRecovery(bytes, authorization: Data([1]), reply: $0) })
            XCTAssertEqual(try data(until: deadline) { proxy.startRecovery(bytes, authorization: Data([2]), reply: $0) }, first)
            XCTAssertNotNil(try data(until: deadline) { proxy.normalCall(reply: $0) })
            XCTAssertNotNil(try data(until: deadline) { proxy.statusCall(reply: $0) })
            let progress = try SetupOrphanRecoveryWire.Progress(requestID: r.requestID).bytes
            let outcome = try XCTUnwrap(data(until: deadline) { proxy.recoveryProgress(progress, reply: $0) })
            XCTAssertEqual(try SetupOrphanRecoveryWire.Reply.decode(outcome).code, .refusedUnavailable)
            XCTAssertEqual(host.harness.imports.withLock { $0 }, 1); XCTAssertTrue(host.importedOnStack.withLock { $0 })
        }
    }
    func testClosingPrivateTransportClosesTheSharedSession() throws {
        try withHost { proxy, host, connection, deadline in
            hello(proxy, until: deadline)
            let r = try E.request(), bytes = try r.bytes
            XCTAssertNotNil(try data(until: deadline) { proxy.startRecovery(bytes, authorization: Data(), reply: $0) })
            let progress = try SetupOrphanRecoveryWire.Progress(requestID: r.requestID).bytes
            XCTAssertNotNil(try data(until: deadline) { proxy.recoveryProgress(progress, reply: $0) })
            let adapter = try XCTUnwrap(host.adapters.withLock { $0.first })
            let invalidated = expectation(description: "The client invalidation reaches the server")
            host.onInvalidated.withLock { $0 = { invalidated.fulfill() } }
            connection.invalidate()
            wait(for: [invalidated], timeout: Self.remaining(deadline))
            XCTAssertTrue(adapter.closed.withLock { $0 })
            XCTAssertEqual(host.invalidations.withLock { $0 }, 1)
            XCTAssertNil(host.slots.mode(adapter.id))
            XCTAssertEqual(host.harness.imports.withLock { $0 }, 1)
        }
    }
    private static func selectors(_ value: Protocol) -> Set<String> {
        var result = Set<String>()
        func visit(_ current: Protocol) {
            for required in [true, false] {
                var count: UInt32 = 0
                if let list = protocol_copyMethodDescriptionList(current, required, true, &count) {
                    for index in 0..<Int(count) { if let name = list[index].name { result.insert(NSStringFromSelector(name)) } }
                    free(list)
                }
            }
            var count: UInt32 = 0
            if let list = protocol_copyProtocolList(current, &count) {
                for index in 0..<Int(count) { visit(list[index]) }
                free(unsafeBitCast(list, to: UnsafeMutableRawPointer.self))
            }
        }
        visit(value); return result
    }
    func testProductionProtocolHasNoRecoverySelectors() {
        let expectedMain: Set<String> = [
            "accountEnrollmentProgressWithReply:",
            "accountStorageProgress:reply:",
            "activateGateway:settings:authorization:reply:",
            "activateRuntime:authorization:reply:",
            "activationHelloWithReply:",
            "activationProgressWithReply:",
            "auditUpgradeHelloWithReply:",
            "auditUpgradeProgressWithReply:",
            "beginAccountEnrollment:authorization:reply:",
            "enrollmentHelloWithReply:",
            "gatewayActivationHelloWithReply:",
            "gatewayActivationProgressWithReply:",
            "gatewayHelloWithReply:",
            "gatewayProgressWithReply:",
            "gatewaySettingsHelloWithReply:",
            "gatewaySettingsProgressWithReply:",
            "helloWithReply:",
            "performAuditUpgrade:authorization:reply:",
            "performPortableImport:authorization:reply:",
            "portableImportHelloWithReply:",
            "portableImportProgressWithReply:",
            "portableImportRecoveryHelloWithReply:",
            "portableImportRecoveryWithReply:",
            "prepareGateway:choices:authorization:reply:",
            "prepareRuntime:fileCustodyAccepted:authorization:reply:",
            "prepareServiceAccounts:authorization:reply:",
            "resumeAccountEnrollment:expectedRevision:authorization:reply:",
            "resumeAccountStorage:setupID:expectedRevision:authorization:reply:",
            "resumeGatewayJournal:authorization:reply:",
            "resumeGatewaySettings:authorization:reply:",
            "retainGatewaySettings:selection:authorization:reply:",
            "retainedInvocationStatus:reply:",
            "runtimeHelloWithReply:",
            "runtimeProgressWithReply:",
            "serviceAccountsHelloWithReply:",
            "serviceAccountsProgressWithReply:"
        ]
        XCTAssertEqual(Self.selectors(AdministrativeSetupServiceXPCProtocol.self), expectedMain)
        let forbidden = ["recoveryHelloWithReply:", "startRecovery:authorization:reply:", "recoveryProgress:reply:"]
        for name in forbidden { XCTAssertFalse(expectedMain.contains(name)) }
    }
}
