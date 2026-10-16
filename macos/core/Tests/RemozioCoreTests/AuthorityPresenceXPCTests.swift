import Darwin
import CryptoKit
import CoreGraphics
import Security
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityPresenceXPCTests: XCTestCase, @unchecked Sendable {
    private enum Failure: Error { case fixture, denied }
    private final class Box<T>: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: T
        init(_ value: T) { stored = value }
        var value: T { get { lock.withLock { stored } } set { lock.withLock { stored = newValue } } }
        func take<Value>() -> Value? where T == Value? {
            lock.withLock { let result = stored; stored = nil; return result }
        }
    }
    private final class Environment: @unchecked Sendable {
        let epoch = UUID()
        let time = Box<UInt64>(100)
        let denied = Box(false)
        let selfDenied = Box(false)
        let verified = Box(0)
        let invalidated = Box(0)
        func now() -> AuthorityMoment { .init(epoch: epoch, milliseconds: time.value) }
        func verify() throws { verified.value += 1; if denied.value { throw Failure.denied } }
    }
    private final class EndpointDriver: PresenceClientDriver, Sendable {
        let endpoint: AuthorityPresenceXPCEndpoint
        let loseModeReply: Bool
        init(endpoint: AuthorityPresenceXPCEndpoint, loseModeReply: Bool = false) { self.endpoint = endpoint; self.loseModeReply = loseModeReply }
        func start(closed: @escaping @Sendable () -> Void) {}
        func invoke(_ call: PresenceClientCall, reply: @escaping @Sendable (PresenceClientReply) -> Void) {
            switch call {
            case .hello: endpoint.hello { reply(.version($0)) }
            case .current: endpoint.current { reply(.status($0)) }
            case .publish(let bytes): endpoint.publish(bytes) { reply(.status($0)) }
            case .setMode(let bytes): endpoint.setMode(bytes) { [loseModeReply] in if !loseModeReply { reply(.status($0)) } }
            }
        }
        func close() { endpoint.close() }
    }
    /// Test-only native transport. The exact running test binary is pinned; Developer ID activation is not simulated.
    private final class NativeDriver: PresenceClientDriver, @unchecked Sendable {
        private let connection: NSXPCConnection
        private let policy: XPCPeerPolicy
        init(endpoint: NSXPCListenerEndpoint, policy: XPCPeerPolicy, requirement: String) {
            connection = NSXPCConnection(listenerEndpoint: endpoint); self.policy = policy
            connection.remoteObjectInterface = NSXPCInterface(with: AuthorityPresenceXPCProtocol.self)
            connection.setCodeSigningRequirement(requirement)
        }
        func start(closed: @escaping @Sendable () -> Void) {
            connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
        }
        func invoke(_ call: PresenceClientCall, reply: @escaping @Sendable (PresenceClientReply) -> Void) {
            let completion = Box<(@Sendable (PresenceClientReply) -> Void)?>(reply)
            let reply: @Sendable (PresenceClientReply) -> Void = { value in
                let callback = completion.take()
                callback?(value)
            }
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any AuthorityPresenceXPCProtocol else {
                reply(.failed); return
            }
            switch call {
            case .hello: proxy.hello { [self] in checked(.version($0), reply: reply) }
            case .current: proxy.current { [self] in checked(.status($0), reply: reply) }
            case .publish(let bytes): proxy.publish(bytes) { [self] in checked(.status($0), reply: reply) }
            case .setMode(let bytes): proxy.setMode(bytes) { [self] in checked(.status($0), reply: reply) }
            }
        }
        private func checked(_ value: PresenceClientReply, reply: @Sendable (PresenceClientReply) -> Void) {
            do {
                let credentials = try policy.verifyCredentials(connection)
                guard credentials.processID == getpid() else { throw Failure.denied }
                reply(value)
            } catch { reply(.failed) }
        }
        func close() { connection.invalidate() }
        deinit { connection.invalidate() }
    }
    /// Forwards native invocations synchronously, preserving the OS invocation guard's original stack.
    private final class CheckedNativeReplies: NSObject, AuthorityPresenceXPCProtocol, @unchecked Sendable {
        let endpoint: AuthorityPresenceXPCEndpoint
        let check: @Sendable () -> Void
        init(endpoint: AuthorityPresenceXPCEndpoint, check: @escaping @Sendable () -> Void) {
            self.endpoint = endpoint; self.check = check
        }
        func hello(reply: @escaping @Sendable (UInt64) -> Void) {
            endpoint.hello { [check] version in
                if version == 1 { check() }; reply(version); if version == 1 { check() }
            }
        }
        func current(reply: @escaping @Sendable (Data?) -> Void) { endpoint.current(reply: checked(reply)) }
        func publish(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) { endpoint.publish(payload, reply: checked(reply)) }
        func setMode(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) { endpoint.setMode(payload, reply: checked(reply)) }
        private func checked(_ reply: @escaping @Sendable (Data?) -> Void) -> @Sendable (Data?) -> Void {
            { [check] bytes in
                if bytes != nil { check() }; reply(bytes); if bytes != nil { check() }
            }
        }
    }
    /// Anonymous listener owned by this test. No Mach service is registered and no Root process runs.
    private final class NativeServer: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
        private let lock = NSRecursiveLock()
        let listener = NSXPCListener.anonymous()
        private let access: AuthorityPresenceAccess
        let environment: Environment
        let mac: Data
        let account: Data
        let policy: XPCPeerPolicy
        private let requirement: String
        private let activityCheck: (@Sendable () -> Void)?
        private var connections: [(NSXPCConnection, AuthorityPresenceXPCEndpoint)] = []
        private var closed = false
        let loseNextModeReply = Box(false)
        init(fixture: Fixture, requirement: String, activityCheck: (@Sendable () -> Void)? = nil) {
            access = fixture.access; environment = fixture.environment; mac = fixture.mac; account = fixture.account
            policy = fixture.policy; self.requirement = requirement; self.activityCheck = activityCheck
            super.init()
            listener.setConnectionCodeSigningRequirement(requirement); listener.delegate = self; listener.activate()
        }
        deinit { close() }
        func close() {
            let removed = lock.withLock {
                closed = true; listener.invalidate(); listener.delegate = nil
                let result = connections; connections.removeAll(); return result
            }
            for (connection, endpoint) in removed { endpoint.close(); connection.invalidate() }
        }
        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            lock.withLock {
                guard !closed, listener === self.listener, connections.count < 8 else { return false }
                do {
                    let credentials = try policy.verifyCredentials(connection)
                    guard credentials.processID == getpid() else { throw Failure.denied }
                    let invocation = XPCInvocationGuard(connection: connection, policy: policy)
                    let binding = try AuthorityPresenceBinding(macID: mac, accountID: account, clockEpoch: environment.epoch, connectionID: UUID())
                    let access = self.access, environment = self.environment, loseReply = loseNextModeReply
                    let endpoint = try AuthorityPresenceXPCEndpoint(binding: binding, budget: .init(maximum: 1), verify: {
                        let current = try invocation.verifyInvocation()
                        guard current == credentials else { throw Failure.denied }
                        try environment.verify()
                    }, acquireActivity: { try access.acquireReleaseActivity() }, verifyCurrent: { try access.verifyCurrent() }, invalidate: { [weak connection] in connection?.invalidate() },
                       withdraw: { access.withdraw(observer: binding.connectionID) }, status: { try access.status(binding: binding) },
                       publish: { try access.publish($0) }, setMode: { change in
                           let status = try access.setMode(change)
                           if loseReply.value { loseReply.value = false; throw Failure.denied }
                           return status
                       })
                    connection.setCodeSigningRequirement(requirement)
                    connection.exportedInterface = NSXPCInterface(with: AuthorityPresenceXPCProtocol.self)
                    if let activityCheck {
                        connection.exportedObject = CheckedNativeReplies(endpoint: endpoint, check: activityCheck)
                    } else { connection.exportedObject = endpoint }
                    connection.invalidationHandler = { [weak endpoint] in endpoint?.close() }
                    connection.interruptionHandler = { [weak endpoint] in endpoint?.close() }
                    connections.append((connection, endpoint)); connection.activate(); return true
                } catch { connection.invalidate(); return false }
            }
        }
    }
    private func runningTestRequirement() throws -> String {
        var code: SecCode?, staticCode: SecStaticCode?, info: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess, let fields = info as? [String: Any],
              let hash = fields[kSecCodeInfoUnique as String] as? Data, hash.count == 20 else { throw Failure.fixture }
        return "cdhash H\"" + hash.map { String(format: "%02x", $0) }.joined() + "\""
    }

    private final class Fixture {
        let root: URL
        let environment = Environment()
        let journal: AuthorityJournal
        let presence: AuthorityPresenceRuntime
        let access: AuthorityPresenceAccess
        let policy: XPCPeerPolicy
        let binding: AuthorityPresenceBinding
        let limits: CBORLimits
        var mac: Data { Data(repeating: 1, count: 16) }
        var account: Data { Data(repeating: 2, count: 16) }
        init(ownerUID: UInt32 = 501) throws {
            let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16), environment = self.environment
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.fixture }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            let directory = root.appendingPathComponent("store").path
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw Failure.fixture }; Darwin.close(fd)
            }
            limits = try .init(maxBytes: 16384, maxDepth: 12, maxItems: 1024)
            let db = try JournalDatabase(lease: .init(anchor: root.path, relativeDirectory: "store", owner: getuid()),
                macID: mac, accountID: account, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 20, busyMilliseconds: 100, initialize: true,
                routingPolicy: .init(clockEpoch: environment.epoch, challengeLifetimeMillis: 1000, maximumOperations: 20,
                    payloadLimits: limits, signingLimits: limits))
            let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
            _ = try db.write { try $0.configureApprovalAuthority(capabilities: .init(contracts: [contract: []]), allowedContracts: [contract]) }
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(mac),
                2: .bytes(account), 3: .bytes(Data(repeating: 3, count: 16)), 4: .unsigned(1), 5: .unsigned(1),
                6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
            let writer = try db.write { try $0.createEpoch(descriptor) }
            let app = try Self.appEntry()
            _ = try db.write { try $0.installCodePolicy(.init(entries: [app]), expectedRevision: nil) }
            let owner = try ApprovalRequestCoordinator(database: db, writer: writer, clockEpoch: environment.epoch,
                maximumRequests: 4, maximumRetainedBytes: 16384, requestLimits: limits, captureLimits: limits,
                decisionLimits: limits, signingLimits: limits, auditLimits: limits)
            journal = AuthorityJournal(requests: owner)
            presence = AuthorityPresenceRuntime(configuration: try .init(macID: mac, accountID: account, ownerUID: ownerUID,
                policy: .init(observationLifetimeMilliseconds: 1000, unavailableGraceMilliseconds: 0)), clockEpoch: environment.epoch)
            policy = try .init(teamID: app.teamID, componentIdentifier: app.identifier, approvedCodeDirectoryHashes: [app.codeDirectoryHash], expectedUserID: ownerUID)
            access = try AuthorityPresenceAccess(journal: journal, presence: presence, appPolicy: policy, now: { environment.now() },
                validateSelf: { _ in if environment.selfDenied.value { throw Failure.denied } })
            binding = try .init(macID: mac, accountID: account, clockEpoch: environment.epoch, connectionID: UUID())
        }
        deinit { presence.close(); try? journal.close(); try? FileManager.default.removeItem(at: root) }
        static func appEntry(generation: UInt64 = 1, active: Bool = true) throws -> AuthorityCodeEntry {
            try .init(role: .app, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.app", installedGeneration: generation,
                minimumGeneration: generation, codeDirectoryHash: Data(repeating: UInt8(generation), count: 20), active: active)
        }
        func endpoint(binding received: AuthorityPresenceBinding? = nil, onHandshake: @escaping @Sendable () -> Void = {}) throws -> AuthorityPresenceXPCEndpoint {
            let binding = received ?? self.binding, environment = self.environment, access = self.access
            return try AuthorityPresenceXPCEndpoint(binding: binding, budget: .init(maximum: 1), verify: { try environment.verify() },
                acquireActivity: { try access.acquireReleaseActivity() },
                verifyCurrent: { try access.verifyCurrent() }, invalidate: { environment.invalidated.value += 1 }, onHandshake: onHandshake,
                withdraw: { access.withdraw(observer: binding.connectionID) }, status: { try access.status(binding: binding) },
                publish: { try access.publish($0) }, setMode: { try access.setMode($0) })
        }
        func current(_ endpoint: AuthorityPresenceXPCEndpoint) throws -> AuthorityPresenceStatus {
            let result = Box<Data?>(nil)
            endpoint.current { result.value = $0 }
            return try AuthorityPresenceCodec.decodeStatus(XCTUnwrap(result.value), expectedMacID: mac, expectedAccountID: account)
        }
        func mode(_ mode: RoutingMode, sequence: UInt64 = 1, revision: UInt64 = 0, binding received: AuthorityPresenceBinding? = nil) throws -> Data {
            try AuthorityPresenceCodec.encodeModeChange(binding: received ?? binding, sequence: sequence, mode: mode, expectedRevision: revision)
        }
        func publication(sequence: UInt64 = 1, sampledAt: UInt64? = nil, binding received: AuthorityPresenceBinding? = nil) throws -> Data {
            let binding = received ?? self.binding, time = sampledAt ?? environment.time.value
            return try AuthorityPresenceCodec.encodePublication(binding: binding, sequence: sequence,
                sampledAt: .init(epoch: binding.clockEpoch, milliseconds: time),
                snapshot: .init(remoteWorkspace: .init(.usable, observedAt: .init(epoch: binding.clockEpoch, milliseconds: time))))
        }
        func records() throws -> [AuditEventMetadata] {
            let limits = self.limits
            return try journal.read { try $0.page(epoch: Data(repeating: 3, count: 16), after: 0,
                maximumRecords: 10, maximumBytes: 16384).canonicalRecords.map { try AuditEventMetadata.decode($0, limits: limits) } }
        }
    }


    @discardableResult
    private static func assertUpdateBusy(_ installer: ReleaseActivityBarrier, file: StaticString = #filePath, line: UInt = #line) -> Bool {
        do {
            let unexpected = try installer.acquireExclusive(); unexpected.close()
            XCTFail("Active RPC did not exclude update admission", file: file, line: line); return false
        } catch {
            XCTAssertEqual(error as? ReleaseActivityError, .busy, file: file, line: line)
            return (error as? ReleaseActivityError) == .busy
        }
    }
    func testPresenceReleaseActivityCoversHandshakeAndAllOperationRepliesButNotIdleConnection() throws {
        let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture()
        try f.journal.attachReleaseActivityBarrier(activity.open())
        let checks = Box(0)
        let check: @Sendable () -> Void = {
            Self.assertUpdateBusy(installer)
            checks.value += 1
        }
        let endpoint = try f.endpoint(onHandshake: check)
        endpoint.hello { XCTAssertEqual($0, 1); check() }
        try installer.acquireExclusive().close()
        endpoint.current { XCTAssertNotNil($0); check() }
        try installer.acquireExclusive().close()
        endpoint.publish(try f.publication()) { XCTAssertNotNil($0); check() }
        try installer.acquireExclusive().close()
        endpoint.setMode(try f.mode(.away, sequence: 2)) { XCTAssertNotNil($0); check() }
        try installer.acquireExclusive().close()
        XCTAssertEqual(checks.value, 5)
        XCTAssertEqual(try f.current(endpoint).state.mode, .away)
        endpoint.close()
        try installer.acquireExclusive().close()
    }
    func testPresenceExclusiveActivityRefusesBeforeMutationAndAllowsFreshConnectionAfterRelease() throws {
        let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture()
        try f.journal.attachReleaseActivityBarrier(activity.open())
        let endpoint = try f.endpoint()
        endpoint.hello { XCTAssertEqual($0, 1) }
        let update = try installer.acquireExclusive()
        endpoint.setMode(try f.mode(.away)) { XCTAssertNil($0) }
        XCTAssertTrue(try f.records().isEmpty)
        XCTAssertEqual(f.environment.invalidated.value, 1)
        update.close()
        let retry = try f.endpoint()
        retry.hello { XCTAssertEqual($0, 1) }
        retry.setMode(try f.mode(.away)) { XCTAssertNotNil($0) }
        XCTAssertEqual(try f.current(retry).state.mode, .away)
        try installer.acquireExclusive().close()
    }
    func testPresenceReleaseActivityClosesAfterMalformedWorkAndChangedMetadata() throws {
        for changed in [false, true] {
            let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture()
            try f.journal.attachReleaseActivityBarrier(activity.open())
            let access = f.access, binding = f.binding, path = activity.directory.appendingPathComponent("activity.lock").path
            let endpoint = try AuthorityPresenceXPCEndpoint(binding: binding, budget: .init(), verify: {},
                acquireActivity: { try access.acquireReleaseActivity() }, verifyCurrent: { try access.verifyCurrent() }, invalidate: {},
                withdraw: { access.withdraw(observer: binding.connectionID) }, status: {
                    let status = try access.status(binding: binding)
                    Self.assertUpdateBusy(installer)
                    if changed { XCTAssertEqual(chmod(path, 0o644), 0) }
                    return status
                }, publish: { try access.publish($0) }, setMode: { try access.setMode($0) })
            endpoint.hello { XCTAssertEqual($0, 1) }
            if changed {
                endpoint.current { XCTAssertNil($0) }
                XCTAssertEqual(chmod(path, 0o600), 0)
            } else { endpoint.publish(Data([0])) { XCTAssertNil($0) } }
            try installer.acquireExclusive().close()
        }
    }
    func testTransportReleaseActivityCoversEverySelectorAndReplyWithIdleAdmissionOpen() throws {
        let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture()
        let mac = f.mac, account = f.account, trust = DirectApprovalTrust(macID: mac, accountID: account, revision: UUID(), peers: [])
        let checks = Box(0)
        let check: @Sendable () -> Void = {
            Self.assertUpdateBusy(installer)
            checks.value += 1
        }
        let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: .init(maximum: 1), activityJournal: f.journal,
            verify: {}, verifyHandshakePolicy: check, invalidate: {}, onHandshake: check,
            snapshot: { check(); return trust }, validate: { _ in check(); return true },
            requestFrame: { _, _ in check(); return nil }, pendingRequestIDs: { _ in check(); return [] },
            exchangeRequest: { _, _, _ in check(); return nil }, pairingReceipt: { _, _ in check(); return nil }, wakeHints: {
                check(); return try .init(binding: .init(ownerID: Data(repeating: 4, count: 16), macID: mac, accountID: account,
                    gatewayID: Data(repeating: 5, count: 16), lifecycleEpoch: Data(repeating: 6, count: 16)), deliveryIDs: [])
            })
        // The endpoint must resolve current journal activity, including attachment after its construction.
        try f.journal.attachReleaseActivityBarrier(activity.open())
        let peer = try AuthorityPeerBinding(scope: .init(macID: mac, accountID: account, phoneID: Data(repeating: 7, count: 16),
            enrollmentEpoch: Data(repeating: 8, count: 16)), transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, revision: UUID())
        let binding = try AuthorityTrustCodec.encodeBinding(peer), requestID = Data(repeating: 9, count: 16)
        let version: @Sendable (UInt64) -> Void = { XCTAssertEqual($0, 1); check() }
        let bytes: @Sendable (Data?) -> Void = { XCTAssertNotNil($0); check() }
        endpoint.hello(reply: version); try installer.acquireExclusive().close()
        endpoint.requestDeliveryVersion(reply: version); try installer.acquireExclusive().close()
        endpoint.requestDiscoveryVersion(reply: version); try installer.acquireExclusive().close()
        endpoint.requestExchangeVersion(reply: version); try installer.acquireExclusive().close()
        endpoint.pairingReceiptVersion(reply: version); try installer.acquireExclusive().close()
        endpoint.requestWakeVersion(reply: version); try installer.acquireExclusive().close()
        endpoint.pendingRequestIDs(binding, reply: bytes); try installer.acquireExclusive().close()
        endpoint.requestFrame(binding, requestID: requestID, reply: bytes); try installer.acquireExclusive().close()
        endpoint.exchangeRequest(binding, query: try AuthorityRequestExchange.encode(requestID: requestID), reply: bytes)
        try installer.acquireExclusive().close()
        endpoint.pairingReceipt(binding, setupID: requestID, reply: bytes); try installer.acquireExclusive().close()
        endpoint.wakeDeliveryHints(reply: bytes); try installer.acquireExclusive().close()
        endpoint.trustSnapshot(reply: bytes); try installer.acquireExclusive().close()
        endpoint.validatePeer(binding) { XCTAssertTrue($0); check() }
        try installer.acquireExclusive().close()
        XCTAssertEqual(checks.value, 24)
    }
    func testTransportReleaseActivityRejectsExclusiveAdmissionAndReleasesBudgetAfterHandlerFailure() throws {
        let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture(), budget = try AuthorityXPCWorkBudget(maximum: 1)
        try f.journal.attachReleaseActivityBarrier(activity.open())
        let calls = Box(0), trust = DirectApprovalTrust(macID: f.mac, accountID: f.account, revision: UUID(), peers: [])
        let make: () -> AuthorityXPCEndpoint = {
            AuthorityXPCEndpoint(macID: trust.macID, accountID: trust.accountID, budget: budget, activityJournal: f.journal,
                verify: {}, verifyHandshakePolicy: { calls.value += 1 }, invalidate: {}, snapshot: {
                    calls.value += 1; Self.assertUpdateBusy(installer); throw Failure.denied
                }, validate: { _ in true })
        }
        let update = try installer.acquireExclusive(), denied = make()
        denied.hello { XCTAssertEqual($0, 0) }
        XCTAssertEqual(calls.value, 0); XCTAssertTrue(budget.acquire()); budget.release(); update.close()
        let retry = make()
        retry.hello { XCTAssertEqual($0, 1) }
        retry.trustSnapshot { XCTAssertNil($0) }
        XCTAssertEqual(calls.value, 2); XCTAssertTrue(budget.acquire()); budget.release()
        try installer.acquireExclusive().close()
    }
    func testTransportReleaseActivityAllowsNestedReplyWithoutDroppingTheOuterReference() throws {
        let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture()
        try f.journal.attachReleaseActivityBarrier(activity.open())
        let trust = DirectApprovalTrust(macID: f.mac, accountID: f.account, revision: UUID(), peers: [])
        let endpoint = try AuthorityXPCEndpoint(macID: f.mac, accountID: f.account, budget: .init(maximum: 1), activityJournal: f.journal,
            verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in true })
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.trustSnapshot { first in
            XCTAssertNotNil(first)
            endpoint.trustSnapshot { XCTAssertNotNil($0); Self.assertUpdateBusy(installer) }
            Self.assertUpdateBusy(installer)
            endpoint.close()
            Self.assertUpdateBusy(installer)
        }
        try installer.acquireExclusive().close()
    }
    func testTransportDisconnectRetainsActivityUntilTheExecutingHandlerReturns() throws {
        let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture()
        try f.journal.attachReleaseActivityBarrier(activity.open())
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let completed = expectation(description: "disconnected handler completed"), replies = Box(0)
        let trust = DirectApprovalTrust(macID: f.mac, accountID: f.account, revision: UUID(), peers: [])
        let endpoint = try AuthorityXPCEndpoint(macID: f.mac, accountID: f.account, budget: .init(maximum: 1), activityJournal: f.journal,
            verify: {}, invalidate: {}, snapshot: {
                entered.signal()
                guard release.wait(timeout: .now() + 5) == .success else { throw Failure.denied }
                Self.assertUpdateBusy(installer)
                return trust
            }, validate: { _ in true })
        endpoint.hello { XCTAssertEqual($0, 1) }
        DispatchQueue.global().async {
            endpoint.trustSnapshot { _ in replies.value += 1 }
            completed.fulfill()
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
        endpoint.close(); Self.assertUpdateBusy(installer)
        release.signal(); wait(for: [completed], timeout: 5)
        XCTAssertEqual(replies.value, 0)
        try installer.acquireExclusive().close()
    }
    func testPresenceNestedReplyRetainsBothActivityReferencesUntilEachCallbackReturns() throws {
        let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture()
        try f.journal.attachReleaseActivityBarrier(activity.open())
        let endpoint = try f.endpoint()
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.current { first in
            XCTAssertNotNil(first)
            endpoint.current { XCTAssertNotNil($0); Self.assertUpdateBusy(installer) }
            Self.assertUpdateBusy(installer)
            endpoint.close(); Self.assertUpdateBusy(installer)
        }
        try installer.acquireExclusive().close()
    }
    func testTransportReleaseActivityRevalidatesAfterHandlerBeforeSendingReply() throws {
        let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture()
        try f.journal.attachReleaseActivityBarrier(activity.open())
        let path = activity.directory.appendingPathComponent("activity.lock").path
        let trust = DirectApprovalTrust(macID: f.mac, accountID: f.account, revision: UUID(), peers: [])
        let endpoint = try AuthorityXPCEndpoint(macID: f.mac, accountID: f.account, budget: .init(), activityJournal: f.journal,
            verify: {}, invalidate: {}, snapshot: { XCTAssertEqual(chmod(path, 0o644), 0); return trust }, validate: { _ in true })
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.trustSnapshot { XCTAssertNil($0) }
        XCTAssertEqual(chmod(path, 0o600), 0)
        try installer.acquireExclusive().close()
    }

    func testLiveAnonymousPresenceWireCommitsAndReconnectsInGuiSession() async throws {
        guard getuid() > 0, getuid() == geteuid(), CGSessionCopyCurrentDictionary() != nil else {
            throw XCTSkip("Requires a supported unprivileged Mac GUI session; installed account checks remain separate")
        }
        let f = try Fixture(ownerUID: getuid()), requirement = try runningTestRequirement(), environment = f.environment
        let activity = try ReleaseActivityFixture(), installer = try activity.open(), activityChecks = Box(0), activityFailures = Box(0)
        try f.journal.attachReleaseActivityBarrier(activity.open())
        let server = NativeServer(fixture: f, requirement: requirement, activityCheck: {
            if !Self.assertUpdateBusy(installer) { activityFailures.value += 1 }; activityChecks.value += 1
        })
        func requireIdle() async throws {
            let deadline = ContinuousClock.now.advanced(by: .seconds(3))
            while true {
                do { try installer.acquireExclusive().close(); return }
                catch ReleaseActivityError.busy {
                    guard ContinuousClock.now < deadline else { throw Failure.fixture }
                    try await Task.sleep(for: .milliseconds(10))
                }
            }
        }
        defer { server.close() }
        func client() -> AuthorityPresenceChannel {
            AuthorityPresenceChannel(driver: NativeDriver(endpoint: server.listener.endpoint, policy: server.policy, requirement: requirement),
                macID: f.mac, accountID: f.account, timeoutMilliseconds: 3000, sample: { _ in environment.now() })
        }
        let first = client(), initial = try await first.start()
        try await requireIdle()
        XCTAssertEqual(initial.state, .init(mode: .automatic, revision: 0))
        let present = try await first.setMode(.present, expectedRevision: 0)
        XCTAssertEqual(present.state, .init(mode: .present, revision: 1)); XCTAssertEqual(present.routing.destination, .localMac)
        let publication = PresenceSnapshot(remoteWorkspace: .init(.usable, observedAt: .init(epoch: environment.epoch, milliseconds: 100)))
        _ = try await first.publish(publication, sampledAt: environment.now())
        let conflict = try await first.setMode(.away, expectedRevision: 0)
        XCTAssertTrue(conflict.conflict); XCTAssertEqual(conflict.state.mode, .present)
        server.loseNextModeReply.value = true
        do { _ = try await first.setMode(.away, expectedRevision: 1); XCTFail("Lost reply confirmed a mode") } catch { }
        await first.close()
        let second = client(), recovered = try await second.start()
        XCTAssertNotEqual(recovered.binding.connectionID, initial.binding.connectionID)
        XCTAssertEqual(recovered.state, .init(mode: .away, revision: 2)); XCTAssertEqual(recovered.routing.destination, .phones)
        let automatic = try await second.setMode(.automatic, expectedRevision: 2)
        XCTAssertEqual(automatic.state, .init(mode: .automatic, revision: 3)); XCTAssertEqual(automatic.routing.reason, .detectorUnavailable)
        await second.close()
        let raw = NativeDriver(endpoint: server.listener.endpoint, policy: server.policy, requirement: requirement)
        raw.start(closed: {})
        let hello = await withCheckedContinuation { continuation in raw.invoke(.hello) { continuation.resume(returning: $0) } }
        guard case .version(1) = hello else { raw.close(); return XCTFail("Native replay fixture did not negotiate") }
        let crossed = try AuthorityPresenceCodec.encodeModeChange(binding: initial.binding, sequence: 1, mode: .present, expectedRevision: 3)
        let refused = await withCheckedContinuation { continuation in raw.invoke(.setMode(crossed)) { continuation.resume(returning: $0) } }
        switch refused {
        case .status(nil), .failed: break
        default: raw.close(); return XCTFail("Old connection binding reached a new native connection")
        }
        raw.close()
        let final = client(), unchanged = try await final.start()
        XCTAssertEqual(unchanged.state, .init(mode: .automatic, revision: 3))
        do { _ = try await final.publish(publication, sampledAt: environment.now()); XCTFail("Discarded publication returned success") } catch { }
        await final.close()
        environment.time.value = 101
        let freshObserver = client()
        _ = try await freshObserver.start()
        let freshSnapshot = PresenceSnapshot(remoteWorkspace: .init(.usable, observedAt: .init(epoch: environment.epoch, milliseconds: 101)))
        let freshStatus = try await freshObserver.publish(freshSnapshot, sampledAt: environment.now())
        XCTAssertEqual(freshStatus.routing.reason, .remoteDesktop)
        await freshObserver.close()
        let reader = client()
        var withdrawn = try await reader.start()
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while withdrawn.routing.reason != .detectorUnavailable, ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(10))
            withdrawn = try await reader.current()
        }
        XCTAssertEqual(withdrawn.routing.reason, .detectorUnavailable)
        await reader.close()
        XCTAssertEqual(try f.records().count, 3)
        XCTAssertGreaterThanOrEqual(environment.verified.value, 19)
        try await requireIdle()
        guard activityChecks.value >= 32, activityFailures.value == 0 else { throw Failure.fixture }
        if let output = ProcessInfo.processInfo.environment["REMOZIO_RPC_ACTIVITY_XPC_EVIDENCE"] {
            let evidence: [String: Any] = ["schemaVersion": 1, "experiment": "authority-presence-native-xpc-release-activity",
                "status": "passed", "osVersion": ProcessInfo.processInfo.operatingSystemVersionString,
                "hostArchitecture": "arm64", "guiSessionAvailable": true, "sameProcessNativeConnection": true,
                "kernelPeerCredentialsChecked": true, "invocationConnectionChecked": true, "testCodeHashRequirementApplied": true,
                "verifiedInvocations": environment.verified.value, "activityChecksBeforeAndAfterNativeReply": activityChecks.value,
                "independentExclusiveDescriptorRefusedInsideReplies": true, "idleConnectionAllowsExclusiveActivity": true,
                "reconnectPreservesMode": true, "lostReplyReconciled": true, "modeChangesAudited": 3,
                "installedRootAccountsTested": false, "developerIDPolicyTested": false, "physicalPresenceSignalsTested": false,
                "serviceInstalled": false, "realApprovalIssued": false, "productionActivationTested": false]
            try JSONSerialization.data(withJSONObject: evidence, options: [.prettyPrinted, .sortedKeys])
                .write(to: URL(fileURLWithPath: output), options: .atomic)
        }
        if let output = ProcessInfo.processInfo.environment["REMOZIO_PRESENCE_XPC_EVIDENCE"] {
            let evidence: [String: Any] = ["schemaVersion": 1, "experiment": "account-presence-anonymous-native-xpc", "status": "passed",
                "osVersion": ProcessInfo.processInfo.operatingSystemVersionString, "guiSessionAvailable": true,
                "sameProcessNativeConnection": true, "testCodeHashRequirementApplied": true, "kernelPeerCredentialsChecked": true,
                "invocationConnectionChecked": true, "verifiedInvocations": environment.verified.value,
                "modeChangesAudited": 3, "conflictReturnedCurrentState": true, "lostReplyCommittedModeRecovered": true,
                "freshConnectionBinding": true, "crossedConnectionMutationRejected": true, "observerWithdrawnOnClose": true,
                "discardedPublicationRejected": true, "freshPublicationAfterRejectionAccepted": true,
                "installedRootAccountsTested": false, "developerIDPolicyTested": false, "physicalPresenceSignalsTested": false,
                "serviceInstalled": false, "realApprovalIssued": false]
            try JSONSerialization.data(withJSONObject: evidence, options: [.prettyPrinted, .sortedKeys]).write(to: URL(fileURLWithPath: output), options: .atomic)
        }
    }

    func testClientControlsCommitThroughRealJournalAndRecoverALostReplyWithoutReplay() async throws {
        let f = try Fixture(), endpoint = try f.endpoint(), environment = f.environment
        let channel = AuthorityPresenceChannel(driver: EndpointDriver(endpoint: endpoint), macID: f.mac, accountID: f.account,
            sample: { _ in environment.now() })
        let initial = try await channel.start()
        let present = try await channel.setMode(.present, expectedRevision: initial.state.revision)
        XCTAssertEqual(present.state, .init(mode: .present, revision: 1)); XCTAssertEqual(present.routing.destination, .localMac)
        await channel.close()
        let secondBinding = try AuthorityPresenceBinding(macID: f.mac, accountID: f.account, clockEpoch: environment.epoch, connectionID: UUID())
        let second = try f.endpoint(binding: secondBinding)
        let interrupted = AuthorityPresenceChannel(driver: EndpointDriver(endpoint: second, loseModeReply: true), macID: f.mac,
            accountID: f.account, timeoutMilliseconds: 100, sample: { _ in environment.now() })
        _ = try await interrupted.start()
        do { _ = try await interrupted.setMode(.away, expectedRevision: 1); XCTFail() }
        catch { XCTAssertEqual(error as? AuthorityPresenceChannelError, .timedOut) }
        let freshBinding = try AuthorityPresenceBinding(macID: f.mac, accountID: f.account, clockEpoch: environment.epoch, connectionID: UUID())
        let fresh = try f.endpoint(binding: freshBinding)
        let recovered = AuthorityPresenceChannel(driver: EndpointDriver(endpoint: fresh), macID: f.mac, accountID: f.account,
            sample: { _ in environment.now() })
        let current = try await recovered.start()
        XCTAssertEqual(current.state, .init(mode: .away, revision: 2)); XCTAssertEqual(current.routing.destination, .phones)
        XCTAssertEqual(try f.records().count, 2)
        await recovered.close()
    }

    func testVerifiedHandshakeAndEverySelectorUseTheRealOwner() throws {
        let f = try Fixture(), endpoint = try f.endpoint()
        endpoint.hello { XCTAssertEqual($0, 1) }
        let initial = try f.current(endpoint)
        XCTAssertEqual(initial.binding, f.binding); XCTAssertEqual(initial.state, .init(mode: .automatic, revision: 0))
        XCTAssertEqual(initial.routing.reason, .detectorUnavailable)
        endpoint.publish(try f.publication()) { XCTAssertNotNil($0) }
        let result = Box<Data?>(nil)
        endpoint.setMode(try f.mode(.away, sequence: 2)) { result.value = $0 }
        let away = try AuthorityPresenceCodec.decodeStatus(XCTUnwrap(result.value), expectedMacID: f.mac, expectedAccountID: f.account)
        XCTAssertEqual(away.state, .init(mode: .away, revision: 1)); XCTAssertEqual(away.routing.reason, .manualAway)
        XCTAssertEqual(f.environment.verified.value, 4)
        XCTAssertEqual(try f.records().map(\.authentication), [.localUser])
        XCTAssertEqual(try f.records().map(\.kind), [.routingChanged])
        endpoint.close(); endpoint.close(); XCTAssertEqual(f.environment.invalidated.value, 1)
    }
    func testMissingHandshakeOrFailedInvocationCannotReadOrMutate() throws {
        for selector in 0..<4 {
            let f = try Fixture(), endpoint = try f.endpoint()
            if selector == 0 { f.environment.denied.value = true; endpoint.hello { XCTAssertEqual($0, 0) } }
            else if selector == 1 { endpoint.current { XCTAssertNil($0) } }
            else if selector == 2 { endpoint.publish(try f.publication()) { XCTAssertNil($0) } }
            else { endpoint.setMode(try f.mode(.present)) { XCTAssertNil($0) } }
            XCTAssertTrue(try f.records().isEmpty)
            XCTAssertEqual(try f.journal.withRequests { try $0.localRoutingState().revision }, 0)
            XCTAssertEqual(f.environment.invalidated.value, 1)
        }
        let f = try Fixture(), endpoint = try f.endpoint()
        endpoint.hello { XCTAssertEqual($0, 1) }
        f.environment.denied.value = true
        endpoint.setMode(try f.mode(.present)) { XCTAssertNil($0) }
        XCTAssertTrue(try f.records().isEmpty)
    }
    func testStaleRevisionReturnsCurrentStatusWithoutSilentlyOverwriting() throws {
        let f = try Fixture(), endpoint = try f.endpoint(), result = Box<Data?>(nil)
        endpoint.hello { XCTAssertEqual($0, 1) }
        let moment = f.environment.now()
        _ = try f.journal.withRequests { try $0.setLocalRoutingMode(.present, expectedRevision: 0, now: moment, receiptTimeMs: nil) }
        endpoint.setMode(try f.mode(.away)) { result.value = $0 }
        let conflict = try AuthorityPresenceCodec.decodeStatus(XCTUnwrap(result.value), expectedMacID: f.mac, expectedAccountID: f.account)
        XCTAssertTrue(conflict.conflict); XCTAssertEqual(conflict.state, .init(mode: .present, revision: 1))
        XCTAssertEqual(conflict.routing.destination, .localMac)
        endpoint.setMode(try f.mode(.away, sequence: 2, revision: 1)) { XCTAssertNotNil($0) }
        XCTAssertEqual(try f.current(endpoint).state, .init(mode: .away, revision: 2))
        XCTAssertEqual(try f.records().count, 2); XCTAssertEqual(f.environment.invalidated.value, 0)
    }
    func testWrongScopeEpochConnectionAndSequenceCannotChangeMode() throws {
        for change in 0..<6 {
            let f = try Fixture(), endpoint = try f.endpoint()
            endpoint.hello { XCTAssertEqual($0, 1) }
            let binding = try AuthorityPresenceBinding(macID: change == 0 ? Data(repeating: 9, count: 16) : f.mac,
                accountID: change == 1 ? Data(repeating: 9, count: 16) : f.account,
                clockEpoch: change == 2 ? UUID() : f.binding.clockEpoch, connectionID: change == 3 ? UUID() : f.binding.connectionID)
            endpoint.setMode(try f.mode(.present, sequence: change == 4 ? 2 : change == 5 ? UInt64.max : 1, binding: binding)) { XCTAssertNil($0) }
            XCTAssertTrue(try f.records().isEmpty); XCTAssertEqual(f.environment.invalidated.value, 1)
        }
    }
    func testPublicationReplayClosesAndWithdrawsItsObservation() throws {
        let f = try Fixture(), endpoint = try f.endpoint(), payload = try f.publication()
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.publish(payload) { XCTAssertNotNil($0) }
        XCTAssertEqual(try f.current(endpoint).routing.reason, .remoteDesktop)
        endpoint.publish(payload) { XCTAssertNil($0) }
        XCTAssertEqual(try f.access.status(binding: f.binding).routing.reason, .detectorUnavailable)
        XCTAssertTrue(try f.records().isEmpty)
    }
    func testDiscardedReplacementPublicationCannotReturnSuccessOrWithdrawAnotherObserver() throws {
        for timestamp: UInt64 in [90, 100] {
            let f = try Fixture(), first = try f.endpoint()
            first.hello { XCTAssertEqual($0, 1) }
            first.publish(try f.publication()) { XCTAssertNotNil($0) }
            let replacementBinding = try AuthorityPresenceBinding(macID: f.mac, accountID: f.account,
                clockEpoch: f.binding.clockEpoch, connectionID: UUID())
            let replacement = try f.endpoint(binding: replacementBinding)
            replacement.hello { XCTAssertEqual($0, 1) }
            replacement.publish(try f.publication(sampledAt: timestamp, binding: replacementBinding)) { XCTAssertNil($0) }
            XCTAssertEqual(f.environment.invalidated.value, 1)
            XCTAssertEqual(try f.current(first).routing.reason, .remoteDesktop)
            first.close()
            XCTAssertEqual(try f.access.status(binding: f.binding).routing.reason, .detectorUnavailable)
            f.environment.time.value = 101
            let freshBinding = try AuthorityPresenceBinding(macID: f.mac, accountID: f.account,
                clockEpoch: f.binding.clockEpoch, connectionID: UUID())
            let fresh = try f.endpoint(binding: freshBinding)
            fresh.hello { XCTAssertEqual($0, 1) }
            fresh.publish(try f.publication(binding: freshBinding)) { XCTAssertNotNil($0) }
            replacement.close(); first.close()
            XCTAssertEqual(try f.current(fresh).routing.reason, .remoteDesktop)
            XCTAssertTrue(try f.records().isEmpty)
            fresh.close()
        }
    }

    func testOldConnectionClosureCannotRemoveNewerObservation() throws {
        let f = try Fixture(), first = try f.endpoint()
        let next = try AuthorityPresenceBinding(macID: f.mac, accountID: f.account, clockEpoch: f.binding.clockEpoch, connectionID: UUID())
        let second = try f.endpoint(binding: next)
        first.hello { XCTAssertEqual($0, 1) }; second.hello { XCTAssertEqual($0, 1) }
        first.publish(try f.publication()) { XCTAssertNotNil($0) }
        f.environment.time.value = 110
        second.publish(try f.publication(binding: next)) { XCTAssertNotNil($0) }
        first.close()
        XCTAssertEqual(try f.current(second).routing.reason, .remoteDesktop)
        second.close()
        XCTAssertEqual(try f.access.status(binding: next).routing.reason, .detectorUnavailable)
    }
    func testChangedAppPolicyAndInvalidRootCodePreventAllAccess() throws {
        for selector in 0..<3 {
            let f = try Fixture(), endpoint = try f.endpoint()
            endpoint.hello { XCTAssertEqual($0, 1) }
            let snapshot = try XCTUnwrap(f.journal.read { try $0.codePolicy() })
            let replacement = try Fixture.appEntry(generation: 2)
            _ = try f.journal.write { try $0.installCodePolicy(.init(entries: [replacement]), expectedRevision: snapshot.revision) }
            if selector == 0 { endpoint.current { XCTAssertNil($0) } }
            else if selector == 1 { endpoint.publish(try f.publication()) { XCTAssertNil($0) } }
            else { endpoint.setMode(try f.mode(.present)) { XCTAssertNil($0) } }
            XCTAssertTrue(try f.records().isEmpty)
        }
        let f = try Fixture(), endpoint = try f.endpoint()
        endpoint.hello { XCTAssertEqual($0, 1) }; f.environment.selfDenied.value = true
        endpoint.setMode(try f.mode(.present)) { XCTAssertNil($0) }
        XCTAssertTrue(try f.records().isEmpty)
    }
    func testFutureAndExpiredSamplesCannotReplacePresence() throws {
        for time: UInt64 in [101, 1100] {
            let f = try Fixture(), endpoint = try f.endpoint()
            endpoint.hello { XCTAssertEqual($0, 1) }
            if time == 1100 { f.environment.time.value = time }
            endpoint.publish(try f.publication(sampledAt: time == 101 ? 101 : 100)) { XCTAssertNil($0) }
            XCTAssertEqual(try f.access.status(binding: f.binding).routing.reason, .detectorUnavailable)
            XCTAssertTrue(try f.records().isEmpty)
        }
    }
    func testCodecPreservesUnknownSignalsAndRejectsUnknownFieldsVersionsAndValues() throws {
        let f = try Fixture(), at = PresenceMoment(epoch: f.binding.clockEpoch, milliseconds: 100)
        let snapshot = PresenceSnapshot(remoteWorkspace: .init(.unsupported, observedAt: at), locked: .init(false, observedAt: at),
            displays: .init([.asleep, .awake(.readable), .awake(.dark), .awake(.unknown), .unknown], observedAt: at),
            lastQualifyingInputMilliseconds: .init(50, observedAt: at))
        let bytes = try AuthorityPresenceCodec.encodePublication(binding: f.binding, sequence: 1, sampledAt: f.environment.now(), snapshot: snapshot)
        let decoded = try AuthorityPresenceCodec.decodePublication(bytes)
        XCTAssertEqual(decoded.snapshot.displays?.value.count, 5); XCTAssertEqual(decoded.snapshot.locked?.value, false)
        XCTAssertEqual(decoded.snapshot.lastQualifyingInputMilliseconds?.value, 50)
        let empty = try AuthorityPresenceCodec.decodePublication(AuthorityPresenceCodec.encodePublication(binding: f.binding,
            sequence: 1, sampledAt: f.environment.now(), snapshot: .init()))
        XCTAssertNil(empty.snapshot.locked); XCTAssertNil(empty.snapshot.remoteWorkspace); XCTAssertNil(empty.snapshot.displays)
        guard case .map(let original) = try DeterministicCBOR.decode(bytes, limits: f.limits) else { return XCTFail() }
        for (field, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (8, .unsigned(2)), (7, .unsigned(3)),
            (9, .array(Array(repeating: .unsigned(0), count: 33))), (10, .unsigned(101)), (11, .null)] {
            var fields = original; fields[field] = value
            XCTAssertThrowsError(try AuthorityPresenceCodec.decodePublication(DeterministicCBOR.encode(.map(fields), limits: f.limits)))
        }
        XCTAssertThrowsError(try AuthorityPresenceCodec.decodePublication(Data(repeating: 0, count: 4097)))
        XCTAssertThrowsError(try AuthorityPresenceCodec.decodeModeChange(bytes))
    }
    func testReplyCanStartNextOperationAtCapacityOne() throws {
        let f = try Fixture(), endpoint = try f.endpoint(), payload = try f.mode(.present)
        endpoint.hello { version in
            XCTAssertEqual(version, 1)
            endpoint.current { current in
                XCTAssertNotNil(current)
                endpoint.setMode(payload) { XCTAssertNotNil($0) }
            }
        }
        XCTAssertEqual(try f.current(endpoint).state.mode, .present); XCTAssertEqual(f.environment.invalidated.value, 0)
    }
}
