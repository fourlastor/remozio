import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityWakePublisherTests: XCTestCase, @unchecked Sendable {
    private final class Driver: GatewayRootDriver {
        struct State {
            var calls = 0
            var snapshots: [GatewayHostSnapshot] = []
            var registrations: [PhoneRequestDelivery] = []
            var withdrawals: [UUID] = []
            var rejectRegistrations = 0
            var holdRegistration = false
            var held: (@Sendable (GatewayRootResponse) -> Void)?
            var onRegistration: (@Sendable () throws -> Void)?
            var closed = 0
            var failHello = false
            var holdHello = false
            var heldHello: (@Sendable (GatewayRootResponse) -> Void)?
            var lost: (@Sendable () -> Void)?
        }
        let value = Mutex(State())
        func start(closed: @escaping @Sendable () -> Void) { value.withLock { $0.lost = closed } }
        func invoke(_ call: GatewayRootCall, reply: @escaping @Sendable (GatewayRootResponse) -> Void) {
            do {
                let response: GatewayRootResponse?
                switch call {
                case .hello:
                    response = value.withLock {
                        $0.calls += 1
                        if $0.holdHello { $0.heldHello = reply; return nil }
                        return $0.failHello ? .failed : .version(3)
                    }
                case .synchronize(let bytes):
                    let snapshot = try GatewayHostSnapshot.decode(bytes)
                    value.withLock { $0.calls += 1; $0.snapshots.append(snapshot) }
                    response = .synchronized(true)
                case .command(let bytes):
                    switch try GatewayRootCommand.decode(bytes) {
                    case .registerWake(let delivery):
                        let hook = value.withLock { $0.onRegistration }
                        try hook?()
                        response = try value.withLock { state in
                            state.calls += 1; state.registrations.append(delivery)
                            if state.holdRegistration { state.held = reply; return nil }
                            if state.rejectRegistrations > 0 { state.rejectRegistrations -= 1; return .command(nil) }
                            return .command(try GatewayRootCommand.reply([.boolean(true)], version: 3))
                        }
                    case .withdraw(let id):
                        value.withLock { $0.calls += 1; $0.withdrawals.append(id) }
                        response = .command(try GatewayRootCommand.reply([.boolean(true)]))
                    default: return reply(.failed)
                    }
                }
                if let response { reply(response) }
            } catch { reply(.failed) }
        }
        func close() { value.withLock { $0.closed += 1 } }
    }

    private final class Fixture: @unchecked Sendable {
        struct State { var time: UInt64 = 110; var mode = RoutingMode.away }
        let state = Mutex(State())
        let root: URL
        let journal: AuthorityJournal
        let epoch = UUID()
        let writer: AuditEpochWriter
        let registration: GatewayRegistrationIdentity
        let request: IssuedRequestPayload
        init(deadline: UInt64 = 200, enablePresence: Bool = false) throws {
            let key = P256.Signing.PrivateKey()
            let limits = try CBORLimits(maxBytes: 4096, maxDepth: 12, maxItems: 256)
            let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
            let capabilities = ContractCapabilities(contracts: [contract: []])
            registration = try GatewayRegistrationIdentity(ownerID: Self.id(3), macID: Self.id(1), accountID: Self.id(2),
                gatewayID: Self.id(4), lifecycleEpoch: Self.id(8), rootPublicKey: key.publicKey.x963Representation)
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw CocoaError(.fileReadUnknown) }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            let directory = root.appendingPathComponent("store").path
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }; Darwin.close(fd)
            }
            let routingPolicy: RoutingJournalPolicy?
            if enablePresence {
                routingPolicy = try .init(clockEpoch: epoch, challengeLifetimeMillis: 1000, maximumOperations: 20,
                    payloadLimits: limits, signingLimits: limits)
            } else { routingPolicy = nil }
            let db = try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()),
                macID: Self.id(1), accountID: Self.id(2), recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 30, busyMilliseconds: 100, initialize: true, routingPolicy: routingPolicy)
            let revision = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(Self.id(1)), 2: .bytes(Self.id(2)), 3: .bytes(Self.id(3)),
                4: .unsigned(3), 5: .unsigned(1), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
            let writer = try db.write { try $0.createEpoch(descriptor) }
            self.writer = writer
            let enrollment = try StoredApprovalEnrollment(epoch: Self.id(9), notificationTag: Self.id(10, count: 32),
                identityPublicKey: key.publicKey.x963Representation,
                approval: ApprovalEnrollment(phoneID: Self.id(5), active: true, capabilities: capabilities,
                    keys: [EnrolledApprovalKey(id: Self.id(6), keyClass: .biometric, publicKey: key.publicKey.x963Representation),
                        EnrolledApprovalKey(id: Self.id(7), keyClass: .decision,
                            publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)]))
            _ = try db.write { try $0.addApprovalEnrollment(enrollment, expectedTrustRevision: revision,
                eventID: Self.id(30), receiptTimeMs: nil, writer: writer, expectedAuditHead: 0) }
            let owner = try ApprovalRequestCoordinator(database: db, writer: writer, clockEpoch: epoch, maximumRequests: 8,
                maximumRetainedBytes: 32768, requestLimits: limits, captureLimits: limits, decisionLimits: limits,
                signingLimits: limits, auditLimits: limits)
            request = try owner.admitFixture(ApprovalRequestDraft(contract: contract, requiredFeatures: [], capture: Data([0xa0]),
                actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
                firstObservedAt: AuthorityMoment(epoch: epoch, milliseconds: 100), deadlineMilliseconds: deadline,
                createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1000 + deadline - 100),
                now: AuthorityMoment(epoch: epoch, milliseconds: 110), receiptTimeMs: nil)
            journal = AuthorityJournal(requests: owner)
        }
        deinit { try? journal.close(); try? FileManager.default.removeItem(at: root) }
        static func id(_ n: UInt8, count: Int = 16) -> Data { Data(repeating: n, count: count) }
        func now() -> AuthorityMoment { .init(epoch: epoch, milliseconds: state.withLock { $0.time }) }
        func routing() throws -> PresenceRouting {
            var router = PresenceRouter(configuration: try PresenceConfiguration(observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 100))
            return router.evaluate(mode: state.withLock { $0.mode }, snapshot: PresenceSnapshot(),
                now: PresenceMoment(epoch: epoch, milliseconds: state.withLock { $0.time }))
        }
        func publisher(_ driver: Driver, lease: UInt64 = 1000) throws -> AuthorityWakePublisher {
            try .init(journal: journal, channel: GatewayRootChannel(driver: driver), registration: registration,
                leaseMilliseconds: lease, clock: { self.now() }, routing: { try self.routing() })
        }
        func cancelAndForget() throws {
            try journal.withRequests { owner in
                _ = try owner.retirePending(requestID: self.request.requestID, reason: .cancelled, now: self.now(), receiptTimeMs: nil)
                try owner.forgetTerminal(requestID: self.request.requestID)
            }
        }
        func revoke() throws {
            try journal.withRequests { owner in
                let revision = try owner.database.read { try $0.approvalTrustSnapshot().revision }
                _ = try owner.database.write { try $0.revokeApprovalEnrollment(phoneID: Self.id(5), epoch: Self.id(9),
                    expectedTrustRevision: revision, eventID: Self.id(31), receiptTimeMs: nil, writer: self.writer, expectedAuditHead: 2) }
            }
        }
    }

    private final class ReceivePort: Sendable { let value = Mutex<mach_port_t>(0) }
    private func commandWorker(_ fixture: Fixture, port: ReceivePort,
                               policyRead: @escaping @Sendable () throws -> Void = {},
                               report: @escaping @Sendable (AuthorityCommandReceiveWorker.Status) -> Void = { _ in }) throws -> AuthorityCommandReceiveWorker {
        let journal = fixture.journal, epoch = fixture.epoch
        let context = CommandSessionRegistry.Context(expression: "always", roleRevision: UUID())
        return try AuthorityCommandReceiveWorker(ownedJournal: journal,
            submissionLimits: CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 256), makeHost: {
                var receiver: mach_port_t = 0
                guard mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &receiver) == KERN_SUCCESS else {
                    throw CommandReceiveHostError.invalidConfiguration
                }
                let host = try CommandReceiveHost(takingReceiveRight: receiver, macID: Fixture.id(1), accountID: Fixture.id(2),
                    userID: geteuid(), auditSessionID: nil, maximumSessions: 4, maximumPayloadBytes: 8192,
                    receiveWaitMilliseconds: 10, replyTimeoutMilliseconds: 100, context: { _ in
                        try policyRead(); return context
                    })
                port.value.withLock { $0 = receiver }; return host
            }, resolve: { _ in .refuse(.policyRejected) }, draft: { _ in throw ApprovalCoordinatorError.invalidDraft },
            clock: { .init(epoch: epoch, milliseconds: 110) }, report: report)
    }
    private static func hasReceiveRight(_ port: mach_port_t) -> Bool {
        var type: mach_port_type_t = 0
        return mach_port_type(mach_task_self_, port, &type) == KERN_SUCCESS &&
            (type & (UInt32(1) << (MACH_PORT_RIGHT_RECEIVE + 16))) != 0
    }
    func testCommandReceiverDrainsBeforeServiceClosesSharedJournal() async throws {
        let f = try Fixture(), port = ReceivePort(), block = Mutex(false), entered = Mutex(false), closes = Mutex(0)
        let gate = DispatchSemaphore(value: 0), journal = f.journal
        let worker = try commandWorker(f, port: port, policyRead: {
            if block.withLock({ $0 }) { entered.withLock { $0 = true }; gate.wait() }
            XCTAssertEqual(try journal.read { _ in 17 }, 17)
        })
        let service = try AuthorityWakeService(makePublisher: { try f.publisher(Driver()) },
            hints: AuthorityWakeHintSource(registration: f.registration), interval: 100, startRequests: {}, closeRequests: {
                XCTAssertEqual(worker.status, .closed)
                XCTAssertFalse(Self.hasReceiveRight(port.value.withLock { $0 }))
                closes.withLock { $0 += 1 }; try journal.close()
            }, commandReceiver: worker)
        defer { gate.signal(); worker.requestStop() }
        try await service.start(); block.withLock { $0 = true }
        try await waitUntil { entered.withLock { $0 } }
        let close = Task { try await service.close() }
        try await waitUntil { await service.wakeStatus == .closed }
        XCTAssertEqual(closes.withLock { $0 }, 0)
        XCTAssertTrue(Self.hasReceiveRight(port.value.withLock { $0 }))
        gate.signal(); try await close.value
        XCTAssertEqual(closes.withLock { $0 }, 1)
    }
    func testServiceCloseDuringReceiverReadinessCannotStartLatePublisher() async throws {
        let f = try Fixture(), port = ReceivePort(), entered = Mutex(false), publishers = Mutex(0), closes = Mutex(0)
        let gate = DispatchSemaphore(value: 0)
        let worker = try commandWorker(f, port: port, report: {
            if $0 == .running { entered.withLock { $0 = true }; gate.wait() }
        })
        let service = try AuthorityWakeService(makePublisher: {
            publishers.withLock { $0 += 1 }; return try f.publisher(Driver())
        }, hints: AuthorityWakeHintSource(registration: f.registration), interval: 100, startRequests: {}, closeRequests: {
            XCTAssertEqual(worker.status, .closed)
            XCTAssertFalse(Self.hasReceiveRight(port.value.withLock { $0 }))
            closes.withLock { $0 += 1 }; try f.journal.close()
        }, commandReceiver: worker)
        let start = Task { try await service.start() }
        defer { start.cancel(); gate.signal(); worker.requestStop() }
        try await waitUntil { entered.withLock { $0 } }
        let close = Task { try await service.close() }
        try await waitUntil { await service.wakeStatus == .closed }
        XCTAssertEqual(closes.withLock { $0 }, 0)
        gate.signal()
        do { try await start.value; XCTFail("Closed service completed startup") }
        catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .closed) }
        try await close.value
        XCTAssertEqual(publishers.withLock { $0 }, 0); XCTAssertEqual(closes.withLock { $0 }, 1)
    }
    func testServiceDeinitDrainsReceiverObserverWithoutRetainingService() async throws {
        let f = try Fixture(deadline: 5000), port = ReceivePort(), closes = Mutex(0)
        let worker = try commandWorker(f, port: port)
        let driver = Driver(); driver.value.withLock { $0.failHello = true }
        var service: AuthorityWakeService? = try AuthorityWakeService(makePublisher: { try f.publisher(driver) },
            hints: AuthorityWakeHintSource(registration: f.registration), interval: 100,
            initialRetryMilliseconds: 30_000, maximumRetryMilliseconds: 30_000, startRequests: {}, closeRequests: {
                XCTAssertEqual(worker.status, .closed)
                XCTAssertFalse(Self.hasReceiveRight(port.value.withLock { $0 }))
                closes.withLock { $0 += 1 }; try f.journal.close()
            }, commandReceiver: worker)
        weak let reference = service
        try await XCTUnwrap(service).start()
        try await waitUntil { await reference?.wakeStatus == .waiting(retryMilliseconds: 30_000) }
        service = nil
        XCTAssertNil(reference)
        try await waitUntil { closes.withLock { $0 == 1 } }
        XCTAssertFalse(worker.isRetired)
    }
    func testCommandPolicyRetirementInterruptsLongGatewayBackoff() async throws {
        let f = try Fixture(deadline: 5000), port = ReceivePort(), failed = Mutex(false), closes = Mutex(0)
        let worker = try commandWorker(f, port: port, policyRead: {
            if failed.withLock({ $0 }) { throw CommandSessionRegistryError.invalidCodePolicy }
        })
        let driver = Driver(); driver.value.withLock { $0.failHello = true }
        let service = try AuthorityWakeService(makePublisher: { try f.publisher(driver) },
            hints: AuthorityWakeHintSource(registration: f.registration), interval: 100,
            initialRetryMilliseconds: 30_000, maximumRetryMilliseconds: 30_000, startRequests: {}, closeRequests: {
                closes.withLock { $0 += 1 }; try f.journal.close()
            }, commandReceiver: worker)
        try await service.start()
        try await waitUntil { await service.wakeStatus == .waiting(retryMilliseconds: 30_000) }
        failed.withLock { $0 = true }
        do { try await waitUntil { closes.withLock { $0 == 1 } } }
        catch { try await service.close(); throw error }
        try await service.close()
        let retired = await service.isRetired
        XCTAssertTrue(retired); XCTAssertTrue(worker.isRetired)
    }
    func testCommandPolicyRetirementInterruptsLongPublicationSleep() async throws {
        let f = try Fixture(deadline: 5000), port = ReceivePort(), failed = Mutex(false), closes = Mutex(0)
        let worker = try commandWorker(f, port: port, policyRead: {
            if failed.withLock({ $0 }) { throw CommandSessionRegistryError.invalidCodePolicy }
        })
        let driver = Driver()
        let service = try AuthorityWakeService(makePublisher: { try f.publisher(driver, lease: 60_000) },
            hints: AuthorityWakeHintSource(registration: f.registration), interval: 30_000, startRequests: {}, closeRequests: {
                closes.withLock { $0 += 1 }; try f.journal.close()
            }, commandReceiver: worker)
        try await service.start()
        try await waitUntil { driver.value.withLock { $0.snapshots.count >= 4 } }
        failed.withLock { $0 = true }
        do { try await waitUntil { closes.withLock { $0 == 1 } } }
        catch { try await service.close(); throw error }
        try await service.close()
        let retired = await service.isRetired
        XCTAssertTrue(retired); XCTAssertTrue(worker.isRetired)
    }
    func testCommandRetirementDuringGatewayHelloPreventsInitialPublication() async throws {
        let f = try Fixture(deadline: 5000), port = ReceivePort(), failed = Mutex(false), closes = Mutex(0)
        let worker = try commandWorker(f, port: port, policyRead: {
            if failed.withLock({ $0 }) { throw CommandSessionRegistryError.invalidCodePolicy }
        })
        let driver = Driver(); driver.value.withLock { $0.holdHello = true }
        let service = try AuthorityWakeService(makePublisher: { try f.publisher(driver) },
            hints: AuthorityWakeHintSource(registration: f.registration), interval: 100, startRequests: {}, closeRequests: {
                closes.withLock { $0 += 1 }; try f.journal.close()
            }, commandReceiver: worker)
        try await service.start()
        try await waitUntil { driver.value.withLock { $0.heldHello != nil } }
        failed.withLock { $0 = true }
        try await waitUntil { worker.isRetired }
        let hello = try XCTUnwrap(driver.value.withLock { $0.heldHello })
        hello(.version(3))
        try await waitUntil { await service.wakeStatus == .closed }
        try await service.close()
        XCTAssertTrue(driver.value.withLock { $0.snapshots.isEmpty })
        XCTAssertTrue(driver.value.withLock { $0.registrations.isEmpty })
        XCTAssertEqual(closes.withLock { $0 }, 1)
    }
    func testCommandPolicyRetirementClosesServiceWithHealthyGateway() async throws {
        let f = try Fixture(deadline: 5000), port = ReceivePort(), failed = Mutex(false), closes = Mutex(0)
        let worker = try commandWorker(f, port: port, policyRead: {
            if failed.withLock({ $0 }) { throw CommandSessionRegistryError.invalidCodePolicy }
        })
        let service = try AuthorityWakeService(makePublisher: { try f.publisher(Driver()) },
            hints: AuthorityWakeHintSource(registration: f.registration), interval: 100, startRequests: {}, closeRequests: {
                XCTAssertEqual(worker.status, .closed)
                XCTAssertFalse(Self.hasReceiveRight(port.value.withLock { $0 }))
                closes.withLock { $0 += 1 }; try f.journal.close()
            }, commandReceiver: worker)
        try await service.start()
        try await waitUntil { await service.wakeStatus == .running }
        failed.withLock { $0 = true }
        do { try await waitUntil { await service.wakeStatus == .closed } }
        catch { try await service.close(); throw error }
        try await service.close()
        XCTAssertTrue(worker.isRetired); XCTAssertEqual(closes.withLock { $0 }, 1)
    }
    func testCommandPolicyRetirementClosesServiceWhileGatewayIsUnavailable() async throws {
        let f = try Fixture(), port = ReceivePort(), failed = Mutex(false), publishers = Mutex(0), closes = Mutex(0)
        let worker = try commandWorker(f, port: port, policyRead: {
            if failed.withLock({ $0 }) { throw CommandSessionRegistryError.invalidCodePolicy }
        })
        let driver = Driver(); driver.value.withLock { $0.failHello = true }
        let service = try AuthorityWakeService(makePublisher: {
            publishers.withLock { $0 += 1 }; return try f.publisher(driver)
        }, hints: AuthorityWakeHintSource(registration: f.registration), interval: 100,
        initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, startRequests: {}, closeRequests: {
            XCTAssertEqual(worker.status, .closed)
            XCTAssertFalse(Self.hasReceiveRight(port.value.withLock { $0 }))
            closes.withLock { $0 += 1 }; try f.journal.close()
        }, commandReceiver: worker)
        try await service.start()
        try await waitUntil { publishers.withLock { $0 >= 2 } }
        try await waitUntil { await service.wakeStatus == .waiting(retryMilliseconds: 100) }
        failed.withLock { $0 = true }
        try await waitUntil { await service.wakeStatus == .closed }
        try await service.close()
        let retired = await service.isRetired
        XCTAssertTrue(retired); XCTAssertTrue(worker.isRetired)
        let attemptsAfterClose = publishers.withLock { $0 }
        XCTAssertGreaterThanOrEqual(attemptsAfterClose, 2)
        XCTAssertEqual(closes.withLock { $0 }, 1, "Request cleanup must complete exactly once")
        try await Task.sleep(for: .milliseconds(150))
        XCTAssertEqual(publishers.withLock { $0 }, attemptsAfterClose, "Retirement must stop gateway attempts")
        XCTAssertEqual(closes.withLock { $0 }, 1, "A later retry interval must not repeat request cleanup")
    }

    func testAccountPresenceModeChangesReachPublisherAndLiveHintFeed() async throws {
        let f = try Fixture(enablePresence: true), driver = Driver()
        let presence = AuthorityPresenceRuntime(configuration: try .init(macID: f.registration.macID, accountID: f.registration.accountID,
            ownerUID: 501, policy: .init(observationLifetimeMilliseconds: 50, unavailableGraceMilliseconds: 0)), clockEpoch: f.epoch)
        let at = PresenceMoment(epoch: f.epoch, milliseconds: 100)
        try presence.publish(.init(remoteWorkspace: .init(.usable, observedAt: at)), observer: UUID(),
            sampledAt: .init(epoch: f.epoch, milliseconds: 100), now: f.now())
        let publisher = try AuthorityWakePublisher(journal: f.journal, channel: GatewayRootChannel(driver: driver), registration: f.registration,
            leaseMilliseconds: 1000, clock: { f.now() }, routing: { XCTFail("Account wake used a separate mode cache"); return try f.routing() },
            ownerRouting: { owner, moment in try presence.routing(owner: owner, now: moment) })
        try await publisher.start(); try await publisher.reconcile()
        XCTAssertTrue(driver.value.withLock { $0.registrations.isEmpty })
        XCTAssertEqual(driver.value.withLock { $0.snapshots.last?.phoneRouting }, false)
        _ = try f.journal.withRequests { try $0.setLocalRoutingMode(.away, expectedRevision: 0, now: f.now(), receiptTimeMs: nil) }
        try await publisher.reconcile()
        let grant = try XCTUnwrap(driver.value.withLock { $0.registrations.first })
        XCTAssertEqual(try publisher.hintFeed.current().deliveryIDs, [grant.id])
        _ = try f.journal.withRequests { try $0.setLocalRoutingMode(.present, expectedRevision: 1, now: f.now(), receiptTimeMs: nil) }
        // The feed consults the current durable mode before the next publisher tick.
        XCTAssertTrue(try publisher.hintFeed.current().deliveryIDs.isEmpty)
        try await publisher.reconcile()
        XCTAssertEqual(driver.value.withLock { $0.snapshots.last?.phoneRouting }, false)
        _ = try f.journal.withRequests { try $0.setLocalRoutingMode(.automatic, expectedRevision: 2, now: f.now(), receiptTimeMs: nil) }
        XCTAssertTrue(try publisher.hintFeed.current().deliveryIDs.isEmpty)
        f.state.withLock { $0.time = 150 }
        XCTAssertTrue(try publisher.hintFeed.current().deliveryIDs.isEmpty)
        try await publisher.reconcile()
        XCTAssertEqual(try publisher.hintFeed.current().deliveryIDs, [grant.id])
        XCTAssertEqual(driver.value.withLock { $0.registrations.count }, 1)
        XCTAssertEqual(grant.deadlineMilliseconds, 200)
        await publisher.close(); presence.close()
    }

    func testRegisteredGrantUsesCurrentJournalLeaseAndIsNotRegisteredAgain() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        try await publisher.start(); try await publisher.reconcile()
        let grant = try XCTUnwrap(driver.value.withLock { $0.registrations.first })
        let hints = try await publisher.readyDeliveryIDs()
        XCTAssertEqual(hints, [grant.id]); XCTAssertEqual(grant.requestID, fixture.request.requestID)
        XCTAssertEqual(grant.deadlineMilliseconds, 200)
        XCTAssertEqual(grant.admittedAt.epoch, fixture.epoch)
        try await publisher.reconcile()
        XCTAssertEqual(driver.value.withLock { $0.registrations }, [grant])
        let snapshots = driver.value.withLock { $0.snapshots }
        XCTAssertEqual(snapshots.map(\.sequence), [1, 2, 3, 4])
        XCTAssertTrue(snapshots.allSatisfy { $0.phoneRouting && $0.registration == fixture.registration })
        XCTAssertEqual(snapshots.last?.enrollments.first?.phoneID, Fixture.id(5))
        await publisher.close()
    }
    func testRejectedRegistrationRetriesOriginalGrantWithoutRenewingRequest() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        driver.value.withLock { $0.rejectRegistrations = 1 }
        try await publisher.start(); try await publisher.reconcile()
        let before = try await publisher.readyDeliveryIDs(); XCTAssertTrue(before.isEmpty)
        fixture.state.withLock { $0.time = 150 }
        try await publisher.reconcile()
        let registrations = driver.value.withLock { $0.registrations }
        XCTAssertEqual(registrations.count, 2); XCTAssertEqual(registrations[0], registrations[1])
        XCTAssertEqual(registrations[1].deadlineMilliseconds, 200)
        let after = try await publisher.readyDeliveryIDs(); XCTAssertEqual(after, [registrations[0].id])
        await publisher.close()
    }
    func testCancellationOrUnenrollmentDuringAcknowledgmentWithdrawsBeforeHint() async throws {
        for revoke in [false, true] {
            let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
            driver.value.withLock { $0.onRegistration = { if revoke { try fixture.revoke() } else { try fixture.cancelAndForget() } } }
            try await publisher.start(); try await publisher.reconcile()
            let grant = try XCTUnwrap(driver.value.withLock { $0.registrations.first })
            XCTAssertEqual(driver.value.withLock { $0.withdrawals }, [grant.id])
            let hints = try await publisher.readyDeliveryIDs(); XCTAssertTrue(hints.isEmpty)
            XCTAssertTrue(try fixture.journal.withRequests {
                try $0.reconcileWakePublications(routing: fixture.routing(), now: fixture.now(), receiptTimeMs: nil).withdrawals.isEmpty
            })
            await publisher.close()
        }
    }
    func testExpiryDuringAcknowledgmentWithdrawsOriginalGrant() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        driver.value.withLock { $0.onRegistration = { fixture.state.withLock { $0.time = 200 } } }
        try await publisher.start(); try await publisher.reconcile()
        let grant = try XCTUnwrap(driver.value.withLock { $0.registrations.first })
        XCTAssertEqual(driver.value.withLock { $0.withdrawals }, [grant.id])
        let hints = try await publisher.readyDeliveryIDs(); XCTAssertTrue(hints.isEmpty)
        XCTAssertEqual(try fixture.journal.withRequests { try $0.state(requestID: fixture.request.requestID).phase }, .expired)
        await publisher.close()
    }
    func testPresenceDuringAcknowledgmentSuppressesHintsAndSynchronizesGateway() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        driver.value.withLock { $0.onRegistration = { fixture.state.withLock { $0.mode = .present } } }
        try await publisher.start(); try await publisher.reconcile()
        let hints = try await publisher.readyDeliveryIDs(); XCTAssertTrue(hints.isEmpty)
        XCTAssertEqual(driver.value.withLock { $0.snapshots.last?.phoneRouting }, false)
        driver.value.withLock { $0.onRegistration = nil }
        fixture.state.withLock { $0.mode = .away; $0.time = 150 }
        // The changed route is not advertised until the gateway acknowledges it.
        let before = try await publisher.readyDeliveryIDs(); XCTAssertTrue(before.isEmpty)
        try await publisher.reconcile()
        let grant = try XCTUnwrap(driver.value.withLock { $0.registrations.first })
        let after = try await publisher.readyDeliveryIDs(); XCTAssertEqual(after, [grant.id])
        XCTAssertEqual(driver.value.withLock { $0.registrations.count }, 1)
        await publisher.close()
    }
    func testLeaseExpiryDuringAcknowledgmentRetiresWakeOnly() async throws {
        let fixture = try Fixture(deadline: 5000), driver = Driver(), publisher = try fixture.publisher(driver)
        driver.value.withLock { $0.onRegistration = { fixture.state.withLock { $0.time = 1110 } } }
        try await publisher.start()
        do { try await publisher.reconcile(); XCTFail("An expired lease published a hint") }
        catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .expiredLease) }
        do { _ = try await publisher.readyDeliveryIDs(); XCTFail("A closed publisher exposed a hint") }
        catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .closed) }
        XCTAssertEqual(driver.value.withLock { $0.closed }, 1)
        XCTAssertEqual(try fixture.journal.withRequests { try $0.state(requestID: fixture.request.requestID).phase }, .queued)
        let retained = try fixture.journal.withRequests {
            try $0.reconcileWakePublications(routing: fixture.routing(), now: fixture.now(), receiptTimeMs: nil)
        }
        XCTAssertEqual(retained.registrations.count, 1)
        XCTAssertTrue(retained.readyDeliveryIDs.isEmpty)
    }
    func testClosingDuringRegistrationRejectsLateAcknowledgmentAndConcurrentDrain() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        driver.value.withLock { $0.holdRegistration = true }
        try await publisher.start()
        let drain = Task { try await publisher.reconcile() }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while driver.value.withLock({ $0.held == nil }) && ContinuousClock.now < deadline { await Task.yield() }
        let reply = try XCTUnwrap(driver.value.withLock { $0.held })
        do { try await publisher.reconcile(); XCTFail("Concurrent drain") }
        catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .busy) }
        await publisher.close()
        reply(.command(try GatewayRootCommand.reply([.boolean(true)], version: 3)))
        do { try await drain.value; XCTFail("Closed drain resumed") } catch {}
        do { _ = try await publisher.readyDeliveryIDs(); XCTFail("Late hint") } catch {}
        XCTAssertEqual(driver.value.withLock { $0.registrations.count }, 1)
        XCTAssertEqual(driver.value.withLock { $0.snapshots.count }, 1)
        XCTAssertEqual(driver.value.withLock { $0.closed }, 1)
    }
    func testClosedJournalCannotExposePreviouslyRegisteredHint() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        try await publisher.start(); try await publisher.reconcile()
        try fixture.journal.close()
        do { _ = try await publisher.readyDeliveryIDs(); XCTFail("Closed journal returned a grant") } catch {}
        await publisher.close()
    }
    func testPublisherFeedComposesWithNegotiatedRootEndpointAndReflectsTerminalForget() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        try await publisher.start(); try await publisher.reconcile()
        let feed = publisher.hintFeed, binding = feed.binding
        let trust = DirectApprovalTrust(macID: binding.macID, accountID: binding.accountID, revision: UUID(), peers: [])
        let endpoint = try AuthorityXPCEndpoint(macID: binding.macID, accountID: binding.accountID, budget: AuthorityXPCWorkBudget(),
            verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in false }, wakeHints: { try feed.current() })
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.requestWakeVersion { XCTAssertEqual($0, 1) }
        let response = Mutex<Data?>(nil)
        endpoint.wakeDeliveryHints { bytes in response.withLock { $0 = bytes } }
        let bytes = try XCTUnwrap(response.withLock { $0 })
        let hint = try AuthorityWakeHints.decode(bytes, expectedBinding: binding)
        XCTAssertEqual(hint.deliveryIDs, driver.value.withLock { $0.registrations.map(\.id) })
        try fixture.cancelAndForget()
        endpoint.wakeDeliveryHints { bytes in response.withLock { $0 = bytes } }
        let terminal = try AuthorityWakeHints.decode(XCTUnwrap(response.withLock { $0 }), expectedBinding: binding)
        XCTAssertTrue(terminal.deliveryIDs.isEmpty)
        try await publisher.reconcile()
        XCTAssertEqual(driver.value.withLock { $0.withdrawals }, hint.deliveryIDs)
        await publisher.close()
        endpoint.wakeDeliveryHints { XCTAssertNil($0) }
    }
    func testServiceShutdownCancelsRunningRegistrationBeforeClosingRequestJournal() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        driver.value.withLock { $0.holdRegistration = true }
        let starts = Mutex(0), closes = Mutex(0), feed = publisher.hintFeed
        let hints = try AuthorityWakeHintSource(registration: fixture.registration)
        let service = try AuthorityWakeService(makePublisher: { publisher }, hints: hints, interval: 100, startRequests: { starts.withLock { $0 += 1 } }, closeRequests: {
            XCTAssertThrowsError(try feed.current())
            closes.withLock { $0 += 1 }
            try fixture.journal.close()
        })
        try await service.start()
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while driver.value.withLock({ $0.held == nil }), ContinuousClock.now < deadline { await Task.yield() }
        XCTAssertNotNil(driver.value.withLock { $0.held })
        async let firstClose: Void = service.close()
        async let secondClose: Void = service.close()
        _ = try await (firstClose, secondClose)
        XCTAssertEqual(starts.withLock { $0 }, 1); XCTAssertEqual(closes.withLock { $0 }, 1)
        XCTAssertEqual(driver.value.withLock { $0.closed }, 1)
    }
    private func waitUntil(_ condition: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { throw GatewayRootChannelError.timedOut }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    func testReplacementPublisherKeepsGrantAndRejectsOldSessionOwnership() async throws {
        let f = try Fixture(deadline: 5000), first = Driver(), second = Driver()
        let old = try f.publisher(first), replacement = try f.publisher(second)
        try await old.start(); try await old.reconcile()
        let original = try XCTUnwrap(first.value.withLock { $0.registrations.first })
        do { try await replacement.start(); XCTFail("Overlapping publisher") } catch {}
        XCTAssertEqual(try old.hintFeed.current().deliveryIDs, [original.id])
        await old.close()
        let next = try f.publisher(second)
        try await next.start(); try await next.reconcile()
        XCTAssertEqual(second.value.withLock { $0.registrations }, [original])
        await old.close()
        XCTAssertEqual(try next.hintFeed.current().deliveryIDs, [original.id])
        await next.close()
    }
    func testUnavailableGatewayAndReconnectLeaveDirectRequestsRunning() async throws {
        let f = try Fixture(deadline: 5000), first = Driver(), second = Driver(), third = Driver()
        first.value.withLock { $0.failHello = true }
        let attempts = Mutex(0), starts = Mutex(0), closes = Mutex(0)
        let hints = try AuthorityWakeHintSource(registration: f.registration)
        let service = try AuthorityWakeService(makePublisher: {
            let number = attempts.withLock { $0 += 1; return $0 }
            return try f.publisher(number == 1 ? first : number == 2 ? second : third)
        }, hints: hints, interval: 100, initialRetryMilliseconds: 100, maximumRetryMilliseconds: 200,
        startRequests: { starts.withLock { $0 += 1 } }, closeRequests: { closes.withLock { $0 += 1 }; try f.journal.close() })
        try await service.start()
        XCTAssertEqual(starts.withLock { $0 }, 1)
        try await waitUntil { await service.wakeStatus == .waiting(retryMilliseconds: 100) }
        XCTAssertEqual(closes.withLock { $0 }, 0)
        XCTAssertTrue(try hints.current().deliveryIDs.isEmpty)
        XCTAssertEqual(try f.journal.withRequests { try $0.state(requestID: f.request.requestID).phase }, .queued)
        try await waitUntil { await service.wakeStatus == .running }
        let original = try XCTUnwrap(second.value.withLock { $0.registrations.first })
        try await waitUntil { (try? hints.current().deliveryIDs) == [original.id] }
        second.value.withLock { $0.lost }?()
        try await waitUntil {
            let status = await service.wakeStatus
            return attempts.withLock { $0 } >= 3 && status == .running
        }
        XCTAssertEqual(third.value.withLock { $0.registrations }, [original])
        try await waitUntil { (try? hints.current().deliveryIDs) == [original.id] }
        XCTAssertEqual(starts.withLock { $0 }, 1); XCTAssertEqual(closes.withLock { $0 }, 0)
        let retired = await service.isRetired; XCTAssertFalse(retired)
        try await service.close()
        XCTAssertEqual(closes.withLock { $0 }, 1)
        XCTAssertThrowsError(try hints.current())
    }
    func testDisconnectedTerminalRequestKeepsWithdrawalAcrossReplacement() async throws {
        let f = try Fixture(deadline: 5000), first = Driver(), second = Driver()
        let old = try f.publisher(first)
        try await old.start(); try await old.reconcile()
        let original = try XCTUnwrap(first.value.withLock { $0.registrations.first })
        await old.close(); try f.cancelAndForget()
        let next = try f.publisher(second)
        try await next.start(); try await next.reconcile()
        XCTAssertEqual(second.value.withLock { $0.withdrawals }, [original.id])
        XCTAssertTrue(second.value.withLock { $0.registrations.isEmpty })
        XCTAssertTrue(try next.hintFeed.current().deliveryIDs.isEmpty)
        await next.close()
    }
    func testFailedRequestShutdownRetainsCleanupForRetry() async throws {
        let f = try Fixture(), attempts = Mutex(0), hints = try AuthorityWakeHintSource(registration: f.registration)
        let service = try AuthorityWakeService(makePublisher: { try f.publisher(Driver()) }, hints: hints, interval: 100,
            startRequests: {}, closeRequests: {
                let attempt = attempts.withLock { $0 += 1; return $0 }
                if attempt == 1 { throw JournalLeaseError.busy }
                try f.journal.close()
            })
        try await service.start()
        do { try await service.close(); XCTFail("Failed cleanup was hidden") }
        catch { XCTAssertEqual(error as? JournalLeaseError, .busy) }
        XCTAssertThrowsError(try hints.current())
        try await service.close(); try await service.close()
        XCTAssertEqual(attempts.withLock { $0 }, 2)
    }
    func testStorageRetirementClosesDirectRequestsWithoutGatewayRetry() async throws {
        let f = try Fixture(), attempts = Mutex(0), closes = Mutex(0), retirement = Mutex(false)
        let hints = try AuthorityWakeHintSource(registration: f.registration)
        let service = try AuthorityWakeService(makePublisher: { attempts.withLock { $0 += 1 }; return try f.publisher(Driver()) },
            hints: hints, interval: 100, startRequests: {}, closeRequests: { closes.withLock { $0 += 1 }; try f.journal.close() },
            requestsRetired: { retirement.withLock { $0 } })
        retirement.withLock { $0 = true }
        try await service.start()
        try await waitUntil { await service.isRetired }
        try await service.close()
        XCTAssertEqual(attempts.withLock { $0 }, 0); XCTAssertEqual(closes.withLock { $0 }, 1)
    }

    func testLateAcknowledgmentCannotAffectReplacementPublisherOrHintSource() async throws {
        let f = try Fixture(deadline: 5000), first = Driver(), second = Driver()
        first.value.withLock { $0.holdRegistration = true }
        let old = try f.publisher(first), next = try f.publisher(second)
        let hints = try AuthorityWakeHintSource(registration: f.registration)
        try await old.start(); try hints.install(old.hintFeed)
        let drain = Task { try await old.reconcile() }
        try await waitUntil { first.value.withLock { $0.held != nil } }
        let reply = try XCTUnwrap(first.value.withLock { $0.held })
        let original = try XCTUnwrap(first.value.withLock { $0.registrations.first })
        hints.clear(old.hintFeed); await old.close()
        XCTAssertTrue(try hints.current().deliveryIDs.isEmpty)
        try await next.start(); try await next.reconcile(); try hints.install(next.hintFeed)
        reply(.command(try GatewayRootCommand.reply([.boolean(true)], version: 3)))
        do { try await drain.value; XCTFail("Old acknowledgment accepted") } catch {}
        hints.clear(old.hintFeed)
        XCTAssertEqual(try hints.current().deliveryIDs, [original.id])
        XCTAssertEqual(second.value.withLock { $0.registrations }, [original])
        await next.close(); hints.close()
    }
    func testRequestExpiredWhileDisconnectedCannotRegainWakeGrant() async throws {
        let f = try Fixture(deadline: 200), first = Driver(), second = Driver()
        let old = try f.publisher(first)
        try await old.start(); try await old.reconcile()
        let original = try XCTUnwrap(first.value.withLock { $0.registrations.first })
        await old.close(); f.state.withLock { $0.time = 201 }
        let next = try f.publisher(second)
        try await next.start(); try await next.reconcile()
        XCTAssertEqual(second.value.withLock { $0.withdrawals }, [original.id])
        XCTAssertTrue(second.value.withLock { $0.registrations.isEmpty })
        XCTAssertTrue(try next.hintFeed.current().deliveryIDs.isEmpty)
        XCTAssertEqual(try f.journal.withRequests { try $0.state(requestID: f.request.requestID).phase }, .expired)
        await next.close()
    }

    func testShutdownDuringBackoffPreventsAnotherConnectionAttempt() async throws {
        let f = try Fixture(), attempts = Mutex(0), closes = Mutex(0)
        let hints = try AuthorityWakeHintSource(registration: f.registration)
        let service = try AuthorityWakeService(makePublisher: {
            attempts.withLock { $0 += 1 }
            let driver = Driver(); driver.value.withLock { $0.failHello = true }
            return try f.publisher(driver)
        }, hints: hints, interval: 100, initialRetryMilliseconds: 100, maximumRetryMilliseconds: 200,
        startRequests: {}, closeRequests: { closes.withLock { $0 += 1 }; try f.journal.close() })
        try await service.start()
        try await waitUntil { await service.wakeStatus == .waiting(retryMilliseconds: 100) }
        let count = attempts.withLock { $0 }
        try await service.close()
        try await Task.sleep(for: .milliseconds(220))
        XCTAssertEqual(attempts.withLock { $0 }, count)
        XCTAssertEqual(closes.withLock { $0 }, 1)
    }

    func testInvalidAuthorityClockRetiresRequestsRatherThanRetryingGateway() async throws {
        let f = try Fixture(), attempts = Mutex(0), closes = Mutex(0)
        let hints = try AuthorityWakeHintSource(registration: f.registration)
        let service = try AuthorityWakeService(makePublisher: {
            attempts.withLock { $0 += 1 }; throw AuthorityWakePublisherError.invalidClock
        }, hints: hints, interval: 100, initialRetryMilliseconds: 100, maximumRetryMilliseconds: 200,
        startRequests: {}, closeRequests: { closes.withLock { $0 += 1 }; try f.journal.close() })
        try await service.start()
        try await waitUntil { await service.isRetired }
        try await service.close()
        XCTAssertEqual(attempts.withLock { $0 }, 1); XCTAssertEqual(closes.withLock { $0 }, 1)
        XCTAssertThrowsError(try hints.current())
    }

}

extension AuthorityWakePublisherTests {
    private func schedulingNotice(_ fixture: Fixture, replacementID: Data? = nil) throws -> AuthorityCommandAuthorizationNotice {
        let original = try fixture.journal.withRequests { try $0.state(requestID: fixture.request.requestID) }
        return .init(state: .init(requestKind: .command, macID: original.macID, accountID: original.accountID,
            requestDigest: original.requestDigest, challenge: original.challenge, reason: .none, terminalAt: nil,
            decisionPhoneID: nil, requestID: replacementID ?? original.requestID, phase: original.phase,
            revision: original.revision, firstObservedAt: original.firstObservedAt, deadlineMilliseconds: original.deadlineMilliseconds))
    }

    func testServiceStartsExecutorBeforeRequestsAndJoinsQueuedWorkBeforeJournalClose() async throws {
        let fixture = try Fixture(deadline: 5000), journal = fixture.journal, notice = try schedulingNotice(fixture)
        let gate = DispatchSemaphore(value: 0), entered = Mutex(false), rejections = Mutex(0), closes = Mutex(0)
        let worker = try AuthorityCommandExecutionWorker(begin: { _, check in
            entered.withLock { $0 = true }
            guard gate.wait(timeout: .now() + 5) == .success else { throw AuthorityCommandExecutionWorkerError.closed }
            XCTAssertEqual(try journal.read { _ in 17 }, 17)
            try check()
        }, rejectUnowned: { _ in
            XCTAssertEqual(try journal.read { _ in 19 }, 19); rejections.withLock { $0 += 1 }
        })
        let service = try AuthorityWakeService(makePublisher: { try fixture.publisher(Driver()) },
            hints: AuthorityWakeHintSource(registration: fixture.registration), interval: 100,
            startRequests: { XCTAssertEqual(worker.enqueue(notice), .queued) }, closeRequests: {
                XCTAssertEqual(worker.enqueue(notice), .closed)
                XCTAssertEqual(rejections.withLock { $0 }, 2); closes.withLock { $0 += 1 }; try journal.close()
            }, commandExecutionWorker: worker)
        defer { gate.signal(); worker.requestStop() }
        try await service.start(); try await waitUntil { entered.withLock { $0 } }
        let close = Task { try await service.close() }
        try await waitUntil { await service.wakeStatus == .closed }
        XCTAssertEqual(closes.withLock { $0 }, 0)
        gate.signal(); try await close.value
        XCTAssertEqual(closes.withLock { $0 }, 1)
    }

    func testExecutorSaturationRetiresItsEnclosingServiceWithoutAbandoningQueuedCleanup() async throws {
        let fixture = try Fixture(deadline: 5000), notice = try schedulingNotice(fixture)
        let overflow = try schedulingNotice(fixture, replacementID: Data(repeating: 0xff, count: 16))
        let gate = DispatchSemaphore(value: 0), entered = Mutex(false), closes = Mutex(0), rejected = Mutex(0)
        let worker = try AuthorityCommandExecutionWorker(maximumPending: 1, begin: { _, check in
            entered.withLock { $0 = true }
            guard gate.wait(timeout: .now() + 5) == .success else { throw AuthorityCommandExecutionWorkerError.closed }
            try check()
        }, rejectUnowned: { _ in rejected.withLock { $0 += 1 } })
        let service = try AuthorityWakeService(makePublisher: { try fixture.publisher(Driver()) },
            hints: AuthorityWakeHintSource(registration: fixture.registration), interval: 100, startRequests: {}, closeRequests: {
                XCTAssertEqual(rejected.withLock { $0 }, 2); closes.withLock { $0 += 1 }; try fixture.journal.close()
            }, commandExecutionWorker: worker)
        defer { gate.signal(); worker.requestStop() }
        try await service.start(); XCTAssertEqual(worker.enqueue(notice), .queued)
        try await waitUntil { entered.withLock { $0 } }
        XCTAssertEqual(worker.enqueue(overflow), .capacity)
        try await waitUntil { await service.isRetired }
        try await waitUntil { await service.wakeStatus == .closed }
        XCTAssertEqual(closes.withLock { $0 }, 0)
        gate.signal(); try await service.close()
        XCTAssertEqual(closes.withLock { $0 }, 1)
    }

    func testServiceDeinitJoinsExecutorBeforeClosingTheSharedJournal() async throws {
        let fixture = try Fixture(deadline: 5000), notice = try schedulingNotice(fixture)
        let gate = DispatchSemaphore(value: 0), entered = Mutex(false), closes = Mutex(0)
        let worker = try AuthorityCommandExecutionWorker(begin: { _, check in
            entered.withLock { $0 = true }
            guard gate.wait(timeout: .now() + 5) == .success else { throw AuthorityCommandExecutionWorkerError.closed }
            try check()
        }, rejectUnowned: { _ in XCTAssertEqual(try fixture.journal.read { _ in 23 }, 23) })
        var service: AuthorityWakeService? = try AuthorityWakeService(makePublisher: { try fixture.publisher(Driver()) },
            hints: AuthorityWakeHintSource(registration: fixture.registration), interval: 100, startRequests: {}, closeRequests: {
                XCTAssertEqual(worker.enqueue(notice), .closed); closes.withLock { $0 += 1 }; try fixture.journal.close()
            }, commandExecutionWorker: worker)
        defer { gate.signal(); worker.requestStop() }
        weak var released = service
        try await service?.start(); XCTAssertEqual(worker.enqueue(notice), .queued)
        try await waitUntil { entered.withLock { $0 } }
        service = nil
        try await waitUntil { released == nil }
        XCTAssertEqual(closes.withLock { $0 }, 0)
        gate.signal(); try await waitUntil { closes.withLock { $0 } == 1 }
    }
}
