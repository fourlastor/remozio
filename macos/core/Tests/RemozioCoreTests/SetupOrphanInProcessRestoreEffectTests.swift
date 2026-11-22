import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class SetupOrphanInProcessRestoreEffectTests: XCTestCase, @unchecked Sendable {
    private typealias Row = RuntimeMaintenanceWindowRecord
    private enum Fault: Error, Equatable { case afterCommit }
    private final class AfterReleaseDrainDriver: AuthorityMaintenanceClientDriver, Sendable {
        let base: any AuthorityMaintenanceClientDriver, context: InProcessUnboundEffectFixture
        init(base: any AuthorityMaintenanceClientDriver, context: InProcessUnboundEffectFixture) {
            self.base = base; self.context = context
        }
        func start(_ invalidated: @escaping @Sendable () -> Void) { base.start(invalidated) }
        func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) { base.hello(reply) }
        func observeIncarnation(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            base.observeIncarnation(bytes, reply)
        }
        func readGate(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            base.readGate(bytes, reply)
        }
        func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            base.exchange(bytes) { [context] value in
                if case .bytes(let bytes) = value, let bytes,
                   let response = try? AuthorityMaintenanceUnboundReleaseResponse.decode(bytes),
                   response.outcome == .released || response.outcome == .alreadyReleased {
                    do {
                        let drain = try context.f.h.barrier.beginDrain()
                        context.foreignDrain.withLock { $0 = drain }
                    } catch { reply(.bytes(nil)); return }
                }
                reply(value)
            }
        }
        func close() { base.close() }
    }
    private func fixture(epoch: UInt8 = 81, _ body: @escaping @Sendable (ExplicitStartupFixture) async throws -> Void) throws {
        try RuntimeMaintenanceExplicitRestorationTests().withFixture(epoch: epoch, body)
    }
    func testNeverHeldCompletesThroughTheConcreteEffectWithoutAReleaseRPC() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let context = try InProcessUnboundEffectFixture(f), effect = try context.effect()
            let (joined, target) = try await context.joined()
            let row = try await effect.restore(joined: joined, target: target, until: .now.advanced(by: .seconds(90)))
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.formatVersion, 1)
            XCTAssertEqual(row.gate?.hold, .released); XCTAssertNil(row.unboundRelease)
            XCTAssertEqual(context.releases.withLock { $0 }, 0)
            XCTAssertEqual(context.writes.withLock { $0 }, [.reopenPending, .restored])
            XCTAssertEqual(f.h.registrations, 0); try f.retained.assertReleased()
        }
    }
    func testARealStartupHoldReleasesBeforeTheVerifiedCompletion() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let context = try InProcessUnboundEffectFixture(f, held: true), effect = try context.effect()
            let (joined, target) = try await context.joined()
            let row = try await effect.restore(joined: joined, target: target, until: .now.advanced(by: .seconds(90)))
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(context.releases.withLock { $0 }, 1)
            try context.authority.withLock { try $0.hold.requireOpen() }; try f.retained.assertReleased()
        }
    }
    func testTheNativeStyleRouteCloseKeepsTheConfirmedIntentAndNoSuccess() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let context = try InProcessUnboundEffectFixture(f), effect = try context.effect()
            context.fault.withLock { $0 = .nativeClosing }
            let (joined, target) = try await context.joined()
            do {
                _ = try await effect.restore(joined: joined, target: target, until: .now.advanced(by: .seconds(90)))
                XCTFail("The current closed native route completed restoration")
            } catch { XCTAssertNotNil(error as? AuthorityMaintenanceClientError) }
            let row = try XCTUnwrap(f.h.frame().window)
            XCTAssertEqual(row.phase, .needsOwnerRecovery); XCTAssertEqual(row.failure, .serviceUnavailable)
            XCTAssertEqual(row.formatVersion, 3); XCTAssertNotNil(row.unboundRelease); XCTAssertNil(row.gate)
            XCTAssertEqual(context.releases.withLock { $0 }, 0); f.retained.assertHeld()
        }
    }
    func testLostReleaseReplyReconcilesTheSameIntentOnAFreshCheckedClaim() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let context = try InProcessUnboundEffectFixture(f, held: true), effect = try context.effect()
            context.fault.withLock { $0 = .lostReleaseReply }
            let (joined, target) = try await context.joined()
            do {
                _ = try await effect.restore(joined: joined, target: target, until: .now.advanced(by: .seconds(90)))
                XCTFail("A lost reply completed the request")
            } catch {}
            let before = try XCTUnwrap(f.h.frame().window), descriptor = try XCTUnwrap(before.unboundRelease)
            XCTAssertEqual(before.phase, .needsOwnerRecovery); XCTAssertEqual(context.releases.withLock { $0 }, 1)
            f.claim?.abandon(); context.fault.withLock { $0 = .none }
            let (retry, retryTarget) = try await context.joined()
            let restored = try await effect.restore(joined: retry, target: retryTarget, until: .now.advanced(by: .seconds(90)))
            XCTAssertEqual(restored.phase, .restored); XCTAssertEqual(restored.gate?.requestRevision, descriptor.pendingRevision)
            XCTAssertEqual(context.releases.withLock { $0 }, 1)
            XCTAssertEqual(context.writes.withLock { $0 }, [.reopenPending, .needsOwnerRecovery, .restored])
            try f.retained.assertReleased()
        }
    }
    func testBusyFromAnotherOwnerKeepsItsDrainAndRepeatedFailureDoesNotRewrite() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let context = try InProcessUnboundEffectFixture(f), effect = try context.effect()
            context.fault.withLock { $0 = .foreignDrain }
            let (joined, target) = try await context.joined()
            do { _ = try await effect.restore(joined: joined, target: target, until: .now.advanced(by: .seconds(90))); XCTFail() }
            catch {}
            let before = try XCTUnwrap(f.h.frame().window), bytes = try before.encoded
            XCTAssertEqual(before.phase, .needsOwnerRecovery); XCTAssertEqual(before.failure, .busy)
            XCTAssertEqual(context.releases.withLock { $0 }, 0)
            try context.foreignDrain.withLock { try XCTUnwrap($0).validate() }
            context.closeForeignDrain()
            context.fault.withLock { $0 = .rpcBusy }
            let calls = context.gateCalls.withLock { $0 }
            f.claim?.abandon()
            let (retry, retryTarget) = try await context.joined()
            do { _ = try await effect.restore(joined: retry, target: retryTarget, until: .now.advanced(by: .seconds(90))); XCTFail() }
            catch {}
            XCTAssertEqual(try f.h.frame().window?.encoded, bytes)
            XCTAssertEqual(context.writes.withLock { $0 }, [.reopenPending, .needsOwnerRecovery])
            XCTAssertEqual(context.gateCalls.withLock { $0 }, calls + 1)
            XCTAssertEqual(context.resourceCount.withLock { $0 }, 2)
            f.retained.assertHeld()
        }
    }
    func testTheAuthorizedRecoveryReceiptSlotHasAConcreteConsumer() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let origin = try XCTUnwrap(f.h.frame().window)
            let recovery = try RuntimeMaintenanceStartupPolicy.row(origin, phase: .needsOwnerRecovery,
                service: .notStopped, failure: .cleanupPending)
            _ = try f.h.write(recovery, previous: origin)
            try XCTUnwrap(f.invocation).retainUnboundAuthorizedOriginTransition(XCTUnwrap(f.h.lastTransition))
            let context = try InProcessUnboundEffectFixture(f), effect = try context.effect()
            let (joined, target) = try await context.joined()
            let row = try await effect.restore(joined: joined, target: target, until: .now.advanced(by: .seconds(90)))
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.gate?.hold, .released)
            try f.retained.assertReleased()
        }
    }
    func testTheKnownEpochRaceKeepsTheNewAuthorityHoldAfterTheOldObservation() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let context = try InProcessUnboundEffectFixture(f), effect = try context.effect()
            context.beforeCompletion.withLock { $0 = { try context.restartAuthorityHeld(epoch: 42) } }
            defer { context.beforeCompletion.withLock { $0 = nil } }
            let (joined, target) = try await context.joined()
            let row = try await effect.restore(joined: joined, target: target, until: .now.advanced(by: .seconds(90)))
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.gate?.authorityIncarnation, Data(repeating: 41, count: 16))
            let newAuthority = context.authority.withLock { $0 }
            XCTAssertEqual(try newAuthority.pairing.liveIncarnation(accountID: row.scope.authority.accountID), Data(repeating: 42, count: 16))
            XCTAssertThrowsError(try newAuthority.hold.requireOpen())
            XCTAssertThrowsError(try newAuthority.boundary.acquireAdmission())
            try f.retained.assertReleased()
        }
    }
    func testAClaimWithACapturedWindowAndNoDurableRowReturnsSessionCodeTen() throws {
        try fixture { f in
            let context = try InProcessUnboundEffectFixture(f), effect = try context.effect()
            try f.retained.lose(&f.invocation)
            let peer = SetupOrphanRecoveryOperations.Peer(credentials: f.retained.binding.peer,
                owner: f.retained.binding.authorityOwner)
            let missingError = Mutex<PreparationStoreError?>(nil)
            let concrete = try effect.effects(verifyPeer: { peer }, routing: { .serving },
                checkHost: { try f.processLease.validate() }, importAuthorization: { _ in try f.retained.authorize() })
            let effects = SetupOrphanRecoveryOperations.Effects(verifyPeer: concrete.verifyPeer,
                routing: concrete.routing, checkHost: concrete.checkHost, importAuthorization: concrete.importAuthorization,
                restore: { joined, target, deadline in
                    do { return try await concrete.restore(joined, target, deadline) }
                    catch { missingError.withLock { $0 = error as? PreparationStoreError }; throw error }
                }, adopt: concrete.adopt)
            let operations = try SetupOrphanRecoveryOperations.owned(owner: f.retained.owner, effects: effects)
            let endpoint = try SetupOrphanRecoveryEndpoint.openOwned(operations: operations, maximumConnections: 8)
            defer { endpoint.close() }
            guard case .observed(let identity) = f.retained.status.identity else { return XCTFail("The captured target disappeared") }
            let id = AccountPreparationIntent.randomID(), request = try SetupOrphanRecoveryWire.Request(requestID: id,
                action: .restore, identity: identity)
            let requestBytes = try request.bytes
            let recorded: Data? = await withCheckedContinuation { continuation in
                endpoint.start(requestBytes, authorization: Data([1])) { continuation.resume(returning: $0) }
            }
            XCTAssertEqual(try SetupOrphanRecoveryWire.Reply.decode(XCTUnwrap(recorded)).code, .requestRecorded)
            await endpoint.waitForWork()
            let progress = try SetupOrphanRecoveryWire.Progress(requestID: id)
            let reply = try SetupOrphanRecoveryWire.Reply.decode(XCTUnwrap(endpoint.progress(progress.bytes)))
            XCTAssertEqual(reply.code.rawValue, 10); XCTAssertNil(try f.h.frame().window)
            XCTAssertEqual(missingError.withLock { $0 }, .notFound)
            XCTAssertEqual(context.writes.withLock { $0 }, []); f.retained.assertHeld()
        }
    }
    func testTheBoundOriginDelegatesToTheExistingSavedTargetRestoration() throws {
        try fixture(epoch: 71) { f in
            try f.seed(.needsOwnerRecovery, retainReceipt: true)
            let original = try XCTUnwrap(f.h.frame().window)
            let context = try InProcessUnboundEffectFixture(f), effect = try context.effect()
            let (joined, target) = try await context.joined()
            let row = try await effect.restore(joined: joined, target: target, until: .now.advanced(by: .seconds(90)))
            XCTAssertEqual(row.phase, .restored); XCTAssertEqual(row.service, .notStopped)
            XCTAssertEqual(row.operation, original.operation)
            XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, [.reopen])
            XCTAssertEqual(f.h.committedRows.map(\.phase), [.restoring, .reopenPending, .restored])
            XCTAssertEqual(context.releases.withLock { $0 }, 0); try f.retained.assertReleased()
        }
    }
    func testRecordedUnboundCompletionAdoptsWithoutAnotherWorkSlotOrRPC() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let context = try InProcessUnboundEffectFixture(f), effect = try context.effect()
            context.afterCompletion.withLock { $0 = { f.rightsLive.value.withLock { $0 = false } } }
            defer { context.afterCompletion.withLock { $0 = nil } }
            let (joined, target) = try await context.joined()
            do {
                _ = try await effect.restore(joined: joined, target: target, until: .now.advanced(by: .seconds(90)))
                XCTFail("Revoked rights settled the record")
            } catch {}
            let recorded = try XCTUnwrap(f.h.frame().window)
            XCTAssertEqual(recorded.phase, .restored); f.retained.assertHeld()
            let writes = context.writes.withLock { $0 }, releases = context.releases.withLock { $0 }
            f.claim?.abandon(); f.rightsLive.value.withLock { $0 = true }
            let (fresh, freshTarget) = try await context.joined()
            let peer = SetupOrphanRecoveryOperations.Peer(credentials: f.retained.binding.peer,
                owner: f.retained.binding.authorityOwner)
            let effects = try effect.effects(verifyPeer: { peer }, routing: { .serving },
                checkHost: { try f.processLease.validate() }, importAuthorization: { _ in try f.retained.authorize() })
            let adopted = try await effects.adopt(fresh, freshTarget)
            XCTAssertEqual(adopted, recorded); XCTAssertEqual(context.writes.withLock { $0 }, writes)
            XCTAssertEqual(context.releases.withLock { $0 }, releases); try f.retained.assertReleased()
        }
    }
    func testAnUncertainIntentWriterCannotReachAnRPCOrAnotherWriteInItsAttempt() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let context = try InProcessUnboundEffectFixture(f), effect = try context.effect()
            context.afterIntent.withLock { $0 = { throw Fault.afterCommit } }
            let (joined, target) = try await context.joined()
            do {
                _ = try await effect.restore(joined: joined, target: target, until: .now.advanced(by: .seconds(90)))
                XCTFail("An uncertain writer completed the attempt")
            } catch { XCTAssertEqual(error as? Fault, .afterCommit) }
            XCTAssertEqual(try f.h.frame().window?.phase, .reopenPending)
            XCTAssertEqual(context.writes.withLock { $0 }, [.reopenPending])
            XCTAssertEqual(context.releases.withLock { $0 }, 0); f.retained.assertHeld()
        }
    }

    private func uncertainIntentRetry(committed: Bool) throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let original = try XCTUnwrap(f.h.frame().window)
            let context = try InProcessUnboundEffectFixture(f), effect = try context.effect()
            if committed { context.afterIntent.withLock { $0 = { throw Fault.afterCommit } } }
            else { context.beforeIntent.withLock { $0 = { throw Fault.afterCommit } } }
            let (joined, target) = try await context.joined()
            do {
                _ = try await effect.restore(joined: joined, target: target, until: .now.advanced(by: .seconds(90)))
                XCTFail("An uncertain writer completed restoration")
            } catch { XCTAssertEqual(error as? Fault, .afterCommit) }
            let actual = try XCTUnwrap(f.h.frame().window)
            if committed {
                XCTAssertEqual(actual.phase, .reopenPending); XCTAssertNotNil(actual.unboundRelease)
            } else { XCTAssertEqual(actual, original) }
            XCTAssertEqual(context.resourceCount.withLock { $0 }, 1)
            XCTAssertEqual(context.releases.withLock { $0 }, 0); f.retained.assertHeld()
            f.claim?.abandon()
            XCTAssertThrowsError(try joined.requireCurrentAuthorization())
            context.afterIntent.withLock { $0 = nil }; context.beforeIntent.withLock { $0 = nil }
            let (fresh, freshTarget) = try await context.joined()
            let restored = try await effect.restore(joined: fresh, target: freshTarget, until: .now.advanced(by: .seconds(90)))
            XCTAssertEqual(restored.phase, .restored)
            if let descriptor = actual.unboundRelease {
                XCTAssertEqual(restored.gate?.requestRevision, descriptor.pendingRevision)
            }
            XCTAssertEqual(context.resourceCount.withLock { $0 }, 2)
            XCTAssertEqual(context.writes.withLock { $0 }, [.reopenPending, .restored])
            XCTAssertEqual(context.releases.withLock { $0 }, 0); try f.retained.assertReleased()
        }
    }
    func testAFreshClaimReconcilesAnIntentThatCommittedBeforeTheWriterFailed() throws {
        try uncertainIntentRetry(committed: true)
    }
    func testAFreshClaimReconcilesAnIntentThatDidNotCommitBeforeTheWriterFailed() throws {
        try uncertainIntentRetry(committed: false)
    }
    func testAnUncertainLiveCustodyRefusesFurtherWritesAndAConcurrentClaim() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let context = try InProcessUnboundEffectFixture(f)
            context.afterIntent.withLock { $0 = { throw Fault.afterCommit } }
            let (joined, _) = try await context.joined(), phases = try joined.restorationPhases()
            let resources = try await phases.run { try context.resources() }
            let custody = try await phases.run {
                try RuntimeMaintenanceStartupRecovery.makeUnboundJoinedCustodyOwned(joined: joined,
                    processLease: f.processLease, frame: resources.read(), release: resources.release,
                    admission: resources.admission, directory: resources.directory, accountBarrier: resources.accountBarrier,
                    read: resources.read, persist: resources.persist, writeIntent: resources.writeIntent,
                    writeCompletion: resources.writeCompletion, verify: resources.verify,
                    until: .now.advanced(by: .seconds(90)))
            }
            try await phases.run {
                XCTAssertThrowsError(try custody.persistUnboundIntent())
                XCTAssertThrowsError(try custody.requireUnboundCleanup())
                XCTAssertThrowsError(try custody.persistUnboundFailure(.serviceUnavailable))
                XCTAssertThrowsError(try custody.releaseUnboundCleanupDrain())
                let authorization = try f.retained.authorize()
                defer { authorization.close() }
                XCTAssertThrowsError(try SetupRetainedOrphanClaim.Target.capture(owner: f.retained.owner,
                    authorization: authorization))
                XCTAssertThrowsError(try f.retained.claim(authorization))
            }
            let row = try XCTUnwrap(f.h.frame().window)
            XCTAssertEqual(row.phase, .reopenPending)
            XCTAssertEqual(context.writes.withLock { $0 }, [.reopenPending])
            XCTAssertEqual(context.releases.withLock { $0 }, 0)
            try await phases.closeActual { custody.closeUnboundCustody() }
            XCTAssertThrowsError(try resources.admission.validateMachineBoundary(directory: resources.directory,
                expected: custody.floor.cohort.machineIdentity))
            f.claim?.abandon(); context.afterIntent.withLock { $0 = nil }
            let (fresh, target) = try await context.joined(), effect = try context.effect()
            XCTAssertThrowsError(try joined.requireCurrentAuthorization())
            let restored = try await effect.restore(joined: fresh, target: target, until: .now.advanced(by: .seconds(90)))
            XCTAssertEqual(restored.phase, .restored); try f.retained.assertReleased()
        }
    }

    func testAnUncertainCompletionCommitKeepsTheRestoredRowButReturnsSessionCodeTen() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let context = try InProcessUnboundEffectFixture(f), effect = try context.effect()
            context.afterCompletion.withLock { $0 = { throw Fault.afterCommit } }
            try f.retained.lose(&f.invocation)
            let peer = SetupOrphanRecoveryOperations.Peer(credentials: f.retained.binding.peer,
                owner: f.retained.binding.authorityOwner)
            let effects = try effect.effects(verifyPeer: { peer }, routing: { .serving },
                checkHost: { try f.processLease.validate() }, importAuthorization: { _ in try f.retained.authorize() })
            let operations = try SetupOrphanRecoveryOperations.owned(owner: f.retained.owner, effects: effects)
            let endpoint = try SetupOrphanRecoveryEndpoint.openOwned(operations: operations, maximumConnections: 8)
            defer { endpoint.close() }
            guard case .observed(let identity) = f.retained.status.identity else { return XCTFail() }
            let id = AccountPreparationIntent.randomID(), request = try SetupOrphanRecoveryWire.Request(requestID: id,
                action: .restore, identity: identity)
            let bytes = try request.bytes
            let recorded: Data? = await withCheckedContinuation { continuation in
                endpoint.start(bytes, authorization: Data([1])) { continuation.resume(returning: $0) }
            }
            XCTAssertEqual(try SetupOrphanRecoveryWire.Reply.decode(XCTUnwrap(recorded)).code, .requestRecorded)
            await endpoint.waitForWork()
            let progress = try SetupOrphanRecoveryWire.Progress(requestID: id)
            let reply = try SetupOrphanRecoveryWire.Reply.decode(XCTUnwrap(endpoint.progress(progress.bytes)))
            XCTAssertEqual(reply.code.rawValue, 10)
            let actual = try XCTUnwrap(f.h.frame().window)
            XCTAssertEqual(actual.phase, .restored); XCTAssertEqual(actual.gate?.hold, .released)
            XCTAssertEqual(context.writes.withLock { $0 }, [.reopenPending, .restored])
            XCTAssertEqual(context.releases.withLock { $0 }, 0); f.retained.assertHeld()
        }
    }

    func testFinalBusyAfterReleaseStaysTypedAndNeverCompletesTheIntent() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let context = try InProcessUnboundEffectFixture(f, held: true)
            let actual = Mutex<SetupOrphanInProcessRestoreEffect.OwnedResources?>(nil)
            let effect = try SetupOrphanInProcessRestoreEffect.owned(processLease: f.processLease,
                read: { try f.h.frame() }, makeResources: {
                    let base = try context.resources(); actual.withLock { $0 = base }
                    return try .init(release: base.release, admission: base.admission, directory: base.directory,
                        accountBarrier: base.accountBarrier, read: base.read, persist: base.persist,
                        writeIntent: base.writeIntent, writeCompletion: base.writeCompletion, verify: base.verify,
                        inspect: base.inspect, observe: base.observe, register: base.register,
                        makeDriver: { phases in AfterReleaseDrainDriver(base: try base.makeDriver(phases), context: context) },
                        capturePeer: base.capturePeer, requirePeerLive: base.requirePeerLive)
                })
            let (joined, target) = try await context.joined()
            do {
                _ = try await effect.restore(joined: joined, target: target, until: .now.advanced(by: .seconds(90)))
                XCTFail("Busy final admission completed restoration")
            } catch { XCTAssertEqual(error as? AuthorityMaintenanceClientError, .busy) }
            let before = try XCTUnwrap(f.h.frame().window), bytes = try before.encoded
            XCTAssertEqual(before.phase, .needsOwnerRecovery); XCTAssertEqual(before.failure, .busy); XCTAssertNil(before.gate)
            XCTAssertEqual(context.releases.withLock { $0 }, 1); XCTAssertEqual(context.gateCalls.withLock { $0 }, 2)
            try context.authority.withLock { try $0.hold.requireOpen() }
            try context.foreignDrain.withLock { try XCTUnwrap($0).validate() }
            let resources = try XCTUnwrap(actual.withLock { $0 }), machine = try f.h.frame().source.actual.admission.machine
            XCTAssertThrowsError(try resources.admission.validateMachineBoundary(directory: resources.directory, expected: machine))
            f.claim?.abandon(); let (retry, retryTarget) = try await context.joined()
            // The held account drain refuses the retry before another RPC.
            do { _ = try await effect.restore(joined: retry, target: retryTarget, until: .now.advanced(by: .seconds(90))); XCTFail() }
            catch { XCTAssertEqual(error as? UpdateAdmissionBarrierError, .busy) }
            XCTAssertEqual(try f.h.frame().window?.encoded, bytes)
            XCTAssertEqual(context.writes.withLock { $0 }, [.reopenPending, .needsOwnerRecovery])
            XCTAssertEqual(context.releases.withLock { $0 }, 1); XCTAssertEqual(context.gateCalls.withLock { $0 }, 2)
            XCTAssertEqual(context.resourceCount.withLock { $0 }, 2)
            try context.foreignDrain.withLock { try XCTUnwrap($0).validate() }
            let retriedResources = try XCTUnwrap(actual.withLock { $0 })
            XCTAssertThrowsError(try retriedResources.admission.validateMachineBoundary(directory: retriedResources.directory, expected: machine))
            f.retained.assertHeld()
        }
    }
    func testShutdownCancelsTheConcreteUnboundTaskWithAnIntentAndAPendingRPC() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let context = try InProcessUnboundEffectFixture(f), effect = try context.effect()
            context.fault.withLock { $0 = .pendingGate }
            let placement = try ReleaseDestinationLease(anchor: f.activity.root.path, relativeDirectory: "Machine", owner: getuid())
            let shutdown = AdministrativeSetupShutdown(owner: f.retained.owner, placement: placement, processLease: f.processLease)
            let session = try shutdown.registerRecoverySession(owner: f.retained.owner)
            XCTAssertTrue(session.reservePublication())
            let (joined, target) = try await context.joined(shutdownSession: session)
            let returned = Mutex(false), succeeded = Mutex(false)
            let actual = Task {
                do {
                    _ = try await effect.restore(joined: joined, target: target, until: .now.advanced(by: .seconds(90)))
                    succeeded.withLock { $0 = true }
                } catch {}
                returned.withLock { $0 = true }
            }
            session.publish(actual)
            let deadline = ContinuousClock.now.advanced(by: RuntimeMaintenanceExplicitRestorationTests.unboundPhaseBudget)
            while !context.gatePending.withLock({ $0 }) {
                guard ContinuousClock.now < deadline else { throw Fault.afterCommit }
                try await ContinuousClock().sleep(for: .milliseconds(1))
            }
            let interrupted = try XCTUnwrap(f.h.frame().window)
            XCTAssertEqual(interrupted.phase, .reopenPending); XCTAssertNotNil(interrupted.unboundRelease)
            XCTAssertFalse(returned.withLock { $0 }); f.retained.assertHeld()
            await shutdown.joinRecoverySessions()
            XCTAssertTrue(returned.withLock { $0 }, "Shutdown returned before the restoration task finished")
            XCTAssertTrue(context.driverClosed.withLock { $0 }, "Shutdown returned before the restoration driver closed")
            await actual.value
            XCTAssertFalse(succeeded.withLock { $0 })
            XCTAssertEqual(context.releases.withLock { $0 }, 0)
            XCTAssertFalse(context.writes.withLock { $0.contains(.restored) })
            let afterCleanup = try XCTUnwrap(f.h.frame().window)
            XCTAssertEqual(afterCleanup.phase, .needsOwnerRecovery); XCTAssertNotNil(afterCleanup.unboundRelease)
            XCTAssertEqual(afterCleanup.unboundRelease, interrupted.unboundRelease)
            f.retained.assertHeld(); XCTAssertNoThrow(try f.processLease.validate()); XCTAssertNoThrow(try placement.validate())
            f.claim?.abandon()
            let restarted = try await Self.discardInterruptedIntentOnFreshStartup(f)
            XCTAssertEqual(restarted.failure, .repairRequired)
            placement.close()
        }
    }
    private static func discardInterruptedIntentOnFreshStartup(_ f: ExplicitStartupFixture) async throws -> RuntimeMaintenanceWindowRecord {
        let activity = try ReleaseActivityFixture()
        let owner = try SetupAccountOwner(machine: f.h.f.machine(),
            expectedReleaseDigest: InstallationInventory.digest(f.h.f.candidate), resume: { _, row in row }, releaseActivity: activity.open())
        let placement = try ReleaseDestinationLease(anchor: activity.root.path, relativeDirectory: "Machine", owner: getuid())
        let shutdown = AdministrativeSetupShutdown(owner: owner, placement: placement, processLease: f.processLease)
        let scope = try owner.acquireMaintenanceRecoveryScope(custody: shutdown), phases = try owner.maintenanceRecoveryPhases(scope: scope)
        defer { scope.close(); try? owner.close(); placement.close() }
        let row = try await phases.run {
            let h = f.h, frame = try h.frame(), drain = try h.barrier.beginDrain()
            defer { drain.close() }
            let result = try RuntimeMaintenanceStartupRecovery.openUnboundStartupOwned(frame: frame,
                processLease: f.processLease, startupPhases: phases, directory: h.f.directory, admission: h.f.admission,
                drain: drain, read: { try h.frame() }, persistFailure: { next, previous, _ in
                    _ = try h.write(next, previous: previous); return try XCTUnwrap(h.lastTransition)
                }, persistDiscard: { previous, authorization, current in
                    try h.f.machine().writeRuntimeMaintenanceUnboundStartupDiscard(replacing: previous,
                        authorization: authorization, expected: current.source.actual, candidate: h.f.candidate,
                        directory: h.f.directory, admission: h.f.admission)
                })
            guard case .terminal(let row) = result else { throw RuntimePreparationError.changedScope }
            return try XCTUnwrap(row)
        }
        XCTAssertEqual(row.phase, .needsOwnerRecovery)
        XCTAssertNil(row.unboundRelease); XCTAssertNil(row.gate)
        return row
    }

}
