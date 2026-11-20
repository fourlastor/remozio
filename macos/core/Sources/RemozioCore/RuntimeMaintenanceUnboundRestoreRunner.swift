import Darwin
import Foundation

/// Runs one unbound attempt inside the existing restoration work slot. It never creates a restart claim.
enum RuntimeMaintenanceUnboundRestoreRunner {
    typealias Row = RuntimeMaintenanceWindowRecord
    typealias Joined = SetupRetainedOrphanClaim.Joined
    typealias Phases = SetupRetainedInvocationReservation.RestorationPhases
    private enum PeerFailure: Error { case busy, refused, unknown }
    private enum ClientSource: Sendable {
        case native
        case owned(SetupOrphanInProcessRestoreEffect.OwnedResources)
    }
    static func restoreOwned(joined: Joined, processLease: SetupProcessLease, expected: Row,
        makeResources: @escaping @Sendable () throws -> SetupOrphanInProcessRestoreEffect.OwnedResources,
        until deadline: ContinuousClock.Instant) async throws -> Row {
        try RuntimeMaintenanceOwnedControl.require()
        let phases = try joined.restorationPhases().forAttempt(until: deadline)
        let work = try await joined.startRestoration { workID in
            let prepared = try await phases.run {
                let resources = try makeResources()
                do {
                    let custody = try RuntimeMaintenanceStartupRecovery.makeUnboundJoinedCustodyOwned(joined: joined,
                        processLease: processLease, frame: resources.read(), release: resources.release,
                        admission: resources.admission, directory: resources.directory, accountBarrier: resources.accountBarrier,
                        read: resources.read, persist: resources.persist, writeIntent: resources.writeIntent,
                        writeCompletion: resources.writeCompletion, verify: resources.verify, until: deadline)
                    return OwnedCustody(custody: custody, resources: resources)
                } catch { resources.admission.close(); resources.directory.close(); throw error }
            }
            return try await finish(custody: prepared.custody, joined: joined, expected: expected,
                workID: workID, phases: phases, source: .owned(prepared.resources), until: deadline)
        }
        return try await joined.finishRestorationOwned(work: work, processLease: processLease)
    }
    static func restoreNative(joined: Joined, processLease: SetupProcessLease, expected: Row,
        until deadline: ContinuousClock.Instant) async throws -> Row {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let phases = try joined.restorationPhases().forAttempt(until: deadline)
        let work = try await joined.startRestoration { workID in
            let custody = try await phases.run {
                try RuntimeMaintenanceStartupRecovery.makeUnboundJoinedCustodyNative(joined: joined,
                    processLease: processLease, accountID: expected.scope.authority.accountID, until: deadline)
            }
            return try await finish(custody: custody, joined: joined, expected: expected,
                workID: workID, phases: phases, source: .native, until: deadline)
        }
        return try await joined.finishRestorationNative(work: work, processLease: processLease)
    }
    private struct OwnedCustody: @unchecked Sendable {
        let custody: RuntimeMaintenanceStartupRecovery.Custody
        let resources: SetupOrphanInProcessRestoreEffect.OwnedResources
    }
    private static func finish(custody: RuntimeMaintenanceStartupRecovery.Custody, joined: Joined, expected: Row,
        workID: UUID, phases: Phases, source: ClientSource, until deadline: ContinuousClock.Instant)
        async throws -> RuntimeMaintenanceStartupRecovery.ExplicitCompletion {
        let failure: (any Error)?
        do {
            try await phases.run {
                guard custody.current == expected else { throw PreparationStoreError.staleRevision }
                if expected.unboundRelease == nil {
                    _ = try joined.requireUnboundAuthorizedOrigin(expected)
                    _ = try custody.persistUnboundIntent()
                } else { try joined.requireUnboundIntentReconciliation(expected) }
                try custody.releaseUnboundCleanupDrain()
            }
            let client = try await phases.run { try makeClient(custody: custody, phases: phases, source: source) }
            do {
                let row = try await phases.run { try custody.requireUnboundCleanup(); return custody.current }
                let gate = custody.floor.cohort.accountIdentity
                let probe = try await client.probeUnboundGate(joined: joined, row: row, gate: gate, until: deadline)
                guard probe.admission != .unavailable else { throw PeerFailure.refused }
                switch probe.hold {
                case .unknown: throw PeerFailure.unknown
                case .held:
                    let release = try await client.releaseUnbound(joined: joined, row: row, gate: gate, until: deadline)
                    switch release.outcome {
                    case .released, .alreadyReleased: break
                    case .busy: throw PeerFailure.busy
                    case .refused: throw PeerFailure.refused
                    }
                case .released, .neverHeld:
                    guard probe.admission == .available else { throw PeerFailure.busy }
                }
                // Only this existing authenticated path can mint the writer's private observation.
                // Its final busy response remains changedScope. The existing verifier does not distinguish that failure.
                let observation = try await client.observeUnboundGate(joined: joined, row: row, gate: gate, until: deadline)
                await client.close()
                _ = try await phases.run { try custody.persistUnboundCompletion(observation) }
            } catch { await client.close(); throw error }
            failure = nil
        } catch {
            failure = error
            // This existing writer does nothing for R(D), restored or a row without an intent.
            // An uncertain writer remains invalidated and cannot reach another write or RPC.
            do { _ = try await phases.cleanup { try custody.persistUnboundFailure(failureKind(error)) } }
            catch { /* Retain the original failure and actual invalidated custody. */ }
        }
        let outcome: Result<RuntimeMaintenanceStartupRecovery.ExplicitCompletion, any Error>
        do {
            outcome = .success(try await phases.cleanup {
                if custody.current.phase == .restored {
                    return try RuntimeMaintenanceStartupRecovery.makeUnboundExplicitCompletion(custody: custody,
                        workID: workID, originalRunFailed: failure != nil)
                }
                if let failure { throw failure }
                throw RuntimePreparationError.changedScope
            })
        } catch { outcome = .failure(error) }
        try await phases.closeActual { custody.closeUnboundCustody() }
        return try outcome.get()
    }
    private static func makeClient(custody: RuntimeMaintenanceStartupRecovery.Custody, phases: Phases,
        source: ClientSource) throws -> AuthorityMaintenanceXPCClient {
        try custody.requireUnboundCleanup()
        let row = custody.current, gate = custody.floor.cohort.accountIdentity
        let context = try AuthorityMaintenanceChannelRequest(action: .open, accountID: row.scope.authority.accountID,
            attemptID: row.id, revision: row.revision, installationID: row.scope.installationID,
            gate: gate, binding: nil, challenge: AccountPreparationIntent.randomID() + AccountPreparationIntent.randomID())
        switch source {
        case .owned(let resources):
            try RuntimeMaintenanceOwnedControl.require()
            guard !custody.native else { throw JournalLeaseError.unsafeMetadata }
            return try .openOwned(context: context, driver: resources.makeDriver(phases), verify: resources.verify,
                recoveryPhases: phases)
        case .native:
            guard getuid() == 0, geteuid() == 0, custody.native else { throw JournalLeaseError.rootRequired }
            let metadata = try RuntimeMaintenanceInProcessNativeFrame.capture(accountID: row.scope.authority.accountID)
            try custody.floor.requireCurrent(metadata.frame, window: row, release: metadata.release)
            return try .init(context: context, authority: custody.floor.code, setup: metadata.setup,
                release: metadata.release, recoveryPhases: phases)
        }
    }
    private static func failureKind(_ error: any Error) -> Row.Failure {
        if let peer = error as? PeerFailure {
            switch peer {
            case .busy: return .busy
            case .refused: return .serviceUnavailable
            case .unknown: return .changedScope
            }
        }
        if error is AuthorityMaintenanceClientError { return .serviceUnavailable }
        return RuntimeMaintenanceStartupRecovery.failure(error, fallback: .admissionUnconfirmed)
    }
}
