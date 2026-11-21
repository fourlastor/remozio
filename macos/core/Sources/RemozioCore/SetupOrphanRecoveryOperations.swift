import Darwin
import Foundation

/// Effect entries only. The shared session decides when each entry is permitted.
final class SetupOrphanRecoveryOperations: @unchecked Sendable {
    typealias Claim = SetupRetainedOrphanClaim
    typealias Authorization = SetupRetainedRecoveryAuthorization
    struct Peer: Equatable, Sendable {
        let credentials: XPCPeerCredentials
        let owner: LocalAccountIdentity
    }
    struct Effects: Sendable {
        let verifyPeer: @Sendable () throws -> Peer
        let routing: @Sendable () -> AdministrativeSetupLifecycle.State
        let checkHost: (@Sendable () throws -> Void)?
        let importAuthorization: @Sendable (Data) throws -> Authorization
        let restore: @Sendable (Claim.Joined, Claim.Target, ContinuousClock.Instant) async throws -> RuntimeMaintenanceWindowRecord
        let adopt: @Sendable (Claim.Joined, Claim.Target) async throws -> RuntimeMaintenanceWindowRecord
        var now: @Sendable () -> ContinuousClock.Instant = { .now }
    }
    struct WorkEffects: Sendable {
        let routing: @Sendable () -> AdministrativeSetupLifecycle.State
        let checkHost: (@Sendable () throws -> Void)?
        let restore: @Sendable (Claim.Joined, Claim.Target, ContinuousClock.Instant) async throws -> RuntimeMaintenanceWindowRecord
        let adopt: @Sendable (Claim.Joined, Claim.Target) async throws -> RuntimeMaintenanceWindowRecord
        let now: @Sendable () -> ContinuousClock.Instant
    }
    struct OwnedCaller: Sendable {
        let verifyPeer: @Sendable () throws -> Peer
        let importAuthorization: @Sendable (Data) throws -> Authorization
    }
    private let owner: SetupAccountOwner
    private let callerLock = NSLock()
    private var ownedCaller: OwnedCaller?
    let effects: WorkEffects
    private let nativeContext: AdministrativeSetupService.NativeRecoveryContext?
    private init(owner: SetupAccountOwner, effects: WorkEffects, ownedCaller: OwnedCaller? = nil,
        nativeContext: AdministrativeSetupService.NativeRecoveryContext? = nil) {
        self.owner = owner; self.effects = effects; self.ownedCaller = ownedCaller; self.nativeContext = nativeContext
    }
    static func native(context: AdministrativeSetupService.NativeRecoveryContext) throws -> SetupOrphanRecoveryOperations {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let owner = try context.currentOwner()
        let effects = WorkEffects(routing: { context.state }, checkHost: { try context.validate() }, restore: { joined, target, deadline in
            try await SetupOrphanInProcessRestoreEffect.restoreNative(joined: joined, target: target,
                processLease: context.processLease, until: deadline)
        }, adopt: { joined, _ in
            try await joined.finishRecordedRestorationNative(processLease: context.processLease)
        }, now: { .now })
        return .init(owner: owner, effects: effects, nativeContext: context)
    }
    func registerNativeSession() throws -> AdministrativeSetupShutdown.RecoverySessionWork {
        guard let nativeContext else { throw JournalLeaseError.unsafeMetadata }
        return try nativeContext.registerSession(owner: owner)
    }
    func requireContext() throws {
        if let nativeContext { try nativeContext.validate() }
        else { try requireOwned() }
    }

    /// Root cannot inject effects. The native context comes from the verified Host.
    static func owned(owner: SetupAccountOwner, effects: Effects) throws -> SetupOrphanRecoveryOperations {
        try RuntimeMaintenanceOwnedControl.require()
        let work = WorkEffects(routing: effects.routing, checkHost: effects.checkHost,
            restore: effects.restore, adopt: effects.adopt, now: effects.now)
        return .init(owner: owner, effects: work,
            ownedCaller: .init(verifyPeer: effects.verifyPeer, importAuthorization: effects.importAuthorization))
    }
    func takeCallerOwned() throws -> OwnedCaller {
        try requireOwned()
        return try callerLock.withLock {
            guard let caller = ownedCaller else { throw JournalLeaseError.unsafeMetadata }
            ownedCaller = nil; return caller
        }
    }
    func requireOwned() throws {
        try RuntimeMaintenanceOwnedControl.require()
        guard nativeContext == nil else { throw JournalLeaseError.unsafeMetadata }
    }
    func capture(_ authorization: Authorization) throws -> Claim.Target {
        try requireContext(); return try .capture(owner: owner, authorization: authorization)
    }
    func claim(_ target: Claim.Target, authorization: Authorization,
        shutdownSession: AdministrativeSetupShutdown.RecoverySessionWork? = nil) throws -> Claim {
        try requireContext(); return try .open(owner: owner, target: target, authorization: authorization, shutdownSession: shutdownSession)
    }
}
