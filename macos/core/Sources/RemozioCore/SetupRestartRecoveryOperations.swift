import Foundation

/// Owned effects only. The session fixes correlation, origin, deadline, cleanup and error disclosure.
final class SetupRestartRecoveryOperations: @unchecked Sendable {
    struct AuthorizationFailure: Error {}
    typealias Claim = SetupRestartRecovery.Claim
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
        let restore: @Sendable (Claim, ContinuousClock.Instant) async throws -> RuntimeMaintenanceWindowRecord
        var now: @Sendable () -> ContinuousClock.Instant = { .now }
    }
    private let owner: SetupAccountOwner
    private let processLease: SetupProcessLease
    let effects: Effects
    private init(owner: SetupAccountOwner, processLease: SetupProcessLease, effects: Effects) {
        self.owner = owner; self.processLease = processLease; self.effects = effects
    }
    static func owned(owner: SetupAccountOwner, processLease: SetupProcessLease, effects: Effects) throws -> SetupRestartRecoveryOperations {
        try RuntimeMaintenanceOwnedControl.require()
        return .init(owner: owner, processLease: processLease, effects: effects)
    }
    func requireOwned() throws { try RuntimeMaintenanceOwnedControl.require() }
    func claim(_ authorization: Authorization, action: SetupRestartRecoveryWire.Action, until deadline: ContinuousClock.Instant) async throws -> Claim {
        try requireOwned()
        return try await .openOwned(owner: owner, authorization: authorization, processLease: processLease,
            policy: action == .restore ? .freshOrReclaim : .reclaimOnly, until: deadline)
    }
    func check(_ claim: Claim) async throws {
        try requireOwned()
        guard let host = effects.checkHost else { throw AdministrativeSetupError.unavailable }
        try await claim.restorationPhases().run {
            try host()
            do { try claim.requireCurrentAuthorization() } catch { throw AuthorizationFailure() }
        }
    }
    func releaseApplicability(_ claim: Claim) async throws -> Claim.ReleaseApplicability {
        try requireOwned(); try await check(claim)
        return try await claim.restorationPhases().run { try claim.releaseApplicability() }
    }
    func releaseIdle(_ claim: Claim) async throws -> Bool {
        try requireOwned(); try await check(claim)
        return try await claim.releaseIdleAfterRequest()
    }
}
