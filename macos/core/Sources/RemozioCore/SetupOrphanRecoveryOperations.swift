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
    private let owner: SetupAccountOwner
    let effects: Effects
    private init(owner: SetupAccountOwner, effects: Effects) { self.owner = owner; self.effects = effects }
    /// Root cannot inject effects. The future producer cut must mint its own native context from the verified Host.
    static func owned(owner: SetupAccountOwner, effects: Effects) throws -> SetupOrphanRecoveryOperations {
        try RuntimeMaintenanceOwnedControl.require()
        return .init(owner: owner, effects: effects)
    }
    func requireOwned() throws { try RuntimeMaintenanceOwnedControl.require() }
    func capture(_ authorization: Authorization) throws -> Claim.Target {
        try requireOwned(); return try .capture(owner: owner, authorization: authorization)
    }
    func claim(_ target: Claim.Target, authorization: Authorization) throws -> Claim {
        try requireOwned(); return try .open(owner: owner, target: target, authorization: authorization)
    }
}
