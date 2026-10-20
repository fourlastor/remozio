import Foundation

/// Coordinates optional preparation before foreground startup and during monitor retries.
/// A completed preparation does not assert delivery readiness or native peer admission.
actor AuthorityGatewaySettingsStartupRecovery {
    enum Snapshot: Sendable {
        case absent
        case retained(AuthorityGatewaySettingsStartupPlan)
        case unavailable
    }
    struct Operations: Sendable {
        let block: @Sendable () async throws -> Void
        let absent: @Sendable () async throws -> Void
        let restore: @Sendable (AuthorityGatewaySettingsStartupPlan, @Sendable () throws -> Void) async throws -> Void
    }
    private var snapshot: Snapshot
    private let reload: @Sendable () throws -> Snapshot
    private let operations: Operations
    private var blocked = false
    private var working = false
    private var prepared = false

    init(snapshot: Snapshot, service: AuthorityWakeService, reload: @escaping @Sendable () throws -> Snapshot) {
        self.snapshot = snapshot; self.reload = reload
        operations = .init(block: { try await service.pauseUnknownPhonePushStartup() },
            absent: { try await service.allowAbsentPhonePushStartup() }, restore: { plan, verify in
                _ = try await service.restorePhonePushStartup(plan.options, commitDigest: plan.activeCommitDigest,
                    pendingChange: plan.pendingChange, requiresConsumerRecovery: plan.requiresConsumerRecovery, verifyCurrent: verify)
            })
    }
    /// Injected operations are owned fixtures. They do not bypass the native constructor or grant runtime authority.
    init(snapshot: Snapshot, reload: @escaping @Sendable () throws -> Snapshot, operations: Operations) {
        self.snapshot = snapshot; self.reload = reload; self.operations = operations
    }
    static func capture(machine: PreparationIntentStore, authority: InstalledAuthorityCommandConfiguration) -> Snapshot {
        do {
            return try AuthorityGatewaySettingsStartupPlan.load(machine: machine, authority: authority).map(Snapshot.retained) ?? .absent
        } catch { return .unavailable }
    }
    /// Return whether initial optional scope is prepared. Pending settings still require a fresh barrier and explicit acceptance.
    /// Optional failures retain the pause. Cancellation propagates to the owner for normal shutdown.
    func prepare(verifyCurrent: @escaping @Sendable () throws -> Void) async throws -> Bool {
        try Task.checkCancellation()
        guard !working else { return false }
        if prepared { return true }
        working = true; defer { working = false }
        do {
            switch snapshot {
            case .absent: break
            case .retained, .unavailable:
                if !blocked { try await operations.block(); blocked = true }
            }
            try Task.checkCancellation(); try verifyCurrent()
            switch snapshot {
            case .absent:
                if blocked { try await operations.absent() }
                prepared = true; return true
            case .retained: break
            case .unavailable:
                snapshot = try reload()
            }
            switch snapshot {
            case .absent:
                try verifyCurrent(); try Task.checkCancellation()
                if blocked { try await operations.absent() }
                prepared = true; return true
            case .retained(let plan):
                try await operations.restore(plan, verifyCurrent)
                prepared = true; return true
            case .unavailable: return false
            }
        } catch {
            try Task.checkCancellation()
            return false
        }
    }
}
