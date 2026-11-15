import Foundation

/// Internal owner observations only. Separate captures are not atomic and grant no idle proof or stop permit.
struct AuthorityMaintenanceRequestWork: Equatable, Sendable {
    let liveRequests: Int
    let commandCaptures: Int
    let activityOwners: Int
}
struct AuthorityMaintenanceExchangeWork: Equatable, Sendable {
    let active: Int
    let stopped: Bool
}
struct AuthorityMaintenanceJournalWork: Equatable, Sendable {
    let requests: AuthorityMaintenanceRequestWork
    let exchanges: AuthorityMaintenanceExchangeWork
    let nativeExecutions: Int
    let executionActivityOwners: Int
}
struct AuthorityMaintenanceExecutionWork: Equatable, Sendable {
    let started: Bool
    let stopping: Bool
    let failed: Bool
    /// Includes the turn that is currently executing, until its report callback returns.
    let queuedTurns: Int
    let rejectedTurns: Int
}

/// A staged confirmation remains work between invocations. This observation never cancels or expires it.
struct AuthorityMaintenancePairingWork: Equatable, Sendable {
    let ready: Bool
    let stagedAttempts: Int
    let activityOwners: Int
    let operationActive: Bool
}
