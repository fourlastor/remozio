import Darwin
import Foundation

/// Shares the existing request owner and clock. The factory opens no second journal or epoch.
public typealias AuthorityCommandExecutionFactory = @Sendable (AuthorityJournal, AuthorityClock) throws -> AuthorityCommandExecutionWorker

extension AuthorityCommandStartupConfiguration {
    /// Configure execution only when versioned host inputs explicitly provide it.
    /// Final code, enrollment, grant, capture and durable release checks remain in the journal.
    public func executionFactory(
        report: @escaping @Sendable (AuthorityCommandAuthorizationNotice, Result<Void, any Error>) -> Void = { _, _ in }) throws -> AuthorityCommandExecutionFactory? {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard let execution else { return nil }
        let policy = try currentElevationPolicy()
        return { journal, clock in
            try journal.read { transaction in
                let trust = try transaction.approvalTrustSnapshot()
                guard trust.macID == policy.macID, trust.accountID == policy.accountID else {
                    throw AuthorityCommandStartupError.wrongPolicyScope
                }
            }
            return try AuthorityCommandExecutionWorker(maximumPending: execution.maximumPending, begin: { notice, check in
                try check()
                try journal.validateCommandAuthorizationNotice(notice, now: clock.now())
                try journal.beginCommandExecution(requestID: notice.requestID, monitorPath: execution.monitorPath,
                    childPath: execution.childPath, preparationMilliseconds: execution.preparationMilliseconds,
                    fileCreationMask: execution.fileCreationMask, maximumActiveCommands: execution.maximumActiveCommands,
                    pollIntervalMilliseconds: execution.pollIntervalMilliseconds, elevationPolicy: policy,
                    clock: { try clock.now() }, receiptTime: Self.executionReceiptTime, checkCancellation: check)
            }, rejectUnowned: { notice in
                _ = try journal.cancelUnownedCommandExecution(notice, now: clock.now(), receiptTimeMs: Self.executionReceiptTime())
            }, report: report)
        }
    }

    private static func executionReceiptTime() -> UInt64? {
        let milliseconds = Date().timeIntervalSince1970 * 1000
        guard milliseconds.isFinite, milliseconds >= 0, milliseconds < Double(UInt64.max) else { return nil }
        return UInt64(milliseconds)
    }
}
