import Darwin
import SQLite3

/// Startup diagnostics only. A temporary failure never grants admission or bypasses storage validation.
public enum AuthorityStartupFailure: Equatable, Sendable {
    case historyRecoveryRequired, repairRequired, temporaryStorageFailure, configurationFailure

    public init(error: any Error) {
        switch error {
        case AuthorityStorageStartupError.historyRecoveryRequired, ContinuityStoreError.historyRecoveryPending: self = .historyRecoveryRequired
        case AuthorityStorageStartupError.repairRequired, ContinuityStoreError.recoveryRequired: self = .repairRequired
        case JournalLeaseError.busy: self = .temporaryStorageFailure
        case JournalLeaseError.system(let code):
            switch code {
            case EINTR, EAGAIN, EBUSY, ENOMEM, EMFILE, ENFILE, EIO, ENOSPC, ETIMEDOUT:
                self = .temporaryStorageFailure
            default: self = .configurationFailure
            }
        case JournalDatabaseError.storage(let code), ContinuityStoreError.storage(let code), AuditJournalError.storage(let code),
             PreparationStoreError.storage(let code):
            switch code & 0xff {
            case SQLITE_BUSY, SQLITE_LOCKED, SQLITE_IOERR, SQLITE_FULL, SQLITE_NOMEM, SQLITE_INTERRUPT:
                self = .temporaryStorageFailure
            default: self = .configurationFailure
            }
        default: self = .configurationFailure
        }
    }
}
