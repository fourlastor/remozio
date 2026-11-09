import Darwin
import Foundation

/// Opens a read-only pair for one account under the caller's closed admission verification.
enum MachineUpdateCompletionPolicyRead {
    static func readNative(accountID: Data, scope: PreparationIntentStore.CompletionSnapshotScope,
        verifyCurrent: () throws -> Void) throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verifyCurrent()
        let current = try scope.read()
        guard let policy = current.intent.policies.first(where: { $0.binding.accountID == accountID }),
              let account = current.restart.source.accounts.first(where: { $0.accountID == accountID }),
              let initial = account.initialization, initial.complete,
              let configuration = try current.restart.configuration.configuration(accountID: accountID) else {
            throw PreparationStoreError.staleRevision
        }
        let service = configuration.startup.host.command.presence.wake.request.service
        guard policy.binding.macID == initial.macID, service.macID == initial.macID,
              service.accountID == accountID, initial.accountID == accountID,
              service.journalDirectory == (initial.journalPath as NSString).deletingLastPathComponent,
              service.continuityDirectory == (initial.continuityPath as NSString).deletingLastPathComponent else {
            throw PreparationStoreError.staleRevision
        }
        let backend = try current.restart.backend.capture(accountID: accountID)
        let gateway = try backend?.source.map {
            try $0.pair.authority.material.phonePush.journalPolicy(clockEpoch: UUID())
        }
        func verify() throws {
            try scope.read().requireSame(as: current)
            try verifyCurrent()
        }
        return try readPaired(macID: initial.macID, accountID: accountID, verifyCurrent: verify) {
            let storage = try AuthorityStorage.openForUpdateHealth(configuration: service, gatewayPolicy: gateway)
            return try AuthorityJournal(updateHealthStorage: storage, validateSelf: { _ in try verify() })
        }
    }

    /// A factory transfers one owned reader. Release it on success or failure before another account can open.
    static func readPaired(macID: Data, accountID: Data, verifyCurrent: () throws -> Void,
        open: () throws -> AuthorityJournal) throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
        try verifyCurrent()
        let journal = try open()
        do {
            try verifyCurrent()
            let boundary = try journal.captureMachineUpdatePolicyBoundaryForRecoveryRead()
            guard boundary.macID == macID, boundary.accountID == accountID else {
                throw PreparationStoreError.staleRevision
            }
            try verifyCurrent()
            try journal.close()
            try verifyCurrent()
            return boundary
        } catch {
            try? journal.close()
            throw error
        }
    }
}
