import Darwin
import Foundation
import RemozioProtocol

enum MachineUpdatePolicyRead {
    static func readNative(accounts: [MachineUpdateRestartSource.Account]) throws -> [MachineUpdatePolicyCapture] {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try accounts.map { account in
            guard let initial = account.initialization else { return .init(accountID: account.accountID, snapshot: nil) }
            let snapshot: AuthorityCodePolicySnapshot?
            do { snapshot = try readNative(initial) }
            // Only an initialization that never captured a checkpoint may lack its journal. A captured checkpoint proves
            // the journal committed, so its loss must stop the preflight (AuthorityAccountInitialization.resume agrees).
            catch JournalLeaseError.system(let code) where code == ENOENT && !initial.complete && initial.checkpoint == nil { snapshot = nil }
            return .init(accountID: account.accountID, snapshot: snapshot)
        }
    }
    static func readNative(_ initial: AuthorityInitializationIntent) throws -> AuthorityCodePolicySnapshot? {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try readInLease(ProtectedJournalLease.acquire(directoryPath: (initial.journalPath as NSString).deletingLastPathComponent),
            macID: initial.macID, accountID: initial.accountID)
    }
    static func readInLease(_ lease: ProtectedJournalLease, macID: Data, accountID: Data) throws -> AuthorityCodePolicySnapshot? {
        let limits = try CBORLimits(maxBytes: 16_777_216, maxDepth: 32, maxItems: 262144)
        let journal = try JournalDatabase(lease: lease, macID: macID, accountID: accountID, recordLimits: limits,
            descriptorLimits: limits, decisionLimits: limits, maximumConsumptions: 1_000_000, busyMilliseconds: 5000,
            initialize: false, readOnlyForCutover: true)
        do { let value = try journal.read { try $0.codePolicy() }; try journal.close(); return value }
        catch { try? journal.close(); throw error }
    }
}
