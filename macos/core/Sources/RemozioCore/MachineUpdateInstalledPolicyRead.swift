import Darwin
import Foundation

/// Reads actual paired facts after metadata finalization. This result grants no startup, writer or admission authority.
enum MachineUpdateInstalledPolicyRead {
    struct Account {
        let accountID: Data
        let ownerUID: UInt32
        let initialization: AuthorityInitializationIntent
        let service: AuthorityServiceConfiguration
        let backend: RuntimeReleaseBackendSource?
        let policy: MachineUpdatePolicyIntentRecord
    }

    /// The native caller retains the machine loan and separately authenticates its current executable.
    static func readNative(scope: PreparationIntentStore.CompletionFinalizationScope, candidate: SignedReleaseEvidence,
        verifyCurrent: () throws -> Void) throws -> [AuthorityJournal.MachineUpdatePolicyBoundary] {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try read(scope: scope, candidate: candidate, verifyCurrent: verifyCurrent, openReadOnly: { account in
            let policy = try account.backend.map { try $0.pair.authority.material.phonePush.journalPolicy(clockEpoch: UUID()) }
            let storage = try AuthorityStorage.openForUpdateHealth(configuration: account.service, gatewayPolicy: policy)
            return try AuthorityJournal(updateHealthStorage: storage, validateSelf: { _ in try verifyCurrent() })
        })
    }

    /// Each factory transfers one reader. Both return paths close it before another account can open.
    static func read(scope: PreparationIntentStore.CompletionFinalizationScope, candidate: SignedReleaseEvidence,
        verifyCurrent: () throws -> Void, openReadOnly: (Account) throws -> AuthorityJournal)
        throws -> [AuthorityJournal.MachineUpdatePolicyBoundary] {
        try verifyCurrent()
        guard case .installed(let actual) = try scope.read(), actual.schemaVersion == 23,
              actual.activation.phase == .finishing else { throw PreparationStoreError.invalidTransition }
        let retainedSource = try scope.readRetainedSource()
        try retainedSource.actual.requireSame(as: actual)
        try actual.installed.validate(candidate: candidate)
        let archive = actual.installed, configuration = try archive.configuration(), backend = try archive.backend()
        let intent = try archive.completionIntent()
        guard intent.policyMarkersRecorded,
              actual.initializations.map(\.accountID) == intent.policies.map({ $0.binding.accountID }) else {
            throw PreparationStoreError.staleRevision
        }
        func verify() throws {
            try verifyCurrent()
            guard case .installed(let current) = try scope.read() else { throw PreparationStoreError.staleRevision }
            try current.requireSame(as: actual)
        }
        var results: [AuthorityJournal.MachineUpdatePolicyBoundary] = []
        for policy in intent.policies {
            try verify()
            guard policy.phase == .recorded,
                  let initial = actual.initializations.first(where: { $0.accountID == policy.binding.accountID }), initial.complete,
                  let metadata = configuration.record.accounts.first(where: { $0.accountID == initial.accountID }),
                  let retained = try configuration.configuration(accountID: initial.accountID) else {
                throw PreparationStoreError.staleRevision
            }
            let service = retained.completion.host.command.presence.wake.request.service
            guard initial.macID == actual.inventory.macID, initial.installationID == actual.inventory.installationID,
                  service.macID == initial.macID, service.accountID == initial.accountID,
                  service.journalDirectory == (initial.journalPath as NSString).deletingLastPathComponent,
                  service.continuityDirectory == (initial.continuityPath as NSString).deletingLastPathComponent else {
                throw PreparationStoreError.staleRevision
            }
            let account = try Account(accountID: initial.accountID, ownerUID: metadata.ownerUID,
                initialization: initial, service: service, backend: backend.capture(accountID: initial.accountID)?.source, policy: policy)
            let boundary = try MachineUpdateCompletionPolicyRead.readPaired(macID: initial.macID,
                accountID: initial.accountID, verifyCurrent: verify, open: { try openReadOnly(account) })
            guard let committed = policy.committedPolicy, let checkpoint = policy.committedCheckpoint,
                  try committed.snapshot() == boundary.policy, try checkpoint == boundary.checkpoint.bytes else {
                throw PreparationStoreError.staleRevision
            }
            results.append(boundary)
        }
        try scope.readRetainedSource().requireSame(as: retainedSource)
        try verify()
        return results
    }
}
