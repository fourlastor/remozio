import Foundation

/// Protected selection metadata only. Dispatch still needs invocation rights, reservation and native custody.
struct SetupRetainedCallerBinding: CustomStringConvertible, CustomDebugStringConvertible {
    typealias Source = MachineUpdateStableRuntimeSource
    struct Runtime: Equatable {
        let accountID: Data
        let state: RuntimePreparationState
        let activationRecord: Data?
        let jobsRegistered: Bool
    }
    struct State {
        let source: Source
        let runtimes: [Runtime]
        let sharedImport: SharedSetupImportCompatibilitySnapshot?

        func target(peerUID: UInt32) throws -> Source.Account {
            guard peerUID > 0, peerUID < UInt32.max,
                  source.actual.inventory.accounts.filter({ $0.ownerUID == peerUID }).count == 1,
                  runtimes.count == source.accounts.count,
                  Set(runtimes.map(\.accountID)) == Set(source.accounts.map(\.accountID)) else {
                throw AdministrativeSetupError.wrongAccount
            }
            let pending = source.accounts.filter { account in
                guard account.origin == .retained, !account.inInventory else { return false }
                let runtime = runtimes.first { $0.accountID == account.accountID }
                let pendingImport = sharedImport?.records.contains {
                    $0.accountID == account.accountID && $0.phase == SharedSetupImportIntent.Phase.retained.rawValue
                } == true
                return runtime?.state.configurationPublished != true || pendingImport
            }
            guard pending.count == 1, let target = pending.first, target.ownerUID != peerUID,
                  let current = source.actual.inventory.accounts.first(where: { $0.ownerUID == peerUID }),
                  target.accountID != current.accountID else { throw AdministrativeSetupError.wrongAccount }
            return target
        }
        func requireSame(as other: Self) throws {
            try source.requireSame(as: other.source)
            guard runtimes == other.runtimes, sharedImport == other.sharedImport else { throw PreparationStoreError.staleRevision }
        }
    }
    let peer: XPCPeerCredentials
    let incarnation: UUID
    let authorityAccountID: Data
    let authorityOwner: LocalAccountIdentity
    let targetOwner: LocalAccountIdentity
    /// The held native authority policy, not this metadata value, supplies execution floors.
    let publishedAuthorityPolicy: AuthorityCodePolicy
    let entry: MachineUpdateRetainedSetupInitialRuntimeEntry
    private let state: State
    private let appRequirement: String
    var description: String { "SetupRetainedCallerBinding(redacted)" }
    var debugDescription: String { description }

    private init(state: State, peer: XPCPeerCredentials, incarnation: UUID, authorityAccountID: Data,
        authorityOwner: LocalAccountIdentity, targetOwner: LocalAccountIdentity, policy: AuthorityCodePolicy,
        entry: MachineUpdateRetainedSetupInitialRuntimeEntry, appRequirement: String) {
        self.state = state; self.peer = peer; self.incarnation = incarnation; self.authorityAccountID = authorityAccountID
        self.authorityOwner = authorityOwner; self.targetOwner = targetOwner; publishedAuthorityPolicy = policy
        self.entry = entry; self.appRequirement = appRequirement
    }

    /// Owned controls exercise selection only. These values cannot create a native approval or invocation scope.
    static func resolve(state: State, peer: XPCPeerCredentials, incarnation: UUID, accepted: XPCPeerPolicy,
        entry: MachineUpdateRetainedSetupInitialRuntimeEntry,
        lookup: (UInt32) throws -> LocalAccountIdentity) throws -> Self {
        let target = try state.target(peerUID: peer.userID)
        try entry.runtime.setup.source.requireSame(as: state.source)
        guard peer.processID > 0, accepted.expectedUserID == peer.userID,
              accepted.expectedAuditSessionID == nil || accepted.expectedAuditSessionID == peer.auditSessionID,
              let member = state.source.actual.inventory.accounts.first(where: { $0.ownerUID == peer.userID }),
              let current = state.source.accounts.first(where: { $0.accountID == member.accountID }),
              let preparation = current.preparation, preparation.storagePrepared,
              target.accountID == entry.runtime.preparation.accountID,
              target.preparation == entry.runtime.preparation,
              !entry.activation.jobsRegistered, entry.activation.plan == nil else {
            throw AdministrativeSetupError.wrongAccount
        }
        let owner = try lookup(peer.userID), targetOwner = try lookup(target.ownerUID)
        try LocalAccountDirectory.validateOwnership(owner, uid: preparation.ownerUID, directoryID: preparation.directoryID)
        try entry.runtime.setup.requireOwner(targetOwner)
        let (_, host) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(
            runtime: entry.runtime, accountID: member.accountID)
        guard let app = host.codePolicy.entries.first(where: { $0.role == .app && $0.active }) else {
            throw AdministrativeSetupError.wrongAccount
        }
        let expected = try XPCPeerPolicy(teamID: app.teamID, componentIdentifier: app.identifier,
            approvedCodeDirectoryHashes: [app.codeDirectoryHash], expectedUserID: peer.userID)
        guard accepted.requirement == expected.requirement else { throw XPCPeerPolicyError.wrongPeer }
        return .init(state: state, peer: peer, incarnation: incarnation, authorityAccountID: member.accountID,
            authorityOwner: owner, targetOwner: targetOwner, policy: host.codePolicy, entry: entry,
            appRequirement: accepted.requirement)
    }

    func requireSame(as other: Self) throws {
        try state.requireSame(as: other.state); try entry.requireSame(as: other.entry)
        guard peer == other.peer, incarnation == other.incarnation, authorityAccountID == other.authorityAccountID,
              authorityOwner == other.authorityOwner, targetOwner == other.targetOwner,
              try publishedAuthorityPolicy.bytes == other.publishedAuthorityPolicy.bytes, appRequirement == other.appRequirement else {
            throw PreparationStoreError.staleRevision
        }
    }
    func requireCapturedState(_ actual: State, entry: MachineUpdateRetainedSetupInitialRuntimeEntry) throws {
        try actual.requireSame(as: state); try entry.requireSame(as: self.entry)
    }
    /// Only real writer receipts permit this record-only comparison. The returned binding retains the actual new frame.
    func recapturing(state actual: State, entry: MachineUpdateRetainedSetupInitialRuntimeEntry,
        transitions: [PreparationIntentStore.RuntimeMaintenanceTransition], candidate: SignedReleaseEvidence,
        capture: RuntimeMaintenanceStopCapture, lookup: (UInt32) throws -> LocalAccountIdentity) throws -> Self {
        guard let bindingTransition = capture.bindingTransition else { throw RuntimePreparationError.changedScope }
        let window = try PreparationIntentStore.RuntimeMaintenanceTransition.requireChain(transitions,
            from: state.source.actual, to: actual.source.actual, binding: bindingTransition)
        try capture.validate()
        guard try capture.configuration.codePolicy.bytes == publishedAuthorityPolicy.bytes else {
            throw RuntimePreparationError.changedScope
        }
        var a = authorityOwner.directoryID.uuid, b = targetOwner.directoryID.uuid
        guard window.scope.authority.accountID == authorityAccountID, window.scope.authority.ownerUID == authorityOwner.uid,
              window.scope.authority.directoryID == withUnsafeBytes(of: &a, { Data($0) }),
              window.scope.target.accountID == self.entry.runtime.preparation.accountID,
              window.scope.target.ownerUID == targetOwner.uid, window.scope.target.directoryID == withUnsafeBytes(of: &b, { Data($0) }),
              window.scope == capture.window.scope, window.purpose == capture.window.purpose,
              window.shutdownBinding == capture.marker.binding,
              try lookup(authorityOwner.uid) == authorityOwner, try lookup(targetOwner.uid) == targetOwner else {
            throw RuntimePreparationError.changedScope
        }
        let normalized = try Source(actual: state.source.actual, preparations: actual.source.preparations,
            initializations: actual.source.initializations, candidate: candidate)
        try State(source: normalized, runtimes: actual.runtimes, sharedImport: actual.sharedImport).requireSame(as: state)
        let runtime = entry.runtime
        let checked = try MachineUpdateStableRuntimePreparationSnapshot(
            setup: .init(source: normalized, owner: runtime.setup.owner), services: .init(plan: runtime.plan, complete: true),
            state: runtime.state, reservedNumbers: runtime.reservedNumbers)
        try MachineUpdateRetainedSetupInitialRuntimeEntry(runtime: checked, activation: entry.activation,
            intent: entry.intent, candidate: candidate).requireSame(as: self.entry)
        let (_, host) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(runtime: runtime, accountID: authorityAccountID)
        guard try host.codePolicy.bytes == publishedAuthorityPolicy.bytes else { throw RuntimePreparationError.changedScope }
        return .init(state: actual, peer: peer, incarnation: incarnation, authorityAccountID: authorityAccountID,
            authorityOwner: authorityOwner, targetOwner: targetOwner, policy: host.codePolicy, entry: entry, appRequirement: appRequirement)
    }

}
