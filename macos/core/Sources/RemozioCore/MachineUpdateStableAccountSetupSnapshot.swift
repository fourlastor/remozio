import Foundation

/// The actual reservation and its provisioning origin. This value grants no key, enrollment, or startup authority.
struct MachineUpdateStableAccountSetupSnapshot: Sendable {
    let source: MachineUpdateStableRuntimeSource
    let owner: LocalAccountIdentity
    let account: MachineUpdateStableRuntimeSource.Account?
    var preparation: AccountPreparationIntent? { account?.preparation }

    init(source: MachineUpdateStableRuntimeSource, owner: LocalAccountIdentity) throws {
        guard owner.uid > 0, owner.uid < UInt32.max else { throw LocalAccountLookupError.invalidScope }
        let account = source.accounts.first { $0.ownerUID == owner.uid }
        if let account {
            guard let preparation = account.preparation else { throw AccountPreparationError.conflict }
            try LocalAccountDirectory.validateOwnership(owner, uid: preparation.ownerUID, directoryID: preparation.directoryID)
        }
        self.source = source; self.owner = owner; self.account = account
    }
    func requireOwner(_ actual: LocalAccountIdentity) throws {
        try LocalAccountDirectory.validateOwnership(actual, uid: owner.uid, directoryID: owner.directoryID)
    }
    func requireSame(as other: Self) throws {
        try requireOwner(other.owner); try source.requireSame(as: other.source)
        guard account == other.account else { throw PreparationStoreError.staleRevision }
    }
    func requireCurrent(machine: PreparationIntentStore, candidate: SignedReleaseEvidence) throws {
        try machine.stableAccountSetupSnapshot(owner: owner, candidate: candidate).requireSame(as: self)
    }
    /// Compares reservation values only. The future writer must prove its authorization and every other row's digest.
    func requireReservation(_ value: AccountPreparationIntent, from before: Self) throws {
        try requireSameInstallation(as: before)
        guard before.account == nil, let account, account.origin == .currentRelease, !account.inInventory,
              account.initialization == nil, account.preparation == value, value.ownerUID == owner.uid,
              value.directoryID == owner.directoryID, value.authorityPublicKey == nil, !value.storagePrepared,
              value.releaseDigest == source.actual.inventory.releaseDigest,
              source.historicalInventory == before.source.historicalInventory,
              source.provisioningHistory == before.source.provisioningHistory,
              source.initializations == before.source.initializations,
              source.preparations.filter({ $0.ownerUID != owner.uid }) == before.source.preparations,
              source.accounts.filter({ $0.ownerUID != owner.uid }) == before.source.accounts else {
            throw PreparationStoreError.staleRevision
        }
    }
    /// Compares storage values only. The future writer must prove its authorization and every other row's digest.
    func requireAccountStorageState(preparation: AccountPreparationIntent, initialization: AuthorityInitializationIntent?,
        from before: Self) throws {
        try requireSameInstallation(as: before)
        guard let prior = before.preparation, let previous = before.account, let account,
              preparation.setupID == prior.setupID, preparation.macID == prior.macID,
              preparation.installationID == prior.installationID, preparation.releaseDigest == prior.releaseDigest,
              preparation.accountID == prior.accountID, preparation.ownerUID == prior.ownerUID,
              preparation.directoryID == prior.directoryID, preparation.policyBytes == prior.policyBytes,
              preparation.initializationBytes == prior.initializationBytes,
              prior.authorityPublicKey == nil || preparation.authorityPublicKey == prior.authorityPublicKey,
              !prior.storagePrepared || preparation.storagePrepared,
              preparation == prior || preparation.revision != prior.revision,
              account.accountID == previous.accountID, account.ownerUID == previous.ownerUID,
              account.origin == previous.origin, account.inInventory == previous.inInventory,
              account.preparation == preparation, account.initialization == initialization,
              previous.initialization == nil || prior.authorityPublicKey != nil,
              !prior.storagePrepared || previous.initialization?.complete == true,
              source.historicalInventory == before.source.historicalInventory,
              source.provisioningHistory == before.source.provisioningHistory,
              source.preparations.filter({ $0.ownerUID != owner.uid }) == before.source.preparations.filter({ $0.ownerUID != owner.uid }),
              source.initializations.filter({ $0.accountID != prior.accountID }) == before.source.initializations.filter({ $0.accountID != prior.accountID }),
              source.accounts.filter({ $0.ownerUID != owner.uid }) == before.source.accounts.filter({ $0.ownerUID != owner.uid }) else {
            throw PreparationStoreError.staleRevision
        }
        if let initialization {
            guard preparation.authorityPublicKey != nil, initialization.macID == preparation.macID,
                  initialization.installationID == preparation.installationID, initialization.accountID == preparation.accountID,
                  initialization.releaseDigest == preparation.releaseDigest,
                  initialization.initializationBytes == preparation.initializationBytes else { throw PreparationStoreError.staleRevision }
            if previous.initialization == nil {
                _ = try MachineUpdateRetainedSetupPromotionNativeSupport.Paths(accountID: preparation.accountID,
                    journalPath: initialization.journalPath, continuityPath: initialization.continuityPath)
            }
        }
        guard !preparation.storagePrepared || initialization?.complete == true else { throw PreparationStoreError.staleRevision }
        if let old = previous.initialization {
            guard let initialization, initialization.setupID == old.setupID,
                  initialization.macID == old.macID, initialization.accountID == old.accountID,
                  initialization.installationID == old.installationID, initialization.releaseDigest == old.releaseDigest,
                  initialization.initializationDigest == old.initializationDigest, initialization.initializationBytes == old.initializationBytes,
                  initialization.journalPath == old.journalPath, initialization.continuityPath == old.continuityPath,
                  old.checkpoint == nil || initialization.checkpoint == old.checkpoint,
                  !old.complete || initialization.complete,
                  initialization == old || initialization.revision != old.revision else { throw PreparationStoreError.staleRevision }
        }
    }
    private func requireSameInstallation(as other: Self) throws {
        try requireOwner(other.owner)
        let actual = source.actual, prior = other.source.actual
        guard actual.schemaVersion == prior.schemaVersion, actual.inventory == prior.inventory,
              actual.activation == prior.activation, actual.admission == prior.admission,
              actual.candidate == prior.candidate,
              actual.installed.record == prior.installed.record, actual.installed.artifacts == prior.installed.artifacts,
              try actual.seal.encoded == prior.seal.encoded else { throw PreparationStoreError.staleRevision }
    }
}
