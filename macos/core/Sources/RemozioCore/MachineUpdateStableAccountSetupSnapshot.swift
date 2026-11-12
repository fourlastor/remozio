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
        try requireOwner(before.owner)
        let actual = source.actual, prior = before.source.actual
        guard actual.schemaVersion == prior.schemaVersion, actual.inventory == prior.inventory,
              actual.activation == prior.activation, actual.admission == prior.admission,
              actual.candidate == prior.candidate,
              actual.installed.record == prior.installed.record, actual.installed.artifacts == prior.installed.artifacts,
              try actual.seal.encoded == prior.seal.encoded,
              before.account == nil, let account, account.origin == .currentRelease, !account.inInventory,
              account.initialization == nil, account.preparation == value, value.ownerUID == owner.uid,
              value.directoryID == owner.directoryID, value.authorityPublicKey == nil, !value.storagePrepared,
              value.releaseDigest == actual.inventory.releaseDigest,
              source.historicalInventory == before.source.historicalInventory,
              source.provisioningHistory == before.source.provisioningHistory,
              source.initializations == before.source.initializations,
              source.preparations.filter({ $0.ownerUID != owner.uid }) == before.source.preparations,
              source.accounts.filter({ $0.ownerUID != owner.uid }) == before.source.accounts else {
            throw PreparationStoreError.staleRevision
        }
    }
}
