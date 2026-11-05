import Darwin
import Foundation

enum UpdateAdmissionOwnerSelection { case retain, designate(Data) }

/// Joins protected files to their durable references. This operation does not close admission or activate an update.
enum UpdateAdmissionRegistrationProvisioning {
    static func prepare(machineDirectory: String, macID: Data, accountID: Data, activity: ReleaseActivityToken,
        store: PreparationIntentStore, installedRelease: SignedReleaseEvidence, policy: AuthorityCodePolicy,
        replacing expected: UpdateAdmissionRegistrationRecord?, ownerSelection: UpdateAdmissionOwnerSelection = .retain,
        verifyCurrent: @escaping () throws -> Void) throws -> UpdateAdmissionRegistrationRecord {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try store.validateStorageLease(nativeDirectory: machineDirectory)
        let directory = try ReleaseDestinationLease.acquire(path: machineDirectory)
        defer { directory.close() }
        return try prepareInLease(directory: directory, owner: 0, macID: macID, accountID: accountID, activity: activity,
            store: store, installedRelease: installedRelease, policy: policy, replacing: expected,
            ownerSelection: ownerSelection, openDirectory: { try ReleaseDestinationLease.acquire(path: machineDirectory) },
            verifyCurrent: verifyCurrent)
    }

    // Same-owner files exercise the actual commit boundary. They cannot grant installed Root authority.
    static func prepareInLease(directory: ReleaseDestinationLease, owner: uid_t, macID: Data, accountID: Data,
        activity: ReleaseActivityToken, store: PreparationIntentStore, installedRelease: SignedReleaseEvidence,
        policy: AuthorityCodePolicy, replacing expected: UpdateAdmissionRegistrationRecord?,
        ownerSelection: UpdateAdmissionOwnerSelection = .retain, openDirectory: @escaping () throws -> ReleaseDestinationLease,
        verifyCurrent: @escaping () throws -> Void, didStage: (UpdateAdmissionFileProvisioning.Stage) throws -> Void = { _ in }) throws -> UpdateAdmissionRegistrationRecord {
        guard getuid() == owner, geteuid() == owner, macID.count == 16, accountID.count == 16 else {
            throw UpdateAdmissionProvisioningError.invalidScope
        }
        try store.validateUpdateAdmissionDirectory(directory); try activity.validateExclusive(in: directory)
        try ReleaseCompatibilityPreflight.validate(installedRelease, policy: policy,
            requirements: .init(formats: UpdateAdmissionRegistrationRecord.requirements, requests: []))
        let runtime = try store.retainedRuntimeCompatibilityInputs()
        guard runtime.schemaVersion >= 16, runtime.macID == macID, let bytes = runtime.inventory else {
            throw RuntimePreparationError.changedScope
        }
        try RuntimeReleaseCompatibilitySnapshot.capture(machine: store).validate(installedRelease, policy: policy, machine: store)
        let inventory = try InstallationInventory.decode(bytes, expectedMacID: macID)
        try inventory.compareRelease(installedRelease)
        guard inventory.accounts.contains(where: { $0.accountID == accountID }) else { throw RuntimePreparationError.changedScope }
        let designatedOwner: Data?
        switch ownerSelection {
        case .retain: designatedOwner = expected?.designatedOwner
        case .designate(let selected):
            guard selected.count == 16, expected?.designatedOwner == nil || expected?.designatedOwner == selected,
                  inventory.accounts.contains(where: { $0.accountID == selected }),
                  selected == accountID || expected?.accounts.contains(where: { $0.accountID == selected }) == true else {
                throw PreparationStoreError.invalidTransition
            }
            designatedOwner = selected
        }
        func verify() throws {
            try activity.validateExclusive(in: directory); try directory.validate(); try verifyCurrent()
        }
        func verifyFiles(_ value: UpdateAdmissionRegistrationRecord) throws {
            try verify()
            let references: [(UpdateAdmissionScope, PreparationFileIdentity)] = [(.machine, value.machine)]
                + value.accounts.map { (.account($0.accountID), $0.identity) }
            for (scope, identity) in references {
                let opened = try openDirectory()
                defer { opened.close() }
                do {
                    let baseline = try directory.preparationAncestry().last, actual = try opened.preparationAncestry().last
                    guard baseline != nil, baseline == actual else { throw RuntimePreparationError.changedScope }
                    let barrier = try UpdateAdmissionBarrier(directory: opened, owner: owner, expected: identity, scope: scope)
                    try barrier.validate()
                } catch { opened.close(); throw error }
            }
            try verify()
        }
        return try store.prepareUpdateAdmissionRegistration(directory: directory, replacing: expected, runtime: runtime,
            prepare: { previous, validateMachine in
                try validateMachine(); try verify()
                if let previous { try verifyFiles(previous) }
                var pinned: [UpdateAdmissionScope: PreparationFileIdentity] = [:]
                if let previous { pinned[.machine] = previous.machine }
                if let account = previous?.accounts.first(where: { $0.accountID == accountID }) { pinned[.account(accountID)] = account.identity }
                let files = try UpdateAdmissionFileProvisioning.prepare(directory: directory, owner: owner,
                    accountID: accountID, activity: activity, mode: .createIfAbsent, expected: pinned, verifyCurrent: {
                        try validateMachine(); try verify()
                    }, didStage: didStage)
                guard let machine = files.identities[.machine], let account = files.identities[.account(accountID)] else {
                    throw UpdateAdmissionProvisioningError.invalidScope
                }
                var accounts = previous?.accounts ?? []
                if !accounts.contains(where: { $0.accountID == accountID }) { accounts.append(.init(accountID: accountID, identity: account)) }
                if let previous, previous.machine == machine, previous.accounts == accounts, previous.designatedOwner == designatedOwner {
                    return previous
                }
                return try .init(macID: macID, installationID: inventory.installationID, machine: machine,
                    accounts: accounts, designatedOwner: designatedOwner)
            }, verifyFiles: verifyFiles)
    }
}
