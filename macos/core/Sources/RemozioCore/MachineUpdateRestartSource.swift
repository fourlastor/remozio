import Darwin
import Foundation
import RemozioProtocol

struct MachineUpdateReplacementContext: Equatable {
    let activation: MachineUpdateActivationRecord
    let inventory: InstallationInventory
    let candidate: UpdateSchedulingCandidateRecord
    let admission: UpdateAdmissionRegistrationRecord
    let replacement: MachineUpdateReplacementRecord?
    let runtime: RuntimeReleaseCompatibilitySnapshot.Inputs
}

/// Historical machine inputs only. This snapshot grants no new release, restart, health or completion authority.
struct MachineUpdateRestartSource: Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    struct Account: Equatable {
        let accountID: Data
        let ownerUID: UInt32
        let preparation: AccountPreparationIntent?
        let initialization: AuthorityInitializationIntent?
        let services: ServiceAccountPlan?
        let servicesComplete: Bool
    }
    let replacement: MachineUpdateReplacementContext
    let accounts: [Account]
    let provisioningHistory: MachineUpdateProvisioningHistory?
    init(replacement: MachineUpdateReplacementContext, accounts: [Account],
        provisioningHistory: MachineUpdateProvisioningHistory? = nil) {
        self.replacement = replacement; self.accounts = accounts; self.provisioningHistory = provisioningHistory
    }
    var description: String { "MachineUpdateRestartSource(redacted)" }
    var debugDescription: String { description }

    /// Keeps the existing runtime digest unchanged and also covers unfinished accounts without runtime material.
    func accountDigest(accountID: Data) throws -> Data {
        guard let account = accounts.first(where: { $0.accountID == accountID }) else { throw RuntimePreparationError.changedScope }
        let runtime = replacement.runtime.runtimes.first { $0.reference.services.accountID == accountID }
        let value = CBORValue.map([0: .bytes(account.accountID), 1: .unsigned(UInt64(account.ownerUID)),
            2: try account.preparation.map { .bytes(try $0.bytes) } ?? .null,
            3: try account.initialization.map { .bytes(try $0.bytes) } ?? .null,
            4: try account.services.map { .bytes(try $0.encoded) } ?? .null,
            5: .boolean(account.servicesComplete), 6: try runtime.map { .bytes(try $0.reference.encoded) } ?? .null,
            7: .boolean(runtime?.configurationPublished ?? false), 8: runtime?.activationRecord.map(CBORValue.bytes) ?? .null,
            9: .boolean(runtime?.jobsRegistered ?? false)])
        let bytes = try DeterministicCBOR.encode(value, limits: .init(maxBytes: 1_048_576, maxDepth: 1, maxItems: 21))
        return MachineUpdateActivationRecord.digest(Data("Remozio/RuntimeReleaseSource/v1\0".utf8) + bytes)
    }


    static func capture(activation: MachineUpdateActivationRecord, machineDirectory: ReleaseDestinationLease,
                        store: PreparationIntentStore) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try store.machineUpdateRestartSource(activation, directory: machineDirectory)
    }

}
