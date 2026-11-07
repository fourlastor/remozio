import Foundation

/// Captures pinned admission before check-in closes the machine writer. It does not create files or authorize an update.
struct AuthorityUpdateAdmissionStartup: Sendable {
    let registration: UpdateAdmissionRegistrationRecord
    let boundary: UpdateAdmissionBoundary
    let recovery: MachineUpdateAdmissionRecovery
    private let initial: MachineUpdateAdmissionState

    static func capture(machine: PreparationIntentStore, macID: Data, installationID: Data, accountID: Data,
        activity: ReleaseActivityBarrier, readCurrent: @escaping @Sendable () throws -> MachineUpdateAdmissionState,
        openBarrier: (UpdateAdmissionScope, PreparationFileIdentity) throws -> UpdateAdmissionBarrier) throws -> Self? {
        guard macID.count == 16, installationID.count == 16, accountID.count == 16 else { throw RuntimePreparationError.changedScope }
        let initial = try machine.updateAdmissionState()
        guard let registration = initial.registration else { return nil }
        guard let inventory = initial.inventory, inventory.macID == macID, inventory.installationID == installationID,
              registration.macID == macID, registration.installationID == installationID,
              inventory.accounts.contains(where: { $0.accountID == accountID }) else { throw RuntimePreparationError.changedScope }
        let global = try openBarrier(.machine, registration.machine)
        let account = try registration.accounts.first(where: { $0.accountID == accountID }).map {
            try openBarrier(.account(accountID), $0.identity)
        }
        let recovery = try MachineUpdateAdmissionRecovery(initial: initial, macID: macID, installationID: installationID,
            accountID: accountID, coordinator: .init(activity: activity, admission: global), readCurrent: readCurrent)
        let boundary = try UpdateAdmissionBoundary(machine: global, account: account, verifyAdmission: { try recovery.prepareAdmission() })
        guard account == nil || boundary.accountID == accountID else { throw RuntimePreparationError.changedScope }
        let captured = Self(registration: registration, boundary: boundary, recovery: recovery, initial: initial)
        try captured.requireCurrent(machine: machine)
        return captured
    }
    func requireCurrent(machine: PreparationIntentStore) throws {
        guard try machine.updateAdmissionState() == initial else { throw RuntimePreparationError.changedScope }
        try boundary.validate(); try recovery.validate()
    }
}
