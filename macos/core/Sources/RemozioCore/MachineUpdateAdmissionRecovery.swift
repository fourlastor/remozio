import Darwin
import Foundation

/// One machine transaction supplies these inputs. A snapshot grants no live lock or activation authority.
struct MachineUpdateAdmissionState: Equatable, Sendable {
    let inventory: InstallationInventory?
    let registration: UpdateAdmissionRegistrationRecord?
    let activation: MachineUpdateActivationRecord?

    func requireScope(macID: Data, installationID: Data, accountID: Data,
                      expected: UpdateAdmissionRegistrationRecord) throws {
        guard let inventory, let registration,
              inventory.macID == macID, inventory.installationID == installationID,
              inventory.accounts.contains(where: { $0.accountID == accountID }),
              registration.macID == macID, registration.installationID == installationID,
              registration.machine == expected.machine,
              registration.accounts.first(where: { $0.accountID == accountID }) ==
                expected.accounts.first(where: { $0.accountID == accountID }) else {
            throw RuntimePreparationError.changedScope
        }
    }


}

/// Restores closed admission and checks durable state around every new admission lease.
/// Its reader must close the machine writer before returning. Existing work keeps its activity references.
final class MachineUpdateAdmissionRecovery: @unchecked Sendable {
    private let lock = NSLock()
    private let processID = getpid()
    private let macID: Data
    private let installationID: Data
    private let accountID: Data
    private let registration: UpdateAdmissionRegistrationRecord
    private let coordinator: UpdateActivationAdmission
    private let readCurrent: @Sendable () throws -> MachineUpdateAdmissionState
    private var drain: UpdateAdmissionDrain?
    private var operationActive = false
    private var closed = false

    init(initial: MachineUpdateAdmissionState, macID: Data, installationID: Data, accountID: Data,
         coordinator: UpdateActivationAdmission,
         readCurrent: @escaping @Sendable () throws -> MachineUpdateAdmissionState) throws {
        guard let registration = initial.registration else { throw RuntimePreparationError.changedScope }
        self.macID = macID; self.installationID = installationID; self.accountID = accountID
        self.registration = registration; self.coordinator = coordinator; self.readCurrent = readCurrent
        try coordinator.requireMachineAdmission(registration.machine)
        try withOperation { try reconcile(initial) }
    }

    func validate() throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        let retained = try lock.withLock {
            guard !closed else { throw JournalLeaseError.invalidated }
            return drain
        }
        try retained?.withClosedAdmission {}
    }

    /// Run before the kernel admission acquisition and again while that shared lease is held.
    func prepareAdmission() throws {
        try withOperation {
            let current = try readCurrent()
            try reconcile(current)
            if current.activation?.phase.blocksMachineWrites == true { throw UpdateAdmissionBarrierError.busy }
        }
    }

    /// Transfers only a restored gate for this exact attempt. The caller still needs quiescence and copy validation.
    func takeRestoredDrain(expected: MachineUpdateActivationRecord) throws -> UpdateAdmissionDrain {
        try withOperation {
            let current = try readCurrent()
            try current.requireScope(macID: macID, installationID: installationID, accountID: accountID, expected: registration)
            guard current.activation == expected, expected.phase.blocksMachineWrites else { throw PreparationStoreError.staleRevision }
            try reconcile(current)
            return try lock.withLock {
                guard !closed else { throw JournalLeaseError.invalidated }
                guard let drain else { throw UpdateAdmissionBarrierError.busy }
                self.drain = nil
                return drain
            }
        }
    }

    private func reconcile(_ current: MachineUpdateAdmissionState) throws {
        try current.requireScope(macID: macID, installationID: installationID, accountID: accountID, expected: registration)
        if current.activation?.phase.blocksMachineWrites == true {
            if let retained = lock.withLock({ drain }) { try retained.withClosedAdmission {}; return }
            try coordinator.requireMachineAdmission(registration.machine)
            let acquired: UpdateAdmissionDrain
            do { acquired = try coordinator.beginDrain() }
            catch UpdateAdmissionBarrierError.busy { return }
            try lock.withLock {
                guard !closed else { acquired.close(); throw JournalLeaseError.invalidated }
                drain = acquired
            }
        } else {
            let old = lock.withLock { let old = drain; drain = nil; return old }
            old?.close()
        }
    }

    private func withOperation<Value>(_ body: () throws -> Value) throws -> Value {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock {
            guard !closed else { throw JournalLeaseError.invalidated }
            guard !operationActive else { throw UpdateAdmissionBarrierError.busy }
            operationActive = true
        }
        defer {
            lock.withLock {
                operationActive = false
                if closed { drain?.close(); drain = nil }
            }
        }
        let result = try body()
        try lock.withLock { guard !closed else { throw JournalLeaseError.invalidated } }
        return result
    }
    func close() {
        guard getpid() == processID else { return }
        lock.withLock {
            closed = true
            if !operationActive { drain?.close(); drain = nil }
        }
    }
    deinit { close() }
}
