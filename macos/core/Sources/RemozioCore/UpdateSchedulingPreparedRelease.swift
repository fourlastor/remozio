import Darwin
import Foundation
import RemozioProtocol

enum UpdateSchedulingPreparedReleaseError: Error, Equatable {
    case wrongScope, changedPreparation, changedPolicy, wrongUpdate
}

/// Binds one inspected inactive copy to retained installation state. This value grants no scheduling or activation authority.
struct UpdateSchedulingPreparedRelease {
    let updateID: Data
    private let macID: Data
    private let accountID: Data
    private let record: PreparationIntentRecord
    private let runtime: RuntimeReleaseCompatibilitySnapshot
    private let policy: AuthorityCodePolicy

    private init(updateID: Data, macID: Data, accountID: Data, record: PreparationIntentRecord,
                 runtime: RuntimeReleaseCompatibilitySnapshot, policy: AuthorityCodePolicy) {
        self.updateID = updateID; self.macID = macID; self.accountID = accountID
        self.record = record; self.runtime = runtime; self.policy = policy
    }

    static func capture(attemptID: UUID, macID: Data, accountID: Data, destination: ReleaseDestinationLease,
                        store: PreparationIntentStore, readPolicy: () throws -> AuthorityCodePolicy) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try captureInLease(attemptID: attemptID, macID: macID, accountID: accountID,
            destination: destination, store: store, readPolicy: readPolicy)
    }

    // Ordinary-owner fixtures use the same retained records and copy checks with synthetic signature evidence.
    static func captureInLease(attemptID: UUID, macID: Data, accountID: Data, destination: ReleaseDestinationLease,
        store: PreparationIntentStore, readPolicy: () throws -> AuthorityCodePolicy,
        inspect: (URL, String, String) throws -> SignedReleaseEvidence = {
            try SignedReleaseInspection.inspect($0, teamID: $1, appIdentifier: $2)
        }) throws -> Self {
        let runtime = try RuntimeReleaseCompatibilitySnapshot.capture(machine: store)
        try requireScope(macID: macID, accountID: accountID, runtime: runtime)
        guard let record = try store.records().first(where: { $0.id == attemptID }),
              record.phase == .copyRecorded, let digest = record.copyDigest else {
            throw UpdateSchedulingPreparedReleaseError.changedPreparation
        }
        let value = Self(updateID: digest, macID: macID, accountID: accountID,
            record: record, runtime: runtime, policy: try readPolicy())
        _ = try value.validateInLease(macID: macID, accountID: accountID, updateID: digest,
            destination: destination, store: store, readPolicy: readPolicy, inspect: inspect)
        return value
    }

    func validate(macID: Data, accountID: Data, updateID: Data, destination: ReleaseDestinationLease,
                  store: PreparationIntentStore, readPolicy: () throws -> AuthorityCodePolicy) throws -> DurableInactiveCopyEvidence {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try validateInLease(macID: macID, accountID: accountID, updateID: updateID,
            destination: destination, store: store, readPolicy: readPolicy)
    }

    /// Reinspect before using an offer. A machine coordinator must separately serialize candidate selection and account commits.
    func validateInLease(macID: Data, accountID: Data, updateID: Data, destination: ReleaseDestinationLease,
        store: PreparationIntentStore, readPolicy: () throws -> AuthorityCodePolicy,
        inspect: (URL, String, String) throws -> SignedReleaseEvidence = {
            try SignedReleaseInspection.inspect($0, teamID: $1, appIdentifier: $2)
        }) throws -> DurableInactiveCopyEvidence {
        guard self.macID == macID, self.accountID == accountID else { throw UpdateSchedulingPreparedReleaseError.wrongScope }
        guard self.updateID == updateID else { throw UpdateSchedulingPreparedReleaseError.wrongUpdate }
        func unchanged() throws {
            try runtime.requireCurrent(machine: store)
            guard try store.records().first(where: { $0.id == record.id }) == record else {
                throw UpdateSchedulingPreparedReleaseError.changedPreparation
            }
        }
        func currentPolicy() throws -> AuthorityCodePolicy {
            try unchanged()
            let current = try readPolicy()
            guard current == policy else { throw UpdateSchedulingPreparedReleaseError.changedPolicy }
            try unchanged()
            return current
        }
        try unchanged()
        let evidence = try DurableReleasePreparation.validateRuntimeCompatibilityInLease(attemptID: record.id,
            destination: destination, store: store, readPolicy: currentPolicy, inspect: inspect)
        guard try DurableReleasePreparation.digest(evidence.copy.signature) == self.updateID else {
            throw UpdateSchedulingPreparedReleaseError.wrongUpdate
        }
        try unchanged()
        return evidence
    }

    private static func requireScope(macID: Data, accountID: Data, runtime: RuntimeReleaseCompatibilitySnapshot) throws {
        guard macID.count == 16, accountID.count == 16, runtime.inputs.macID == macID,
              let bytes = runtime.inputs.inventory else { throw UpdateSchedulingPreparedReleaseError.wrongScope }
        let inventory = try InstallationInventory.decode(bytes, expectedMacID: macID)
        guard inventory.macID == macID, inventory.accounts.contains(where: { $0.accountID == accountID }),
              inventory.services.contains(where: { $0.accountID == accountID && $0.role == .authority && $0.kind == .daemon }) else {
            throw UpdateSchedulingPreparedReleaseError.wrongScope
        }
    }
}


/// Exists only inside a verified machine selection. It cannot be decoded, renewed or transferred across a process boundary.
final class LiveUpdateSchedulingCandidate: CustomStringConvertible, CustomDebugStringConvertible {
    let updateID: Data
    let generation: UInt64
    private let macID: Data
    private let accountID: Data
    private let designatedOwner: Data?
    private let activationPhase: MachineUpdateActivationRecord.Phase?
    private let processID = getpid()
    private let lock = NSLock()
    private var validation: (() throws -> Void)?
    fileprivate init(record: UpdateSchedulingCandidateRecord, macID: Data, accountID: Data, designatedOwner: Data?,
                     activationPhase: MachineUpdateActivationRecord.Phase?,
                     validate: @escaping () throws -> Void) {
        updateID = record.updateID; generation = record.generation
        self.macID = macID; self.accountID = accountID; self.designatedOwner = designatedOwner; validation = validate
        self.activationPhase = activationPhase
    }
    func requireCurrent(macID: Data, accountID: Data) throws {
        guard getpid() == processID else { throw UpdateSchedulingCandidateLeaseError.expired }
        guard self.macID == macID, self.accountID == accountID else { throw UpdateSchedulingCandidateLeaseError.wrongScope }
        try lock.withLock {
            guard let validation else { throw UpdateSchedulingCandidateLeaseError.expired }
            try validation()
        }
    }
    func requireAction(_ action: UpdateSchedulingAction, macID: Data, accountID: Data) throws {
        try requireCurrent(macID: macID, accountID: accountID)
        if activationPhase?.irreversible == true { throw MachineUpdateActivationError.tooLate }
        if action == .deferUpdate, designatedOwner != accountID {
            throw UpdateSchedulingCandidateLeaseError.notDesignatedUpdateOwner
        }
    }
    var description: String { "LiveUpdateSchedulingCandidate(redacted)" }
    var debugDescription: String { description }
    fileprivate func retire() {
        guard getpid() == processID else { return }
        lock.withLock { validation = nil }
    }
    deinit { retire() }
}

extension UpdateSchedulingPreparedRelease {
    func selectCurrent(macID: Data, accountID: Data, destination: ReleaseDestinationLease,
                       store: PreparationIntentStore, replacing expected: UpdateSchedulingCandidateRecord?,
                       readPolicy: () throws -> AuthorityCodePolicy) throws -> UpdateSchedulingCandidateRecord {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try selectCurrentInLease(macID: macID, accountID: accountID, destination: destination,
            store: store, replacing: expected, readPolicy: readPolicy)
    }
    func selectCurrentInLease(macID: Data, accountID: Data, destination: ReleaseDestinationLease,
        store: PreparationIntentStore, replacing expected: UpdateSchedulingCandidateRecord?,
        readPolicy: () throws -> AuthorityCodePolicy,
        inspect: (URL, String, String) throws -> SignedReleaseEvidence = {
            try SignedReleaseInspection.inspect($0, teamID: $1, appIdentifier: $2)
        }) throws -> UpdateSchedulingCandidateRecord {
        _ = try validateInLease(macID: macID, accountID: accountID, updateID: updateID,
            destination: destination, store: store, readPolicy: readPolicy, inspect: inspect)
        let value = try store.selectUpdateCandidate(preparation: record, runtime: runtime.inputs, replacing: expected)
        _ = try validateInLease(macID: macID, accountID: accountID, updateID: updateID,
            destination: destination, store: store, readPolicy: readPolicy, inspect: inspect)
        guard try store.updateCandidate() == value else { throw PreparationStoreError.staleRevision }
        return value
    }

    /// Hold this boundary through the account's checkpointed commit. The callback cannot await or reenter the machine store.
    func withCurrentCandidate<Value: Sendable>(macID: Data, accountID: Data, expected: UpdateSchedulingCandidateRecord,
        destination: ReleaseDestinationLease, store: PreparationIntentStore, readPolicy: () throws -> AuthorityCodePolicy,
        _ body: () throws -> Value) throws -> Value {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try withCurrentCandidateInLease(macID: macID, accountID: accountID, expected: expected,
            destination: destination, store: store, readPolicy: readPolicy, body)
    }
    func withCurrentCandidateInLease<Value: Sendable>(macID: Data, accountID: Data, expected: UpdateSchedulingCandidateRecord,
        destination: ReleaseDestinationLease, store: PreparationIntentStore, readPolicy: () throws -> AuthorityCodePolicy,
        inspect: (URL, String, String) throws -> SignedReleaseEvidence = {
            try SignedReleaseInspection.inspect($0, teamID: $1, appIdentifier: $2)
        }, _ body: () throws -> Value) throws -> Value {
        try withCurrentCandidateLeaseInLease(macID: macID, accountID: accountID, expected: expected,
            destination: destination, store: store, readPolicy: readPolicy, inspect: inspect) { _ in try body() }
    }

    func withCurrentCandidateLease<Value: Sendable>(macID: Data, accountID: Data, expected: UpdateSchedulingCandidateRecord,
        destination: ReleaseDestinationLease, store: PreparationIntentStore, readPolicy: () throws -> AuthorityCodePolicy,
        _ body: (LiveUpdateSchedulingCandidate) throws -> Value) throws -> Value {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try withCurrentCandidateLeaseInLease(macID: macID, accountID: accountID, expected: expected,
            destination: destination, store: store, readPolicy: readPolicy, body)
    }

    func withCurrentCandidateLeaseInLease<Value: Sendable>(macID: Data, accountID: Data, expected: UpdateSchedulingCandidateRecord,
        destination: ReleaseDestinationLease, store: PreparationIntentStore, readPolicy: () throws -> AuthorityCodePolicy,
        inspect: (URL, String, String) throws -> SignedReleaseEvidence = {
            try SignedReleaseInspection.inspect($0, teamID: $1, appIdentifier: $2)
        }, _ body: (LiveUpdateSchedulingCandidate) throws -> Value) throws -> Value {
        guard expected.macID == macID, expected.preparation == record, expected.updateID == updateID else {
            throw UpdateSchedulingPreparedReleaseError.changedPreparation
        }
        _ = try validateInLease(macID: macID, accountID: accountID, updateID: updateID,
            destination: destination, store: store, readPolicy: readPolicy, inspect: inspect)
        let registration = try runtime.inputs.updateAdmissionRegistration.map(UpdateAdmissionRegistrationRecord.decode)
        let activation = try runtime.inputs.machineUpdateActivation.map(MachineUpdateActivationRecord.decode)
        let value = try store.withValidatedUpdateCandidate(expected, runtime: runtime.inputs) { validate in
            let candidate = LiveUpdateSchedulingCandidate(record: expected, macID: macID, accountID: accountID,
                designatedOwner: registration?.designatedOwner, activationPhase: activation?.phase, validate: validate)
            defer { candidate.retire() }
            return try body(candidate)
        }
        _ = try validateInLease(macID: macID, accountID: accountID, updateID: updateID,
            destination: destination, store: store, readPolicy: readPolicy, inspect: inspect)
        return try store.withSelectedUpdateCandidate(expected, runtime: runtime.inputs) { value }
    }
}
