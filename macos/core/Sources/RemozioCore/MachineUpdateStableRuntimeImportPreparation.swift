import CryptoKit
import Darwin
import Foundation

/// Joins retained import inputs with stable publication. The publication owner verifies actual runtime storage and files.
enum MachineUpdateStableRuntimeImportPreparation {
    typealias Verify = () throws -> Void
    struct RelaySelection: Equatable {
        let plan: SharedSetupImportRelayPlan?
        let snapshot: SharedSetupImportRelayStorage.Snapshot?
        init(plan: SharedSetupImportRelayPlan?, snapshot: SharedSetupImportRelayStorage.Snapshot?) throws {
            guard (plan == nil) == (snapshot == nil) else { throw SharedSetupImportError.conflict }
            if let plan, let snapshot {
                guard snapshot.digest == Data(SHA256.hash(data: plan.bytes)) else { throw SharedSetupImportError.conflict }
            }
            self.plan = plan; self.snapshot = snapshot
        }
        static func read(_ expected: SharedSetupImportIntent, directory: ProtectedSetupDirectory, owner: uid_t) throws -> Self {
            try .init(plan: SharedSetupImportRelayStorage.read(expected: expected, directory: directory, owner: owner),
                snapshot: SharedSetupImportRelayStorage.snapshot(expected: expected, directory: directory, owner: owner))
        }
    }
    typealias Publish = (SharedSetupImportIntent?, SharedSetupImportRelayPlan?, @escaping Verify) throws -> RuntimePreparationState
    typealias Validate = (SharedSetupImportIntent?, SharedSetupImportRelayPlan?, RuntimePreparationState, @escaping Verify) throws -> Void

    static func prepareNative(machine: PreparationIntentStore, expected: MachineUpdateStableRuntimePreparationSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        fileCustodyAccepted: Bool, verifyCurrent: @escaping (MachineUpdateStableRuntimePreparationSnapshot) throws -> Void,
        publish: Publish, validatePublished: Validate) throws -> RuntimePreparationState {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard directory.path == MachineBootstrap.machineDirectory,
              expected.setup.source.actual.inventory.bundlePath == MachineBootstrap.bundlePath else {
            throw MachineUpdateActivationError.wrongBoundary
        }
        return try prepare(machine: machine, expected: expected, candidate: candidate, directory: directory, admission: admission,
            fileCustodyAccepted: fileCustodyAccepted, verifyCurrent: verifyCurrent, publish: publish, validatePublished: validatePublished)
    }
    static func prepare(machine: PreparationIntentStore, expected: MachineUpdateStableRuntimePreparationSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        fileCustodyAccepted: Bool, verifyCurrent: @escaping (MachineUpdateStableRuntimePreparationSnapshot) throws -> Void,
        publish: Publish, validatePublished: Validate) throws -> RuntimePreparationState {
        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
        try expected.requireCurrent(machine: machine, candidate: candidate)
        return try machine.withSharedImportJournal { journal in
            if let journal {
                return try machine.withSharedImportSnapshot(journal: journal) { relayDirectory, owner in
                    try prepareInJournal(machine: machine, expected: expected, candidate: candidate, directory: directory,
                        admission: admission, journal: journal, fileCustodyAccepted: fileCustodyAccepted, verifyCurrent: verifyCurrent,
                        readRelay: { try RelaySelection.read($0, directory: relayDirectory, owner: owner) },
                        publish: publish, validatePublished: validatePublished)
                }
            }
            return try prepareInJournal(machine: machine, expected: expected, candidate: candidate, directory: directory,
                admission: admission, journal: journal, fileCustodyAccepted: fileCustodyAccepted, verifyCurrent: verifyCurrent,
                readRelay: { _ in throw SharedSetupImportError.conflict }, publish: publish, validatePublished: validatePublished)
        }
    }
    /// Owned controls use real journals. The verification callback checks imports and admission without nesting a machine transaction.
    static func prepareInJournal(machine: PreparationIntentStore, expected: MachineUpdateStableRuntimePreparationSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        journal: SharedSetupImportJournal?, fileCustodyAccepted: Bool,
        verifyCurrent: @escaping (MachineUpdateStableRuntimePreparationSnapshot) throws -> Void,
        readRelay: @escaping (SharedSetupImportIntent) throws -> RelaySelection,
        publish: Publish, validatePublished: Validate) throws -> RuntimePreparationState {
        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
        if let journal {
            return try machine.withSharedImportSnapshot(journal: journal) { _, _ in
                try prepareCaptured(machine: machine, expected: expected, candidate: candidate, directory: directory,
                    admission: admission, journal: journal, verifyCurrent: verifyCurrent, readRelay: readRelay,
                    publish: publish, validatePublished: validatePublished)
            }
        }
        return try prepareCaptured(machine: machine, expected: expected, candidate: candidate, directory: directory,
            admission: admission, journal: nil, verifyCurrent: verifyCurrent, readRelay: readRelay,
            publish: publish, validatePublished: validatePublished)
    }
    private static func prepareCaptured(machine: PreparationIntentStore, expected: MachineUpdateStableRuntimePreparationSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        journal: SharedSetupImportJournal?, verifyCurrent: @escaping (MachineUpdateStableRuntimePreparationSnapshot) throws -> Void,
        readRelay: @escaping (SharedSetupImportIntent) throws -> RelaySelection,
        publish: Publish, validatePublished: Validate) throws -> RuntimePreparationState {
        let processID = getpid(), thread = pthread_self()
        var active = true
        weak var writer = machine
        defer { active = false; writer = nil }
        try expected.requireCurrent(machine: machine, candidate: candidate)
        let scope = try importScope(expected)
        var retained = try journal?.current(scope: scope)
        let relay = try retained.map(readRelay)
        if let retained {
            if retained.recipe.cloudflare != nil {
                guard let plan = relay?.plan else { throw RuntimePreparationError.incomplete }
                try plan.validate(expected: retained)
            } else { guard relay?.plan == nil else { throw SharedSetupImportError.conflict } }
            if retained.phase != .retained {
                guard expected.state.configurationPublished, expected.state.reference != nil else { throw RuntimePreparationError.incomplete }
            }
        }
        func verify() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            guard active, writer != nil else { throw JournalLeaseError.invalidated }
            try admission.validateMachineBoundary(directory: directory, expected: expected.setup.source.actual.admission.machine)
            try verifyCurrent(expected)
            guard try journal?.current(scope: scope) == retained else { throw SharedSetupImportError.wrongScope }
            if let retained { guard try readRelay(retained) == relay else { throw SharedSetupImportError.conflict } }
            try admission.validateMachineBoundary(directory: directory, expected: expected.setup.source.actual.admission.machine)
        }
        try verify()
        let result = try publish(retained, relay?.plan, verify)
        try verify()
        var actual = try machine.stableRuntimePreparationSnapshot(owner: expected.setup.owner, candidate: candidate)
        try actual.requirePublished(from: expected)
        guard actual.state == result else { throw RuntimePreparationError.changedScope }
        try validatePublished(retained, relay?.plan, result, verify)
        try verify(); try actual.requireCurrent(machine: machine, candidate: candidate)
        if let prior = retained, prior.phase == .retained {
            guard let journal else { throw SharedSetupImportError.wrongScope }
            let advanced = try machine.advanceStableRuntimeImport(expected: actual, previous: prior, journal: journal,
                candidate: candidate, directory: directory, admission: admission)
            retained = advanced.intent; actual = advanced.snapshot
        }
        try verify(); try actual.requireCurrent(machine: machine, candidate: candidate)
        return result
    }
    private static func importScope(_ expected: MachineUpdateStableRuntimePreparationSnapshot) throws -> SharedSetupImportIntent.Scope {
        let account = expected.preparation
        let provisioning = try expected.setup.source.provisioningInventory(accountID: account.accountID,
            ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
        return try .init(account: account, inventory: provisioning)
    }
}
