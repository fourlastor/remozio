// Frozen reader 1 from21efca1b. Only the type name and module import differ. Metadata grants no authority.
import Foundation
import RemozioProtocol
@testable import RemozioCore

/// Retained window metadata only. Decoding grants no admission, service operation or native custody.
struct FrozenMaintenanceWindowReader1: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.maintenance-window-record"
    enum Purpose: UInt64, CaseIterable, Sendable { case retainedPolicy = 1, retainedRuntime = 2, markerReplacement = 3 }
    enum Phase: UInt64, CaseIterable, Sendable {
        case authorized = 1, draining = 2, stopping = 3, stopped = 4, executing = 5
        case workSettled = 6, restoring = 7, reopenPending = 8, restored = 9, needsOwnerRecovery = 10
    }
    enum OperationOutcome: UInt64, CaseIterable, Sendable { case notStarted = 1, committed = 2, failed = 3, unknown = 4 }
    enum ServiceOutcome: UInt64, CaseIterable, Sendable {
        case notStopped = 1, stopped = 2, restartPending = 3, registered = 4, healthy = 5, failed = 6, unknown = 7
    }
    enum Failure: UInt64, CaseIterable, Sendable {
        case busy = 1, changedScope = 2, cleanupPending = 3, serviceUnavailable = 4
        case healthFailed = 5, admissionUnconfirmed = 6, repairRequired = 7, operationUncertain = 8
    }
    struct Account: Equatable, Sendable {
        let accountID: Data, directoryID: Data
        let ownerUID: UInt32
        init(accountID: Data, ownerUID: UInt32, directoryID: Data) throws {
            guard accountID.count == 16, directoryID.count == 16, ownerUID > 0, ownerUID < UInt32.max else {
                throw RuntimePreparationError.invalidRecord
            }
            self.accountID = accountID; self.ownerUID = ownerUID; self.directoryID = directoryID
        }
        fileprivate var value: CBORValue { .array([.bytes(accountID), .unsigned(UInt64(ownerUID)), .bytes(directoryID)]) }
        fileprivate static func decode(_ value: CBORValue) throws -> Self {
            let a = try maintenanceArray(value, count: 3), uid = try maintenanceUInt(a[1])
            guard uid < UInt64(UInt32.max) else { throw RuntimePreparationError.invalidRecord }
            return try .init(accountID: maintenanceData(a[0], count: 16), ownerUID: UInt32(uid), directoryID: maintenanceData(a[2], count: 16))
        }
    }
    /// Digests are opaque immutable references. M07 must prove their semantics, including candidateDigest; bytes grant no authority.
    struct Scope: Equatable, Sendable {
        let macID: Data, installationID: Data
        let authority: Account, target: Account
        let releaseDigest: Data, candidateDigest: Data, authorityPolicyDigest: Data
        let operationDigest: Data, restorationDigest: Data, mutationFootprintDigest: Data
        let authorityGrantDigest: Data, targetConsentDigest: Data, administratorIntentDigest: Data
        init(macID: Data, installationID: Data, authority: Account, target: Account,
            releaseDigest: Data, candidateDigest: Data, authorityPolicyDigest: Data, operationDigest: Data,
            restorationDigest: Data, mutationFootprintDigest: Data, authorityGrantDigest: Data,
            targetConsentDigest: Data, administratorIntentDigest: Data) throws {
            guard macID.count == 16, installationID.count == 16,
                  authority.accountID != target.accountID, authority.ownerUID != target.ownerUID,
                  authority.directoryID != target.directoryID,
                  [releaseDigest, candidateDigest, authorityPolicyDigest, operationDigest, restorationDigest,
                   mutationFootprintDigest, authorityGrantDigest, targetConsentDigest, administratorIntentDigest].allSatisfy({ $0.count == 32 }) else {
                throw RuntimePreparationError.invalidRecord
            }
            self.macID = macID; self.installationID = installationID; self.authority = authority; self.target = target
            self.releaseDigest = releaseDigest; self.candidateDigest = candidateDigest; self.authorityPolicyDigest = authorityPolicyDigest
            self.operationDigest = operationDigest; self.restorationDigest = restorationDigest; self.mutationFootprintDigest = mutationFootprintDigest
            self.authorityGrantDigest = authorityGrantDigest; self.targetConsentDigest = targetConsentDigest; self.administratorIntentDigest = administratorIntentDigest
        }
        fileprivate var value: CBORValue {
            .array([.bytes(macID), .bytes(installationID), authority.value, target.value, .bytes(releaseDigest),
                .bytes(candidateDigest), .bytes(authorityPolicyDigest), .bytes(operationDigest), .bytes(restorationDigest),
                .bytes(mutationFootprintDigest), .bytes(authorityGrantDigest), .bytes(targetConsentDigest), .bytes(administratorIntentDigest)])
        }
        fileprivate static func decode(_ value: CBORValue) throws -> Self {
            let a = try maintenanceArray(value, count: 13)
            return try .init(macID: maintenanceData(a[0], count: 16), installationID: maintenanceData(a[1], count: 16),
                authority: Account.decode(a[2]), target: Account.decode(a[3]), releaseDigest: maintenanceData(a[4], count: 32),
                candidateDigest: maintenanceData(a[5], count: 32), authorityPolicyDigest: maintenanceData(a[6], count: 32),
                operationDigest: maintenanceData(a[7], count: 32), restorationDigest: maintenanceData(a[8], count: 32),
                mutationFootprintDigest: maintenanceData(a[9], count: 32), authorityGrantDigest: maintenanceData(a[10], count: 32),
                targetConsentDigest: maintenanceData(a[11], count: 32), administratorIntentDigest: maintenanceData(a[12], count: 32))
        }
    }
    /// Stores actual gate observations, not an acknowledgement. The native owner must independently verify them.
    struct GateReadback: Equatable, Sendable {
        enum Hold: UInt64, CaseIterable, Sendable { case held = 1, released = 2, unknown = 3 }
        enum Admission: UInt64, CaseIterable, Sendable { case available = 1, busy = 2, unavailable = 3 }
        let attemptID: Data, requestRevision: Data, authorityIncarnation: Data, challenge: Data, responseDigest: Data
        let identity: PreparationFileIdentity
        let hold: Hold
        let admission: Admission
        init(attemptID: Data, requestRevision: Data, identity: PreparationFileIdentity, authorityIncarnation: Data,
            challenge: Data, responseDigest: Data, hold: Hold, admission: Admission) throws {
            guard [attemptID, requestRevision, authorityIncarnation, challenge].allSatisfy({ $0.count == 16 }),
                  responseDigest.count == 32, identity.inode > 0 else { throw RuntimePreparationError.invalidRecord }
            self.attemptID = attemptID; self.requestRevision = requestRevision; self.identity = identity
            self.authorityIncarnation = authorityIncarnation; self.challenge = challenge; self.responseDigest = responseDigest
            self.hold = hold; self.admission = admission
        }
        fileprivate var value: CBORValue {
            .array([.bytes(attemptID), .bytes(requestRevision), .unsigned(UInt64(identity.device)), .unsigned(identity.inode),
                .bytes(authorityIncarnation), .bytes(challenge), .bytes(responseDigest), .unsigned(hold.rawValue), .unsigned(admission.rawValue)])
        }
        fileprivate static func decode(_ value: CBORValue) throws -> Self {
            let a = try maintenanceArray(value, count: 9), device = try maintenanceUInt(a[2])
            guard device <= UInt64(UInt32.max), let hold = Hold(rawValue: try maintenanceUInt(a[7])),
                  let admission = Admission(rawValue: try maintenanceUInt(a[8])) else { throw RuntimePreparationError.invalidRecord }
            return try .init(attemptID: maintenanceData(a[0], count: 16), requestRevision: maintenanceData(a[1], count: 16),
                identity: .init(device: UInt32(device), inode: maintenanceUInt(a[3])), authorityIncarnation: maintenanceData(a[4], count: 16),
                challenge: maintenanceData(a[5], count: 16), responseDigest: maintenanceData(a[6], count: 32), hold: hold, admission: admission)
        }
    }
    let id: Data, revision: Data
    let purpose: Purpose
    let scope: Scope
    let phase: Phase
    let operation: OperationOutcome
    let service: ServiceOutcome
    let failure: Failure?
    let gate: GateReadback?
    var description: String { "RuntimeMaintenanceWindowRecord(redacted)" }
    var debugDescription: String { description }
    init(id: Data, revision: Data, purpose: Purpose, scope: Scope, phase: Phase = .authorized,
        operation: OperationOutcome = .notStarted, service: ServiceOutcome = .notStopped,
        failure: Failure? = nil, gate: GateReadback? = nil) throws {
        guard id.count == 16, revision.count == 16, gate == nil || gate?.attemptID == id,
              ![Phase.authorized, .draining, .stopping, .stopped].contains(phase) || operation == .notStarted,
              phase != .executing || operation == .unknown,
              phase != .needsOwnerRecovery || failure != nil,
              phase != .reopenPending || service == .healthy || (service == .notStopped && operation == .notStarted),
              phase != .restored || (failure == nil && (service == .healthy || (service == .notStopped && operation == .notStarted))
                && gate?.hold == .released && gate?.admission == .available) else {
            throw RuntimePreparationError.invalidRecord
        }
        self.id = id; self.revision = revision; self.purpose = purpose; self.scope = scope; self.phase = phase
        self.operation = operation; self.service = service; self.failure = failure; self.gate = gate
    }
    func requireSameScope(as other: Self) throws {
        guard id == other.id, purpose == other.purpose, scope == other.scope else {
            throw RuntimePreparationError.changedScope
        }
    }
    func requireReplacing(_ previous: Self?) throws {
        guard revision != previous?.revision else { throw PreparationStoreError.staleRevision }
        guard let previous, previous.id == id else {
            guard previous == nil || previous?.phase == .restored, phase == .authorized,
                  operation == .notStarted, service == .notStopped, failure == nil, gate == nil else {
                throw PreparationStoreError.invalidTransition
            }
            return
        }
        try requireSameScope(as: previous)
        let edges: [Phase: Set<Phase>] = [
            .authorized: [.draining, .reopenPending, .needsOwnerRecovery], .draining: [.stopping, .reopenPending, .needsOwnerRecovery],
            .stopping: [.stopped, .needsOwnerRecovery], .stopped: [.executing, .restoring, .needsOwnerRecovery],
            .executing: [.workSettled, .needsOwnerRecovery], .workSettled: [.restoring, .needsOwnerRecovery],
            .restoring: [.reopenPending, .needsOwnerRecovery], .reopenPending: [.restored, .needsOwnerRecovery],
            .needsOwnerRecovery: [.restoring, .needsOwnerRecovery], .restored: []]
        let outcome: Bool
        switch previous.operation {
        case .committed, .failed: outcome = operation == previous.operation
        case .unknown: outcome = operation != .notStarted
        case .notStarted: outcome = operation == .notStarted || previous.phase == .stopped && phase == .executing && operation == .unknown
        }
        guard edges[previous.phase]?.contains(phase) == true, outcome,
              phase != .reopenPending || ![Phase.authorized, .draining].contains(previous.phase)
                || (service == .notStopped && operation == .notStarted),
              previous.phase != .reopenPending || previous.service != .notStopped || service == .notStopped,
              phase != .restored || gate?.requestRevision == previous.revision else { throw PreparationStoreError.invalidTransition }
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.formatName),
            2: .bytes(id), 3: .bytes(revision), 4: .unsigned(purpose.rawValue), 5: scope.value,
            6: .unsigned(phase.rawValue), 7: .unsigned(operation.rawValue), 8: .unsigned(service.rawValue),
            9: failure.map { .unsigned($0.rawValue) } ?? .null, 10: gate?.value ?? .null]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...10),
              f[0] == .unsigned(1), f[1] == .text(Self.formatName),
              let purpose = Purpose(rawValue: try maintenanceUInt(f[4]!)), let phase = Phase(rawValue: try maintenanceUInt(f[6]!)),
              let operation = OperationOutcome(rawValue: try maintenanceUInt(f[7]!)),
              let service = ServiceOutcome(rawValue: try maintenanceUInt(f[8]!)) else { throw RuntimePreparationError.invalidRecord }
        let failure: Failure?
        if f[9] == .null { failure = nil }
        else { guard let value = Failure(rawValue: try maintenanceUInt(f[9]!)) else { throw RuntimePreparationError.invalidRecord }; failure = value }
        let result = try Self(id: maintenanceData(f[2]!, count: 16), revision: maintenanceData(f[3]!, count: 16), purpose: purpose,
            scope: Scope.decode(f[5]!), phase: phase, operation: operation, service: service, failure: failure,
            gate: f[10] == .null ? nil : GateReadback.decode(f[10]!))
        guard try result.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return result
    }
    static let limits = try! CBORLimits(maxBytes: 4096, maxDepth: 4, maxItems: 128)
}

private func maintenanceArray(_ value: CBORValue, count: Int) throws -> [CBORValue] {
    guard case .array(let values) = value, values.count == count else { throw RuntimePreparationError.invalidRecord }; return values
}
private func maintenanceData(_ value: CBORValue, count: Int) throws -> Data {
    guard case .bytes(let bytes) = value, bytes.count == count else { throw RuntimePreparationError.invalidRecord }; return bytes
}
private func maintenanceUInt(_ value: CBORValue) throws -> UInt64 {
    guard case .unsigned(let number) = value else { throw RuntimePreparationError.invalidRecord }; return number
}
