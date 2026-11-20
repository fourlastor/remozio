import CryptoKit
import Foundation
import RemozioProtocol

/// Correlation only. Native peer authentication and protected row validation remain mandatory.
struct AuthorityMaintenanceUnboundRequest: Equatable, Sendable {
    enum Kind: String, Sendable {
        case release = "authority.maintenance-unbound-release"
        case gate = "authority.maintenance-unbound-gate"
    }
    let kind: Kind
    let installationID: Data, accountID: Data, attemptID: Data, revision: Data, rowDigest: Data
    let pendingRevision: Data, intentID: Data, gate: PreparationFileIdentity
    let authorityIncarnation: Data, challenge: Data
    init(kind: Kind, installationID: Data, accountID: Data, attemptID: Data, revision: Data, rowDigest: Data,
        pendingRevision: Data, intentID: Data, gate: PreparationFileIdentity, authorityIncarnation: Data, challenge: Data) throws {
        guard [installationID, accountID, attemptID, revision, pendingRevision, intentID, authorityIncarnation, challenge]
            .allSatisfy({ $0.count == 16 }), rowDigest.count == 32, gate.inode > 0 else {
            throw RuntimePreparationError.invalidRecord
        }
        self.kind = kind; self.installationID = installationID; self.accountID = accountID; self.attemptID = attemptID
        self.revision = revision; self.rowDigest = rowDigest; self.pendingRevision = pendingRevision; self.intentID = intentID
        self.gate = gate; self.authorityIncarnation = authorityIncarnation; self.challenge = challenge
    }
    func requireWindow(_ row: RuntimeMaintenanceWindowRecord, gateIdentity: PreparationFileIdentity) throws {
        guard let descriptor = row.unboundRelease, row.purpose == .retainedRuntime,
              [.reopenPending, .needsOwnerRecovery].contains(row.phase),
              row.operation == .notStarted, row.service == .notStopped, row.shutdownBinding == nil,
              installationID == row.scope.installationID, accountID == row.scope.authority.accountID,
              attemptID == row.id, revision == row.revision,
              rowDigest == (try RuntimeMaintenanceUnboundRelease.digest(row)),
              pendingRevision == descriptor.pendingRevision, intentID == descriptor.intentID,
              gate == gateIdentity else { throw RuntimePreparationError.changedScope }
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(kind.rawValue), 2: .bytes(installationID),
            3: .bytes(accountID), 4: .bytes(attemptID), 5: .bytes(revision), 6: .bytes(rowDigest),
            7: .bytes(pendingRevision), 8: .bytes(intentID), 9: .array([.unsigned(UInt64(gate.device)), .unsigned(gate.inode)]),
            10: .bytes(authorityIncarnation), 11: .bytes(challenge)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(f.keys) == Set(UInt64(0)...11), f[0] == .unsigned(1),
              case .text(let name) = f[1], let kind = Kind(rawValue: name),
              case .array(let identity) = f[9], identity.count == 2,
              case .unsigned(let device) = identity[0], device <= UInt64(UInt32.max),
              case .unsigned(let inode) = identity[1] else { throw RuntimePreparationError.invalidRecord }
        func data(_ key: UInt64) throws -> Data {
            guard case .bytes(let value) = f[key] else { throw RuntimePreparationError.invalidRecord }; return value
        }
        let result = try Self(kind: kind, installationID: data(2), accountID: data(3), attemptID: data(4),
            revision: data(5), rowDigest: data(6), pendingRevision: data(7), intentID: data(8),
            gate: .init(device: UInt32(device), inode: inode), authorityIncarnation: data(10), challenge: data(11))
        guard try result.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return result
    }
    static func requireFormats(_ candidate: SignedReleaseEvidence) throws {
        for role in [AuthorityCodeRole.authority, .setupController] {
            guard let component = candidate.manifest.components.first(where: { $0.role == role }) else {
                throw PreparationStoreError.incompatibleStore
            }
            for kind in [Kind.release, .gate] {
                guard let format = component.formats.first(where: { $0.name == kind.rawValue }),
                      format.readers.contains(1), format.writers.contains(1) else {
                    throw PreparationStoreError.incompatibleStore
                }
            }
        }
    }
    private static let limits = try! CBORLimits(maxBytes: 1024, maxDepth: 2, maxItems: 32)
}

/// A decoded observation grants no writer capability. The actual client must authenticate the complete reply.
struct AuthorityMaintenanceUnboundGateResponse: Equatable, Sendable {
    enum Hold: UInt64, Sendable { case held = 1, released = 2, neverHeld = 3, unknown = 4 }
    let request: AuthorityMaintenanceUnboundRequest
    let hold: Hold
    let admission: RuntimeMaintenanceWindowRecord.GateReadback.Admission
    init(request: AuthorityMaintenanceUnboundRequest, hold: Hold,
        admission: RuntimeMaintenanceWindowRecord.GateReadback.Admission) throws {
        guard request.kind == .gate else { throw RuntimePreparationError.invalidRecord }
        self.request = request; self.hold = hold; self.admission = admission
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("authority.maintenance-unbound-gate.reply"),
            2: .bytes(try request.encoded), 3: .unsigned(hold.rawValue), 4: .unsigned(admission.rawValue)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(f.keys) == Set(UInt64(0)...4), f[0] == .unsigned(1),
              f[1] == .text("authority.maintenance-unbound-gate.reply"), case .bytes(let request) = f[2],
              case .unsigned(let h) = f[3], let hold = Hold(rawValue: h),
              case .unsigned(let a) = f[4], let admission = RuntimeMaintenanceWindowRecord.GateReadback.Admission(rawValue: a) else {
            throw RuntimePreparationError.invalidRecord
        }
        let result = try Self(request: .decode(request), hold: hold, admission: admission)
        guard try result.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return result
    }
    /// Only the typed writer may store this normalization after it checks its real Joined and exact predecessor.
    func completedGateReadback() throws -> RuntimeMaintenanceWindowRecord.GateReadback {
        guard admission == .available, hold == .released || hold == .neverHeld else {
            throw RuntimePreparationError.changedScope
        }
        return try .init(attemptID: request.attemptID, requestRevision: request.pendingRevision,
            identity: request.gate, authorityIncarnation: request.authorityIncarnation, challenge: request.challenge,
            responseDigest: Data(SHA256.hash(data: encoded)), hold: .released, admission: .available)
    }
    private static let limits = try! CBORLimits(maxBytes: 1024, maxDepth: 1, maxItems: 11)
}
