import Foundation
import RemozioProtocol

enum RuntimeActivationCompatibilityError: Error, Equatable {
    case missingRetainedSnapshot, unexpectedRetainedSnapshot
    case ownerUnavailable(UInt32), ownerIdentityChanged(UInt32)
}

/// Protected account claims only. A claim does not prove a current directory identity.
struct RuntimeStableCompatibilityOwner: Equatable {
    let accountID: Data
    let ownerUID: UInt32
    let directoryID: UUID
}

enum RuntimeStableCompatibilityCapture {
    /// Resolves public identities outside the store. The final read checks the complete original frame again.
    static func capture(machine: PreparationIntentStore, expected: MachineUpdateStableRuntimeSource,
        candidate: SignedReleaseEvidence, lookup: (UInt32) throws -> LocalAccountIdentity = LocalAccountDirectory.lookup)
        throws -> RuntimeReleaseCompatibilitySnapshot {
        let claims = try machine.retainedSetupCompatibilityOwners(expected: expected, candidate: candidate)
        var retained: [MachineUpdateRetainedSetupActivationSnapshot] = []
        for claim in claims {
            let owner: LocalAccountIdentity
            do { owner = try lookup(claim.ownerUID) }
            catch { throw RuntimeActivationCompatibilityError.ownerUnavailable(claim.ownerUID) }
            do { try LocalAccountDirectory.validateOwnership(owner, uid: claim.ownerUID, directoryID: claim.directoryID) }
            catch { throw RuntimeActivationCompatibilityError.ownerIdentityChanged(claim.ownerUID) }
            let snapshot = try machine.retainedSetupActivationSnapshot(owner: owner, candidate: candidate)
            guard snapshot.runtime.preparation.accountID == claim.accountID else { throw PreparationStoreError.staleRevision }
            try snapshot.runtime.setup.source.requireSame(as: expected)
            retained.append(snapshot)
        }
        return try machine.stableRuntimeCompatibilitySnapshot(expected: expected, retained: retained, candidate: candidate)
    }
}

/// Reads compatibility values only. An ordinary activation state cannot hold the retained branch.
enum RuntimeActivationCompatibilityProjection {
    case ordinary(RuntimeActivationPlan)
    case retained(RuntimeRetainedSetupActivationPlan)

    static func decode(_ bytes: Data) throws -> Self {
        let limits = try CBORLimits(maxBytes: RuntimeRetainedSetupActivationPlan.maximumBytes, maxDepth: 1, maxItems: 23)
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              case .unsigned(let version) = fields[0] else { throw RuntimeActivationError.invalidPlan }
        if version == RuntimeRetainedSetupActivationArchive.formatVersion {
            return try .retained(.decode(bytes))
        }
        return try .ordinary(.decode(bytes))
    }
    var reference: RuntimeMaterialReference {
        switch self { case .ordinary(let plan): plan.reference; case .retained(let plan): plan.reference }
    }
    var formatVersion: UInt64 {
        switch self { case .ordinary(let plan): plan.formatVersion; case .retained(let plan): plan.formatVersion }
    }
    var host: InstalledAuthorityCommandConfiguration {
        switch self { case .ordinary(let plan): plan.host; case .retained(let plan): plan.host }
    }
    var phoneRoutingVersion: UInt64? {
        switch self { case .ordinary(let plan): plan.phoneRoutingVersion; case .retained(let plan): plan.phoneRoutingVersion }
    }
    var phoneAuditVersion: UInt64? {
        switch self { case .ordinary(let plan): plan.phoneAuditVersion; case .retained(let plan): plan.phoneAuditVersion }
    }
    var phoneUpdateSchedulingVersion: UInt64? {
        switch self { case .ordinary(let plan): plan.phoneUpdateSchedulingVersion; case .retained(let plan): plan.phoneUpdateSchedulingVersion }
    }
    var encoded: Data { get throws {
        switch self { case .ordinary(let plan): try plan.encoded; case .retained(let plan): try plan.encoded }
    } }
}
