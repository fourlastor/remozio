import Darwin
import Foundation

/// Reads fixed retained material and the derived artifacts. It creates no destination and publishes no file.
enum MachineUpdateRetainedSetupRuntimeNativeFiles {
    typealias Runtime = MachineUpdateStableRuntimePreparationSnapshot
    typealias Material = RuntimePreparationMaterial
    typealias Artifact = RuntimePublishedArtifactValidation.Artifact
    typealias Verify = () throws -> Void
    enum Requirement: Equatable { case optionalLeaf, required }
    static func readMaterial(runtime: Runtime, verifyCurrent: Verify) throws -> Material {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verifyCurrent()
        guard runtime.state.reference != nil else { throw RuntimePreparationError.incomplete }
        let path = try RuntimePreparationPaths(accountID: runtime.preparation.accountID).privateDirectory
            + "/" + AdministrativeSetupPublication.File.runtimeRecord.name
        let material = try Material.decode(ProtectedServiceConfiguration.read(path: path))
        try requireMaterial(material, runtime: runtime); try verifyCurrent(); return material
    }
    /// Reads a possible unrecorded material file without creating or retaining it.
    static func readOptionalMaterial(runtime: Runtime, verifyCurrent: Verify) throws -> Material? {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verifyCurrent()
        let path = try RuntimePreparationPaths(accountID: runtime.preparation.accountID).privateDirectory
            + "/" + AdministrativeSetupPublication.File.runtimeRecord.name
        guard let bytes = try ProtectedServiceConfiguration.readOptionalPrivate(path: path, kind: .root) else {
            try verifyCurrent(); return nil
        }
        let material = try Material.decode(bytes)
        try material.services.validate(account: runtime.preparation)
        guard try material.services.encoded == runtime.plan.encoded else { throw RuntimePreparationError.conflictingMaterial }
        try material.reference.validate(account: runtime.preparation, services: runtime.plan)
        if let reference = runtime.state.reference, try material.reference != reference { throw RuntimePreparationError.conflictingMaterial }
        if let activity = material.serviceActivity {
            try RuntimeMaterialPreparation.validateServiceActivity(account: runtime.preparation, activity: activity, verifyCurrent: verifyCurrent)
        }
        try verifyCurrent(); return material
    }
    /// Checks values only. It does not establish native placement, file identity or service activity.
    static func requireMaterial(_ material: Material, runtime: Runtime) throws {
        guard let reference = runtime.state.reference, reference.serviceActivity != nil else { throw RuntimePreparationError.incomplete }
        try reference.validate(account: runtime.preparation, services: runtime.plan)
        try material.services.validate(account: runtime.preparation)
        guard try material.reference == reference, try material.services.encoded == runtime.plan.encoded else {
            throw RuntimePreparationError.conflictingMaterial
        }
    }
    static func verifyActivity(_ activity: ServiceReleaseActivityReference, runtime: Runtime, verifyCurrent: Verify) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verifyCurrent()
        guard runtime.state.reference?.serviceActivity == activity else { throw RuntimePreparationError.conflictingMaterial }
        try RuntimeMaterialPreparation.validateServiceActivity(account: runtime.preparation, activity: activity, verifyCurrent: verifyCurrent)
        try verifyCurrent()
    }
    static func readArtifact(_ artifact: Artifact, bundle: RuntimeConfigurationBundle, material: Material,
        runtime: Runtime, verifyCurrent: Verify) throws -> Data? {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try readCheckedArtifact(artifact, bundle: bundle, material: material, runtime: runtime,
            verifyCurrent: verifyCurrent) { selected, requirement in
                if requirement == .required { return try RuntimePublishedArtifactValidation.nativeRead(selected) }
                switch selected.access {
                case .privateRoot: return try ProtectedServiceConfiguration.readOptionalPrivate(path: selected.path, kind: .root)
                case .publicRoot: return try ProtectedServiceConfiguration.readOptionalPublic(path: selected.path)
                case .servicePrivate(let uid):
                    return try ProtectedServiceConfiguration.readOptionalPrivate(path: selected.path, kind: .service(uid))
                }
            }
    }
    /// Owned readers prove derivation and comparison only. They cannot mint native custody or approval.
    static func readCheckedArtifact(_ artifact: Artifact, bundle: RuntimeConfigurationBundle, material: Material,
        runtime: Runtime, verifyCurrent: Verify, read: (Artifact, Requirement) throws -> Data?) throws -> Data? {
        try verifyCurrent(); try requireMaterial(material, runtime: runtime)
        let paths = try RuntimePreparationPaths(accountID: runtime.preparation.accountID)
        guard bundle.paths.privateDirectory == paths.privateDirectory, bundle.paths.serviceDirectory == paths.serviceDirectory,
              bundle.paths.authorityDirectory == paths.authorityDirectory, bundle.command.macID == runtime.preparation.macID,
              bundle.command.accountID == runtime.preparation.accountID, bundle.command.callerUID == runtime.preparation.ownerUID else {
            throw RuntimePreparationError.changedScope
        }
        let expected = try RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: material)
        guard expected.count == 8, Set(expected.map(\.path)).count == 8,
              let selected = expected.first(where: { $0.path == artifact.path }),
              selected.access == artifact.access, selected.bytes == artifact.bytes else { throw RuntimePreparationError.changedScope }
        let requirement: Requirement = runtime.state.configurationPublished ? .required : .optionalLeaf
        let actual = try read(selected, requirement); try verifyCurrent()
        guard actual != nil || requirement == .optionalLeaf else { throw RuntimePreparationError.incomplete }
        if let actual, actual != selected.bytes { throw AdministrativeSetupPublicationError.conflictingConfiguration }
        return actual
    }
}
