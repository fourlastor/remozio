import Foundation

/// Validates published bytes without creating or repairing a file.
enum RuntimePublishedArtifactValidation {
    enum Access: Equatable { case privateRoot, publicRoot, servicePrivate(UInt32) }
    struct Artifact: CustomStringConvertible, CustomDebugStringConvertible {
        let path: String
        let bytes: Data
        let access: Access
        var description: String { "RuntimePublishedArtifact(redacted)" }
        var debugDescription: String { description }
    }
    static func artifacts(bundle: RuntimeConfigurationBundle, material: RuntimePreparationMaterial) throws -> [Artifact] {
        guard let transport = material.services.claims.first(where: { $0.role == .transport }) else { throw RuntimePreparationError.incomplete }
        let owner = material.services.ownerUID, paths = bundle.paths
        var result: [Artifact] = [
            .init(path: paths.policy, bytes: bundle.elevationPolicy.canonicalBytes, access: .privateRoot),
            .init(path: paths.commandConfiguration, bytes: bundle.command.canonicalBytes, access: .privateRoot),
            .init(path: paths.transportIdentity, bytes: material.transportIdentity, access: .servicePrivate(transport.number)),
            .init(path: paths.transportConfiguration, bytes: bundle.transport.canonicalBytes, access: .publicRoot),
            .init(path: RuntimePreparationPaths.sharedDirectory + "/" + AdministrativeSetupPublication.File.presenceClient(ownerUID: owner).name,
                bytes: bundle.presenceClient.canonicalBytes, access: .publicRoot),
            .init(path: RuntimePreparationPaths.sharedDirectory + "/" + AdministrativeSetupPublication.File.pairingClient(ownerUID: owner).name,
                bytes: bundle.pairingClient.canonicalBytes, access: .publicRoot),
            .init(path: RuntimePreparationPaths.sharedDirectory + "/" + AdministrativeSetupPublication.File.frontendClient(ownerUID: owner).name,
                bytes: bundle.frontendClient.canonicalBytes, access: .publicRoot)
        ]
        if let host = try bundle.gatewaySettingsHost {
            result.append(try .init(path: paths.serviceDirectory + "/" + AdministrativeSetupPublication.File.gatewaySettingsHost.name, bytes: host.encoded, access: .publicRoot))
        }
        return result
    }
    static func validate(bundle: RuntimeConfigurationBundle, material: RuntimePreparationMaterial,
                         verifyCurrent: () throws -> Void, read: (Artifact) throws -> Data = RuntimePublishedArtifactValidation.nativeRead) throws {
        try verifyCurrent()
        for artifact in try artifacts(bundle: bundle, material: material) {
            try verifyCurrent(); let actual = try read(artifact); try verifyCurrent()
            guard actual == artifact.bytes else { throw AdministrativeSetupPublicationError.conflictingConfiguration }
        }
        try verifyCurrent()
    }
    private static func nativeRead(_ artifact: Artifact) throws -> Data {
        switch artifact.access {
        case .privateRoot: return try ProtectedServiceConfiguration.read(path: artifact.path)
        case .publicRoot: return try ProtectedServiceConfiguration.readPublic(path: artifact.path)
        case .servicePrivate(let uid): return try ProtectedServiceConfiguration.readServicePrivate(path: artifact.path, serviceUID: uid)
        }
    }
}
