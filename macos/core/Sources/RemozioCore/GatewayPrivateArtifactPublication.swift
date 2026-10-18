import Darwin
import Foundation

/// File preparation only. The setup host must authorize the transition and verify the current signed release.
/// Creation requires a protected, pending activation intent. Ordinary recovery validates retained files without creation.
enum GatewayPrivateArtifactPublication {
    enum Mode { case prepareUnactivated, validateRetained }
    enum Artifact: CaseIterable, Hashable { case provider, receipt, transportWake }
    struct Result: Equatable {
        let files: [Artifact: AdministrativeSetupPublicationResult]
    }

    static func publish(account: AccountPreparationIntent, expected: GatewayMaterialReference, mode: Mode,
                        verifyCurrent: () throws -> Void) throws -> Result {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try expected.runtime.validate(account: account, services: expected.runtime.services)
        try verifyCurrent()
        let paths = try RuntimePreparationPaths(accountID: account.accountID)
        let privateState = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.privateDirectory.dropFirst()),
            owner: 0, createIfMissing: false)
        defer { privateState.close() }
        let services = expected.runtime.services
        guard let gateway = services.claims.first(where: { $0.role == .gateway }),
              let transport = services.claims.first(where: { $0.role == .transport }) else {
            throw GatewayPreparationError.incomplete
        }
        let accounts = try NativeServiceAccountDirectory(accountID: account.accountID, ownerUID: account.ownerUID)
        func load() throws -> GatewayPreparationMaterial {
            try verifyCurrent(); try privateState.validate()
            for claim in services.claims {
                try accounts.validateGroup(claim); try accounts.validateUser(claim, ownerUID: account.ownerUID)
            }
            let runtime = try RuntimePreparationMaterial.decode(ProtectedServiceConfiguration.read(anchor: privateState.path,
                relativePath: AdministrativeSetupPublication.File.runtimeRecord.name, owner: 0))
            guard try runtime.reference == expected.runtime else { throw GatewayPreparationError.changedScope }
            let material = try GatewayPreparationMaterial.decode(ProtectedServiceConfiguration.read(anchor: privateState.path,
                relativePath: AdministrativeSetupPublication.File.gatewayMaterial.name, owner: 0))
            guard try material.reference == expected else { throw GatewayPreparationError.conflictingMaterial }
            return material
        }
        let material = try load()
        let shared = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { shared.close() }
        return try publish(material: material, expected: expected, directory: shared, owner: 0,
            gatewayUID: gateway.number, gatewayGID: gateway.number, transportUID: transport.number, transportGID: transport.number,
            mode: mode, verifyCurrent: { _ = try load() })
    }

    // Owned fixtures exercise real publication. They do not prove Root authorization or separate service access.
    static func publish(material: GatewayPreparationMaterial, expected: GatewayMaterialReference,
                        directory: ProtectedSetupDirectory, owner: uid_t,
                        gatewayUID: uid_t, gatewayGID: gid_t, transportUID: uid_t, transportGID: gid_t,
                        mode: Mode, verifyCurrent: () throws -> Void,
                        didPublish: (Artifact) throws -> Void = { _ in }) throws -> Result {
        guard try material.reference == expected else { throw GatewayPreparationError.conflictingMaterial }
        let files: [(Artifact, Data, AdministrativeSetupPublication.File)] = [
            (.provider, material.providerJSON, .gatewayProvider(ownerUID: gatewayUID, groupID: gatewayGID)),
            (.receipt, material.receiptKeyRecord, .gatewayReceiptKey(ownerUID: gatewayUID, groupID: gatewayGID)),
            (.transportWake, try material.wakeKeyRecord.encode(), .transportWakeKey(ownerUID: transportUID, groupID: transportGID))
        ]
        func verify() throws {
            try verifyCurrent(); try directory.validate()
        }
        // Refuse any existing conflict before creating a sibling. A later interruption can leave a resumable subset.
        for (_, bytes, file) in files {
            try file.validate(); try verify()
            let exists = try directory.withSharedDirectory { parent in
                var info = stat()
                if fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
                guard errno == ENOENT else { throw JournalLeaseError.system(errno) }; return false
            }
            if exists || mode == .validateRetained {
                try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: owner, verify: verify)
            }
        }
        var results: [Artifact: AdministrativeSetupPublicationResult] = [:]
        for (artifact, bytes, file) in files {
            try verify()
            if mode == .prepareUnactivated {
                results[artifact] = try AdministrativeSetupPublication.publish(bytes, file: file, directory: directory, owner: owner, verify: verify)
            } else {
                try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: owner, verify: verify)
                results[artifact] = .retained
            }
            try didPublish(artifact); try verify()
        }
        for (_, bytes, file) in files {
            try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: owner, verify: verify)
        }
        try verify()
        return Result(files: results)
    }
}
