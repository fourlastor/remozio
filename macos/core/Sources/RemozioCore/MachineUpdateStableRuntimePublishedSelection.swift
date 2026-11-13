import Foundation

/// Validated existing files. The caller retains admission, current code checks, and the protected file reader.
struct MachineUpdateStableRuntimePublishedSelection: CustomStringConvertible, CustomDebugStringConvertible {
    typealias Artifact = RuntimePublishedArtifactValidation.Artifact
    let bundle: RuntimeConfigurationBundle
    let artifacts: [Artifact]
    private struct RetainedPolicy {
        let intent: MachineUpdateRetainedSetupPolicyIntentRecord
        let binding: RuntimeRetainedSetupReleaseBinding
    }
    private let retainedPolicy: RetainedPolicy?
    var description: String { "MachineUpdateStableRuntimePublishedSelection(redacted)" }
    var debugDescription: String { description }

    static func capture(snapshot: MachineUpdateStableRuntimePreparationSnapshot, view: MachineUpdateStableRuntimeView,
        material: RuntimePreparationMaterial, candidate: SignedReleaseEvidence, currentCodePolicy: AuthorityCodePolicy,
        retained: MachineUpdateRetainedSetupPolicySnapshot? = nil,
        readPolicyBoundary: (() throws -> AuthorityJournal.MachineUpdatePolicyBoundary)? = nil,
        verifyCurrent: () throws -> Void,
        read: (Artifact) throws -> Data = RuntimePublishedArtifactValidation.nativeRead) throws -> Self {
        try verifyCurrent()
        try view.compatibility.source.requireSame(as: snapshot.setup.source)
        let preparation = snapshot.preparation, reference = try material.reference
        guard snapshot.state.configurationPublished, snapshot.state.reference == reference,
              let account = view.accounts.first(where: { $0.accountID == preparation.accountID && $0.scope.ownerUID == preparation.ownerUID }),
              account.scope == snapshot.setup.account,
              account.runtime?.configurationPublished == true, account.runtime?.reference == reference else {
            throw RuntimePreparationError.changedScope
        }
        if account.scope.origin == .retained && account.configuration == nil {
            guard account.ordinaryActivation == nil, let retained, let readPolicyBoundary,
                  let intent = retained.intent else { throw RuntimeActivationError.incomplete }
            try retained.activation.runtime.requireSame(as: snapshot)
            let selected = try RuntimeRetainedSetupPublishedSelection.capture(snapshot: retained,
                readPolicyBoundary: readPolicyBoundary, material: material, candidate: candidate,
                currentCodePolicy: currentCodePolicy, verifyCurrent: verifyCurrent, read: read)
            let artifacts = try RuntimePublishedArtifactValidation.artifacts(bundle: selected.bundle, material: material)
            let result = Self(bundle: selected.bundle, artifacts: artifacts,
                retainedPolicy: .init(intent: intent, binding: selected.binding))
            try result.validate(readPolicyBoundary: readPolicyBoundary, verifyCurrent: verifyCurrent, read: read)
            return result
        }
        guard retained == nil, readPolicyBoundary == nil else { throw RuntimePreparationError.changedScope }
        let paths = try RuntimePreparationPaths(accountID: preparation.accountID)
        func captured(_ path: String, access: RuntimePublishedArtifactValidation.Access) throws -> Data {
            try verifyCurrent()
            let bytes = try read(.init(path: path, bytes: Data(), access: access))
            try verifyCurrent(); return bytes
        }
        let command: AuthorityCommandStartupConfiguration, transport: TransportPairingStartupConfiguration
        let clients: RuntimeActivationClients
        let host: InstalledAuthorityCommandConfiguration?
        if let selected = account.configuration {
            guard account.ordinaryActivation == nil, selected.policyStage == .completion else { throw RuntimePreparationError.changedScope }
            host = selected.host; command = selected.host.command; transport = selected.transport; clients = selected.clients
        } else if let selected = account.ordinaryActivation {
            host = selected.host; command = selected.host.command; transport = selected.transport
            clients = try .init(presence: .decode(captured(RuntimePreparationPaths.sharedDirectory + "/" +
                AdministrativeSetupPublication.File.presenceClient(ownerUID: preparation.ownerUID).name, access: .publicRoot)),
                pairing: .decode(captured(RuntimePreparationPaths.sharedDirectory + "/" +
                    AdministrativeSetupPublication.File.pairingClient(ownerUID: preparation.ownerUID).name, access: .publicRoot)),
                frontend: .decode(captured(RuntimePreparationPaths.sharedDirectory + "/" +
                    AdministrativeSetupPublication.File.frontendClient(ownerUID: preparation.ownerUID).name, access: .publicRoot)))
        } else {
            guard account.runtime?.jobsRegistered == false, account.runtime?.activationRecord == nil else {
                throw RuntimePreparationError.incomplete
            }
            if account.scope.origin == .retained {
                _ = try snapshot.setup.source.unconfiguredRetainedAccount(accountID: preparation.accountID,
                    ownerUID: preparation.ownerUID)
            }
            host = nil
            command = try .decode(captured(paths.commandConfiguration, access: .privateRoot))
            transport = try .decode(captured(paths.transportConfiguration, access: .publicRoot))
            clients = try .init(presence: .decode(captured(RuntimePreparationPaths.sharedDirectory + "/" +
                AdministrativeSetupPublication.File.presenceClient(ownerUID: preparation.ownerUID).name, access: .publicRoot)),
                pairing: .decode(captured(RuntimePreparationPaths.sharedDirectory + "/" +
                    AdministrativeSetupPublication.File.pairingClient(ownerUID: preparation.ownerUID).name, access: .publicRoot)),
                frontend: .decode(captured(RuntimePreparationPaths.sharedDirectory + "/" +
                    AdministrativeSetupPublication.File.frontendClient(ownerUID: preparation.ownerUID).name, access: .publicRoot)))
        }
        if let host {
            _ = try host.validate(inventory: snapshot.setup.source.actual.inventory, release: candidate,
                bundlePath: snapshot.setup.source.actual.inventory.bundlePath)
            guard try host.codePolicy.bytes == currentCodePolicy.bytes else { throw RuntimePreparationError.changedScope }
        }
        let bundle = try RuntimeConfigurationBundle.stableCompleted(snapshot: snapshot, reference: reference,
            candidate: candidate, currentCodePolicy: currentCodePolicy, command: command, transport: transport, clients: clients)
        var artifacts = try RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: material)
        if let host {
            guard let index = artifacts.firstIndex(where: { $0.path == paths.commandConfiguration }) else { throw RuntimePreparationError.incomplete }
            artifacts[index] = .init(path: paths.privateDirectory + "/" + AdministrativeSetupPublication.File.commandHost.name,
                bytes: host.canonicalBytes, access: .privateRoot)
        }
        let result = Self(bundle: bundle, artifacts: artifacts, retainedPolicy: nil)
        try result.validate(verifyCurrent: verifyCurrent, read: read)
        return result
    }

    func validate(readPolicyBoundary: (() throws -> AuthorityJournal.MachineUpdatePolicyBoundary)? = nil,
        verifyCurrent: () throws -> Void,
        read: (Artifact) throws -> Data = RuntimePublishedArtifactValidation.nativeRead) throws {
        func verify() throws {
            try verifyCurrent()
            if let retainedPolicy {
                guard let readPolicyBoundary else { throw RuntimeActivationError.incomplete }
                let current = try readPolicyBoundary()
                try verifyCurrent()
                try retainedPolicy.intent.requireRecorded(current)
                try retainedPolicy.binding.requireRecordedBoundary(current)
            } else if readPolicyBoundary != nil { throw RuntimePreparationError.changedScope }
        }
        try verify()
        for artifact in artifacts {
            try verify(); let actual = try read(artifact); try verify()
            guard actual == artifact.bytes else { throw AdministrativeSetupPublicationError.conflictingConfiguration }
        }
        try verify()
    }
}
