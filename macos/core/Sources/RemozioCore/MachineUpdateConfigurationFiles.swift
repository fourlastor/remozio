import Darwin
import Foundation

/// Fixed configuration paths only. It never opens a key, token, journal writer or service manager.
enum MachineUpdateConfigurationFiles {
    static func publishNative(_ archive: MachineUpdateConfigurationEpoch.Archive, accountID: Data,
        file: MachineUpdatePublicationProgress.File, verify: () throws -> Void,
        didStage: (AdministrativeSetupPublication.Stage) throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let paths = try RuntimePreparationPaths(accountID: accountID)
        let path: String, visibility: ProtectedSetupDirectory.Visibility
        switch file {
        case .host: path = paths.privateDirectory; visibility = .privateState
        case .transport, .gateway: path = paths.serviceDirectory; visibility = .sharedMetadata
        case .presence, .pairing, .frontend: path = RuntimePreparationPaths.sharedDirectory; visibility = .sharedMetadata
        }
        try verify()
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(path.dropFirst()), owner: 0,
            visibility: visibility, createIfMissing: false)
        defer { directory.close() }
        try publishInLease(archive, accountID: accountID, file: file, directory: directory, owner: 0,
            verify: verify, didStage: didStage)
    }
    /// Owned files exercise the same typed compare-and-swap. The native entry separately authenticates Root and fixed placement.
    static func publishInLease(_ archive: MachineUpdateConfigurationEpoch.Archive, accountID: Data,
        file: MachineUpdatePublicationProgress.File, directory: ProtectedSetupDirectory, owner: uid_t,
        verify: () throws -> Void, didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws {
        try archive.validate()
        guard let progress = archive.record.publication,
              try progress.state(accountID: accountID, file: file) == .writing,
              let account = archive.record.accounts.first(where: { $0.accountID == accountID }),
              let config = try archive.configuration(accountID: accountID) else { throw PreparationStoreError.invalidTransition }
        let selected: AdministrativeSetupPublication.File
        switch file {
        case .host: selected = .commandHost
        case .transport: selected = .transportConfiguration
        case .gateway: selected = .gatewaySettingsHost
        case .presence: selected = .presenceClient(ownerUID: account.ownerUID)
        case .pairing: selected = .pairingClient(ownerUID: account.ownerUID)
        case .frontend: selected = .frontendClient(ownerUID: account.ownerUID)
        }
        try AdministrativeSetupPublication.replaceMachineUpdateConfiguration(config.bytes(file, target: true),
            expected: config.bytes(file, target: false), file: selected, directory: directory, owner: owner,
            verify: verify, didStage: didStage)
    }
}
