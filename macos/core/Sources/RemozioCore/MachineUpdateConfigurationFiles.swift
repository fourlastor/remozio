import Darwin
import Foundation

/// Fixed configuration paths only. It never opens a key, token, journal writer or service manager.
enum MachineUpdateConfigurationFiles {
    /// Owned fixtures exercise typed replacement only. This helper grants no native file authority.
    static func publishInLease(_ archive: MachineUpdateConfigurationEpoch.Archive, accountID: Data,
        file: MachineUpdatePublicationProgress.File, directory: ProtectedSetupDirectory, owner: uid_t,
        verify: () throws -> Void, didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws {
        guard owner != 0, getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        try archive.validate()
        guard let progress = archive.record.publication,
              try progress.state(accountID: accountID, file: file) == .writing,
              let account = archive.record.accounts.first(where: { $0.accountID == accountID }),
              let config = try archive.configuration(accountID: accountID) else { throw PreparationStoreError.invalidTransition }
        let selected = artifact(file, ownerUID: account.ownerUID)
        try AdministrativeSetupPublication.replaceMachineUpdateConfiguration(config.bytes(file, target: true),
            expected: config.bytes(file, target: false), file: selected, directory: directory, owner: owner,
            verify: verify, didStage: didStage)
    }

    /// Verifies the exact startup bytes already published under closed admission.
    static func requirePublishedNative(_ archive: MachineUpdateConfigurationEpoch.Archive,
        accountID: Data, verify: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard archive.record.publication?.complete == true else { throw PreparationStoreError.invalidTransition }
        for file in MachineUpdatePublicationProgress.File.allCases {
            try verify()
            let directory = try openNativeDirectory(accountID: accountID, file: file)
            defer { directory.close() }
            try requirePublishedInLease(archive, accountID: accountID, file: file, directory: directory, owner: 0, verify: verify)
        }
    }

    static func requirePublishedInLease(_ archive: MachineUpdateConfigurationEpoch.Archive, accountID: Data,
        file: MachineUpdatePublicationProgress.File, directory: ProtectedSetupDirectory, owner: uid_t,
        verify: () throws -> Void) throws {
        try archive.validate()
        guard let progress = archive.record.publication,
              try progress.state(accountID: accountID, file: file) == .published,
              let account = archive.record.accounts.first(where: { $0.accountID == accountID }),
              let config = try archive.configuration(accountID: accountID) else { throw PreparationStoreError.invalidTransition }
        try AdministrativeSetupPublication.validateRetained(config.bytes(file, target: true),
            file: artifact(file, ownerUID: account.ownerUID), directory: directory, owner: owner, verify: verify)
    }

    private static func openNativeDirectory(accountID: Data,
        file: MachineUpdatePublicationProgress.File) throws -> ProtectedSetupDirectory {
        let paths = try RuntimePreparationPaths(accountID: accountID)
        let path: String, visibility: ProtectedSetupDirectory.Visibility
        switch file {
        case .host: path = paths.privateDirectory; visibility = .privateState
        case .transport, .gateway: path = paths.serviceDirectory; visibility = .sharedMetadata
        case .presence, .pairing, .frontend: path = RuntimePreparationPaths.sharedDirectory; visibility = .sharedMetadata
        }
        return try .init(anchor: "/", relativePath: String(path.dropFirst()), owner: 0,
            visibility: visibility, createIfMissing: false)
    }

    private static func artifact(_ file: MachineUpdatePublicationProgress.File,
        ownerUID: uid_t) -> AdministrativeSetupPublication.File {
        switch file {
        case .host: .commandHost
        case .transport: .transportConfiguration
        case .gateway: .gatewaySettingsHost
        case .presence: .presenceClient(ownerUID: ownerUID)
        case .pairing: .pairingClient(ownerUID: ownerUID)
        case .frontend: .frontendClient(ownerUID: ownerUID)
        }
    }
}
