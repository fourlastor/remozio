import Darwin
import Foundation

/// Publishes a pending pause record and removes only its exact completed successor.
/// The authorized owner retains its machine/release scope; this helper never advances transition phases.
enum GatewayRuntimeSettingsFencePublication {
    enum Removal: Equatable { case removed, absent }
    struct Scope {
        let plan: GatewayRuntimeSettingsPublicationPlan
        let machine: PreparationIntentStore
        let account: AccountPreparationIntent
        let foreground: RuntimeActivationPlan
        let inventory: InstallationInventory
        var fence: GatewayRuntimeSettingsFence { get throws { try .init(plan) } }
        func validateCommon() throws {
            try machine.validateAccountPreparation(account)
            let services = plan.pair.authority.material.runtime.services
            try services.validate(account: account)
            let activeForeground = try machine.runtimeActivation(accountID: account.accountID)
            guard activeForeground.jobsRegistered, try machine.inventory() == inventory,
                  inventory.macID == services.macID, inventory.installationID == services.installationID,
                  inventory.releaseDigest == services.releaseDigest,
                  try activeForeground.plan?.encoded == foreground.encoded else {
                throw GatewayPreparationError.changedScope
            }
            let runtime = try machine.gatewayRuntimeActivation(accountID: account.accountID)
            guard runtime.filesPublished, runtime.jobRegistered, try runtime.plan?.encoded == plan.activation.encoded else {
                throw GatewayPreparationError.changedScope
            }
        }
        func validatePending() throws {
            try validateCommon()
            let state = try machine.gatewaySettingsTransition(accountID: account.accountID)
            guard try state.pending?.encoded == plan.revision.encoded, state.phase != nil else { throw GatewayPreparationError.changedScope }
            let expected = try GatewayRuntimeSettingsPublicationPlan(revision: plan.revision, previous: state.active,
                activation: plan.activation, journal: machine.gatewayJournalPreparation(accountID: account.accountID),
                foreground: foreground, inventory: inventory)
            guard try GatewayRuntimeSettingsFence(expected).encoded == fence.encoded else { throw GatewayPreparationError.changedScope }
        }
        func validateComplete() throws {
            try validateCommon()
            let state = try machine.gatewaySettingsTransition(accountID: account.accountID)
            guard state.pending == nil, state.phase == nil, try state.active?.encoded == plan.revision.encoded else {
                throw GatewayPreparationError.changedScope
            }
        }
    }
    static func prepare(_ scope: Scope, release: SignedReleaseEvidence,
                        verifyCurrent: () throws -> Void) throws -> AdministrativeSetupPublicationResult {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        func verify() throws {
            try verifyCurrent(); try scope.validatePending()
            try scope.foreground.host.validateRelease(release, bundlePath: scope.inventory.bundlePath)
            try GatewayRuntimeSettingsFenceReleaseValidation.validate(release, policy: scope.foreground.host.codePolicy)
        }
        try verify()
        let paths = try RuntimePreparationPaths(accountID: scope.account.accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { directory.close() }
        return try publish(scope, directory: directory, owner: 0, verifyCurrent: verify)
    }
    static func removeCompleted(_ scope: Scope, release: SignedReleaseEvidence,
                                verifyCurrent: () throws -> Void) throws -> Removal {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        func verify() throws {
            try verifyCurrent(); try scope.validateComplete()
            try scope.foreground.host.validateRelease(release, bundlePath: scope.inventory.bundlePath)
            try GatewayRuntimeSettingsFenceReleaseValidation.validate(release, policy: scope.foreground.host.codePolicy)
        }
        try verify()
        let paths = try RuntimePreparationPaths(accountID: scope.account.accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { directory.close() }
        return try remove(scope, directory: directory, owner: 0, verifyCurrent: verify)
    }
    // Owned fixtures use real protected files and retained state. They do not prove native Root admission.
    static func publish(_ scope: Scope, directory: ProtectedSetupDirectory, owner: uid_t,
                        verifyCurrent: () throws -> Void,
                        didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        func verify() throws { try verifyCurrent(); try scope.validatePending(); try directory.validate() }
        try verify()
        return try AdministrativeSetupPublication.publish(scope.fence.encoded, file: .gatewaySettingsFence,
            directory: directory, owner: owner, verify: verify, didStage: didStage)
    }
    private static func validateSelected(_ scope: Scope, directory: ProtectedSetupDirectory, owner: uid_t,
                                         verify: () throws -> Void) throws {
        let fence = try scope.fence
        func read(_ file: AdministrativeSetupPublication.File) throws -> Data {
            try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name, owner: owner, privateFile: file.mode == 0o600)
        }
        for target in [GatewayRuntimeExtension.Target.authority, .transport] {
            guard let loaded = try GatewayRuntimeLoader.load(target: target, read: read, verifyCurrent: verify, validate: {
                if target == .authority { try $0.validate(authority: scope.foreground.host) }
                else { try $0.validate(transport: scope.foreground.transport) }
            }), try loaded.commit.encoded == fence.selected.encoded else { throw GatewayPreparationError.changedScope }
        }
    }
    static func remove(_ scope: Scope, directory: ProtectedSetupDirectory, owner: uid_t,
                       verifyCurrent: () throws -> Void, didValidate: () throws -> Void = {},
                       didRemove: () throws -> Void = {}) throws -> Removal {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        let file = AdministrativeSetupPublication.File.gatewaySettingsFence, bytes = try scope.fence.encoded
        func verify() throws { try verifyCurrent(); try scope.validateComplete(); try directory.validate() }
        try verify(); try validateSelected(scope, directory: directory, owner: owner, verify: verify)
        return try directory.withSharedDirectory { parent in
            let fd = openat(parent, file.name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            if fd < 0 {
                guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
                try verify(); try validateSelected(scope, directory: directory, owner: owner, verify: verify)
                guard fsync(parent) == 0 else { throw JournalLeaseError.system(errno) }
                return .absent
            }
            defer { _ = Darwin.close(fd) }
            func inspect() throws -> stat {
                var held = stat(), named = stat()
                guard fstat(fd, &held) == 0, fstatat(parent, file.name, &named, AT_SYMLINK_NOFOLLOW) == 0 else { throw JournalLeaseError.system(errno) }
                guard held.st_dev == named.st_dev, held.st_ino == named.st_ino else { throw JournalLeaseError.identityChanged }
                try ProtectedStorageMetadata.validate(fd, held, directory: false, privateObject: false, owner: owner, ancestorOwner: owner)
                guard held.st_mode & 0o7777 == file.mode, held.st_size == bytes.count else { throw JournalLeaseError.unsafeMetadata }
                return held
            }
            let original = try inspect()
            var data = Data(count: bytes.count), offset = 0
            while offset < data.count {
                let count = data.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw JournalLeaseError.identityChanged }; offset += count
            }
            guard data == bytes else { throw GatewayPreparationError.changedScope }
            try didValidate(); try verify(); try validateSelected(scope, directory: directory, owner: owner, verify: verify)
            let current = try inspect()
            guard current.st_dev == original.st_dev, current.st_ino == original.st_ino,
                  current.st_mtimespec.tv_sec == original.st_mtimespec.tv_sec, current.st_mtimespec.tv_nsec == original.st_mtimespec.tv_nsec,
                  current.st_ctimespec.tv_sec == original.st_ctimespec.tv_sec, current.st_ctimespec.tv_nsec == original.st_ctimespec.tv_nsec else {
                throw JournalLeaseError.identityChanged
            }
            guard unlinkat(parent, file.name, 0) == 0, fsync(parent) == 0 else { throw JournalLeaseError.system(errno) }
            try didRemove(); try verify(); try validateSelected(scope, directory: directory, owner: owner, verify: verify)
            return .removed
        }
    }
}
