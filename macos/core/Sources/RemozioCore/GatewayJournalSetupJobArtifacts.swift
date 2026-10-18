import Darwin
import Foundation

/// Only pending setup may create artifacts. Completed setup may remove its stopped job without reopening journal creation.
enum GatewayJournalSetupJobArtifacts {
    enum Mode { case preparePending, validateRetained }
    enum Artifact: Hashable { case configuration, job }
    struct Result: Equatable { let files: [Artifact: AdministrativeSetupPublicationResult] }
    enum Removal: Equatable { case removed, absent }

    static func prepare(configuration: GatewayJournalSetupServiceConfiguration, account: AccountPreparationIntent,
                        machine: PreparationIntentStore, foreground: RuntimeActivationPlan, inventory: InstallationInventory,
                        release: SignedReleaseEvidence, mode: Mode = .preparePending, verifyCurrent: () throws -> Void) throws -> Result {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let expected = GatewayJournalPreparationState(intent: configuration.intent, initialized: false)
        func verify() throws {
            try verifyCurrent()
            guard try machine.loadInventory() == inventory,
                  try machine.gatewayJournalPreparation(accountID: configuration.intent.accountID) == expected else {
                throw GatewayPreparationError.changedScope
            }
            try configuration.validate(foreground: foreground, inventory: inventory, release: release)
            try configuration.intent.material.runtime.services.validate(account: account)
            let directory = try NativeServiceAccountDirectory(accountID: account.accountID, ownerUID: account.ownerUID)
            for claim in configuration.intent.material.runtime.services.claims {
                try directory.validateGroup(claim); try directory.validateUser(claim, ownerUID: account.ownerUID)
            }
        }
        try verify()
        let paths = try RuntimePreparationPaths(accountID: configuration.intent.accountID)
        let service = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()), owner: 0,
            visibility: .sharedMetadata, createIfMissing: false)
        defer { service.close() }
        let jobs = try ProtectedSetupDirectory(anchor: "/", relativePath: String(InstalledAccountJobManifest.directory.dropFirst()), owner: 0,
            visibility: .sharedMetadata, createIfMissing: false)
        defer { jobs.close() }
        return try publish(configuration: configuration, service: service, jobs: jobs, owner: 0, mode: mode, verifyCurrent: verify)
    }
    static func validateRetainedJob(_ job: GatewayJournalSetupJobManifest, verifyCurrent: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let jobs = try ProtectedSetupDirectory(anchor: "/", relativePath: String(InstalledAccountJobManifest.directory.dropFirst()), owner: 0,
            visibility: .sharedMetadata, createIfMissing: false)
        defer { jobs.close() }
        try validateRetainedJob(job, jobs: jobs, owner: 0, verifyCurrent: verifyCurrent)
    }
    static func validateRetainedJob(_ job: GatewayJournalSetupJobManifest, jobs: ProtectedSetupDirectory, owner: uid_t,
                                    verifyCurrent: () throws -> Void) throws {
        let file = AdministrativeSetupPublication.File.gatewayJournalJob(accountID: job.configuration.intent.accountID, intentID: job.configuration.intent.id)
        guard file.name == job.label + ".plist" else { throw GatewayPreparationError.invalidRecord }
        try AdministrativeSetupPublication.validateRetained(job.bytes, file: file, directory: jobs, owner: owner, verify: verifyCurrent)
    }
    static func removeAfterJobAbsent(configuration: GatewayJournalSetupServiceConfiguration, machine: PreparationIntentStore,
                                     verifyCurrent: () throws -> Void) throws -> Removal {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let job = try GatewayJournalSetupJobManifest(configuration: configuration)
        func verify() throws {
            try verifyCurrent()
            guard try machine.gatewayJournalPreparation(accountID: configuration.intent.accountID).intent == configuration.intent else {
                throw GatewayPreparationError.changedScope
            }
        }
        try verify()
        let jobs = try ProtectedSetupDirectory(anchor: "/", relativePath: String(InstalledAccountJobManifest.directory.dropFirst()), owner: 0,
            visibility: .sharedMetadata, createIfMissing: false)
        defer { jobs.close() }
        return try removeJobFile(job: job, jobs: jobs, owner: 0, jobIsAbsent: { try GatewayJournalSetupJobRegistration.isAbsent(job) }, verifyCurrent: verify)
    }

    // Owned fixtures exercise actual publication and unlink. They do not establish Root placement or system job admission.
    static func publish(configuration: GatewayJournalSetupServiceConfiguration, service: ProtectedSetupDirectory, jobs: ProtectedSetupDirectory,
                        owner: uid_t, mode: Mode, verifyCurrent: () throws -> Void,
                        didPublish: (Artifact) throws -> Void = { _ in }) throws -> Result {
        let job = try GatewayJournalSetupJobManifest(configuration: configuration)
        let jobFile = AdministrativeSetupPublication.File.gatewayJournalJob(accountID: configuration.intent.accountID, intentID: configuration.intent.id)
        guard jobFile.name == job.label + ".plist" else { throw GatewayPreparationError.invalidRecord }
        let records: [(Artifact, Data, AdministrativeSetupPublication.File, ProtectedSetupDirectory)] = [
            (.configuration, configuration.canonicalBytes, .gatewayJournalService, service), (.job, job.bytes, jobFile, jobs)]
        func verify() throws { try verifyCurrent(); try service.validate(); try jobs.validate() }
        // Check every retained destination before creating a sibling in either directory.
        for (_, bytes, file, directory) in records {
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
        var result: [Artifact: AdministrativeSetupPublicationResult] = [:]
        for (artifact, bytes, file, directory) in records {
            try verify()
            if mode == .preparePending {
                result[artifact] = try AdministrativeSetupPublication.publish(bytes, file: file, directory: directory, owner: owner, verify: verify)
            } else {
                try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: owner, verify: verify)
                result[artifact] = .retained
            }
            try didPublish(artifact); try verify()
        }
        for (_, bytes, file, directory) in records {
            try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: owner, verify: verify)
        }
        try verify(); return .init(files: result)
    }
    static func removeJobFile(job: GatewayJournalSetupJobManifest, jobs: ProtectedSetupDirectory, owner: uid_t,
                              jobIsAbsent: () throws -> Bool, verifyCurrent: () throws -> Void,
                              didValidate: () throws -> Void = {}, didRemove: () throws -> Void = {}) throws -> Removal {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        let file = AdministrativeSetupPublication.File.gatewayJournalJob(accountID: job.configuration.intent.accountID, intentID: job.configuration.intent.id)
        try file.validate()
        guard file.name == job.label + ".plist" else { throw GatewayPreparationError.invalidRecord }
        func verify() throws { try verifyCurrent(); try jobs.validate() }
        try verify()
        guard try jobIsAbsent() else { throw GatewayServiceError.unavailable }
        return try jobs.withSharedDirectory { parent in
            let descriptor = openat(parent, file.name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            if descriptor < 0 {
                guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
                try verify(); guard try jobIsAbsent() else { throw GatewayServiceError.unavailable }
                return .absent
            }
            defer { _ = Darwin.close(descriptor) }
            func inspect() throws -> stat {
                var held = stat(), named = stat()
                guard fstat(descriptor, &held) == 0, fstatat(parent, file.name, &named, AT_SYMLINK_NOFOLLOW) == 0 else { throw JournalLeaseError.system(errno) }
                guard held.st_dev == named.st_dev, held.st_ino == named.st_ino else { throw JournalLeaseError.identityChanged }
                try ProtectedStorageMetadata.validate(descriptor, held, directory: false, privateObject: false, owner: owner, ancestorOwner: owner)
                guard held.st_mode & 0o7777 == file.mode else { throw JournalLeaseError.unsafeMetadata }
                return held
            }
            let original = try inspect()
            guard original.st_size == job.bytes.count, original.st_size > 0, original.st_size <= ProtectedServiceConfiguration.maximumBytes else {
                throw GatewayPreparationError.changedScope
            }
            var bytes = Data(count: Int(original.st_size)), offset = 0
            while offset < bytes.count {
                let count = bytes.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw JournalLeaseError.identityChanged }; offset += count
            }
            try job.validateBytes(bytes); try didValidate(); try verify()
            guard try jobIsAbsent() else { throw GatewayServiceError.unavailable }
            let current = try inspect()
            guard current.st_dev == original.st_dev, current.st_ino == original.st_ino, current.st_size == original.st_size,
                  current.st_mtimespec.tv_sec == original.st_mtimespec.tv_sec, current.st_mtimespec.tv_nsec == original.st_mtimespec.tv_nsec,
                  current.st_ctimespec.tv_sec == original.st_ctimespec.tv_sec, current.st_ctimespec.tv_nsec == original.st_ctimespec.tv_nsec else {
                throw JournalLeaseError.identityChanged
            }
            guard unlinkat(parent, file.name, 0) == 0, fsync(parent) == 0 else { throw JournalLeaseError.system(errno) }
            try didRemove(); try verify()
            guard try jobIsAbsent() else { throw GatewayServiceError.unavailable }
            return .removed
        }
    }
}
