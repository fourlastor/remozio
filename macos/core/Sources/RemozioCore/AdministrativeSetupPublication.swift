import Darwin
import Foundation
import RemozioProtocol

public enum AdministrativeSetupPublicationError: Error, Equatable {
    case conflictingConfiguration, changedInventory, invalidArtifact
}

/// Publication evidence only. It proves no service registration, account enrollment or runtime health.
public enum AdministrativeSetupPublicationResult: Equatable, Sendable { case created, retained }

/// Publishes the fixed private setup file after checking the retained inventory and protected signed release.
public enum AdministrativeSetupPublication {
    public static func publish(_ configuration: AdministrativeSetupConfiguration) throws -> AdministrativeSetupPublicationResult {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let store = try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID)
        defer { try? store.close() }
        guard let inventory = try store.loadInventory() else { throw AdministrativeSetupPublicationError.changedInventory }
        let bundle = URL(fileURLWithPath: inventory.bundlePath)
        let placement = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path)
        defer { placement.close() }
        guard let app = configuration.codePolicy.entries.first(where: { $0.role == .app && $0.active }) else {
            throw AdministrativeSetupServiceError.invalidConfiguration
        }
        func verify() throws {
            guard try store.loadInventory() == inventory else { throw AdministrativeSetupPublicationError.changedInventory }
            _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
            let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
            try configuration.validate(inventory: inventory, release: release)
            try placement.validate()
        }
        try verify()
        let parent = URL(fileURLWithPath: AdministrativeSetupConfiguration.startupPath).deletingLastPathComponent().path
        let directory = try ProtectedSetupDirectory.createOrOpen(path: parent, visibility: .sharedMetadata)
        defer { directory.close() }
        return try publish(configuration, directory: directory, owner: 0, verify: verify)
    }

    enum Stage { case staged, published }
    // Ordinary-owner fixtures exercise real file operations without claiming Root or native signing evidence.
    static func publish(_ configuration: AdministrativeSetupConfiguration, directory: ProtectedSetupDirectory, owner: uid_t,
                        verify: () throws -> Void = {}, didStage: (Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        try publish(configuration.canonicalBytes, file: .startup, directory: directory, owner: owner,
                    verify: verify, didStage: didStage)
    }

    enum File {
        case startup, bootstrapIntent, bootstrapCompletion
        case importRelayPlan(accountID: Data), importRelayProvisioning(accountID: Data), importAccessApplication(accountID: Data), importDNSRecord(accountID: Data), importRelayRunReference(accountID: Data)
        case authorityGatewayRuntime, transportGatewayRuntime, gatewayRuntimeCommit, gatewaySettingsRevision, gatewaySettingsFence, transportRelayReference
        case runtimeRecord, gatewayMaterial, relayRunMaterial, gatewaySettingsHost, gatewayConfiguration, gatewayJournalSetup, gatewayJournalService, commandConfiguration, commandHost, elevationPolicy, transportConfiguration
        case accountJob(accountID: Data, role: AuthorityCodeRole)
        case gatewayJournalJob(accountID: Data, intentID: Data)
        case transportIdentity(ownerUID: uid_t, groupID: gid_t), transportTunnelToken(ownerUID: uid_t, groupID: gid_t)
        case gatewayProvider(ownerUID: uid_t, groupID: gid_t), gatewayReceiptKey(ownerUID: uid_t, groupID: gid_t)
        case transportWakeKey(ownerUID: uid_t, groupID: gid_t)
        case presenceClient(ownerUID: uid_t), pairingClient(ownerUID: uid_t), frontendClient(ownerUID: uid_t)
        var name: String {
            switch self {
            case .authorityGatewayRuntime: "authority-gateway-runtime.cbor"
            case .transportGatewayRuntime: "transport-gateway-runtime.cbor"
            case .gatewayRuntimeCommit: "gateway-runtime-commit.cbor"
            case .gatewaySettingsRevision: "gateway-settings-revision.cbor"
            case .gatewaySettingsFence: "gateway-settings-fence.cbor"
            case .importRelayPlan(let account): "import-relay-" + account.map { String(format: "%02x", $0) }.joined() + ".cbor"
            case .importRelayProvisioning(let account): "import-relay-state-" + account.map { String(format: "%02x", $0) }.joined() + ".cbor"
            case .importAccessApplication(let account): "import-relay-access-" + account.map { String(format: "%02x", $0) }.joined() + ".cbor"
            case .importDNSRecord(let account): "import-relay-dns-" + account.map { String(format: "%02x", $0) }.joined() + ".cbor"
            case .importRelayRunReference(let account): "import-relay-run-" + account.map { String(format: "%02x", $0) }.joined() + ".cbor"
            case .startup: URL(fileURLWithPath: AdministrativeSetupConfiguration.startupPath).lastPathComponent
            case .bootstrapIntent: "bootstrap-intent.cbor"
            case .bootstrapCompletion: "bootstrap-complete.cbor"
            case .runtimeRecord: "runtime-material.cbor"
            case .gatewayMaterial: "gateway-material.cbor"
            case .relayRunMaterial: "relay-run-material.cbor"
            case .transportTunnelToken: "transport-tunnel.token"
            case .transportRelayReference: "transport-relay-reference.cbor"
            case .gatewaySettingsHost: GatewaySettingsConsumerHostConfiguration.gatewayFileName
            case .gatewayConfiguration: "gateway-host.cbor"
            case .gatewayJournalSetup: "gateway-journal-setup.cbor"
            case .gatewayJournalService: GatewayJournalSetupServiceConfiguration.fileName
            case .gatewayProvider: "gateway-provider.json"
            case .gatewayReceiptKey: "gateway-receipt-key.cbor"
            case .transportWakeKey: "transport-wake-key.cbor"
            case .commandConfiguration: "command-runtime.cbor"
            case .commandHost: "command-host.cbor"
            case .accountJob(let account, let role):
                "dev.remozio.account." + account.map { String(format: "%02x", $0) }.joined()
                    + (role == .authority ? ".authority.plist" : role == .notificationGateway ? ".gateway.plist" : ".transport.plist")
            case .gatewayJournalJob(let account, let intent):
                "dev.remozio.account." + account.map { String(format: "%02x", $0) }.joined()
                    + ".gateway-journal-setup." + intent.map { String(format: "%02x", $0) }.joined() + ".plist"
            case .elevationPolicy: "command-policy.cbor"
            case .transportConfiguration: "transport-host.cbor"
            case .transportIdentity: "transport-identity.cbor"
            case .presenceClient(let uid): "presence-client-\(uid).cbor"
            case .pairingClient(let uid): "pairing-client-\(uid).cbor"
            case .frontendClient(let uid): "frontend-\(uid).cbor"
            }
        }
        var mode: mode_t {
            switch self {
            case .transportRelayReference, .transportGatewayRuntime, .gatewayRuntimeCommit, .gatewaySettingsRevision, .gatewaySettingsFence, .gatewaySettingsHost, .gatewayConfiguration, .gatewayJournalSetup, .gatewayJournalService, .transportConfiguration, .presenceClient, .pairingClient, .frontendClient, .accountJob, .gatewayJournalJob: 0o644
            default: 0o600
            }
        }
        var requiresSharedDirectory: Bool {
            switch self {
            case .transportIdentity, .transportTunnelToken, .gatewayProvider, .gatewayReceiptKey, .transportWakeKey: return true
            default: return mode == 0o644
            }
        }
        func fileOwner(processOwner: uid_t) -> uid_t {
            switch self {
            case .transportIdentity(let uid, _), .transportTunnelToken(let uid, _), .gatewayProvider(let uid, _), .gatewayReceiptKey(let uid, _), .transportWakeKey(let uid, _): return uid
            default: return processOwner
            }
        }
        var groupID: gid_t? {
            switch self {
            case .transportIdentity(_, let gid), .transportTunnelToken(_, let gid), .gatewayProvider(_, let gid), .gatewayReceiptKey(_, let gid), .transportWakeKey(_, let gid): return gid
            default: return nil
            }
        }
        func validate() throws {
            let uid: uid_t
            switch self {
            case .transportIdentity(let value, let group), .transportTunnelToken(let value, let group), .gatewayProvider(let value, let group),
                 .gatewayReceiptKey(let value, let group), .transportWakeKey(let value, let group):
                guard group > 0, group < UInt32.max else { throw AdministrativeSetupPublicationError.invalidArtifact }
                uid = value
            case .presenceClient(let value), .pairingClient(let value), .frontendClient(let value): uid = value
            case .importRelayPlan(let account), .importRelayProvisioning(let account), .importAccessApplication(let account), .importDNSRecord(let account), .importRelayRunReference(let account):
                guard account.count == 16 else { throw AdministrativeSetupPublicationError.invalidArtifact }; return
            case .gatewayJournalJob(let account, let intent):
                guard account.count == 16, intent.count == 16 else { throw AdministrativeSetupPublicationError.invalidArtifact }; return
            case .accountJob(let account, let role):
                guard account.count == 16, role == .authority || role == .transport || role == .notificationGateway else {
                    throw AdministrativeSetupPublicationError.invalidArtifact
                }
                return
            default: return
            }
            guard uid > 0, uid < UInt32.max else { throw AdministrativeSetupPublicationError.invalidArtifact }
        }
    }
    // Only typed setup operations select these fixed names. No public arbitrary-file publisher exists.
    static func publish(_ bytes: Data, file: File, directory: ProtectedSetupDirectory, owner: uid_t,
                        verify: () throws -> Void = {}, didStage: (Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        guard getuid() == owner, geteuid() == owner, !bytes.isEmpty,
              bytes.count <= ProtectedServiceConfiguration.maximumBytes else { throw JournalLeaseError.unsafeMetadata }
        try file.validate()
        let name = file.name, fileOwner = file.fileOwner(processOwner: owner)
        let publish: (Int32) throws -> AdministrativeSetupPublicationResult = { parent in
            try verify()
            var existing = stat()
            if fstatat(parent, name, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
                try match(bytes, file: file, directory: directory, owner: owner)
                try synchronizeRetained(parent: parent, name: name, bytes: bytes, owner: fileOwner, mode: file.mode, group: file.groupID)
                guard fsync(parent) == 0 else { throw JournalLeaseError.system(errno) }
                try match(bytes, file: file, directory: directory, owner: owner)
                try verify(); try directory.validate()
                return .retained
            }
            guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
            let staging = ".remozio-setup-" + UUID().uuidString
            let fd = openat(parent, staging, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }
            var published = false
            defer {
                if !published {
                    var held = stat(), named = stat()
                    if fstat(fd, &held) == 0, fstatat(parent, staging, &named, AT_SYMLINK_NOFOLLOW) == 0,
                       held.st_dev == named.st_dev, held.st_ino == named.st_ino {
                        _ = unlinkat(parent, staging, 0)
                    }
                }
                _ = Darwin.close(fd)
            }
            var initial = stat()
            guard fstat(fd, &initial) == 0 else { throw JournalLeaseError.system(errno) }
            try ProtectedStorageMetadata.validate(fd, initial, directory: false, privateObject: false, owner: owner, ancestorOwner: owner)
            guard let acl = acl_init(0) else { throw JournalLeaseError.system(errno) }
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            guard acl_set_fd(fd, acl) == 0, fchmod(fd, 0o600) == 0 else { throw JournalLeaseError.system(errno) }
            var offset = 0
            while offset < bytes.count {
                let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw JournalLeaseError.system(count == 0 ? EIO : errno) }
                offset += count
            }
            if let group = file.groupID {
                var current = stat()
                guard fstat(fd, &current) == 0 else { throw JournalLeaseError.system(errno) }
                if current.st_uid != fileOwner || current.st_gid != group {
                    guard fchown(fd, fileOwner, group) == 0 else { throw JournalLeaseError.system(errno) }
                }
            }
            guard fchmod(fd, file.mode) == 0, fsync(fd) == 0 else { throw JournalLeaseError.system(errno) }
            var staged = stat(), named = stat()
            guard fstat(fd, &staged) == 0, fstatat(parent, staging, &named, AT_SYMLINK_NOFOLLOW) == 0 else {
                throw JournalLeaseError.system(errno)
            }
            guard staged.st_dev == named.st_dev, staged.st_ino == named.st_ino,
                  staged.st_size == bytes.count else { throw JournalLeaseError.identityChanged }
            guard staged.st_uid == fileOwner, staged.st_mode & 0o777 == file.mode,
                  file.groupID == nil || staged.st_gid == file.groupID else { throw JournalLeaseError.unsafeMetadata }
            try ProtectedStorageMetadata.validate(fd, staged, directory: false, privateObject: file.mode == 0o600,
                owner: fileOwner, ancestorOwner: owner)
            try directory.validate(); try didStage(.staged); try verify(); try directory.validate()
            try validateNamedFile(fd: fd, parent: parent, name: staging, bytes: bytes, owner: fileOwner, mode: file.mode, group: file.groupID)
            guard renameatx_np(parent, staging, parent, name, UInt32(RENAME_EXCL)) == 0 else {
                throw JournalLeaseError.system(errno)
            }
            published = true
            try didStage(.published)
            guard fsync(parent) == 0 else { throw JournalLeaseError.system(errno) }
            try match(bytes, file: file, directory: directory, owner: owner)
            try verify(); try directory.validate()
            return .created
        }
        if file.requiresSharedDirectory { return try directory.withSharedDirectory(publish) }
        return try directory.withDirectory(publish)
    }

    /// Replace only optional settings metadata. The caller holds its scope and independently verifies native quiescence.
    static func replaceSettings(_ bytes: Data, expected: Data?, file: File, directory: ProtectedSetupDirectory,
                                owner: uid_t, verify: () throws -> Void,
                                didStage: (Stage) throws -> Void = { _ in }) throws -> GatewayRuntimeSettingsFileResult {
        switch file {
        case .gatewayConfiguration, .authorityGatewayRuntime, .transportGatewayRuntime, .gatewaySettingsRevision, .gatewayRuntimeCommit: break
        default: throw AdministrativeSetupPublicationError.invalidArtifact
        }
        return try replaceSettingsRecord(bytes, expected: expected, file: file, directory: directory, owner: owner,
            verify: verify, didStage: didStage)
    }

    /// Replace only a recognized fence for the same completed settings. The owner authenticates its retained scope.
    static func replaceRecoveryFence(_ bytes: Data, expected: Data?, directory: ProtectedSetupDirectory,
                                     owner: uid_t, verify: () throws -> Void,
                                     didStage: (Stage) throws -> Void = { _ in }) throws -> GatewayRuntimeSettingsFileResult {
        let selected = try GatewayRuntimeSettingsFence.decode(bytes)
        guard selected.version == 2 else { throw AdministrativeSetupPublicationError.invalidArtifact }
        if let expected {
            let previous = try GatewayRuntimeSettingsFence.decode(expected)
            guard previous.macID == selected.macID, previous.accountID == selected.accountID,
                  previous.installationID == selected.installationID, previous.releaseDigest == selected.releaseDigest,
                  try previous.revision.encoded == selected.revision.encoded,
                  try previous.selected.encoded == selected.selected.encoded else {
                throw AdministrativeSetupPublicationError.conflictingConfiguration
            }
        }
        return try replaceSettingsRecord(bytes, expected: expected, file: .gatewaySettingsFence, directory: directory,
            owner: owner, verify: verify, didStage: didStage)
    }

    /// Scope and transition checks precede the existing protected compare-and-swap publisher.
    static func replaceRelayProvisioning(_ bytes: Data, previous: Data?, expected: SharedSetupImportIntent,
                                         plan: SharedSetupImportRelayPlan, directory: ProtectedSetupDirectory, owner: uid_t,
                                         verify: () throws -> Void, didStage: (Stage) throws -> Void = { _ in }) throws -> GatewayRuntimeSettingsFileResult {
        let next = try SharedSetupRelayProvisioningRecord.decode(bytes, expected: expected, plan: plan)
        let old = try previous.map { try SharedSetupRelayProvisioningRecord.decode($0, expected: expected, plan: plan) }
        try next.validateTransition(from: old)
        return try replaceSettingsRecord(bytes, expected: previous, file: .importRelayProvisioning(accountID: expected.scope.accountID),
            directory: directory, owner: owner, verify: verify, didStage: didStage)
    }

    static func replaceAccessApplication(_ bytes: Data, previous: Data?, expected: SharedSetupImportIntent,
                                         plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                                         directory: ProtectedSetupDirectory, owner: uid_t,
                                         verify: () throws -> Void, didStage: (Stage) throws -> Void = { _ in }) throws -> GatewayRuntimeSettingsFileResult {
        let next = try SharedSetupAccessApplicationRecord.decode(bytes, expected: expected, plan: plan, createdTunnel: createdTunnel)
        let old = try previous.map { try SharedSetupAccessApplicationRecord.decode($0, expected: expected, plan: plan, createdTunnel: createdTunnel) }
        try next.validateTransition(from: old)
        return try replaceSettingsRecord(bytes, expected: previous, file: .importAccessApplication(accountID: expected.scope.accountID),
            directory: directory, owner: owner, verify: verify, didStage: didStage)
    }

    static func replaceDNSRecord(_ bytes: Data, previous: Data?, expected: SharedSetupImportIntent,
                                 plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                                 application: SharedSetupAccessApplicationRecord, directory: ProtectedSetupDirectory, owner: uid_t,
                                 verify: () throws -> Void, didStage: (Stage) throws -> Void = { _ in }) throws -> GatewayRuntimeSettingsFileResult {
        let next = try SharedSetupDNSRecord.decode(bytes, expected: expected, plan: plan, createdTunnel: createdTunnel, application: application)
        let old = try previous.map { try SharedSetupDNSRecord.decode($0, expected: expected, plan: plan, createdTunnel: createdTunnel, application: application) }
        try next.validateTransition(from: old)
        return try replaceSettingsRecord(bytes, expected: previous, file: .importDNSRecord(accountID: expected.scope.accountID),
            directory: directory, owner: owner, verify: verify, didStage: didStage)
    }

    private static func replaceSettingsRecord(_ bytes: Data, expected: Data?, file: File, directory: ProtectedSetupDirectory,
                                              owner: uid_t, verify: () throws -> Void,
                                              didStage: (Stage) throws -> Void) throws -> GatewayRuntimeSettingsFileResult {
        guard getuid() == owner, geteuid() == owner, !bytes.isEmpty,
              bytes.count <= ProtectedServiceConfiguration.maximumBytes else { throw JournalLeaseError.unsafeMetadata }
        guard let expected else {
            switch file {
            case .gatewaySettingsRevision, .gatewaySettingsFence, .importRelayProvisioning, .importAccessApplication, .importDNSRecord: break
            default: throw AdministrativeSetupPublicationError.invalidArtifact
            }
            let result = try publish(bytes, file: file, directory: directory, owner: owner, verify: verify, didStage: didStage)
            return result == .created ? .created : .retained
        }
        guard !expected.isEmpty, expected.count <= ProtectedServiceConfiguration.maximumBytes else { throw JournalLeaseError.unsafeMetadata }
        try file.validate(); try verify(); try directory.validate()
        let body: (Int32) throws -> GatewayRuntimeSettingsFileResult = { parent in
            do {
                try match(bytes, file: file, directory: directory, owner: owner)
                try synchronizeRetained(parent: parent, name: file.name, bytes: bytes, owner: owner, mode: file.mode, group: nil)
                guard fsync(parent) == 0 else { throw JournalLeaseError.system(errno) }
                try verify(); try directory.validate(); return .retained
            } catch AdministrativeSetupPublicationError.conflictingConfiguration { }
            try match(expected, file: file, directory: directory, owner: owner)
            let old = openat(parent, file.name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard old >= 0 else { throw JournalLeaseError.system(errno) }
            defer { _ = Darwin.close(old) }
            try validateNamedFile(fd: old, parent: parent, name: file.name, bytes: expected, owner: owner, mode: file.mode, group: nil)
            let staging = ".remozio-settings-" + UUID().uuidString
            let fd = openat(parent, staging, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }
            var exchanged = false
            defer {
                // Remove only the exact owned staging inode. Preserve an unexpected displaced file for diagnosis.
                if exchanged {
                    if (try? validateNamedFile(fd: old, parent: parent, name: staging, bytes: expected, owner: owner, mode: file.mode, group: nil)) != nil {
                        _ = unlinkat(parent, staging, 0); _ = fsync(parent)
                    }
                } else {
                    var held = stat(), named = stat()
                    if fstat(fd, &held) == 0, fstatat(parent, staging, &named, AT_SYMLINK_NOFOLLOW) == 0,
                       held.st_dev == named.st_dev, held.st_ino == named.st_ino { _ = unlinkat(parent, staging, 0) }
                }
                _ = Darwin.close(fd)
            }
            var initial = stat()
            guard fstat(fd, &initial) == 0 else { throw JournalLeaseError.system(errno) }
            try ProtectedStorageMetadata.validate(fd, initial, directory: false, privateObject: false, owner: owner, ancestorOwner: owner)
            guard let acl = acl_init(0) else { throw JournalLeaseError.system(errno) }
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            guard acl_set_fd(fd, acl) == 0, fchmod(fd, 0o600) == 0 else { throw JournalLeaseError.system(errno) }
            var offset = 0
            while offset < bytes.count {
                let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw JournalLeaseError.system(count == 0 ? EIO : errno) }; offset += count
            }
            guard fchmod(fd, file.mode) == 0, fsync(fd) == 0 else { throw JournalLeaseError.system(errno) }
            try didStage(.staged); try verify(); try directory.validate()
            try validateNamedFile(fd: fd, parent: parent, name: staging, bytes: bytes, owner: owner, mode: file.mode, group: nil)
            try validateNamedFile(fd: old, parent: parent, name: file.name, bytes: expected, owner: owner, mode: file.mode, group: nil)
            guard renameatx_np(parent, staging, parent, file.name, UInt32(RENAME_SWAP)) == 0 else { throw JournalLeaseError.system(errno) }
            exchanged = true
            try validateNamedFile(fd: old, parent: parent, name: staging, bytes: expected, owner: owner, mode: file.mode, group: nil)
            try validateNamedFile(fd: fd, parent: parent, name: file.name, bytes: bytes, owner: owner, mode: file.mode, group: nil)
            try didStage(.published)
            guard fsync(parent) == 0 else { throw JournalLeaseError.system(errno) }
            try match(bytes, file: file, directory: directory, owner: owner)
            try verify(); try directory.validate(); return .replaced
        }
        if file.requiresSharedDirectory { return try directory.withSharedDirectory(body) }
        return try directory.withDirectory(body)
    }

    // Read-only retention check. Missing established artifacts never become implicit creation here.
    static func validateRetained(_ bytes: Data, file: File, directory: ProtectedSetupDirectory, owner: uid_t,
                                 verify: () throws -> Void = {}) throws {
        guard getuid() == owner, geteuid() == owner, !bytes.isEmpty,
              bytes.count <= ProtectedServiceConfiguration.maximumBytes else { throw JournalLeaseError.unsafeMetadata }
        try file.validate(); try verify()
        if file.requiresSharedDirectory { try directory.withSharedDirectory { _ in try match(bytes, file: file, directory: directory, owner: owner) } }
        else { try match(bytes, file: file, directory: directory, owner: owner) }
        try verify(); try directory.validate()
    }

    private static func synchronizeRetained(parent: Int32, name: String, bytes: Data, owner: uid_t,
                                            mode: mode_t, group: gid_t?) throws {
        let fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        defer { _ = Darwin.close(fd) }
        try validateNamedFile(fd: fd, parent: parent, name: name, bytes: bytes, owner: owner, mode: mode, group: group)
        guard fsync(fd) == 0 else { throw JournalLeaseError.system(errno) }
        try validateNamedFile(fd: fd, parent: parent, name: name, bytes: bytes, owner: owner, mode: mode, group: group)
    }

    private static func validateNamedFile(fd: Int32, parent: Int32, name: String, bytes: Data, owner: uid_t,
                                          mode: mode_t, group: gid_t?) throws {
        var before = stat(), named = stat()
        guard fstat(fd, &before) == 0, fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw JournalLeaseError.system(errno)
        }
        guard before.st_dev == named.st_dev, before.st_ino == named.st_ino,
              before.st_size == bytes.count else { throw JournalLeaseError.identityChanged }
        guard before.st_mode & 0o777 == mode, group == nil || before.st_gid == group else { throw JournalLeaseError.unsafeMetadata }
        try ProtectedStorageMetadata.validate(fd, before, directory: false, privateObject: mode == 0o600, owner: owner, ancestorOwner: owner)
        var retained = Data(count: bytes.count), offset = 0
        while offset < retained.count {
            let count = retained.withUnsafeMutableBytes { pread(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset, off_t(offset)) }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw JournalLeaseError.identityChanged }
            offset += count
        }
        var after = stat()
        guard retained == bytes, fstat(fd, &after) == 0,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino, before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
            throw JournalLeaseError.identityChanged
        }
        guard fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              named.st_dev == after.st_dev, named.st_ino == after.st_ino else { throw JournalLeaseError.identityChanged }
        guard after.st_mode & 0o777 == mode, group == nil || after.st_gid == group else { throw JournalLeaseError.unsafeMetadata }
        try ProtectedStorageMetadata.validate(fd, after, directory: false, privateObject: mode == 0o600, owner: owner, ancestorOwner: owner)
    }

    private static func match(_ bytes: Data, file: File, directory: ProtectedSetupDirectory, owner: uid_t) throws {
        try directory.validate()
        let retained = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name,
            owner: file.fileOwner(processOwner: owner), privateFile: file.mode == 0o600, ancestorOwner: owner)
        guard retained == bytes else { throw AdministrativeSetupPublicationError.conflictingConfiguration }
        try directory.withDirectory { parent in
            let fd = openat(parent, file.name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }
            defer { _ = Darwin.close(fd) }
            try validateNamedFile(fd: fd, parent: parent, name: file.name, bytes: bytes,
                owner: file.fileOwner(processOwner: owner), mode: file.mode, group: file.groupID)
        }
        try directory.validate()
    }
}
