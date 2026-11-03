import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

/// Private historical recovery data. A canonical graph grants no current scope, quiescence or activation authority.
struct RuntimeAuditUpgradeGraph: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    static let formatName = "runtime.audit-upgrade-graph"
    static let supportedVersions: Set<UInt64> = [1]
    static let maximumBytes = 8 * 1024 * 1024
    static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 8, maxItems: 65536)
    let upgrade: RuntimeAuditUpgradeRecord
    let snapshot: RuntimeAuditUpgradeArtifactSnapshot
    let gatewayJournalIdentity: GatewayJournalFileIdentity?
    let bytes: Data
    var digest: Data { Data(SHA256.hash(data: bytes)) }
    var description: String { "RuntimeAuditUpgradeGraph(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
    private var plan: RuntimeAuditUpgradeArtifactPlan { snapshot.plan }

    init(observation: RuntimeAuditUpgradeCollector.Result, upgrade: RuntimeAuditUpgradeRecord,
         installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy) throws {
        try Self.validateCapabilities(installedRelease, policy: currentPolicy)
        guard upgrade.phase == .materialStaged, upgrade.intent == observation.artifacts.plan.preparation.intent else {
            throw RuntimePreparationError.changedScope
        }
        self.upgrade = upgrade; snapshot = observation.artifacts; gatewayJournalIdentity = observation.gatewayJournalIdentity
        bytes = try Self.encode(upgrade: upgrade, snapshot: snapshot, journal: gatewayJournalIdentity)
    }
    private init(upgrade: RuntimeAuditUpgradeRecord, snapshot: RuntimeAuditUpgradeArtifactSnapshot,
                 journal: GatewayJournalFileIdentity?, bytes: Data) {
        self.upgrade = upgrade; self.snapshot = snapshot; gatewayJournalIdentity = journal; self.bytes = bytes
    }
    static var requirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].map {
            try .init(role: $0, name: formatName, readVersions: [1], writeVersions: $0 == .setupController ? [1] : [])
        }
    } }
    static func validateCapabilities(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy) throws {
        try ReleaseCompatibilityPreflight.validate(release, policy: policy, requirements: .init(formats: requirements, requests: []))
    }
    func requireOwner(_ owner: uid_t) throws {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        if snapshot.ownership == .native { guard owner == 0 else { throw JournalLeaseError.rootRequired } }
        else {
            guard owner > 0, snapshot.leaves.first(where: { $0.entry.file.name == "runtime-material.cbor" })?.metadata?.uid == owner else {
                throw JournalLeaseError.unsafeMetadata
            }
        }
    }
    private static func optional(_ value: Data?) -> CBORValue { value.map(CBORValue.bytes) ?? .null }
    private static func identity(_ value: ProtectedStorageLease.DirectoryIdentity) -> CBORValue {
        .array([.unsigned(UInt64(UInt32(bitPattern: value.device))), .unsigned(value.inode)])
    }
    private static func journalValue(_ value: GatewayJournalFileIdentity?) -> CBORValue {
        value.map { .array([$0.directory, $0.writer, $0.database].map(identity)) } ?? .null
    }
    private static func metadataValue(_ value: RuntimeAuditUpgradeArtifactSnapshot.Metadata?) -> CBORValue {
        guard let v = value else { return .null }
        return .array([UInt64(UInt32(bitPattern: v.device)), v.inode, UInt64(v.size), UInt64(v.uid), UInt64(v.gid), UInt64(v.mode),
            UInt64(bitPattern: Int64(v.modifiedSeconds)), UInt64(v.modifiedNanoseconds), UInt64(bitPattern: Int64(v.changedSeconds)),
            UInt64(v.changedNanoseconds), UInt64(bitPattern: Int64(v.bornSeconds)), UInt64(v.bornNanoseconds), UInt64(v.generation)].map(CBORValue.unsigned))
    }
    private static func encode(upgrade: RuntimeAuditUpgradeRecord, snapshot: RuntimeAuditUpgradeArtifactSnapshot,
                               journal: GatewayJournalFileIdentity?) throws -> Data {
        let p = snapshot.plan, g = p.sourceGateway
        guard let root = snapshot.leaves.first(where: { $0.entry.file.name == "runtime-material.cbor" })?.metadata,
              let transport = snapshot.leaves.first(where: { $0.entry.file.name == "transport-identity.cbor" })?.metadata else {
            throw RuntimePreparationError.invalidRecord
        }
        let profile: CBORValue = .array([.unsigned(snapshot.ownership == .native ? 1 : 2), .unsigned(UInt64(root.uid)),
            .unsigned(snapshot.ownership == .native ? 0 : UInt64(transport.gid))])
        let gateway: CBORValue = try .map([0: optional(g.reference?.encoded), 1: optional(g.journal.intent?.encoded),
            2: .boolean(g.journal.initialized), 3: optional(g.activation.plan?.encoded), 4: .boolean(g.activation.filesPublished),
            5: .boolean(g.activation.jobRegistered), 6: optional(g.settings.active?.encoded), 7: optional(g.settings.pending?.encoded),
            8: g.settings.phase.map { .unsigned(UInt64($0.rawValue)) } ?? .null])
        let parents: CBORValue = .array(snapshot.retainedParents.sorted { $0.key.rawValue < $1.key.rawValue }.map { area, v in
            .array([.unsigned(area.rawValue), .text(v.path), .unsigned(UInt64(UInt32(bitPattern: v.device))), .unsigned(v.inode), .boolean(v.missingChild)])
        })
        let leaves: CBORValue = .array(snapshot.leaves.sorted { $0.entry.key < $1.entry.key }.map { v in
            .array([.unsigned(v.entry.directory.rawValue), .text(v.entry.file.name), optional(v.source), optional(v.target), metadataValue(v.metadata)])
        })
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-private-audit-upgrade-graph"),
            2: .bytes(upgrade.encoded), 3: profile, 4: .bytes(p.sourceAccount.bytes), 5: .bytes(p.sourceInitialization.bytes),
            6: .bytes(p.sourceInventory.canonicalBytes), 7: .bytes(p.preparation.source.encoded), 8: .boolean(p.sourceJobsRegistered),
            9: gateway, 10: optional(p.sourceImport?.intent.bytes), 11: parents, 12: leaves, 13: journalValue(journal)]), limits: limits)
    }
    /// Reconstructs both sides from source inputs and the pinned signed release. It does not inspect current files or authorize reuse.
    static func decode(_ bytes: Data, expectedDigest: Data, installedRelease: SignedReleaseEvidence,
                       currentPolicy: AuthorityCodePolicy, ownership: RuntimeAuditUpgradeArtifactSnapshot.Ownership) throws -> Self {
        guard bytes.count <= maximumBytes, expectedDigest.count == 32, Data(SHA256.hash(data: bytes)) == expectedDigest else {
            throw RuntimePreparationError.conflictingMaterial
        }
        try validateCapabilities(installedRelease, policy: currentPolicy)
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...13),
              f[0] == .unsigned(1), f[1] == .text("remozio-private-audit-upgrade-graph"),
              case .array(let profile) = f[3], profile.count == 3,
              case .unsigned(let mode) = profile[0], mode == (ownership == .native ? 1 : 2),
              case .unsigned(let uidRaw) = profile[1], let uid = UInt32(exactly: uidRaw),
              case .unsigned(let gidRaw) = profile[2], let group = UInt32(exactly: gidRaw),
              (ownership == .native ? uid == 0 && group == 0 : uid > 0 && uid < UInt32.max && group > 0 && group < UInt32.max),
              case .boolean(let registered) = f[8], case .map(let g) = f[9], Set(g.keys) == Set(UInt64(0)...8),
              case .array(let rawParents) = f[11], rawParents.count == 5,
              case .array(let rawLeaves) = f[12], (1...64).contains(rawLeaves.count) else { throw RuntimePreparationError.invalidRecord }
        func data(_ map: [UInt64: CBORValue], _ key: UInt64) throws -> Data {
            guard case .bytes(let value) = map[key] else { throw RuntimePreparationError.invalidRecord }; return value
        }
        func opt(_ value: CBORValue?) throws -> Data? {
            switch value { case .null?: return nil; case .bytes(let value)?: return value; default: throw RuntimePreparationError.invalidRecord }
        }
        func boolean(_ key: UInt64) throws -> Bool {
            guard case .boolean(let value) = g[key] else { throw RuntimePreparationError.invalidRecord }; return value
        }
        let upgrade = try RuntimeAuditUpgradeRecord.decode(data(f, 2))
        guard upgrade.phase == .materialStaged else { throw RuntimePreparationError.invalidRecord }
        let account = try AccountPreparationIntent.decode(data(f, 4)), initial = try AuthorityInitializationIntent.decode(data(f, 5))
        let inventory = try InstallationInventory.decode(data(f, 6), expectedMacID: account.macID)
        let source = try RuntimeActivationPlan.decode(data(f, 7))
        let preparation = try RuntimeAuditUpgradePreparation(source: source, intent: upgrade.intent,
            installedRelease: installedRelease, currentPolicy: currentPolicy)
        struct RawLeaf { let area: RuntimeAuditUpgradeArtifactPlan.Directory; let name: String; let source: Data?; let target: Data?; let metadata: RuntimeAuditUpgradeArtifactSnapshot.Metadata? }
        var raw: [String: RawLeaf] = [:]
        for value in rawLeaves {
            guard case .array(let a) = value, a.count == 5, case .unsigned(let area) = a[0],
                  let directory = RuntimeAuditUpgradeArtifactPlan.Directory(rawValue: area), case .text(let name) = a[1],
                  !name.isEmpty, name.utf8.count <= 255, name.utf8.allSatisfy({ (45...46).contains($0) || (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) }) else {
                throw RuntimePreparationError.invalidRecord
            }
            let before = try opt(a[2]), after = try opt(a[3]), metadata = try decodeMetadata(a[4])
            guard (before == nil) == (metadata == nil), before.map({ off_t($0.count) == (metadata?.size ?? -1) }) ?? true,
                  before.map({ $0.count <= ProtectedServiceConfiguration.maximumBytes }) ?? true,
                  after.map({ !$0.isEmpty && $0.count <= ProtectedServiceConfiguration.maximumBytes }) ?? true else { throw RuntimePreparationError.invalidRecord }
            let key = "\(area):" + name
            guard raw[key] == nil else { throw RuntimePreparationError.invalidRecord }
            raw[key] = .init(area: directory, name: name, source: before, target: after, metadata: metadata)
        }
        func leaf(_ area: RuntimeAuditUpgradeArtifactPlan.Directory, _ file: AdministrativeSetupPublication.File) throws -> RawLeaf {
            guard let value = raw["\(area.rawValue):" + file.name] else { throw RuntimePreparationError.invalidRecord }; return value
        }
        func required(_ area: RuntimeAuditUpgradeArtifactPlan.Directory, _ file: AdministrativeSetupPublication.File) throws -> Data {
            let observed = try leaf(area, file)
            guard let value = observed.source else { throw RuntimePreparationError.invalidRecord }; return value
        }
        let material = try RuntimePreparationMaterial.decode(required(.runtime, .runtimeRecord))
        let clients = try RuntimeActivationClients(presence: .decode(required(.clients, .presenceClient(ownerUID: account.ownerUID))),
            pairing: .decode(required(.clients, .pairingClient(ownerUID: account.ownerUID))),
            frontend: .decode(required(.clients, .frontendClient(ownerUID: account.ownerUID))))
        let phase: GatewayRuntimeSettingsPhase?
        switch g[8] {
        case .null?: phase = nil
        case .unsigned(let value)?: guard let n = Int64(exactly: value), let p = GatewayRuntimeSettingsPhase(rawValue: n) else { throw RuntimePreparationError.invalidRecord }; phase = p
        default: throw RuntimePreparationError.invalidRecord
        }
        let gateway = try RuntimeAuditUpgradeArtifactPlan.GatewayInputs(
            material: leaf(.runtime, .gatewayMaterial).source.map(GatewayPreparationMaterial.decode),
            reference: opt(g[0]).map(GatewayMaterialReference.decode),
            journal: .init(intent: opt(g[1]).map(GatewayJournalSetupIntent.decode), initialized: boolean(2)),
            activation: .init(plan: opt(g[3]).map(GatewayRuntimeActivationPlan.decode), filesPublished: boolean(4), jobRegistered: boolean(5)),
            settings: .init(active: opt(g[6]).map(GatewayRuntimeSettingsRevision.decode), pending: opt(g[7]).map(GatewayRuntimeSettingsRevision.decode), phase: phase),
            service: leaf(.services, .gatewayJournalService).source.map(GatewayJournalSetupServiceConfiguration.decode),
            fence: leaf(.services, .gatewaySettingsFence).source.map(GatewayRuntimeSettingsFence.decode))
        let imported: RuntimeAuditUpgradeImportPreparation?
        if let encoded = try opt(f[10]) {
            let expected = try SharedSetupImportIntent.decode(encoded), id = account.accountID
            let relayBytes = try leaf(.imports, .importRelayPlan(accountID: id)).source
            let relay = try relayBytes.map { try SharedSetupImportRelayPlan.decode($0, expected: expected) }
            let createdBytes = try leaf(.imports, .importRelayProvisioning(accountID: id)).source
            let created = try createdBytes.map { bytes in
                guard let relay else { throw RuntimePreparationError.invalidRecord }
                return try SharedSetupRelayProvisioningRecord.decode(bytes, expected: expected, plan: relay)
            }
            let accessBytes = try leaf(.imports, .importAccessApplication(accountID: id)).source
            let access = try accessBytes.map { bytes in
                guard let relay, let created else { throw RuntimePreparationError.invalidRecord }
                return try SharedSetupAccessApplicationRecord.decode(bytes, expected: expected, plan: relay, createdTunnel: created)
            }
            if let dns = try leaf(.imports, .importDNSRecord(accountID: id)).source {
                guard let relay, let created, let access else { throw RuntimePreparationError.invalidRecord }
                _ = try SharedSetupDNSRecord.decode(dns, expected: expected, plan: relay, createdTunnel: created, application: access)
            }
            let privateMaterial = try leaf(.runtime, .relayRunMaterial).source.map { bytes in
                guard let relay, let created else { throw RuntimePreparationError.invalidRecord }
                return try RelayRunCredentialMaterial.decode(bytes, expected: expected, plan: relay, created: created,
                    runtime: upgrade.intent.source, account: account, inventory: inventory)
            }
            let reference = try leaf(.imports, .importRelayRunReference(accountID: id)).source.map { bytes in
                guard let relay, let created else { throw RuntimePreparationError.invalidRecord }
                return try RelayRunCredentialReference.decodeRetainedMetadata(bytes, expected: expected, plan: relay, created: created)
            }
            func record(_ file: AdministrativeSetupPublication.File) throws -> SharedSetupImportRelayStorage.Snapshot? {
                let value = try leaf(.imports, file)
                guard let bytes = value.source, let metadata = value.metadata else { return nil }
                return .init(identity: .init(device: metadata.device, inode: metadata.inode), digest: Data(SHA256.hash(data: bytes)))
            }
            let run: SharedSetupRelayRunReferenceStorage.Snapshot?
            if let reference {
                let value = try leaf(.imports, .importRelayRunReference(accountID: id)), metadata = try unwrap(value.metadata)
                run = try .init(identity: .init(device: metadata.device, inode: metadata.inode), digest: Data(SHA256.hash(data: reference.encoded)), reference: reference)
            } else { run = nil }
            let captured = try SharedSetupImportCompatibilitySnapshot.Record(accountID: id, operationID: expected.operationID,
                revision: expected.revision, phase: expected.phase.rawValue, digest: Data(SHA256.hash(data: expected.bytes)),
                portableVersion: expected.originalPortableVersion, settingsVersion: expected.recipe.settingsVersion,
                relay: record(.importRelayPlan(accountID: id)), relayProvisioning: record(.importRelayProvisioning(accountID: id)),
                accessApplication: record(.importAccessApplication(accountID: id)), dnsRecord: record(.importDNSRecord(accountID: id)), runCredential: run)
            let target = try privateMaterial.map { try $0.preparingAuditUpgrade(preparation, expected: $0.reference) }
            var preserved: [RuntimeAuditUpgradeImportPreparation.PreservedFile] = []
            for file: AdministrativeSetupPublication.File in [.importRelayPlan(accountID: id), .importRelayProvisioning(accountID: id),
                .importAccessApplication(accountID: id), .importDNSRecord(accountID: id)] {
                if let bytes = try leaf(.imports, file).source { preserved.append(.init(file: file, bytes: bytes)) }
            }
            imported = try .init(intent: expected, source: captured, preservedFiles: preserved, sourceMaterial: privateMaterial,
                targetMaterial: target, targetReference: reference == nil ? nil : target?.reference)
        } else { imported = nil }
        let transport = try leaf(.services, .transportRelayReference).source.map { bytes in
            guard let port = source.transport.relayPort else { throw RuntimePreparationError.invalidRecord }
            return try RelayRunCredentialReference.decodeForTransport(bytes, runtime: upgrade.intent.source, relayPort: port)
        }
        let plan = try RuntimeAuditUpgradeArtifactPlan(preparation, material: material, account: account, initialization: initial,
            inventory: inventory, clients: clients, installedRelease: installedRelease, sourceJobsRegistered: registered,
            gateway: gateway, imported: imported, transportRelayReference: transport)
        guard Set(raw.keys) == Set(plan.entries.map(\.key)) else { throw RuntimePreparationError.invalidRecord }
        let leaves = try plan.entries.map { entry -> RuntimeAuditUpgradeArtifactSnapshot.Leaf in
            let value = try unwrap(raw[entry.key])
            if let metadata = value.metadata {
                let expectedUID = ownership == .native ? entry.file.fileOwner(processOwner: 0) : uid
                let expectedGroup = ownership == .native ? entry.file.groupID : entry.file.groupID.map { _ in group }
                guard metadata.uid == expectedUID, metadata.mode == mode_t(S_IFREG) | entry.file.mode,
                      expectedGroup == nil || metadata.gid == expectedGroup else { throw RuntimePreparationError.invalidRecord }
            }
            return .init(entry: entry, metadata: value.metadata, source: value.source, target: value.target)
        }
        var parents: [RuntimeAuditUpgradeArtifactPlan.Directory: RuntimeAuditUpgradeArtifactSnapshot.ParentIdentity] = [:]
        let paths = try RuntimePreparationPaths(accountID: account.accountID)
        let expectedPaths: [RuntimeAuditUpgradeArtifactPlan.Directory: String] = [.runtime: paths.privateDirectory, .services: paths.serviceDirectory,
            .clients: RuntimePreparationPaths.sharedDirectory, .jobs: InstalledAccountJobManifest.directory,
            .imports: MachineBootstrap.machineDirectory + "/SharedSetupImport"]
        for value in rawParents {
            guard case .array(let a) = value, a.count == 5, case .unsigned(let raw) = a[0],
                  let area = RuntimeAuditUpgradeArtifactPlan.Directory(rawValue: raw), case .text(let path) = a[1],
                  path.hasPrefix("/"), path.utf8.count < Int(PATH_MAX), !path.utf8.contains(0),
                  path.dropFirst().split(separator: "/", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
                  case .unsigned(let device) = a[2], let dev = UInt32(exactly: device), case .unsigned(let inode) = a[3], inode > 0,
                  case .boolean(let missing) = a[4], !missing || area == .imports, parents[area] == nil,
                  ownership != .native || path == expectedPaths[area] else { throw RuntimePreparationError.invalidRecord }
            parents[area] = .init(path: path, device: dev_t(bitPattern: dev), inode: inode, missingChild: missing)
        }
        if parents[.imports]?.missingChild == true {
            guard leaves.filter({ $0.entry.directory == .imports }).allSatisfy({ $0.source == nil }) else { throw RuntimePreparationError.invalidRecord }
        }
        let journal = try decodeJournal(f[13])
        if let expected = gateway.journal.intent?.files, journal != expected { throw RuntimePreparationError.invalidRecord }
        let snapshot = try RuntimeAuditUpgradeArtifactSnapshot.restore(plan: plan, leaves: leaves, parents: parents, ownership: ownership)
        guard try encode(upgrade: upgrade, snapshot: snapshot, journal: journal) == bytes else { throw RuntimePreparationError.invalidRecord }
        return .init(upgrade: upgrade, snapshot: snapshot, journal: journal, bytes: bytes)
    }
    private static func unwrap<T>(_ value: T?) throws -> T {
        guard let value else { throw RuntimePreparationError.invalidRecord }; return value
    }
    private static func decodeJournal(_ value: CBORValue?) throws -> GatewayJournalFileIdentity? {
        if value == .null { return nil }
        guard case .array(let a) = value, a.count == 3 else { throw RuntimePreparationError.invalidRecord }
        let values = try a.map { value -> ProtectedStorageLease.DirectoryIdentity in
            guard case .array(let v) = value, v.count == 2, case .unsigned(let d) = v[0], let device = UInt32(exactly: d),
                  case .unsigned(let inode) = v[1], inode > 0 else { throw RuntimePreparationError.invalidRecord }
            return .init(device: dev_t(bitPattern: device), inode: inode)
        }
        guard values.allSatisfy({ $0.device == values[0].device }), Set(values.map(\.inode)).count == 3 else { throw RuntimePreparationError.invalidRecord }
        return .init(directory: values[0], writer: values[1], database: values[2])
    }
    private static func decodeMetadata(_ value: CBORValue) throws -> RuntimeAuditUpgradeArtifactSnapshot.Metadata? {
        if value == .null { return nil }
        guard case .array(let a) = value, a.count == 13 else { throw RuntimePreparationError.invalidRecord }
        let v = try a.map { x -> UInt64 in guard case .unsigned(let n) = x else { throw RuntimePreparationError.invalidRecord }; return n }
        guard let device = UInt32(exactly: v[0]), v[1] > 0, (1...UInt64(ProtectedServiceConfiguration.maximumBytes)).contains(v[2]),
              let uid = UInt32(exactly: v[3]), let gid = UInt32(exactly: v[4]), let mode = UInt16(exactly: v[5]),
              [v[7], v[9], v[11]].allSatisfy({ $0 < 1_000_000_000 }), let generation = UInt32(exactly: v[12]) else { throw RuntimePreparationError.invalidRecord }
        var s = stat(); s.st_dev = dev_t(bitPattern: device); s.st_ino = v[1]; s.st_size = off_t(v[2]); s.st_uid = uid; s.st_gid = gid
        s.st_mode = mode; s.st_mtimespec = .init(tv_sec: Int(Int64(bitPattern: v[6])), tv_nsec: Int(v[7]))
        s.st_ctimespec = .init(tv_sec: Int(Int64(bitPattern: v[8])), tv_nsec: Int(v[9]))
        s.st_birthtimespec = .init(tv_sec: Int(Int64(bitPattern: v[10])), tv_nsec: Int(v[11])); s.st_gen = generation
        return .init(s)
    }
}
