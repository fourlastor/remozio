import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

/// Local public choices only. The imported bundle supplies no port, tunnel identity or destination hostname.
struct SharedSetupImportRelayPlan: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "setup.shared-import-relay-plan"
    static let supportedVersions: Set<UInt64> = [1]
    static let maximumBytes = 2048
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 32)
    let port: UInt16
    let hostname: String
    let tunnelName: String
    let bytes: Data
    var accessApplicationName: String { tunnelName + "-approval" }
    var description: String { "SharedSetupImportRelayPlan(redacted)" }
    var debugDescription: String { description }
    init(expected: SharedSetupImportIntent, port: UInt16) throws {
        guard port >= 1024, let cloud = expected.recipe.cloudflare else { throw SharedSetupImportError.invalidRecord }
        let suffix = expected.operationID.map { String(format: "%02x", $0) }.joined()
        hostname = "m-" + suffix + "." + cloud.dnsSuffix
        try SetupCloudflareConfiguration.validateScope(accountID: cloud.accountID, zoneID: cloud.zoneID, dnsSuffix: hostname)
        tunnelName = "remozio-" + suffix; self.port = port
        let scope = expected.scope
        bytes = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .text("remozio-local-import-relay"), 2: .bytes(scope.macID), 3: .bytes(scope.installationID),
            4: .bytes(scope.releaseDigest), 5: .bytes(scope.accountID), 6: .unsigned(UInt64(scope.ownerUID)),
            7: .bytes(scope.accountBinding), 8: .bytes(expected.operationID), 9: .bytes(expected.proposalDigest),
            10: .unsigned(UInt64(port)), 11: .text(cloud.accountID), 12: .text(cloud.zoneID), 13: .text(cloud.dnsSuffix)
        ]), limits: Self.limits)
    }
    func validate(expected: SharedSetupImportIntent) throws {
        guard try Self(expected: expected, port: port).bytes == bytes else { throw SharedSetupImportError.wrongScope }
    }
    static func decode(_ bytes: Data, expected: SharedSetupImportIntent) throws -> Self {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...13), case let .unsigned(value) = fields[10],
              let port = UInt16(exactly: value) else { throw SharedSetupImportError.invalidRecord }
        let result = try Self(expected: expected, port: port)
        guard result.bytes == bytes else { throw SharedSetupImportError.wrongScope }; return result
    }
}

/// Selection is provisional until the configured carrier binds. A later collision never changes a retained port automatically.
enum SharedSetupRelayPortSelection {
    static func choose(reserved: Set<UInt16>, candidate: () throws -> UInt16 = nativeCandidate) throws -> UInt16 {
        for _ in 0..<64 {
            let port = try candidate()
            guard port >= 1024 else { throw SharedSetupImportError.invalidRecord }
            if !reserved.contains(port) { return port }
        }
        throw SharedSetupImportError.capacity
    }
    private static func nativeCandidate() throws -> UInt16 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        defer { close(fd) }
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw JournalLeaseError.system(errno) }
        var address = sockaddr_in(); address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET); address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) { value in
            value.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0 else { throw JournalLeaseError.system(errno) }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let loaded = withUnsafeMutablePointer(to: &address) { value in
            value.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        guard loaded == 0, length == socklen_t(MemoryLayout<sockaddr_in>.size), address.sin_family == sa_family_t(AF_INET) else {
            throw SharedSetupImportError.invalidRecord
        }
        return UInt16(bigEndian: address.sin_port)
    }
}

/// The setup owner holds the machine and import leases. Missing accepted output is never repaired after runtime publication.
enum SharedSetupImportRelayStorage {
    struct Snapshot: Equatable, Sendable { let identity: ProtectedStorageLease.DirectoryIdentity; let digest: Data }
    static func validateTrackedFiles(records: [SharedSetupImportIntent], directory: ProtectedSetupDirectory) throws {
        try directory.validate()
        let names = Set(records.flatMap { [AdministrativeSetupPublication.File.importRelayPlan(accountID: $0.scope.accountID).name,
            AdministrativeSetupPublication.File.importRelayProvisioning(accountID: $0.scope.accountID).name,
            AdministrativeSetupPublication.File.importAccessApplication(accountID: $0.scope.accountID).name,
            AdministrativeSetupPublication.File.importDNSRecord(accountID: $0.scope.accountID).name] })
        let allNames = Set(try FileManager.default.contentsOfDirectory(atPath: directory.path))
        let retained = allNames.filter { $0.hasPrefix("import-relay-") }
        guard retained.allSatisfy({ $0.range(of: #"^import-relay-(?:(?:state|access|dns)-)?[0-9a-f]{32}\.cbor$"#,
            options: .regularExpression) != nil }) else { throw SharedSetupImportError.incompatibleStore }
        guard retained.allSatisfy({ names.contains($0) }) else { throw SharedSetupImportError.corruptRecord }
        guard allNames.isSubset(of: names.union(["setup-import.sqlite", "writer.lock"])) else { throw SharedSetupImportError.incompatibleStore }
        try directory.validate()
    }
    static func read(expected: SharedSetupImportIntent, directory: ProtectedSetupDirectory, owner: uid_t) throws -> SharedSetupImportRelayPlan? {
        let file = AdministrativeSetupPublication.File.importRelayPlan(accountID: expected.scope.accountID)
        let present = try directory.withPrivateDirectory { parent in
            var info = stat()
            if fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
            guard errno == ENOENT else { throw JournalLeaseError.system(errno) }; return false
        }
        guard present else { return nil }
        let bytes = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name, owner: owner)
        let value = try SharedSetupImportRelayPlan.decode(bytes, expected: expected)
        try AdministrativeSetupPublication.validateRetained(value.bytes, file: file, directory: directory, owner: owner, verify: {})
        return value
    }
    static func snapshot(expected: SharedSetupImportIntent, directory: ProtectedSetupDirectory, owner: uid_t) throws -> Snapshot? {
        guard let value = try read(expected: expected, directory: directory, owner: owner) else { return nil }
        let file = AdministrativeSetupPublication.File.importRelayPlan(accountID: expected.scope.accountID)
        let identity = try directory.withPrivateDirectory { parent -> ProtectedStorageLease.DirectoryIdentity in
            var info = stat()
            guard fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) == 0 else { throw JournalLeaseError.system(errno) }
            return .init(device: info.st_dev, inode: info.st_ino)
        }
        guard try read(expected: expected, directory: directory, owner: owner) == value else { throw SharedSetupImportError.conflict }
        try directory.withPrivateDirectory { parent in
            var info = stat()
            guard fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) == 0,
                  info.st_dev == identity.device, info.st_ino == identity.inode else { throw JournalLeaseError.identityChanged }
        }
        return .init(identity: identity, digest: Data(SHA256.hash(data: value.bytes)))
    }
    static func prepare(expected: SharedSetupImportIntent, records: [SharedSetupImportIntent], runtimePublished: Bool,
                        directory: ProtectedSetupDirectory, owner: uid_t, select: (Set<UInt16>) throws -> UInt16,
                        verifyCurrent: () throws -> Void) throws -> SharedSetupImportRelayPlan {
        try verifyCurrent()
        guard expected.recipe.cloudflare != nil, records.contains(expected) else { throw SharedSetupImportError.wrongScope }
        try validateTrackedFiles(records: records, directory: directory)
        var ports = Set<UInt16>(), retained: SharedSetupImportRelayPlan?
        for record in records {
            let plan = try read(expected: record, directory: directory, owner: owner)
            let tunnel = try SharedSetupRelayProvisioningStorage.read(expected: record, plan: plan, directory: directory, owner: owner)
            let access = try SharedSetupAccessApplicationStorage.read(expected: record, plan: plan, createdTunnel: tunnel, directory: directory, owner: owner)
            _ = try SharedSetupDNSStorage.read(expected: record, plan: plan, createdTunnel: tunnel, application: access, directory: directory, owner: owner)
            if let plan {
                guard ports.insert(plan.port).inserted else { throw SharedSetupImportError.conflict }
                if record.scope.accountID == expected.scope.accountID { retained = plan }
            }
        }
        if let retained { try verifyCurrent(); return retained }
        guard expected.phase == .retained, !runtimePublished else { throw SharedSetupImportError.invalidTransition }
        let chosen = try select(ports)
        guard !ports.contains(chosen) else { throw SharedSetupImportError.conflict }
        let plan = try SharedSetupImportRelayPlan(expected: expected, port: chosen)
        let file = AdministrativeSetupPublication.File.importRelayPlan(accountID: expected.scope.accountID)
        try verifyCurrent()
        _ = try AdministrativeSetupPublication.publish(plan.bytes, file: file, directory: directory, owner: owner, verify: verifyCurrent)
        guard try read(expected: expected, directory: directory, owner: owner) == plan else { throw SharedSetupImportError.conflict }
        try verifyCurrent(); return plan
    }
}
