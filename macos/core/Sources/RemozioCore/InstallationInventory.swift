import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

public enum InstallationInventoryError: Error, Equatable {
    case invalidRecord, corruptRecord, wrongMac, releaseMismatch
}

/// An account context using the shared installed bundle. It carries no command or enrollment grant.
public struct InstallationAccount: Equatable, Sendable {
    public let accountID: Data
    public let ownerUID: uid_t
    public init(accountID: Data, ownerUID: uid_t) throws {
        guard accountID.count == 16, ownerUID > 0, ownerUID < UInt32.max else {
            throw InstallationInventoryError.invalidRecord
        }
        self.accountID = accountID; self.ownerUID = ownerUID
    }
    fileprivate var value: CBORValue { .map([0: .bytes(accountID), 1: .unsigned(UInt64(ownerUID))]) }
}

public enum InstallationServiceKind: UInt64, Sendable { case mainApp = 1, agent, daemon }

/// Recorded registration scope. This declaration does not prove that launchd registered or stopped a process.
public struct InstallationService: Equatable, Sendable {
    public let role: AuthorityCodeRole
    public let kind: InstallationServiceKind
    /// Nil denotes the system domain. User domains retain their actual owner UID.
    public let domainUID: uid_t?
    public let executionUID: uid_t
    /// Nil is reserved for machine-wide roles without an account configuration.
    public let accountID: Data?
    public let label: String
    public let plistName: String?

    public init(role: AuthorityCodeRole, kind: InstallationServiceKind, domainUID: uid_t?, executionUID: uid_t,
                label: String, plistName: String?, accountID: Data? = nil) throws {
        guard Self.token(label), executionUID < UInt32.max, accountID == nil || accountID?.count == 16,
              domainUID == nil || (domainUID! > 0 && domainUID! < UInt32.max) else {
            throw InstallationInventoryError.invalidRecord
        }
        switch kind {
        case .mainApp:
            guard role == .app, domainUID == executionUID, plistName == nil, accountID != nil else {
                throw InstallationInventoryError.invalidRecord
            }
        case .agent:
            guard role == .guiAgent, domainUID == executionUID, accountID != nil, let plistName,
                  Self.token(plistName), plistName.hasSuffix(".plist") else { throw InstallationInventoryError.invalidRecord }
        case .daemon:
            guard domainUID == nil,
                  ![.authority, .transport, .notificationGateway].contains(role) || accountID != nil, let plistName, Self.token(plistName), plistName.hasSuffix(".plist"),
                  [.authority, .transport, .notificationGateway, .tunnelClient, .setupController, .bridgeEndpoint].contains(role),
                  [.authority, .setupController].contains(role) ? executionUID == 0 : executionUID > 0 else {
                throw InstallationInventoryError.invalidRecord
            }
        }
        self.role = role; self.kind = kind; self.domainUID = domainUID; self.executionUID = executionUID
        self.label = label; self.plistName = plistName; self.accountID = accountID
    }
    fileprivate var value: CBORValue {
        .map([0: .unsigned(role.rawValue), 1: .unsigned(kind.rawValue),
              2: domainUID.map { .unsigned(UInt64($0)) } ?? .null, 3: .unsigned(UInt64(executionUID)),
              4: .text(label), 5: plistName.map(CBORValue.text) ?? .null,
              6: accountID.map(CBORValue.bytes) ?? .null])
    }
    fileprivate static func token(_ value: String) -> Bool {
        value.hasPrefix("dev.remozio.") && value.utf8.count <= 255 && value.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45
        }
    }
}

/// Machine-scoped metadata. Decoding grants no installation, live-process or update activation authority.
public struct InstallationInventory: Equatable, Sendable, CustomStringConvertible {
    public let macID: Data
    public let installationID: Data
    public let revision: Data
    public let bundlePath: String
    public let releaseDigest: Data
    public let accounts: [InstallationAccount]
    public let services: [InstallationService]
    public let canonicalBytes: Data
    public var description: String { "InstallationInventory(redacted)" }

    public init(macID: Data, installationID: Data, revision: Data, bundlePath: String, releaseDigest: Data,
                accounts: [InstallationAccount], services: [InstallationService]) throws {
        let parts = bundlePath.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        guard [macID, installationID, revision].allSatisfy({ $0.count == 16 }), releaseDigest.count == 32,
              bundlePath.hasPrefix("/"), bundlePath.utf8.count < Int(PATH_MAX), parts.count <= 64,
              parts.last?.hasSuffix(".app") == true,
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }),
              !accounts.isEmpty, accounts.count <= 64, Set(accounts.map(\.accountID)).count == accounts.count,
              Set(accounts.map(\.ownerUID)).count == accounts.count, !services.isEmpty, services.count <= 256 else {
            throw InstallationInventoryError.invalidRecord
        }
        let owners = Set(accounts.map(\.ownerUID))
        var domains: [UInt64: Set<String>] = [:]
        var roles: [UInt64: [Data?: Set<AuthorityCodeRole>]] = [:]
        for service in services {
            let domain = service.domainUID.map(UInt64.init) ?? 0
            let account = service.accountID.flatMap { id in accounts.first { $0.accountID == id } }
            guard service.accountID == nil || account != nil,
                  service.domainUID == nil || account?.ownerUID == service.domainUID,
                  service.domainUID == nil || owners.contains(service.domainUID!),
                  service.kind != .daemon || service.executionUID == 0 || !owners.contains(service.executionUID),
                  domains[domain, default: []].insert(service.label).inserted,
                  roles[domain, default: [:]][service.accountID, default: []].insert(service.role).inserted else { throw InstallationInventoryError.invalidRecord }
        }
        guard services.contains(where: { $0.role == .authority && $0.kind == .daemon }) else { throw InstallationInventoryError.invalidRecord }
        self.macID = macID; self.installationID = installationID; self.revision = revision
        self.bundlePath = bundlePath; self.releaseDigest = releaseDigest
        self.accounts = accounts.sorted { $0.accountID.lexicographicallyPrecedes($1.accountID) }
        self.services = services.sorted {
            let a = $0.domainUID ?? 0, b = $1.domainUID ?? 0
            if a != b { return a < b }
            let x = $0.accountID ?? Data(), y = $1.accountID ?? Data()
            return x == y ? $0.role.rawValue < $1.role.rawValue : x.lexicographicallyPrecedes(y)
        }
        canonicalBytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(macID), 2: .bytes(installationID),
            3: .bytes(revision), 4: .text(bundlePath), 5: .bytes(releaseDigest),
            6: .array(self.accounts.map(\.value)), 7: .array(self.services.map(\.value))]), limits: Self.limits)
    }

    /// Root startup reads retained metadata only. It never initializes, migrates or repairs inventory.
    public static func load(path: String, expectedMacID: Data) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try decode(ProtectedServiceConfiguration.read(path: path), expectedMacID: expectedMacID)
    }

    public static func decode(_ bytes: Data, expectedMacID: Data) throws -> Self {
        guard expectedMacID.count == 16 else { throw InstallationInventoryError.invalidRecord }
        let decoded: CBORValue
        do { decoded = try DeterministicCBOR.decode(bytes, limits: limits) }
        catch { throw InstallationInventoryError.corruptRecord }
        guard case .map(let f) = decoded, Set(f.keys) == Set(UInt64(0)...7), f[0] == .unsigned(1),
              case .bytes(let mac) = f[1], case .bytes(let installation) = f[2], case .bytes(let revision) = f[3],
              case .text(let path) = f[4], case .bytes(let digest) = f[5],
              case .array(let accountValues) = f[6], case .array(let serviceValues) = f[7],
              accountValues.count <= 64, serviceValues.count <= 256 else { throw InstallationInventoryError.corruptRecord }
        guard mac == expectedMacID else { throw InstallationInventoryError.wrongMac }
        let accounts = try accountValues.map { value in
            guard case .map(let a) = value, Set(a.keys) == [0, 1], case .bytes(let id) = a[0],
                  case .unsigned(let raw) = a[1], let uid = uid_t(exactly: raw) else { throw InstallationInventoryError.corruptRecord }
            return try InstallationAccount(accountID: id, ownerUID: uid)
        }
        let services = try serviceValues.map { value in
            guard case .map(let s) = value, Set(s.keys) == Set(UInt64(0)...6),
                  case .unsigned(let rawRole) = s[0], let role = AuthorityCodeRole(rawValue: rawRole),
                  case .unsigned(let rawKind) = s[1], let kind = InstallationServiceKind(rawValue: rawKind),
                  case .unsigned(let rawUID) = s[3], let uid = uid_t(exactly: rawUID),
                  case .text(let label) = s[4] else { throw InstallationInventoryError.corruptRecord }
            let domain: uid_t?, plist: String?, accountID: Data?
            switch s[2] {
            case .null?: domain = nil
            case .unsigned(let raw)?: guard let value = uid_t(exactly: raw) else { throw InstallationInventoryError.corruptRecord }; domain = value
            default: throw InstallationInventoryError.corruptRecord
            }
            switch s[5] {
            case .null?: plist = nil
            case .text(let name)?: plist = name
            default: throw InstallationInventoryError.corruptRecord
            }
            switch s[6] {
            case .null?: accountID = nil
            case .bytes(let id)?: accountID = id
            default: throw InstallationInventoryError.corruptRecord
            }
            return try InstallationService(role: role, kind: kind, domainUID: domain, executionUID: uid,
                                           label: label, plistName: plist, accountID: accountID)
        }
        let result = try Self(macID: mac, installationID: installation, revision: revision, bundlePath: path,
                              releaseDigest: digest, accounts: accounts, services: services)
        guard result.canonicalBytes == bytes else { throw InstallationInventoryError.corruptRecord }
        return result
    }

    /// Compares retained metadata with fresh signing evidence. Placement, registration, floors and quiescence remain separate.
    public func compareRelease(_ evidence: SignedReleaseEvidence) throws {
        guard try Self.digest(evidence) == releaseDigest,
              services.allSatisfy({ service in evidence.manifest.components.contains { $0.role == service.role } }),
              services.filter({ $0.kind == .mainApp }).allSatisfy({ service in
                  evidence.manifest.components.first(where: { $0.role == .app })?.identifier == service.label
              }) else { throw InstallationInventoryError.releaseMismatch }
    }

    public static func digest(_ evidence: SignedReleaseEvidence) throws -> Data {
        guard Set(evidence.codeDirectoryHashes.keys) == Set(evidence.manifest.components.map(\.role)),
              evidence.codeDirectoryHashes.values.allSatisfy({ $0.count == 20 }),
              evidence.manifest.components.allSatisfy({ $0.role == .app || $0.codeDirectoryHash == evidence.codeDirectoryHashes[$0.role] }),
              Set(evidence.dependencyCodeDirectoryHashes.keys) == Set(evidence.manifest.dependencies.map(\.executablePath)),
              evidence.manifest.dependencies.allSatisfy({ $0.codeDirectoryHash == evidence.dependencyCodeDirectoryHashes[$0.executablePath] }) else {
            throw InstallationInventoryError.releaseMismatch
        }
        let hashes = Dictionary(uniqueKeysWithValues: evidence.codeDirectoryHashes.map { ($0.key.rawValue, CBORValue.bytes($0.value)) })
        let dependencies = evidence.dependencyCodeDirectoryHashes.sorted { $0.key < $1.key }.map {
            CBORValue.array([.text($0.key), .bytes($0.value)])
        }
        let bytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(evidence.manifest.canonicalBytes),
            2: .map(hashes), 3: .array(dependencies)]), limits: .init(maxBytes: ReleaseManifest.maximumBytes + 8192, maxDepth: 3, maxItems: 512))
        return Data(SHA256.hash(data: Data("Remozio/InstallationInventoryRelease/v1\0".utf8) + bytes))
    }
    static var limits: CBORLimits { get throws { try .init(maxBytes: 65_536, maxDepth: 4, maxItems: 4096) } }
}
