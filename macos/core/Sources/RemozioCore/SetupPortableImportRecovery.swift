import CryptoKit
import Foundation
import RemozioProtocol

/// Historical metadata only. Authenticate its Root channel before use; this value grants no authorization or live readiness.
public struct SetupPortableImportRecovery: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public enum Resource: UInt64, CaseIterable, Sendable { case tunnel = 1, accessApplication, dnsRecord }
    public enum Phase: UInt64, Sendable { case prepared = 1, dispatched, created, rejected, unknown }
    public enum Refusal: UInt64, Sendable { case unauthorized = 1, rateLimited, providerRejected }
    public struct RelayScope: Equatable, Sendable {
        public let providerAccountID: String
        public let providerZoneID: String
        public let hostname: String
        public let tunnelName: String
        init(account: String, zone: String, hostname: String, tunnelName: String) throws {
            try SetupCloudflareConfiguration.validateScope(accountID: account, zoneID: zone, dnsSuffix: hostname)
            guard (1...63).contains(tunnelName.utf8.count), tunnelName.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }) else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            providerAccountID = account; providerZoneID = zone; self.hostname = hostname; self.tunnelName = tunnelName
        }
        var value: CBORValue { .map([0: .text(providerAccountID), 1: .text(providerZoneID), 2: .text(hostname), 3: .text(tunnelName)]) }
        static func decode(_ value: CBORValue) throws -> Self {
            guard case .map(let f) = value, Set(f.keys) == Set(UInt64(0)...3), case .text(let account) = f[0],
                  case .text(let zone) = f[1], case .text(let hostname) = f[2], case .text(let name) = f[3] else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            return try .init(account: account, zone: zone, hostname: hostname, tunnelName: name)
        }
    }
    public struct Record: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        public let resource: Resource
        public let phase: Phase
        public let recordDigest: Data
        public let attemptNumber: UInt64
        public let providerID: String?
        public let refusal: Refusal?
        public var description: String { "SetupPortableImportRecovery.Record(redacted)" }
        public var debugDescription: String { description }
        public var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
        init(resource: Resource, phase: Phase, digest: Data, attempt: UInt64, providerID: String?, refusal: Refusal?) throws {
            guard digest.count == 32, attempt > 0, (phase == .created) == (providerID != nil),
                  (phase == .rejected) == (refusal != nil) else { throw AdministrativeSetupChannelError.invalidMessage }
            if let providerID {
                if resource == .dnsRecord {
                    guard SharedSetupDNSRecord.validProviderID(providerID) else { throw AdministrativeSetupChannelError.invalidMessage }
                } else {
                    guard providerID.utf8.count == 36, let uuid = UUID(uuidString: providerID), uuid.uuidString.lowercased() == providerID else {
                        throw AdministrativeSetupChannelError.invalidMessage
                    }
                }
            }
            self.resource = resource; self.phase = phase; recordDigest = digest; attemptNumber = attempt
            self.providerID = providerID; self.refusal = refusal
        }
        init(resource: Resource, phase: UInt64, bytes: Data, attempt: UInt64, providerID: String?, refusal: UInt64?) throws {
            guard let phase = Phase(rawValue: phase) else { throw AdministrativeSetupChannelError.invalidMessage }
            let typed: Refusal?
            if let refusal { guard let value = Refusal(rawValue: refusal) else { throw AdministrativeSetupChannelError.invalidMessage }; typed = value }
            else { typed = nil }
            try self.init(resource: resource, phase: phase, digest: Data(SHA256.hash(data: bytes)), attempt: attempt, providerID: providerID, refusal: typed)
        }
        var value: CBORValue { .map([0: .unsigned(resource.rawValue), 1: .unsigned(phase.rawValue), 2: .bytes(recordDigest),
            3: .unsigned(attemptNumber), 4: providerID.map(CBORValue.text) ?? .null, 5: refusal.map { .unsigned($0.rawValue) } ?? .null]) }
        static func decode(_ value: CBORValue) throws -> Self {
            guard case .map(let f) = value, Set(f.keys) == Set(UInt64(0)...5), case .unsigned(let kind) = f[0], let resource = Resource(rawValue: kind),
                  case .unsigned(let raw) = f[1], let phase = Phase(rawValue: raw), case .bytes(let digest) = f[2], case .unsigned(let attempt) = f[3] else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            let id: String?, refusal: Refusal?
            switch f[4] { case .null?: id = nil; case .text(let value)?: id = value; default: throw AdministrativeSetupChannelError.invalidMessage }
            switch f[5] {
            case .null?: refusal = nil
            case .unsigned(let raw)?: guard let typed = Refusal(rawValue: raw) else { throw AdministrativeSetupChannelError.invalidMessage }; refusal = typed
            default: throw AdministrativeSetupChannelError.invalidMessage
            }
            return try .init(resource: resource, phase: phase, digest: digest, attempt: attempt, providerID: id, refusal: refusal)
        }
    }
    public static let formatName = "setup.shared-import-recovery"
    public static let supportedVersions: Set<UInt64> = [1]
    public static let maximumByteCount = 4096
    private static let limits = try! CBORLimits(maxBytes: maximumByteCount, maxDepth: 3, maxItems: 96)
    public let progress: SetupPortableImportProgress
    public let relayConfigured: Bool
    public let relayScope: RelayScope?
    public let records: [Record]
    public var description: String { "SetupPortableImportRecovery(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
    public func rejectedRecord(for resource: Resource) -> Record? { records.first { $0.resource == resource && $0.phase == .rejected } }
    init(progress: SetupPortableImportProgress, relayConfigured: Bool, relayScope: RelayScope?, records: [Record]) throws {
        guard records.count <= 3, records.map({ $0.resource.rawValue }) == records.map({ $0.resource.rawValue }).sorted(),
              Set(records.map(\.resource)).count == records.count else { throw AdministrativeSetupChannelError.invalidMessage }
        guard relayConfigured || (relayScope == nil && records.isEmpty), relayScope != nil || records.isEmpty,
              progress.operationID != nil || (!relayConfigured && relayScope == nil && records.isEmpty) else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        if let relayScope {
            guard let operation = progress.operationID else { throw AdministrativeSetupChannelError.invalidMessage }
            let suffix = operation.map { String(format: "%02x", $0) }.joined()
            guard relayConfigured, relayScope.tunnelName == "remozio-" + suffix, relayScope.hostname.hasPrefix("m-" + suffix + ".") else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
        } else if relayConfigured {
            guard progress.phase == .retained, progress.runtime.materialID == nil, !progress.runtime.configurationPublished else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
        }
        if records.contains(where: { $0.resource == .accessApplication }), records.first(where: { $0.resource == .tunnel })?.phase != .created {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        if records.contains(where: { $0.resource == .dnsRecord }), records.first(where: { $0.resource == .accessApplication })?.phase != .created {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        if relayConfigured, progress.phase == .relayPrepared || progress.phase == .rootComplete {
            guard records.count == 3, records.allSatisfy({ $0.phase == .created }) else { throw AdministrativeSetupChannelError.invalidMessage }
        }
        self.progress = progress; self.relayConfigured = relayConfigured; self.relayScope = relayScope; self.records = records
        _ = try bytes
    }
    public var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-portable-import-recovery"), 2: .bytes(try progress.bytes),
            3: .boolean(relayConfigured), 4: relayScope?.value ?? .null, 5: .array(records.map(\.value))]), limits: Self.limits)
    } }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...5),
              f[0] == .unsigned(1), f[1] == .text("remozio-portable-import-recovery"), case .bytes(let progress) = f[2],
              case .boolean(let configured) = f[3], let scope = f[4], case .array(let rows) = f[5] else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        let result = try Self(progress: .decode(progress), relayConfigured: configured,
            relayScope: scope == .null ? nil : RelayScope.decode(scope), records: rows.map(Record.decode))
        guard try result.bytes == bytes else { throw AdministrativeSetupChannelError.invalidMessage }; return result
    }
}
