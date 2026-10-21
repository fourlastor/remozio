import CryptoKit
import Foundation

/// Capture content and inode identities together. Call requireCurrent before publishing a derived read-only response.
struct SharedSetupImportRecoveryProjection: Equatable {
    let plan: SharedSetupImportRelayPlan?
    let tunnel: SharedSetupRelayProvisioningRecord?
    let application: SharedSetupAccessApplicationRecord?
    let dns: SharedSetupDNSRecord?
    private let planIdentity: SharedSetupImportRelayStorage.Snapshot?
    private let tunnelIdentity: SharedSetupRelayProvisioningStorage.Snapshot?
    private let applicationIdentity: SharedSetupAccessApplicationStorage.Snapshot?
    private let dnsIdentity: SharedSetupDNSStorage.Snapshot?
    static func capture(expected: SharedSetupImportIntent, directory: ProtectedSetupDirectory, owner: uid_t) throws -> Self {
        let plan = try SharedSetupImportRelayStorage.read(expected: expected, directory: directory, owner: owner)
        let tunnel = try SharedSetupRelayProvisioningStorage.read(expected: expected, plan: plan, directory: directory, owner: owner)
        let application = try SharedSetupAccessApplicationStorage.read(expected: expected, plan: plan, createdTunnel: tunnel, directory: directory, owner: owner)
        let dns = try SharedSetupDNSStorage.read(expected: expected, plan: plan, createdTunnel: tunnel, application: application, directory: directory, owner: owner)
        let a = try SharedSetupImportRelayStorage.snapshot(expected: expected, directory: directory, owner: owner)
        let b = try SharedSetupRelayProvisioningStorage.snapshot(expected: expected, plan: plan, directory: directory, owner: owner)
        let c = try SharedSetupAccessApplicationStorage.snapshot(expected: expected, plan: plan, createdTunnel: tunnel, directory: directory, owner: owner)
        let d = try SharedSetupDNSStorage.snapshot(expected: expected, plan: plan, createdTunnel: tunnel, application: application, directory: directory, owner: owner)
        func digest(_ bytes: Data?) -> Data? { bytes.map { Data(SHA256.hash(data: $0)) } }
        guard digest(plan?.bytes) == a?.digest, digest(tunnel?.bytes) == b?.digest,
              digest(application?.bytes) == c?.digest, digest(dns?.bytes) == d?.digest else { throw RelayProvisioningError.staleRecord }
        return .init(plan: plan, tunnel: tunnel, application: application, dns: dns, planIdentity: a, tunnelIdentity: b, applicationIdentity: c, dnsIdentity: d)
    }
    func requireCurrent(expected: SharedSetupImportIntent, directory: ProtectedSetupDirectory, owner: uid_t) throws {
        guard try Self.capture(expected: expected, directory: directory, owner: owner) == self else { throw RelayProvisioningError.staleRecord }
    }
    func recovery(progress: SetupPortableImportProgress, retained: SharedSetupImportIntent) throws -> SetupPortableImportRecovery {
        let scope: SetupPortableImportRecovery.RelayScope?
        if let plan {
            guard let cloud = retained.recipe.cloudflare else { throw SharedSetupImportError.wrongScope }
            scope = try .init(account: cloud.accountID, zone: cloud.zoneID, hostname: plan.hostname, tunnelName: plan.tunnelName)
        } else { scope = nil }
        var records: [SetupPortableImportRecovery.Record] = []
        if let tunnel { records.append(try .init(resource: .tunnel, phase: tunnel.phase.rawValue, bytes: tunnel.bytes,
            attempt: tunnel.attemptNumber, providerID: tunnel.tunnelID, refusal: tunnel.refusal?.rawValue)) }
        if let application { records.append(try .init(resource: .accessApplication, phase: application.phase.rawValue, bytes: application.bytes,
            attempt: application.attemptNumber, providerID: application.applicationID, refusal: application.refusal?.rawValue)) }
        if let dns { records.append(try .init(resource: .dnsRecord, phase: dns.phase.rawValue, bytes: dns.bytes,
            attempt: dns.attemptNumber, providerID: dns.dnsRecordID, refusal: dns.refusal?.rawValue)) }
        return try .init(progress: progress, relayConfigured: retained.recipe.cloudflare != nil, relayScope: scope, records: records)
    }
}
