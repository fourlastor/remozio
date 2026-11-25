import CryptoKit
import Foundation
import RemozioProtocol

enum PairingColdDisableError: Error, Equatable {
    case notEnabled, changedConfiguration, unavailable
}

/// The installed host wraps the same private command bytes as the runtime file.
struct PairingColdDisableConfiguration {
    let source: InstalledAuthorityCommandConfiguration
    let target: InstalledAuthorityCommandConfiguration

    init(source: InstalledAuthorityCommandConfiguration) throws {
        let command = source.command
        let presence = command.presence
        guard let pairing = presence.pairing, pairing.v2ActivationEnabled == true else {
            throw PairingColdDisableError.notEnabled
        }
        let disabled = try AuthorityPairingSetupConfiguration(transportPublicKey: pairing.transportPublicKey,
            lifetimeMilliseconds: pairing.lifetimeMilliseconds, v2ActivationEnabled: false)
        let nextPresence = try AuthorityPresenceStartupConfiguration.decode(Self.replace(presence.canonicalBytes,
            key: 10, expected: pairing.canonicalBytes, target: disabled.canonicalBytes))
        let nextCommand = try AuthorityCommandStartupConfiguration.decode(Self.replace(command.canonicalBytes,
            key: 1, expected: presence.canonicalBytes, target: nextPresence.canonicalBytes))
        target = try InstalledAuthorityCommandConfiguration.decode(Self.replace(source.canonicalBytes,
            key: 5, expected: command.canonicalBytes, target: nextCommand.canonicalBytes))
        self.source = source
    }

    static func requirePairingOnlyDifference(derived: AuthorityCommandStartupConfiguration,
        retained: AuthorityCommandStartupConfiguration) throws {
        guard let source = derived.presence.pairing, let disabled = retained.presence.pairing,
              disabled.v2ActivationEnabled == false, disabled.lanScope == nil,
              source.transportPublicKey == disabled.transportPublicKey else { throw RuntimeActivationError.changedScope }
        do {
            let presence = try replace(retained.presence.canonicalBytes, key: 10,
                expected: disabled.canonicalBytes, target: source.canonicalBytes)
            let reset = try replace(retained.canonicalBytes, key: 1,
                expected: retained.presence.canonicalBytes, target: presence)
            guard reset == derived.canonicalBytes else { throw RuntimeActivationError.changedScope }
        } catch { throw RuntimeActivationError.changedScope }
    }

    private static func replace(_ bytes: Data, key: UInt64, expected: Data, target: Data) throws -> Data {
        let limits = try CBORLimits(maxBytes: ProtectedServiceConfiguration.maximumBytes, maxDepth: 6, maxItems: 1024)
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              fields[key] == .bytes(expected) else { throw PairingColdDisableError.changedConfiguration }
        fields[key] = .bytes(target)
        return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
}

/// The completed record survives a lost restart reply until Setup retires it.
struct PairingColdDisableIntent: Equatable, Sendable {
    static let fileName = "pairing-cold-disable.cbor"
    let macID: Data
    let accountID: Data
    let installationID: Data
    let releaseDigest: Data
    let sourceHost: Data
    let targetHost: Data
    let sourceCommand: Data
    let targetCommand: Data
    let targetPairing: Data
    let completed: Bool

    init(_ configuration: PairingColdDisableConfiguration) throws {
        let source = configuration.source, target = configuration.target
        guard let pairing = target.command.presence.pairing else { throw PairingColdDisableError.changedConfiguration }
        try self.init(macID: source.command.macID, accountID: source.command.accountID,
            installationID: source.installationID, releaseDigest: source.releaseDigest,
            sourceHost: Self.digest(source.canonicalBytes), targetHost: Self.digest(target.canonicalBytes),
            sourceCommand: Self.digest(source.command.canonicalBytes), targetCommand: Self.digest(target.command.canonicalBytes),
            targetPairing: Self.digest(pairing.canonicalBytes), completed: false)
    }

    private init(macID: Data, accountID: Data, installationID: Data, releaseDigest: Data, sourceHost: Data,
                 targetHost: Data, sourceCommand: Data, targetCommand: Data, targetPairing: Data, completed: Bool) throws {
        guard [macID, accountID, installationID].allSatisfy({ $0.count == 16 }),
              [releaseDigest, sourceHost, targetHost, sourceCommand, targetCommand, targetPairing].allSatisfy({ $0.count == 32 }),
              sourceHost != targetHost, sourceCommand != targetCommand else { throw PairingColdDisableError.changedConfiguration }
        self.macID = macID
        self.accountID = accountID
        self.installationID = installationID
        self.releaseDigest = releaseDigest
        self.sourceHost = sourceHost
        self.targetHost = targetHost
        self.sourceCommand = sourceCommand
        self.targetCommand = targetCommand
        self.targetPairing = targetPairing
        self.completed = completed
    }

    func completion() throws -> Self {
        try .init(macID: macID, accountID: accountID, installationID: installationID, releaseDigest: releaseDigest,
            sourceHost: sourceHost, targetHost: targetHost, sourceCommand: sourceCommand, targetCommand: targetCommand,
            targetPairing: targetPairing, completed: true)
    }

    func requireScope(_ host: InstalledAuthorityCommandConfiguration) throws {
        guard host.command.macID == macID, host.command.accountID == accountID, host.installationID == installationID,
              host.releaseDigest == releaseDigest else { throw PairingColdDisableError.changedConfiguration }
    }

    func requirePairingTarget(_ host: InstalledAuthorityCommandConfiguration) throws {
        guard host.command.macID == macID, host.command.accountID == accountID, host.installationID == installationID,
              let pairing = host.command.presence.pairing, pairing.v2ActivationEnabled == false, pairing.lanScope == nil,
              Self.digest(pairing.canonicalBytes) == targetPairing else { throw PairingColdDisableError.changedConfiguration }
    }

    func requireTarget(_ host: InstalledAuthorityCommandConfiguration) throws {
        try requirePairingTarget(host)
        guard host.releaseDigest == releaseDigest, Self.digest(host.canonicalBytes) == targetHost,
              Self.digest(host.command.canonicalBytes) == targetCommand else { throw PairingColdDisableError.changedConfiguration }
    }

    var encoded: Data {
        get throws {
            try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID),
                3: .bytes(installationID), 4: .bytes(releaseDigest), 5: .bytes(sourceHost), 6: .bytes(targetHost),
                7: .bytes(sourceCommand), 8: .bytes(targetCommand), 9: .bytes(targetPairing), 10: .boolean(completed)]), limits: Self.limits)
        }
    }

    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let values) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(values.keys) == Set(UInt64(0)...10), values[0] == .unsigned(1),
              case .boolean(let completed) = values[10] else { throw PairingColdDisableError.changedConfiguration }
        func data(_ key: UInt64) throws -> Data {
            guard case .bytes(let value) = values[key] else { throw PairingColdDisableError.changedConfiguration }
            return value
        }
        let record = try Self(macID: data(1), accountID: data(2), installationID: data(3), releaseDigest: data(4),
            sourceHost: data(5), targetHost: data(6), sourceCommand: data(7), targetCommand: data(8),
            targetPairing: data(9), completed: completed)
        guard try record.encoded == bytes else { throw PairingColdDisableError.changedConfiguration }
        return record
    }

    static func requirePairingOpen(macID: Data, accountID: Data, pairingDigest: Data, read: () throws -> Data?) throws {
        guard let bytes = try read() else { return }
        let intent = try decode(bytes)
        guard intent.completed, intent.macID == macID, intent.accountID == accountID,
              intent.targetPairing == pairingDigest else { throw AuthorityPairingSetupError.unavailable }
    }

    static func read(accountID: Data) throws -> Data? {
        let path = try RuntimePreparationPaths(accountID: accountID).privateDirectory + "/" + fileName
        return try ProtectedServiceConfiguration.readOptionalPrivate(path: path, kind: .root)
    }

    static func digest(_ bytes: Data) -> Data { Data(SHA256.hash(data: bytes)) }
    private static let limits = try! CBORLimits(maxBytes: 768, maxDepth: 1, maxItems: 24)
}
