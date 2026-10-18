import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

/// Retained setup inputs only. This record grants no service health, provider access or command authority.
struct GatewayJournalSetupIntent: Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    let id: Data
    let material: GatewayMaterialReference
    let configuration: GatewayServiceConfiguration
    let files: GatewayJournalFileIdentity
    var description: String { "GatewayJournalSetupIntent(redacted)" }
    var debugDescription: String { description }
    var accountID: Data { material.runtime.services.accountID }

    init(id: Data, material: GatewayMaterialReference, configuration: GatewayServiceConfiguration, files: GatewayJournalFileIdentity) throws {
        let services = material.runtime.services, paths = try RuntimePreparationPaths(accountID: services.accountID)
        guard id.count == 16, let gateway = services.claims.first(where: { $0.role == .gateway }),
              let transport = services.claims.first(where: { $0.role == .transport }),
              configuration.registration == material.runtime.gateway, configuration.serviceUID == gateway.number,
              configuration.ownerUID == services.ownerUID, configuration.serviceName == paths.gatewayService,
              configuration.directoryPath == paths.gatewayDirectory, configuration.providerPath == paths.gatewayProvider,
              configuration.receiptKeyPath == paths.gatewayReceiptKey,
              configuration.receiptPublicKey == material.phonePush.gatewayReceiptPublicKey,
              configuration.project == material.phonePush.projectID, configuration.packageName == material.phonePush.packageName,
              configuration.wakeEndpoint?.transportUID == transport.number,
              configuration.wakeEndpoint?.serviceName == paths.gatewayWakeService,
              material.phonePush.maximumControls <= configuration.settings.maximumStoredControls,
              material.phonePush.candidateLifetimeMilliseconds <= configuration.settings.maximumCandidateLifetimeMillis,
              files.directory.device == files.writer.device, files.directory.device == files.database.device,
              [files.directory.inode, files.writer.inode, files.database.inode].allSatisfy({ $0 > 0 }),
              Set([files.directory.inode, files.writer.inode, files.database.inode]).count == 3 else {
            throw GatewayPreparationError.invalidRecord
        }
        self.id = id; self.material = material; self.configuration = configuration; self.files = files
    }
    static func == (left: Self, right: Self) -> Bool {
        left.id == right.id && left.material == right.material && left.configuration.canonicalBytes == right.configuration.canonicalBytes && left.files == right.files
    }
    /// Reconstruct the gateway proposal from the current foreground scope before trusting retained settings or code pins.
    func validate(foreground: RuntimeActivationPlan, inventory: InstallationInventory) throws {
        guard let endpoint = configuration.wakeEndpoint else { throw GatewayPreparationError.invalidRecord }
        let proposal = try GatewayConfigurationBundle(foreground: foreground, material: material, inventory: inventory,
            settings: configuration.settings, wakeMaximumConnections: endpoint.maximumConnections,
            wakeMaximumOperations: endpoint.maximumOperations, wakeChallengeLifetimeMilliseconds: endpoint.challengeLifetimeMillis)
        guard proposal.gateway.canonicalBytes == configuration.canonicalBytes else { throw GatewayPreparationError.changedScope }
    }
    private var fileValue: CBORValue {
        .array([files.directory, files.writer, files.database].map {
            .array([.unsigned(UInt64(UInt32(bitPattern: $0.device))), .unsigned($0.inode)])
        })
    }
    var fileDigest: Data { get throws { Data(SHA256.hash(data: try DeterministicCBOR.encode(fileValue, limits: Self.limits))) } }
    var digest: Data { get throws { Data(SHA256.hash(data: try encoded)) } }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-journal-setup"), 2: .bytes(id),
            3: .bytes(material.encoded), 4: .bytes(configuration.canonicalBytes), 5: fileValue]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...5),
              fields[0] == .unsigned(1), fields[1] == .text("remozio-gateway-journal-setup"), case .bytes(let id) = fields[2],
              case .bytes(let material) = fields[3], case .bytes(let configuration) = fields[4],
              case .array(let entries) = fields[5], entries.count == 3 else { throw GatewayPreparationError.invalidRecord }
        let identities: [ProtectedStorageLease.DirectoryIdentity] = try entries.map { entry in
            guard case .array(let values) = entry, values.count == 2, case .unsigned(let device) = values[0],
                  let device = UInt32(exactly: device), case .unsigned(let inode) = values[1] else { throw GatewayPreparationError.invalidRecord }
            return .init(device: dev_t(bitPattern: device), inode: inode)
        }
        let result = try Self(id: id, material: .decode(material), configuration: .decode(configuration),
            files: .init(directory: identities[0], writer: identities[1], database: identities[2]))
        guard try result.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return result
    }
    static var limits: CBORLimits { get throws { try .init(maxBytes: 131072, maxDepth: 3, maxItems: 32) } }
}

/// Historical initialization progress only. Runtime startup must independently validate its service files and journal.
struct GatewayJournalPreparationState: Equatable {
    let intent: GatewayJournalSetupIntent?
    let initialized: Bool
}
