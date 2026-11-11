import Foundation
import RemozioProtocol

/// Reads exact replacement metadata. This value grants no file access, publication, native health, or startup authority.
struct RuntimeRetainedSetupCompletionPublication: CustomStringConvertible, CustomDebugStringConvertible {
    enum File: UInt64, CaseIterable, Sendable { case host = 1, transport, gateway, presence, pairing, frontend }
    enum Location: Sendable { case runtime, services, clients }
    struct Artifact {
        let kind: File
        let location: Location
        let file: AdministrativeSetupPublication.File
        let previous: Data
        let selected: Data
    }
    static let formatName = "runtime.retained-setup-completion-publication"
    static let maximumBytes = 3_145_728
    let configuration: RuntimeRetainedSetupCompletionConfiguration
    let sourceClients: RuntimeActivationClients
    let artifacts: [Artifact]
    var description: String { "RuntimeRetainedSetupCompletionPublication(redacted)" }
    var debugDescription: String { description }

    private init(configuration: RuntimeRetainedSetupCompletionConfiguration, sourceClients: RuntimeActivationClients) throws {
        let original = try configuration.archive.originalActivation()
        let gateway = original.gatewaySettingsHost
        guard try RuntimeReleaseConfigurationSource(host: original.host, transport: original.transport,
            gateway: gateway, clients: sourceClients).digest == configuration.sourceDigest else {
            throw RuntimeActivationError.changedScope
        }
        let uid = configuration.archive.binding.startupBinding.ownerUID
        self.configuration = configuration; self.sourceClients = sourceClients
        artifacts = try [
            .init(kind: .host, location: .runtime, file: .commandHost,
                previous: original.host.canonicalBytes, selected: configuration.host.canonicalBytes),
            .init(kind: .transport, location: .services, file: .transportConfiguration,
                previous: original.transport.canonicalBytes, selected: configuration.transport.canonicalBytes),
            .init(kind: .gateway, location: .services, file: .gatewaySettingsHost,
                previous: gateway.encoded, selected: configuration.gateway.encoded),
            .init(kind: .presence, location: .clients, file: .presenceClient(ownerUID: uid),
                previous: sourceClients.presence.canonicalBytes, selected: configuration.clients.presence.canonicalBytes),
            .init(kind: .pairing, location: .clients, file: .pairingClient(ownerUID: uid),
                previous: sourceClients.pairing.canonicalBytes, selected: configuration.clients.pairing.canonicalBytes),
            .init(kind: .frontend, location: .clients, file: .frontendClient(ownerUID: uid),
                previous: sourceClients.frontend.canonicalBytes, selected: configuration.clients.frontend.canonicalBytes)
        ]
        guard artifacts.map(\.kind) == File.allCases else { throw RuntimeActivationError.invalidPlan }
        for artifact in artifacts {
            try artifact.file.validate()
            guard !artifact.previous.isEmpty, !artifact.selected.isEmpty,
                  artifact.previous.count <= ProtectedServiceConfiguration.maximumBytes,
                  artifact.selected.count <= ProtectedServiceConfiguration.maximumBytes else {
                throw RuntimeActivationError.invalidPlan
            }
        }
    }

    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.formatName),
            2: .bytes(configuration.encoded), 3: .bytes(sourceClients.presence.canonicalBytes),
            4: .bytes(sourceClients.pairing.canonicalBytes), 5: .bytes(sourceClients.frontend.canonicalBytes)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes,
                  case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
                  Set(fields.keys) == Set(UInt64(0)...5), fields[0] == .unsigned(1), fields[1] == .text(formatName) else {
                throw RuntimeActivationError.invalidPlan
            }
            func data(_ key: UInt64) throws -> Data {
                guard case .bytes(let value) = fields[key] else { throw RuntimeActivationError.invalidPlan }; return value
            }
            let value = try Self(configuration: .decode(data(2)),
                sourceClients: .init(presence: .decode(data(3)), pairing: .decode(data(4)), frontend: .decode(data(5))))
            guard try value.encoded == bytes else { throw RuntimeActivationError.invalidPlan }
            return value
        } catch { throw RuntimeActivationError.invalidPlan }
    }
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 13)
}
