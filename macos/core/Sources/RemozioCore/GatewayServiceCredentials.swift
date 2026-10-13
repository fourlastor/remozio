import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization

/// Gateway receipts cannot grant approval or certify a credential recipient. This key is never exported with shared setup.
/// The dedicated service stores an independent software key beside its provider credential under protected Root-owned ancestors.
final class GatewayReceiptSigner: Sendable {
    private let key: Mutex<P256.Signing.PrivateKey>

    init(bytes: Data, expectedPublicKey: Data) throws {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes,
                limits: CBORLimits(maxBytes: 4096, maxDepth: 1, maxItems: 7)),
              Set(fields.keys) == Set(UInt64(0)...2), fields[0] == .unsigned(1),
              fields[1] == .text("remozio-gateway-receipt-key"), case .bytes(let encoded) = fields[2], encoded.count == 97,
              let value = try? P256.Signing.PrivateKey(x963Representation: encoded), value.x963Representation == encoded,
              let derived = try? P256.Signing.PrivateKey(rawRepresentation: value.rawRepresentation),
              derived.publicKey.x963Representation == value.publicKey.x963Representation,
              value.publicKey.x963Representation == expectedPublicKey else { throw GatewayServiceError.invalidCredentials }
        key = Mutex(value)
    }

    /// Only the gateway's typed recovery encoders receive this callback. Never expose a generic signing RPC.
    func sign(_ input: Data) throws -> Data { try key.withLock { try $0.signature(for: input).rawRepresentation } }
}

struct GatewayServiceCredentials: Sendable {
    let account: FCMServiceAccount
    let receipts: GatewayReceiptSigner

    static func load(configuration: GatewayServiceConfiguration) throws -> Self {
        try configuration.requireNativeProcess()
        return try load(configuration: configuration, read: ProtectedServiceConfiguration.readServicePrivate)
    }

    /// Fixture seam. Production checks both process UIDs before any credential read.
    static func load(configuration: GatewayServiceConfiguration, read: (String, uid_t) throws -> Data) throws -> Self {
        let provider = try read(configuration.providerPath, configuration.serviceUID)
        struct Project: Decodable { let project_id: String }
        guard !provider.isEmpty, provider.count <= 65536,
              let fields = try? JSONDecoder().decode(Project.self, from: provider), fields.project_id == configuration.project else {
            throw GatewayServiceError.invalidCredentials
        }
        let account = try FCMServiceAccount(json: provider)
        let receipts = try GatewayReceiptSigner(bytes: read(configuration.receiptKeyPath, configuration.serviceUID),
                                               expectedPublicKey: configuration.receiptPublicKey)
        return Self(account: account, receipts: receipts)
    }
}
