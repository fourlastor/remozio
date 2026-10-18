import Darwin
import Foundation
import RemozioProtocol

public struct GatewaySetupPreparationChoices: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let provider: SetupFCMConfiguration
    public let senderID: String
    public let packageName: String
    public let settings: GatewayServiceSettings
    public let fileWakeCustodyAccepted: Bool
    public var description: String { "GatewaySetupPreparationChoices(redacted)" }
    public var debugDescription: String { description }
    public init(provider: SetupFCMConfiguration, senderID: String, packageName: String, settings: GatewayServiceSettings, fileWakeCustodyAccepted: Bool) throws {
        _ = try PhonePushTokenOffer(token: "validation", projectID: provider.project, senderID: senderID, packageName: packageName)
        self.provider = provider; self.senderID = senderID; self.packageName = packageName
        self.settings = settings; self.fileWakeCustodyAccepted = fileWakeCustodyAccepted
    }
    public var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.purpose), 2: .bytes(provider.gatewayCredentialJSON()),
            3: .text(senderID), 4: .text(packageName), 5: .bytes(settings.setupBytes), 6: .boolean(fileWakeCustodyAccepted)]), limits: Self.limits)
    } }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...6),
              f[0] == .unsigned(1), f[1] == .text(purpose), case .bytes(let provider) = f[2], provider.count <= 32768,
              case .text(let sender) = f[3], case .text(let package) = f[4], case .bytes(let settings) = f[5],
              case .boolean(let accepted) = f[6],
              let fields = try JSONSerialization.jsonObject(with: provider) as? [String: String],
              Set(fields.keys) == Set(["type", "token_uri", "project_id", "client_email", "private_key_id", "private_key"]),
              fields["type"] == "service_account", fields["token_uri"] == FCMServiceAccount.tokenEndpoint,
              try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys]) == provider else {
            throw GatewayPreparationError.invalidRecord
        }
        let value = try Self(provider: .init(project: fields["project_id"]!, clientEmail: fields["client_email"]!,
            privateKeyID: fields["private_key_id"]!, privateKeyPEM: fields["private_key"]!), senderID: sender,
            packageName: package, settings: .decodeSetupBytes(settings), fileWakeCustodyAccepted: accepted)
        guard try value.bytes == bytes else { throw GatewayPreparationError.invalidRecord }; return value
    }
    private static let purpose = "remozio-gateway-setup-choices"
    private static let limits = try! CBORLimits(maxBytes: 49152, maxDepth: 1, maxItems: 15)
}

/// Native preparation for the current foreground account. The setup endpoint must validate administrator rights before use.
/// No service, provider request or normal runtime configuration is activated here.
enum GatewaySetupAccountPreparation {
    static func prepare(machine: PreparationIntentStore, account: AccountPreparationIntent, choices: GatewaySetupPreparationChoices,
                        verifyCurrent: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verifyCurrent(); try machine.validateAccountPreparation(account)
        let state = try machine.gatewayPreparation(accountID: account.accountID)
        let prepared = try GatewayMaterialPreparationController.prepare(machine: machine, account: account, expected: state,
            provider: choices.provider, senderID: choices.senderID, packageName: choices.packageName,
            fileWakeCustodyAccepted: choices.fileWakeCustodyAccepted, verifyCurrent: verifyCurrent)
        guard let material = prepared.reference, let foreground = try machine.runtimeActivation(accountID: account.accountID).plan,
              let inventory = try machine.inventory() else { throw GatewayPreparationError.incomplete }
        let proposal = try GatewayConfigurationBundle(foreground: foreground, material: material, inventory: inventory, settings: choices.settings)
        try verifyCurrent()
        _ = try GatewayJournalSetupPreparation.prepare(machine: machine, account: account, material: material,
            configuration: proposal.gateway, expected: machine.gatewayJournalPreparation(accountID: account.accountID), verifyCurrent: verifyCurrent)
        try verifyCurrent()
    }
}
