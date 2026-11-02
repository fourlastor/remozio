import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Disposable provider keys and value transformations only. No provider calls, installed services or live cutover.
final class RuntimeAuditUpgradeDependenciesTests: XCTestCase {
    private struct Refused: Error {}
    private let limits = try! CBORLimits(maxBytes: 262144, maxDepth: 3, maxItems: 512)
    private static let pem = Result { () throws -> String in
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        try process.run(); let data = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw Refused() }
        return String(decoding: data, as: UTF8.self)
    }
    private func fields(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let values) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw Refused() }
        return values
    }
    func fixture(port: UInt16? = nil) throws -> (RuntimeActivationFixture, RuntimeAuditUpgradePreparation, InstallationInventory) {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneAudit: true,
            auditDelivery: true, materialAuditDelivery: false)
        var source = f.plan
        if let port {
            var transport = try fields(source.transport.canonicalBytes); transport[3] = .unsigned(UInt64(port))
            var plan = try fields(source.encoded)
            plan[4] = .bytes(try DeterministicCBOR.encode(.map(transport), limits: limits))
            source = try .decode(DeterministicCBOR.encode(.map(plan), limits: limits))
        }
        let material = try RuntimeAuditMaterialUpgrade.prepare(material: f.material, expected: f.material.reference,
            account: f.account, activity: XCTUnwrap(f.material.serviceActivity), installedRelease: XCTUnwrap(f.nativeRelease),
            policy: source.host.codePolicy)
        let intent = try RuntimeAuditUpgradeIntent(source: f.material.reference, target: material.reference, policy: source.host.codePolicy)
        let preparation = try RuntimeAuditUpgradePreparation(source: source, intent: intent,
            installedRelease: XCTUnwrap(f.nativeRelease), currentPolicy: source.host.codePolicy)
        return (f, preparation, try source.enrolledInventory(XCTUnwrap(f.machine.inventory())))
    }
    func gateway(_ preparation: RuntimeAuditUpgradePreparation) throws -> GatewayPreparationMaterial {
        let provider = try SetupFCMConfiguration(project: "synthetic-project", clientEmail: "fixture@fixture.iam.gserviceaccount.com",
            privateKeyID: "fixture-key", privateKeyPEM: Self.pem.get())
        return try .create(runtime: preparation.intent.source, provider: provider, senderID: "123456789",
            packageName: "dev.remozio.android", fileWakeCustodyAccepted: true,
            maximumControls: 77, candidateLifetimeMilliseconds: 98765)
    }
    func journal(_ material: GatewayPreparationMaterial, _ preparation: RuntimeAuditUpgradePreparation,
                         _ inventory: InstallationInventory) throws -> GatewayJournalPreparationState {
        let settings = try GatewayServiceSettings(delivery: .init(maximumFlights: 7, minimumSendIntervalMillis: 1133),
            probe: .init(maximumAttempts: 5, minimumRetryDelayMillis: 1200, maximumTTLSeconds: 250),
            wake: .init(maximumEntries: 41, maximumAttempts: 5, minimumEnrollmentIntervalMillis: 1300,
                maximumLifetimeMillis: 300000, maximumTTLSeconds: 250))
        let bundle = try GatewayConfigurationBundle(foreground: preparation.source, material: material.reference,
            inventory: inventory, settings: settings, wakePollMilliseconds: 777, wakeTimeoutMilliseconds: 8888,
            wakeMaximumConnections: 6, wakeMaximumOperations: 11, wakeChallengeLifetimeMilliseconds: 7000)
        let intent = try GatewayJournalSetupIntent(id: AccountPreparationIntent.randomID(), material: material.reference,
            configuration: bundle.gateway, files: .init(directory: .init(device: 1, inode: 61),
                writer: .init(device: 1, inode: 62), database: .init(device: 1, inode: 63)))
        return .init(intent: intent, initialized: true)
    }
    struct Relay {
        let material: RelayRunCredentialMaterial
        let imported: SharedSetupImportIntent
        let plan: SharedSetupImportRelayPlan
        let created: SharedSetupRelayProvisioningRecord
    }
    func relay(_ f: RuntimeActivationFixture, _ preparation: RuntimeAuditUpgradePreparation,
                       _ inventory: InstallationInventory) throws -> Relay {
        let proposal = try PortableSetup(defaults: .init(presence: preparation.source.host.command.presence.presence.policy, gateway: GatewaySetupForm().settingsSelection()),
            cloudflare: .init(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
                dnsSuffix: "remozio.example.invalid", apiToken: "synthetic-provider-token-only"))
        let imported = try SharedSetupImportIntent(scope: .init(account: f.account, inventory: inventory), proposal: proposal)
        let plan = try SharedSetupImportRelayPlan(expected: imported, port: 51001)
        let created = try SharedSetupRelayProvisioningRecord(expected: imported, plan: plan)
            .transition(to: .dispatched).transition(to: .created, tunnelID: "11111111-1111-4111-8111-111111111111")
        let tunnel = try created.createdTunnel(expected: imported, plan: plan)
        let token = try JSONSerialization.data(withJSONObject: ["a": tunnel.accountID, "t": tunnel.tunnelID,
            "s": Data(repeating: 0x71, count: 32).base64EncodedString()], options: [.sortedKeys, .withoutEscapingSlashes]).base64EncodedData()
        let material = try RelayRunCredentialMaterial(expected: imported, plan: plan, created: created,
            runtime: preparation.intent.source, account: f.account, inventory: inventory, credential: .restore(token, tunnel: tunnel))
        return .init(material: material, imported: imported, plan: plan, created: created)
    }
    func testGatewayPrivateMaterialChangesOnlyItsRuntimeAndKeepsOperationalKeys() throws {
        let (_, preparation, _) = try fixture(), source = try gateway(preparation), before = try source.encoded
        let expected = try source.reference, target = try source.preparingAuditUpgrade(preparation, expected: expected)
        var values = try fields(before); values[3] = .bytes(try preparation.intent.target.encoded)
        XCTAssertEqual(try fields(target.encoded), values)
        XCTAssertEqual(try source.encoded, before)
        XCTAssertEqual(target.providerJSON, source.providerJSON); XCTAssertEqual(target.receiptKeyRecord, source.receiptKeyRecord)
        XCTAssertEqual(try target.wakeKeyRecord.encode(), try source.wakeKeyRecord.encode())
        XCTAssertEqual(target.phonePush.canonicalBytes, source.phonePush.canonicalBytes)
        XCTAssertEqual(try target.reference.wakePublicKey, expected.wakePublicKey)
        XCTAssertNotEqual(try target.reference.materialDigest, expected.materialDigest)
        XCTAssertEqual(try GatewayPreparationMaterial.decode(target.encoded).reference, try target.reference)
        XCTAssertNil(try target.reference.encoded.range(of: target.providerJSON))
        XCTAssertNil(try target.reference.encoded.range(of: target.receiptKeyRecord))
        XCTAssertEqual(try source.preparingAuditUpgrade(preparation, expected: expected).encoded, try target.encoded)
        XCTAssertEqual(String(reflecting: preparation), "RuntimeAuditUpgradePreparation(redacted)")
    }
    func testGatewayJournalAndBaselineActivationPreserveSettingsFileIdentitiesAndWakeConfiguration() throws {
        let (f, preparation, inventory) = try fixture(), material = try gateway(preparation)
        let journal = try journal(material, preparation, inventory)
        let activation = try GatewayRuntimeActivationPlan(journal: journal, foreground: preparation.source,
            inventory: inventory, wakePollMilliseconds: 777, wakeTimeoutMilliseconds: 8888)
        let before = try activation.encoded, oldIntent = try XCTUnwrap(journal.intent)
        let target = try preparation.gateway(material: material, expected: material.reference,
            journal: journal, activation: activation, inventory: inventory)
        let nextIntent = try XCTUnwrap(target.journal.intent)
        XCTAssertEqual(nextIntent.material.runtime, preparation.intent.target)
        XCTAssertEqual(nextIntent.id, oldIntent.id); XCTAssertEqual(nextIntent.files, oldIntent.files)
        XCTAssertEqual(nextIntent.configuration.canonicalBytes, oldIntent.configuration.canonicalBytes)
        XCTAssertNotEqual(try nextIntent.digest, try oldIntent.digest)
        XCTAssertTrue(target.journal.initialized)
        XCTAssertEqual(target.activation.extensions.transport.wake?.canonicalBytes, activation.extensions.transport.wake?.canonicalBytes)
        XCTAssertEqual(target.activation.extensions.authority.intentID, activation.extensions.authority.intentID)
        XCTAssertNotEqual(target.activation.extensions.authority.intentDigest, activation.extensions.authority.intentDigest)
        XCTAssertEqual(try target.activation.gatewayJob.bytes, try activation.gatewayJob.bytes)
        XCTAssertEqual(target.activation.extensions.authority.material, try target.material.reference)
        XCTAssertEqual(try GatewayRuntimeActivationPlan.decode(target.activation.encoded).encoded, try target.activation.encoded)
        let proposal = try target.activation.proposal(journal: target.journal, foreground: preparation.target, inventory: inventory)
        XCTAssertEqual(proposal.commandHost.command.presence.wake.request.service.auditVersions, [1])
        XCTAssertEqual(try activation.encoded, before)
        XCTAssertEqual(try f.machine.runtimePreparation(accountID: f.account.accountID).reference, preparation.intent.source)
    }
    func testChangedGatewayReferenceAndForeignOrIncompleteJournalAreRefused() throws {
        let (_, preparation, inventory) = try fixture(), material = try gateway(preparation)
        let other = try gateway(preparation), journal = try journal(material, preparation, inventory)
        let activation = try GatewayRuntimeActivationPlan(journal: journal, foreground: preparation.source, inventory: inventory)
        XCTAssertThrowsError(try material.preparingAuditUpgrade(preparation, expected: other.reference))
        let uninitialized = GatewayJournalPreparationState(intent: journal.intent, initialized: false)
        XCTAssertThrowsError(try preparation.gateway(material: material, expected: material.reference,
            journal: uninitialized, activation: activation, inventory: inventory))
        let foreign = try self.journal(other, preparation, inventory)
        XCTAssertThrowsError(try preparation.gateway(material: material, expected: material.reference,
            journal: foreign, activation: activation, inventory: inventory))
        let target = try material.preparingAuditUpgrade(preparation, expected: material.reference)
        XCTAssertThrowsError(try target.preparingAuditUpgrade(preparation, expected: target.reference))
    }
    func testRelayUpgradeKeepsTheCredentialPlanTunnelAndImportBytes() throws {
        let (f, preparation, inventory) = try fixture(port: 51001), relay = try relay(f, preparation, inventory)
        let source = relay.material, before = try source.encoded, expected = try source.reference
        let target = try source.preparingAuditUpgrade(preparation, expected: expected), reference = try target.reference
        var values = try fields(before); values[5] = .bytes(try preparation.intent.target.encoded)
        XCTAssertEqual(try fields(target.encoded), values)
        XCTAssertEqual(reference.runtime, preparation.intent.target); XCTAssertEqual(reference.materialID, expected.materialID)
        XCTAssertEqual(reference.planBytes, expected.planBytes); XCTAssertEqual(reference.tunnelRecordDigest, expected.tunnelRecordDigest)
        XCTAssertEqual(reference.tunnel, expected.tunnel); XCTAssertEqual(reference.credentialDigest, expected.credentialDigest)
        XCTAssertNotEqual(reference.materialDigest, expected.materialDigest)
        let publicBytes = try reference.encoded
        source.withCredentialBytes { bytes in
            target.withCredentialBytes { XCTAssertEqual($0, bytes) }
            XCTAssertNil(publicBytes.range(of: bytes))
        }
        let decoded = try RelayRunCredentialMaterial.decode(target.encoded, expected: relay.imported,
            plan: relay.plan, created: relay.created, runtime: preparation.intent.target, account: f.account, inventory: inventory)
        XCTAssertEqual(try decoded.reference, reference)
        XCTAssertEqual(try RelayRunCredentialReference.decodeForTransport(reference.encoded,
            runtime: preparation.intent.target, relayPort: 51001), reference)
        XCTAssertEqual(try source.encoded, before)
        XCTAssertEqual(try source.preparingAuditUpgrade(preparation, expected: expected).encoded, try target.encoded)
        XCTAssertThrowsError(try RelayRunCredentialReference.decodeForTransport(expected.encoded,
            runtime: preparation.intent.target, relayPort: 51001))
    }
    func testRelayCannotDropOrChangeTheRetainedPortOrAdoptADifferentMaterial() throws {
        for port: UInt16? in [nil, 51002] {
            let (f, preparation, inventory) = try fixture(port: port), relay = try relay(f, preparation, inventory)
            let original = try relay.material.encoded
            XCTAssertThrowsError(try relay.material.preparingAuditUpgrade(preparation, expected: relay.material.reference))
            XCTAssertEqual(try relay.material.encoded, original)
        }
        let (f, preparation, inventory) = try fixture(port: 51001), relay = try relay(f, preparation, inventory)
        let different = try self.relay(f, preparation, inventory)
        XCTAssertThrowsError(try relay.material.preparingAuditUpgrade(preparation, expected: different.material.reference))
        let target = try relay.material.preparingAuditUpgrade(preparation, expected: relay.material.reference)
        XCTAssertThrowsError(try target.preparingAuditUpgrade(preparation, expected: target.reference))
    }
    func testForeignPreparationCannotRebindGatewayOrRelayCredentials() throws {
        let (f, preparation, inventory) = try fixture(port: 51001), material = try gateway(preparation)
        let relay = try relay(f, preparation, inventory), (_, foreign, _) = try fixture(port: 51001)
        XCTAssertThrowsError(try material.preparingAuditUpgrade(foreign, expected: material.reference))
        XCTAssertThrowsError(try relay.material.preparingAuditUpgrade(foreign, expected: relay.material.reference))
    }
}
