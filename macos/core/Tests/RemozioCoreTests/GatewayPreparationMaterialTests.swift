import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewayPreparationMaterialTests: XCTestCase {
    private struct Refused: Error {}
    private static let pem = Result { () throws -> String in
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        try process.run(); let bytes = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw Refused() }; return String(decoding: bytes, as: UTF8.self)
    }
    private func provider(project: String = "synthetic-project", keyID: String = "fixture-key") throws -> SetupFCMConfiguration {
        try .init(project: project, clientEmail: "fixture@fixture.iam.gserviceaccount.com", privateKeyID: keyID, privateKeyPEM: Self.pem.get())
    }
    private func replacingProvider(_ value: GatewayPreparationMaterial, with providerJSON: Data) throws -> GatewayPreparationMaterial {
        guard case .map(let fields) = try DeterministicCBOR.decode(value.encoded, limits: GatewayPreparationMaterial.limits),
              case .bytes(let wakeKey) = fields[8] else { throw Refused() }
        return try .init(materialID: value.materialID, runtime: value.runtime, phonePush: value.phonePush,
            providerJSON: providerJSON, receiptKeyRecord: value.receiptKeyRecord,
            wakeCredentialID: value.wakeCredentialID, wakePrivateKey: wakeKey)
    }
    private func fixture(_ body: (AccountPreparationIntent, RuntimePreparationMaterial, ProtectedSetupDirectory) throws -> Void) throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner file fixture") }
        let f = try AccountPreparationFixture(), machine = try f.open(initialize: true)
        defer { try? machine.close() }
        let account = try f.resume(machine, f.begin(machine))
        let claims = try [ServiceAccountClaim(accountID: account.accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
            .init(accountID: account.accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())]
        let services = try ServiceAccountPlan(account: account, planID: AccountPreparationIntent.randomID(), claims: claims)
        let runtime = try RuntimePreparationMaterial.create(services: services, notValidBefore: Date().addingTimeInterval(-60),
            notValidAfter: Date().addingTimeInterval(600))
        let directory = try ProtectedSetupDirectory(anchor: f.root.path, relativePath: "runtime", owner: getuid())
        defer { directory.close() }
        try body(account, runtime, directory)
    }
    private func make(_ runtime: RuntimeMaterialReference) throws -> GatewayPreparationMaterial {
        try .create(runtime: runtime, provider: provider(), senderID: "123", packageName: "dev.remozio.android", fileWakeCustodyAccepted: true)
    }
    private func path(_ directory: ProtectedSetupDirectory) -> String { directory.path + "/gateway-material.cbor" }
    private func restore(_ directory: ProtectedSetupDirectory, _ runtime: RuntimeMaterialReference,
                         expected: GatewayMaterialReference? = nil, provider supplied: SetupFCMConfiguration? = nil,
                         sender: String = "123", package: String = "dev.remozio.android", verify: () throws -> Void = {},
                         make: () throws -> GatewayPreparationMaterial,
                         stage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> GatewayPreparationMaterial {
        try GatewayMaterialPreparation.restoreOrCreate(directory: directory, owner: getuid(), runtime: runtime, expected: expected,
            provider: supplied ?? provider(), senderID: sender, packageName: package, verifyCurrent: verify, make: make, didStage: stage)
    }

    func testRoundTripBindsIndependentReceiptKeyAndKeepsPrivateBytesOutOfReference() throws {
        try fixture { _, runtime, _ in
            let value = try make(runtime.reference), restored = try GatewayPreparationMaterial.decode(value.encoded)
            let reference = try value.reference, bytes = try reference.encoded
            XCTAssertEqual(try restored.reference, reference)
            XCTAssertEqual(try GatewayMaterialReference.decode(bytes), reference)
            XCTAssertEqual(reference.runtime, try runtime.reference)
            XCTAssertEqual(reference.materialDigest, Data(SHA256.hash(data: try value.encoded)))
            XCTAssertNotEqual(value.phonePush.gatewayReceiptPublicKey, runtime.services.authorityPublicKey)
            XCTAssertNotEqual(value.phonePush.gatewayReceiptPublicKey, try runtime.reference.transportPublicKeyX963)
            XCTAssertNil(bytes.range(of: value.providerJSON)); XCTAssertNil(bytes.range(of: value.receiptKeyRecord))
            XCTAssertNil(bytes.range(of: runtime.transportIdentity))
            XCTAssertNil(bytes.range(of: try value.wakeKeyRecord.encode()))
            XCTAssertEqual(try restored.wakeKeyRecord.encode(), try value.wakeKeyRecord.encode())
            XCTAssertEqual(reference.wakeCredentialID, value.wakeCredentialID)
            XCTAssertEqual(reference.wakePublicKey, try value.wakeKeyRecord.publicKey)
            XCTAssertEqual(try value.wakeKeyRecord.custody, .protectedFile)
            for rendered in [String(reflecting: value), String(reflecting: reference)] {
                XCTAssertFalse(rendered.contains("PRIVATE KEY")); XCTAssertFalse(rendered.contains("fixture-key"))
            }
        }
    }
    func testPreparedCredentialsLoadThroughTheExistingGatewayContractWithoutNetwork() throws {
        try fixture { _, runtime, _ in
            let value = try make(runtime.reference)
            let settings = try GatewayServiceSettings(delivery: .init(maximumFlights: 4, minimumSendIntervalMillis: 1000),
                probe: .init(maximumAttempts: 3, minimumRetryDelayMillis: 1000, maximumTTLSeconds: 300),
                wake: .init(maximumEntries: 32, maximumAttempts: 3, minimumEnrollmentIntervalMillis: 1000,
                    maximumLifetimeMillis: 300000, maximumTTLSeconds: 300))
            let config = try GatewayServiceConfiguration(registration: runtime.gateway, receiptPublicKey: value.phonePush.gatewayReceiptPublicKey,
                directoryPath: "/Library/Remozio/gateway", providerPath: "/Library/Remozio/provider.json",
                receiptKeyPath: "/Library/Remozio/receipt.cbor", serviceUID: 20001, ownerUID: runtime.services.ownerUID,
                serviceName: "dev.remozio.fixture.gateway", teamID: "ABCDEFGHIJ", authorityIdentifier: "dev.remozio.authority",
                authorityHashes: [Data(repeating: 1, count: 20)], project: value.phonePush.projectID,
                packageName: value.phonePush.packageName, settings: settings)
            var reads = 0
            let credentials = try GatewayServiceCredentials.load(configuration: config) { path, owner in
                reads += 1; XCTAssertEqual(owner, 20001)
                if path == config.providerPath { return value.providerJSON }
                XCTAssertEqual(path, config.receiptKeyPath); return value.receiptKeyRecord
            }
            let input = Data("synthetic-receipt-input".utf8), signature = try credentials.receipts.sign(input)
            XCTAssertTrue(try P256.Signing.PublicKey(x963Representation: config.receiptPublicKey)
                .isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: signature), for: input))
            XCTAssertEqual(reads, 2)
            let wakeRecord = try value.wakeKeyRecord
            let wakeConfig = try GatewayWakeSignerConfiguration(binding: wakeRecord.binding, credentialID: wakeRecord.credentialID,
                transportUID: 20000, ownerUID: runtime.services.ownerUID, gatewayUID: 20001,
                serviceName: "dev.remozio.fixture.gateway.wake", teamID: "ABCDEFGHIJ", gatewayIdentifier: "dev.remozio.gateway",
                gatewayHashes: [Data(repeating: 2, count: 20)], custody: .protectedFile,
                keyRecordPath: "/Library/Remozio/wake.cbor", publicKey: wakeRecord.publicKey)
            let signer = try GatewayWakeSigner.load(configuration: wakeConfig, realUID: 20000, effectiveUID: 20000) { path, owner in
                XCTAssertEqual(path, wakeConfig.keyRecordPath); XCTAssertEqual(owner, 20000)
                return try wakeRecord.encode()
            }
            let submission = try GatewayWakeSubmission(binding: wakeRecord.binding, credentialID: wakeRecord.credentialID,
                deliveryID: Data(repeating: 9, count: 16), challenge: Data(repeating: 8, count: 32))
            XCTAssertTrue(try P256.Signing.PublicKey(x963Representation: wakeRecord.publicKey).isValidSignature(
                P256.Signing.ECDSASignature(rawRepresentation: signer.sign(submission)), for: submission.signingInput()))
        }
    }
    func testLostAcknowledgmentRetainsMaterialAndLeavesTheRuntimeFileUnchanged() throws {
        try fixture { _, runtime, directory in
            let bytes = try runtime.encoded, reference = try runtime.reference
            _ = try AdministrativeSetupPublication.publish(bytes, file: .runtimeRecord, directory: directory, owner: getuid(), verify: {})
            var creations = 0
            XCTAssertThrowsError(try restore(directory, reference, make: { creations += 1; return try self.make(reference) },
                stage: { if case .published = $0 { throw Refused() } })) { XCTAssertTrue($0 is Refused) }
            let retained = try Data(contentsOf: URL(fileURLWithPath: path(directory)))
            let value = try restore(directory, reference, make: { XCTFail("Do not regenerate retained material"); throw Refused() })
            XCTAssertEqual(try value.encoded, retained); XCTAssertEqual(creations, 1)
            let again = try restore(directory, reference, expected: value.reference, make: { throw Refused() })
            XCTAssertEqual(try again.reference, try value.reference)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: directory.path + "/runtime-material.cbor")), bytes)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), ["gateway-material.cbor", "runtime-material.cbor"])
            var info = stat(); XCTAssertEqual(lstat(path(directory), &info), 0); XCTAssertEqual(info.st_mode & 0o7777, 0o600)
        }
    }
    func testMissingEstablishedMaterialNeverInvokesTheFactory() throws {
        try fixture { _, runtime, directory in
            let reference = try runtime.reference
            let value = try restore(directory, reference, make: { try self.make(reference) })
            try FileManager.default.removeItem(atPath: path(directory))
            XCTAssertThrowsError(try restore(directory, reference, expected: value.reference,
                make: { XCTFail("Never replace an established receipt key"); throw Refused() })) {
                XCTAssertEqual($0 as? GatewayPreparationError, .missingMaterial)
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory)))
        }
    }
    func testDifferentRetainedKeyAndChangedProviderInputsAreNotAdopted() throws {
        try fixture { _, runtime, directory in
            let reference = try runtime.reference
            let value = try restore(directory, reference, make: { try self.make(reference) })
            for (provider, sender, package) in [(try self.provider(keyID: "replacement-key"), "123", "dev.remozio.android"),
                (try self.provider(project: "other-project"), "123", "dev.remozio.android"),
                (try self.provider(), "456", "dev.remozio.android"), (try self.provider(), "123", "other.package")] {
                XCTAssertThrowsError(try restore(directory, reference, provider: provider, sender: sender, package: package,
                    make: { XCTFail("Never reset changed provider inputs"); throw Refused() })) {
                    XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
                }
            }
            let substitute = try make(reference), bytes = try substitute.encoded
            try bytes.write(to: URL(fileURLWithPath: path(directory))); XCTAssertEqual(chmod(path(directory), 0o600), 0)
            XCTAssertThrowsError(try restore(directory, reference, expected: value.reference, make: { throw Refused() })) {
                XCTAssertEqual($0 as? GatewayPreparationError, .conflictingMaterial)
            }
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path(directory))), bytes)
        }
    }
    func testChangedRuntimeAndExpectedReferenceCannotGenerateNewMaterial() throws {
        try fixture { _, runtime, directory in
            let reference = try runtime.reference, value = try make(reference)
            let alternate = try RuntimePreparationMaterial.create(services: runtime.services,
                notValidBefore: Date().addingTimeInterval(-60), notValidAfter: Date().addingTimeInterval(600))
            XCTAssertThrowsError(try restore(directory, alternate.reference, expected: value.reference,
                make: { XCTFail("Never migrate runtime scope implicitly"); throw Refused() })) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
        }
    }
    func testMalformedPublicOrLinkedExistingRecordsAreNotReset() throws {
        for kind in 0...2 {
            try fixture { _, runtime, directory in
                let reference = try runtime.reference, bytes = kind == 0 ? Data([0xff]) : try make(reference).encoded
                let file = path(directory)
                if kind == 2 {
                    let target = directory.path + "/target"; try bytes.write(to: URL(fileURLWithPath: target)); XCTAssertEqual(chmod(target, 0o600), 0)
                    try FileManager.default.createSymbolicLink(atPath: file, withDestinationPath: target)
                } else { try bytes.write(to: URL(fileURLWithPath: file)); XCTAssertEqual(chmod(file, kind == 1 ? 0o644 : 0o600), 0) }
                XCTAssertThrowsError(try restore(directory, reference, make: { XCTFail("Never reset unsafe existing state"); throw Refused() }))
                XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file)), bytes)
            }
        }
    }
    func testFailedScopeOrStagingVerificationPublishesNoRecord() throws {
        try fixture { _, runtime, directory in
            let reference = try runtime.reference
            XCTAssertThrowsError(try restore(directory, reference, verify: { throw Refused() },
                make: { XCTFail("Verify before material creation"); throw Refused() }))
            var checks = 0
            XCTAssertThrowsError(try restore(directory, reference, verify: { checks += 1; if checks == 2 { throw Refused() } },
                make: { try self.make(reference) }))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
            XCTAssertThrowsError(try restore(directory, reference, make: { try self.make(reference) },
                stage: { if case .staged = $0 { throw Refused() } }))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
        }
    }
    func testPrivateRecordRejectsUnknownVersionsFieldsAndNoncanonicalProviderJSON() throws {
        try fixture { _, runtime, _ in
            let value = try make(runtime.reference)
            guard case .map(let original) = try DeterministicCBOR.decode(value.encoded, limits: GatewayPreparationMaterial.limits) else { return XCTFail() }
            for (key, replacement): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("other-purpose")),
                (2, .bytes(Data())), (5, .bytes(Data(" ".utf8) + value.providerJSON)), (9, .null), (7, .bytes(Data())), (8, .bytes(Data(repeating: 0, count: 32)))] {
                var fields = original; fields[key] = replacement
                XCTAssertThrowsError(try GatewayPreparationMaterial.decode(DeterministicCBOR.encode(.map(fields), limits: CBORLimits(maxBytes: 131072, maxDepth: 2, maxItems: 64))))
            }
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: value.providerJSON) as? [String: String])
            for key in ["project_id", "token_uri", "extra"] {
                var copy = fields; copy[key] = "untrusted"
                XCTAssertThrowsError(try replacingProvider(value, with: JSONSerialization.data(withJSONObject: copy, options: [.sortedKeys])))
            }
            fields.removeValue(forKey: "private_key")
            XCTAssertThrowsError(try replacingProvider(value, with: JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])))
        }
    }
    func testPublicReferenceRejectsRootOrTransportKeyReuseAndWrongVersions() throws {
        try fixture { _, runtime, _ in
            let value = try make(runtime.reference)
            for key in [runtime.services.authorityPublicKey, try runtime.reference.transportPublicKeyX963] {
                let policy = try AuthorityPhonePushStartupConfiguration(projectID: "synthetic-project", senderID: "123",
                    packageName: "dev.remozio.android", gatewayReceiptPublicKey: key)
                XCTAssertThrowsError(try GatewayMaterialReference(materialID: value.materialID, runtime: runtime.reference,
                    phonePush: policy, materialDigest: Data(repeating: 1, count: 32),
                    wakeCredentialID: value.wakeCredentialID, wakePublicKey: value.reference.wakePublicKey))
            }
            guard case .map(let original) = try DeterministicCBOR.decode(value.reference.encoded, limits: GatewayMaterialReference.limits) else { return XCTFail() }
            for (key, replacement): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("other-purpose")), (5, .bytes(Data())), (8, .null), (6, .bytes(Data())), (7, .bytes(Data()))] {
                var fields = original; fields[key] = replacement
                XCTAssertThrowsError(try GatewayMaterialReference.decode(DeterministicCBOR.encode(.map(fields), limits: CBORLimits(maxBytes: 131072, maxDepth: 2, maxItems: 64))))
            }
        }
    }
    func testFileWakeCreationRequiresConsentAndNeverReusesAnotherKeyRole() throws {
        try fixture { _, runtime, _ in
            XCTAssertThrowsError(try GatewayPreparationMaterial.create(runtime: runtime.reference, provider: provider(), senderID: "invalid",
                packageName: "dev.remozio.android", fileWakeCustodyAccepted: false)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .custodyNotAccepted)
            }
            let value = try make(runtime.reference)
            for key in [runtime.services.authorityPublicKey, try runtime.reference.transportPublicKeyX963, value.phonePush.gatewayReceiptPublicKey] {
                XCTAssertThrowsError(try GatewayMaterialReference(materialID: value.materialID, runtime: value.runtime, phonePush: value.phonePush,
                    materialDigest: Data(repeating: 1, count: 32), wakeCredentialID: value.wakeCredentialID, wakePublicKey: key))
            }
        }
    }
    func testNativePreparationRefusesOrdinaryIdentityBeforeProtectedAccess() throws {
        try fixture { account, runtime, _ in
            XCTAssertThrowsError(try GatewayMaterialPreparation.prepare(account: account, runtime: runtime.reference, expected: nil,
                provider: provider(), senderID: "123", packageName: "dev.remozio.android", fileWakeCustodyAccepted: true, verifyCurrent: { XCTFail("No protected access") })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
    }
}
