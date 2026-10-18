import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

public enum GatewayPreparationError: Error, Equatable {
    case invalidRecord, changedScope, missingMaterial, conflictingMaterial, custodyNotAccepted, incomplete, exhausted
}

/// Public preparation reference only. It contains no provider credential, receipt key or activation claim.
struct GatewayMaterialReference: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let materialID: Data
    let runtime: RuntimeMaterialReference
    let phonePush: AuthorityPhonePushStartupConfiguration
    let materialDigest: Data
    let wakeCredentialID: Data
    let wakePublicKey: Data
    var description: String { "GatewayMaterialReference(redacted)" }
    var debugDescription: String { description }

    init(materialID: Data, runtime: RuntimeMaterialReference, phonePush: AuthorityPhonePushStartupConfiguration,
         materialDigest: Data, wakeCredentialID: Data, wakePublicKey: Data) throws {
        let transport = try runtime.transportPublicKeyX963
        guard materialID.count == 16, materialDigest.count == 32,
              phonePush.gatewayReceiptPublicKey != transport, wakeCredentialID.count == 16,
              wakePublicKey.count == 65, (try? P256.Signing.PublicKey(x963Representation: wakePublicKey)) != nil,
              ![transport, runtime.services.authorityPublicKey, phonePush.gatewayReceiptPublicKey].contains(wakePublicKey) else {
            throw GatewayPreparationError.invalidRecord
        }
        _ = try phonePush.registrationPolicy(runtime.gateway)
        self.materialID = materialID; self.runtime = runtime; self.phonePush = phonePush; self.materialDigest = materialDigest
        self.wakeCredentialID = wakeCredentialID; self.wakePublicKey = wakePublicKey
    }
    static func == (left: Self, right: Self) -> Bool {
        left.materialID == right.materialID && left.runtime == right.runtime &&
            left.phonePush.canonicalBytes == right.phonePush.canonicalBytes && left.materialDigest == right.materialDigest &&
            left.wakeCredentialID == right.wakeCredentialID && left.wakePublicKey == right.wakePublicKey
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-file-material-reference"),
            2: .bytes(materialID), 3: .bytes(runtime.encoded), 4: .bytes(phonePush.canonicalBytes),
            5: .bytes(materialDigest), 6: .bytes(wakeCredentialID), 7: .bytes(wakePublicKey)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...7),
              f[0] == .unsigned(1), f[1] == .text("remozio-gateway-file-material-reference"),
              case .bytes(let id) = f[2], case .bytes(let runtime) = f[3], case .bytes(let policy) = f[4],
              case .bytes(let digest) = f[5], case .bytes(let credential) = f[6], case .bytes(let wakeKey) = f[7] else { throw GatewayPreparationError.invalidRecord }
        let value = try Self(materialID: id, runtime: .decode(runtime), phonePush: .decode(policy), materialDigest: digest, wakeCredentialID: credential, wakePublicKey: wakeKey)
        guard try value.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return value
    }
    static var limits: CBORLimits { get throws { try .init(maxBytes: 16384, maxDepth: 1, maxItems: 17) } }
}

/// Independent Root-private gateway material. Existing runtime material and shared setup bytes remain unchanged.
struct GatewayPreparationMaterial: CustomStringConvertible, CustomDebugStringConvertible {
    let materialID: Data
    let runtime: RuntimeMaterialReference
    let phonePush: AuthorityPhonePushStartupConfiguration
    let providerJSON: Data
    let receiptKeyRecord: Data
    let wakeCredentialID: Data
    private let wakePrivateKey: Data
    var description: String { "GatewayPreparationMaterial(redacted)" }
    var debugDescription: String { description }

    init(materialID: Data, runtime: RuntimeMaterialReference, phonePush: AuthorityPhonePushStartupConfiguration,
         providerJSON: Data, receiptKeyRecord: Data, wakeCredentialID: Data, wakePrivateKey: Data) throws {
        guard wakePrivateKey.count == 32, let wakeKey = try? P256.Signing.PrivateKey(rawRepresentation: wakePrivateKey) else {
            throw GatewayPreparationError.invalidRecord
        }
        _ = try GatewayMaterialReference(materialID: materialID, runtime: runtime, phonePush: phonePush,
            materialDigest: Data(repeating: 0, count: 32), wakeCredentialID: wakeCredentialID,
            wakePublicKey: wakeKey.publicKey.x963Representation)
        guard providerJSON.count <= 32768, receiptKeyRecord.count <= 4096,
              let fields = try JSONSerialization.jsonObject(with: providerJSON) as? [String: String],
              Set(fields.keys) == Set(["type", "token_uri", "project_id", "client_email", "private_key_id", "private_key"]),
              fields["project_id"] == phonePush.projectID,
              try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys]) == providerJSON else {
            throw GatewayPreparationError.invalidRecord
        }
        _ = try FCMServiceAccount(json: providerJSON)
        _ = try GatewayReceiptSigner(bytes: receiptKeyRecord, expectedPublicKey: phonePush.gatewayReceiptPublicKey)
        self.materialID = materialID; self.runtime = runtime; self.phonePush = phonePush
        self.providerJSON = providerJSON; self.receiptKeyRecord = receiptKeyRecord
        self.wakeCredentialID = wakeCredentialID; self.wakePrivateKey = wakePrivateKey
    }
    static func create(runtime: RuntimeMaterialReference, provider: SetupFCMConfiguration, senderID: String,
                       packageName: String, fileWakeCustodyAccepted: Bool, maximumControls: Int = 4096,
                       candidateLifetimeMilliseconds: UInt64 = 300000) throws -> Self {
        guard fileWakeCustodyAccepted else { throw GatewayPreparationError.custodyNotAccepted }
        let receipt = P256.Signing.PrivateKey(), wake = P256.Signing.PrivateKey()
        let key = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-receipt-key"),
            2: .bytes(receipt.x963Representation)]), limits: CBORLimits(maxBytes: 4096, maxDepth: 1, maxItems: 7))
        let policy = try AuthorityPhonePushStartupConfiguration(projectID: provider.project, senderID: senderID,
            packageName: packageName, gatewayReceiptPublicKey: receipt.publicKey.x963Representation,
            maximumControls: maximumControls, candidateLifetimeMilliseconds: candidateLifetimeMilliseconds)
        return try Self(materialID: AccountPreparationIntent.randomID(), runtime: runtime, phonePush: policy,
            providerJSON: provider.gatewayCredentialJSON(), receiptKeyRecord: key,
            wakeCredentialID: AccountPreparationIntent.randomID(), wakePrivateKey: wake.rawRepresentation)
    }
    var wakeKeyRecord: GatewayWakeKeyRecord { get throws {
        let r = runtime.gateway
        return try .init(binding: GatewaySubmissionBinding(ownerID: r.ownerID, macID: r.macID, accountID: r.accountID,
            gatewayID: r.gatewayID, lifecycleEpoch: r.lifecycleEpoch), credentialID: wakeCredentialID,
            fileKey: P256.Signing.PrivateKey(rawRepresentation: wakePrivateKey))
    } }
    var reference: GatewayMaterialReference { get throws {
        try .init(materialID: materialID, runtime: runtime, phonePush: phonePush, materialDigest: Data(SHA256.hash(data: encoded)),
            wakeCredentialID: wakeCredentialID, wakePublicKey: wakeKeyRecord.publicKey)
    } }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-private-file-material"),
            2: .bytes(materialID), 3: .bytes(runtime.encoded), 4: .bytes(phonePush.canonicalBytes),
            5: .bytes(providerJSON), 6: .bytes(receiptKeyRecord), 7: .bytes(wakeCredentialID),
            8: .bytes(wakePrivateKey)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...8),
              f[0] == .unsigned(1), f[1] == .text("remozio-gateway-private-file-material"),
              case .bytes(let id) = f[2], case .bytes(let runtime) = f[3], case .bytes(let policy) = f[4],
              case .bytes(let provider) = f[5], case .bytes(let key) = f[6],
              case .bytes(let credential) = f[7], case .bytes(let wakeKey) = f[8] else { throw GatewayPreparationError.invalidRecord }
        let value = try Self(materialID: id, runtime: .decode(runtime), phonePush: .decode(policy),
            providerJSON: provider, receiptKeyRecord: key, wakeCredentialID: credential, wakePrivateKey: wakeKey)
        guard try value.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return value
    }
    static var limits: CBORLimits { get throws { try .init(maxBytes: 65536, maxDepth: 1, maxItems: 19) } }
}

/// Retains optional gateway material without replacing the established runtime identity or starting services.
enum GatewayMaterialPreparation {
    static func prepare(account: AccountPreparationIntent, runtime: RuntimeMaterialReference,
                        expected: GatewayMaterialReference?, provider: SetupFCMConfiguration, senderID: String,
                        packageName: String, fileWakeCustodyAccepted: Bool,
                        verifyCurrent: () throws -> Void) throws -> GatewayPreparationMaterial {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard fileWakeCustodyAccepted else { throw GatewayPreparationError.custodyNotAccepted }
        try runtime.validate(account: account, services: runtime.services); try verifyCurrent()
        let paths = try RuntimePreparationPaths(accountID: account.accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.privateDirectory.dropFirst()),
            owner: 0, createIfMissing: false)
        defer { directory.close() }
        let retained = try RuntimePreparationMaterial.decode(ProtectedServiceConfiguration.read(anchor: directory.path,
            relativePath: AdministrativeSetupPublication.File.runtimeRecord.name, owner: 0))
        guard try retained.reference == runtime else { throw GatewayPreparationError.changedScope }
        return try restoreOrCreate(directory: directory, owner: 0, runtime: runtime, expected: expected,
            provider: provider, senderID: senderID, packageName: packageName, verifyCurrent: verifyCurrent,
            make: { try .create(runtime: runtime, provider: provider, senderID: senderID, packageName: packageName,
                fileWakeCustodyAccepted: fileWakeCustodyAccepted) })
    }

    // Same-owner fixtures prove file behavior, not Root isolation, service access or administrator authorization.
    static func restoreOrCreate(directory: ProtectedSetupDirectory, owner: uid_t, runtime: RuntimeMaterialReference,
                                expected: GatewayMaterialReference?, provider: SetupFCMConfiguration, senderID: String,
                                packageName: String, verifyCurrent: () throws -> Void,
                                make: () throws -> GatewayPreparationMaterial,
                                didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> GatewayPreparationMaterial {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        if let expected { guard expected.runtime == runtime else { throw GatewayPreparationError.changedScope } }
        let providerBytes = try provider.gatewayCredentialJSON()
        func verify(_ value: GatewayPreparationMaterial) throws {
            try verifyCurrent()
            guard value.runtime == runtime, value.phonePush.projectID == provider.project,
                  value.phonePush.senderID == senderID, value.phonePush.packageName == packageName,
                  value.providerJSON == providerBytes else { throw GatewayPreparationError.changedScope }
            if let expected { guard try value.reference == expected else { throw GatewayPreparationError.conflictingMaterial } }
            try directory.validate()
        }
        let file = AdministrativeSetupPublication.File.gatewayMaterial
        func read() throws -> GatewayPreparationMaterial? {
            try directory.withPrivateDirectory { parent in
                var info = stat()
                if fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) != 0 {
                    if errno == ENOENT { return nil }; throw JournalLeaseError.system(errno)
                }
                return try GatewayPreparationMaterial.decode(ProtectedServiceConfiguration.read(anchor: directory.path,
                    relativePath: file.name, owner: owner))
            }
        }
        try verifyCurrent()
        if let retained = try read() {
            try verify(retained)
            _ = try AdministrativeSetupPublication.publish(retained.encoded, file: file, directory: directory,
                owner: owner, verify: verifyCurrent)
            try verify(retained); return retained
        }
        guard expected == nil else { throw GatewayPreparationError.missingMaterial }
        let created = try make(); try verify(created)
        _ = try AdministrativeSetupPublication.publish(created.encoded, file: file, directory: directory,
            owner: owner, verify: verifyCurrent, didStage: didStage)
        guard let retained = try read(), try retained.reference == created.reference else {
            throw GatewayPreparationError.conflictingMaterial
        }
        try verify(retained); return retained
    }
}

/// Historical private-material reference only. It proves no file publication, service activation or delivery.
struct GatewayPreparationState: Equatable {
    let reference: GatewayMaterialReference?
}
