import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

public enum RuntimePreparationError: Error, Equatable {
    case invalidRecord, changedScope, missingMaterial, conflictingMaterial, custodyNotAccepted, incomplete, exhausted
}

/// Public identity reference only. This record contains no private transport key or provider credential.
struct RuntimeMaterialReference: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let materialID: Data
    let services: ServiceAccountPlan
    let materialDigest: Data
    let transportPublicKeyInfo: Data
    let gateway: GatewayRegistrationIdentity
    var description: String { "RuntimeMaterialReference(redacted)" }
    var debugDescription: String { description }
    init(materialID: Data, services: ServiceAccountPlan, materialDigest: Data,
         transportPublicKeyInfo: Data, gateway: GatewayRegistrationIdentity) throws {
        guard materialID.count == 16, materialDigest.count == 32,
              transportPublicKeyInfo.count == 91,
              let key = try? P256.Signing.PublicKey(derRepresentation: transportPublicKeyInfo),
              key.derRepresentation == transportPublicKeyInfo, key.x963Representation != services.authorityPublicKey,
              gateway.macID == services.macID, gateway.accountID == services.accountID,
              gateway.rootPublicKey == services.authorityPublicKey else { throw RuntimePreparationError.invalidRecord }
        self.materialID = materialID; self.services = services; self.materialDigest = materialDigest
        self.transportPublicKeyInfo = transportPublicKeyInfo; self.gateway = gateway
    }
    var transportPublicKeyX963: Data { get throws {
        try P256.Signing.PublicKey(derRepresentation: transportPublicKeyInfo).x963Representation
    } }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(materialID), 2: .bytes(services.encoded),
            3: .bytes(materialDigest), 4: .bytes(transportPublicKeyInfo), 5: .bytes(gateway.encode())]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...5), fields[0] == .unsigned(1),
              case .bytes(let id) = fields[1], case .bytes(let services) = fields[2],
              case .bytes(let digest) = fields[3], case .bytes(let pin) = fields[4],
              case .bytes(let gateway) = fields[5] else { throw RuntimePreparationError.invalidRecord }
        let result = try Self(materialID: id, services: .decode(services), materialDigest: digest,
            transportPublicKeyInfo: pin, gateway: .decode(gateway))
        guard try result.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return result
    }
    func validate(account: AccountPreparationIntent, services: ServiceAccountPlan) throws {
        try self.services.validate(account: account)
        guard try self.services.encoded == services.encoded else { throw RuntimePreparationError.changedScope }
    }
    static var limits: CBORLimits { get throws { try .init(maxBytes: 8192, maxDepth: 1, maxItems: 13) } }
}

/// Retained publication progress only. Completion is not current health or service activation.
struct RuntimePreparationState: Equatable {
    let reference: RuntimeMaterialReference?
    let configurationPublished: Bool
}

/// Root-private bootstrap material. The transport file key is never part of shared setup exports or RPC progress.
/// This initial record is immutable. Certificate renewal requires a separate protected transition.
struct RuntimePreparationMaterial: CustomStringConvertible, CustomDebugStringConvertible {
    let materialID: Data
    let services: ServiceAccountPlan
    let transportIdentity: Data
    let transportPublicKeyInfo: Data
    let gateway: GatewayRegistrationIdentity
    var description: String { "RuntimePreparationMaterial(redacted)" }
    var debugDescription: String { description }
    init(materialID: Data, services: ServiceAccountPlan, transportIdentity: Data,
         transportPublicKeyInfo: Data, gateway: GatewayRegistrationIdentity) throws {
        _ = try RuntimeMaterialReference(materialID: materialID, services: services, materialDigest: Data(repeating: 0, count: 32),
            transportPublicKeyInfo: transportPublicKeyInfo, gateway: gateway)
        guard !transportIdentity.isEmpty, transportIdentity.count <= 16_384 else { throw RuntimePreparationError.invalidRecord }
        // The configured TLS loader still checks the current certificate validity on every startup.
        _ = try TransportFileIdentity.load(bytes: transportIdentity, publicKeyInfo: transportPublicKeyInfo)
        self.materialID = materialID; self.services = services; self.transportIdentity = transportIdentity
        self.transportPublicKeyInfo = transportPublicKeyInfo; self.gateway = gateway
    }
    static func create(services: ServiceAccountPlan, notValidBefore: Date, notValidAfter: Date) throws -> Self {
        let transport = try TransportFileIdentity.create(notValidBefore: notValidBefore, notValidAfter: notValidAfter)
        let registration = try GatewayRegistrationIdentity(ownerID: AccountPreparationIntent.randomID(), macID: services.macID,
            accountID: services.accountID, gatewayID: AccountPreparationIntent.randomID(),
            lifecycleEpoch: AccountPreparationIntent.randomID(), rootPublicKey: services.authorityPublicKey)
        return try .init(materialID: AccountPreparationIntent.randomID(), services: services,
            transportIdentity: transport.encoded, transportPublicKeyInfo: transport.subjectPublicKeyInfo, gateway: registration)
    }
    var reference: RuntimeMaterialReference { get throws {
        try .init(materialID: materialID, services: services, materialDigest: Data(SHA256.hash(data: encoded)),
            transportPublicKeyInfo: transportPublicKeyInfo, gateway: gateway)
    } }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-runtime-file-material"), 2: .bytes(materialID),
            3: .bytes(services.encoded), 4: .bytes(transportIdentity), 5: .bytes(transportPublicKeyInfo),
            6: .bytes(gateway.encode())]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...6), fields[0] == .unsigned(1),
              fields[1] == .text("remozio-runtime-file-material"), case .bytes(let id) = fields[2],
              case .bytes(let services) = fields[3], case .bytes(let transport) = fields[4],
              case .bytes(let pin) = fields[5], case .bytes(let gateway) = fields[6] else { throw RuntimePreparationError.invalidRecord }
        let result = try Self(materialID: id, services: .decode(services), transportIdentity: transport,
            transportPublicKeyInfo: pin, gateway: .decode(gateway))
        guard try result.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return result
    }
    static var limits: CBORLimits { get throws { try .init(maxBytes: 32_768, maxDepth: 1, maxItems: 15) } }
}

/// Initial credential retention only. Registration, provider setup and runtime health are independent steps.
enum RuntimeMaterialPreparation {
    static func prepareFileIdentity(account: AccountPreparationIntent, services: ServiceAccountPlan,
                                    expected: RuntimeMaterialReference?, fileCustodyAccepted: Bool,
                                    verifyCurrent: () throws -> Void) throws -> RuntimePreparationMaterial {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
        try services.validate(account: account); try verifyCurrent()
        let authority = try AccountPreparationController.authorityDirectory(accountID: account.accountID)
        let directory = try ProtectedSetupDirectory.createOrOpen(path: (authority as NSString).deletingLastPathComponent + "/Runtime")
        defer { directory.close() }
        return try restoreOrCreate(directory: directory, owner: 0, account: account, services: services,
            expected: expected, verifyCurrent: verifyCurrent, make: {
                let now = Date()
                return try .create(services: services, notValidBefore: now.addingTimeInterval(-60),
                    notValidAfter: now.addingTimeInterval(365 * 86_400))
            })
    }
    // Same-owner fixtures cannot prove Root isolation, service ownership transfer, or administrator authorization.
    static func restoreOrCreate(directory: ProtectedSetupDirectory, owner: uid_t, account: AccountPreparationIntent,
                                services: ServiceAccountPlan, expected: RuntimeMaterialReference?,
                                verifyCurrent: () throws -> Void, make: () throws -> RuntimePreparationMaterial,
                                didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> RuntimePreparationMaterial {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        try services.validate(account: account); try expected?.validate(account: account, services: services)
        let file = AdministrativeSetupPublication.File.runtimeRecord
        func verify(_ value: RuntimePreparationMaterial) throws {
            try verifyCurrent(); try value.services.validate(account: account)
            guard try value.services.encoded == services.encoded else { throw RuntimePreparationError.changedScope }
            if let expected { guard try value.reference == expected else { throw RuntimePreparationError.conflictingMaterial } }
            try directory.validate()
        }
        func read() throws -> RuntimePreparationMaterial? {
            try directory.withPrivateDirectory { parent in
                var info = stat()
                if fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) != 0 {
                    if errno == ENOENT { return nil }
                    throw JournalLeaseError.system(errno)
                }
                return try RuntimePreparationMaterial.decode(ProtectedServiceConfiguration.read(anchor: directory.path,
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
        guard expected == nil else { throw RuntimePreparationError.missingMaterial }
        let created = try make(); try verify(created)
        _ = try AdministrativeSetupPublication.publish(created.encoded, file: file, directory: directory,
            owner: owner, verify: verifyCurrent, didStage: didStage)
        guard let retained = try read(), try retained.reference == created.reference else {
            throw RuntimePreparationError.conflictingMaterial
        }
        try verify(retained); return retained
    }
}
