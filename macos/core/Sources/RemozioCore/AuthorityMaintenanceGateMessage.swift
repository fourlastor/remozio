import CryptoKit
import Foundation
import RemozioProtocol

/// Correlates one authenticated gate observation. These bytes cannot release a hold or grant native ownership.
struct AuthorityMaintenanceGateRequest: Equatable, Sendable {
    static let formatName = "authority.maintenance-gate"
    static func requireFormats(_ release: SignedReleaseEvidence) throws {
        for role: AuthorityCodeRole in [.authority, .setupController] {
            guard let format = release.manifest.components.first(where: { $0.role == role })?.formats.first(where: { $0.name == formatName }),
                  format.readers.contains(1), format.writers.contains(1) else { throw PreparationStoreError.incompatibleStore }
        }
    }
    let accountID: Data, attemptID: Data, revision: Data, installationID: Data, challenge: Data
    let gate: PreparationFileIdentity
    let target: AuthorityMaintenanceBinding
    init(accountID: Data, attemptID: Data, revision: Data, installationID: Data,
        gate: PreparationFileIdentity, target: AuthorityMaintenanceBinding, challenge: Data) throws {
        guard [accountID, attemptID, revision, installationID, challenge].allSatisfy({ $0.count == 16 }),
              gate.inode > 0, target.accountID == accountID, target.attemptID == attemptID else {
            throw RuntimePreparationError.invalidRecord
        }
        self.accountID = accountID; self.attemptID = attemptID; self.revision = revision
        self.installationID = installationID; self.challenge = challenge; self.gate = gate; self.target = target
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("authority.maintenance-gate-request"),
            2: .bytes(accountID), 3: .bytes(attemptID), 4: .bytes(revision), 5: .bytes(installationID),
            6: .unsigned(UInt64(gate.device)), 7: .unsigned(gate.inode), 8: .bytes(target.encoded),
            9: .bytes(challenge)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...9),
              f[0] == .unsigned(1), f[1] == .text("authority.maintenance-gate-request"),
              case .bytes(let target) = f[8] else { throw RuntimePreparationError.invalidRecord }
        let device = try gateUInt(f[6]); guard device <= UInt64(UInt32.max) else { throw RuntimePreparationError.invalidRecord }
        let value = try Self(accountID: gateData(f[2]), attemptID: gateData(f[3]), revision: gateData(f[4]),
            installationID: gateData(f[5]), gate: .init(device: UInt32(device), inode: gateUInt(f[7])),
            target: .decode(target), challenge: gateData(f[9]))
        guard try value.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return value
    }
    private static let limits = try! CBORLimits(maxBytes: 512, maxDepth: 1, maxItems: 21)
}

/// Carries independently observed hold and kernel admission results. The native owner verifies scope before constructing it.
struct AuthorityMaintenanceGateResponse: Equatable, Sendable {
    typealias Readback = RuntimeMaintenanceWindowRecord.GateReadback
    let request: AuthorityMaintenanceGateRequest
    let authorityIncarnation: Data
    let hold: Readback.Hold
    let admission: Readback.Admission
    init(request: AuthorityMaintenanceGateRequest, authorityIncarnation: Data,
        hold: Readback.Hold, admission: Readback.Admission) throws {
        guard authorityIncarnation.count == 16 else { throw RuntimePreparationError.invalidRecord }
        self.request = request; self.authorityIncarnation = authorityIncarnation; self.hold = hold; self.admission = admission
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("authority.maintenance-gate-response"),
            2: .bytes(request.encoded), 3: .bytes(authorityIncarnation),
            4: .unsigned(hold.rawValue), 5: .unsigned(admission.rawValue)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data, expected: AuthorityMaintenanceGateRequest) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...5),
              f[0] == .unsigned(1), f[1] == .text("authority.maintenance-gate-response"),
              f[2] == .bytes(try expected.encoded), let hold = Readback.Hold(rawValue: try gateUInt(f[4])),
              let admission = Readback.Admission(rawValue: try gateUInt(f[5])) else {
            throw RuntimePreparationError.invalidRecord
        }
        let value = try Self(request: expected, authorityIncarnation: gateData(f[3]), hold: hold, admission: admission)
        guard try value.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return value
    }
    /// The digest binds the exact canonical response, including its fresh dedicated sixteen-byte challenge.
    func readback(expectedIncarnation: Data) throws -> Readback {
        guard authorityIncarnation == expectedIncarnation else { throw RuntimePreparationError.changedScope }
        return try .init(attemptID: request.attemptID, requestRevision: request.revision, identity: request.gate,
            authorityIncarnation: authorityIncarnation, challenge: request.challenge,
            responseDigest: Data(SHA256.hash(data: encoded)), hold: hold, admission: admission)
    }
    private static let limits = try! CBORLimits(maxBytes: 1024, maxDepth: 1, maxItems: 13)
}

private func gateUInt(_ value: CBORValue?) throws -> UInt64 {
    guard case .unsigned(let value) = value else { throw RuntimePreparationError.invalidRecord }; return value
}
private func gateData(_ value: CBORValue?) throws -> Data {
    guard case .bytes(let value) = value else { throw RuntimePreparationError.invalidRecord }; return value
}
