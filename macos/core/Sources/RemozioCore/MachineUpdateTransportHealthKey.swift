import CryptoKit
import Foundation
import Security

/// Holds the existing TLS identity for a fixed-purpose health reply. It opens no listener and creates no key.
final class MachineUpdateTransportHealthKey: @unchecked Sendable {
    typealias Requirement = MachineUpdateRestartHealthPlan.Requirement
    private let lock = NSRecursiveLock()
    private let requirement: Requirement
    private let publicKeyInfo: Data
    private let expectedRequest: Data?
    private let verifyCurrent: @Sendable () throws -> Void
    private let release: @Sendable () -> Void
    private var identity: SecIdentity?
    private var key: SecKey?
    private var certificate: SecCertificate?
    private var answering = false
    private var retired = false
    private var closed = false

    /// Borrows the identity already retained by ordinary transport. Construction performs no key or credential lookup.
    final class LiveIdentity: @unchecked Sendable {
        private let lock = NSRecursiveLock()
        private let identity: SecIdentity
        init(_ identity: SecIdentity) { self.identity = identity }

        /// The caller must bind the native peer, completed configuration, and ordinary runtime before this fixed-purpose signing operation.
        func answer(_ request: MachineUpdateConsumerHealthRequest, expected: Requirement, publicKeyInfo: Data,
            verifyCurrent: @escaping @Sendable () throws -> Void) throws -> Data {
            try request.claim(); try request.validate()
            guard request.requirement == expected else { throw MachineUpdateRoleChallengeError.changedScope }
            return try lock.withLock {
                try request.validate(); try verifyCurrent()
                let borrowed = try MachineUpdateTransportHealthKey(identity: identity, publicKeyInfo: publicKeyInfo,
                    requirement: expected, expectedRequest: request.bytes,
                    verifyCurrent: { try request.validate(); try verifyCurrent() }, release: {})
                defer { borrowed.close() }
                let reply = try borrowed.answer(request.bytes)
                try request.validate(); try verifyCurrent()
                return try MachineUpdateConsumerHealthPacket(roleReply: reply, gatewayHead: nil).encoded
            }
        }
    }

    /// A disposable identity exercises signing. This factory does not establish a native service account or code identity.
    static func openOwned(identity: SecIdentity, publicKeyInfo: Data, requirement: Requirement, expectedRequest: Data? = nil,
        verifyCurrent: @escaping @Sendable () throws -> Void, release: @escaping @Sendable () -> Void = {}) throws -> MachineUpdateTransportHealthKey {
        try Self(identity: identity, publicKeyInfo: publicKeyInfo, requirement: requirement, expectedRequest: expectedRequest, verifyCurrent: verifyCurrent, release: release)
    }
    private init(identity: SecIdentity, publicKeyInfo: Data, requirement: Requirement, expectedRequest: Data?,
        verifyCurrent: @escaping @Sendable () throws -> Void, release: @escaping @Sendable () -> Void) throws {
        self.identity = identity; self.publicKeyInfo = publicKeyInfo; self.requirement = requirement; self.expectedRequest = expectedRequest
        self.verifyCurrent = verifyCurrent; self.release = release
        do {
            guard requirement.role == .transport, requirement.executionUID > 0, requirement.executionUID < UInt32.max,
                  try P256.Signing.PublicKey(derRepresentation: publicKeyInfo).x963Representation == requirement.publicKey else {
                throw RuntimePreparationError.changedScope
            }
            if let expectedRequest {
                guard try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(expectedRequest) == requirement else {
                    throw MachineUpdateRoleChallengeError.changedScope
                }
            }
            try verifyCurrent()
            var key: SecKey?, certificate: SecCertificate?
            guard SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key,
                  SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate,
                  SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256) else {
                throw ApprovalTransportStartupError.invalidIdentity
            }
            self.key = key; self.certificate = certificate
            try validate()
        } catch { close(); throw error }
    }
    private func validate() throws {
        try lock.withLock {
            guard !closed, !retired, identity != nil, let key, let certificate else { throw MachineUpdateRoleChallengeError.unavailable }
            try verifyCurrent()
            try ApprovalTransportIdentity.validate(key: key, certificate: certificate, publicKeyInfo: publicKeyInfo)
            try verifyCurrent()
            guard !closed, !retired else { throw MachineUpdateRoleChallengeError.unavailable }
        }
    }
    func answer(_ request: Data) throws -> Data {
        try lock.withLock {
            guard !closed, !retired, !answering else { throw MachineUpdateRoleChallengeError.unavailable }
            answering = true; defer { answering = false }
            do {
                guard expectedRequest == nil || expectedRequest == request else { throw MachineUpdateRoleChallengeError.changedScope }
                try validate()
                let result = try MachineUpdateRoleChallengeSession.answer(request, expected: requirement,
                    verifyCurrent: { try self.validate() }, sign: { input in
                        guard let key = self.key,
                              let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, input as CFData, nil) as Data? else {
                            throw ApprovalTransportStartupError.identityUnavailable
                        }
                        return try P256.Signing.ECDSASignature(derRepresentation: signature).rawRepresentation
                    })
                try validate(); return result
            } catch { retired = true; throw error }
        }
    }
    func close() {
        lock.withLock {
            guard !closed else { return }; closed = true
            key = nil; certificate = nil; identity = nil; release()
        }
    }
    deinit { close() }
}
