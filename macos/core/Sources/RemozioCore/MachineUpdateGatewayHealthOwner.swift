import Foundation
import RemozioProtocol

/// Checks retained credentials and a read-only store. It starts no provider work and grants no update completion authority.
final class MachineUpdateGatewayHealthOwner: @unchecked Sendable {
    typealias Requirement = MachineUpdateRestartHealthPlan.Requirement
    private let lock = NSRecursiveLock()
    private let database: GatewayDatabase
    private let configuration: GatewayServiceConfiguration
    private let requirement: Requirement
    private let expectedRequest: Data?
    private let verifyCurrent: @Sendable () throws -> Void
    private let release: @Sendable () -> Void
    private var signer: GatewayReceiptSigner?
    private var head: GatewayHeadEvidence?
    private var answering = false
    private var closed = false
    private var closing = false
    private var retired = false

    static func openNative(configurationPath: String, request: MachineUpdateConsumerHealthRequest) throws -> MachineUpdateGatewayHealthOwner {
        try openAdmitted(request: request) {
            try openNativeClaimed(configurationPath: configurationPath, request: request)
        }
    }

    /// A hot journal leaves the claimed request with the endpoint for one final authenticated failure reply.
    static func openAdmitted(request: MachineUpdateConsumerHealthRequest,
        open: () throws -> MachineUpdateGatewayHealthOwner) throws -> MachineUpdateGatewayHealthOwner {
        try request.claim()
        do {
            guard request.requirement.role == .notificationGateway else { throw MachineUpdateRoleChallengeError.changedScope }
            return try open()
        } catch GatewayDatabaseError.updateHealthRecoveryRequired {
            throw GatewayDatabaseError.updateHealthRecoveryRequired
        } catch {
            request.close()
            throw error
        }
    }

    private static func openNativeClaimed(configurationPath: String,
        request: MachineUpdateConsumerHealthRequest) throws -> MachineUpdateGatewayHealthOwner {
        let requirement = request.requirement
        let opened = try GatewaySettingsConsumerNativeScope.openGatewayForUpdateHealth(path: configurationPath)
        let scope = opened.scope, host = scope.configuration
        var database: GatewayDatabase?
        do {
            try request.validate(); try scope.validate()
            guard host.releaseBinding == requirement.binding, host.consumerCode == requirement.code,
                  host.serviceUID == requirement.executionUID else { throw MachineUpdateRoleChallengeError.changedScope }
            let paths = try RuntimePreparationPaths(accountID: host.runtime.services.accountID)
            let read: @Sendable (AdministrativeSetupPublication.File) throws -> Data = { file in
                try ProtectedServiceConfiguration.readPublic(path: paths.serviceDirectory + "/" + file.name)
            }
            let verify: @Sendable () throws -> Void = { try request.validate(); try scope.validate() }
            let fence: @Sendable () throws -> GatewayRuntimeSettingsFence? = {
                try GatewayRuntimeSettingsFenceReader.load(macID: host.runtime.services.macID,
                    accountID: host.runtime.services.accountID, verifyCurrent: verify)
            }
            let publication = try GatewayRuntimeLoader.loadForUpdateHealth(host: host,
                readFence: fence, read: read, verifyCurrent: verify)
            let marker = try publication.commit.encoded
            let configuration = publication.configuration
            guard configuration.registration.macID == requirement.binding.macID,
                  configuration.registration.accountID == requirement.binding.accountID,
                  configuration.serviceUID == requirement.executionUID,
                  configuration.receiptPublicKey == requirement.publicKey else { throw MachineUpdateRoleChallengeError.changedScope }
            let verifyPublication: @Sendable () throws -> Void = {
                let current = try GatewayRuntimeLoader.loadForUpdateHealth(host: host,
                    readFence: fence, read: read, verifyCurrent: verify)
                guard try current.commit.encoded == marker,
                      current.configuration.canonicalBytes == configuration.canonicalBytes else {
                    throw GatewayPreparationError.changedScope
                }
            }
            try verifyPublication()
            let openedDatabase = try GatewayDatabase.openForUpdateHealth(configuration: configuration, clockEpoch: UUID())
            database = openedDatabase
            let signer = try loadReceiptSigner(database: openedDatabase, configuration: configuration,
                verifyCurrent: verifyPublication, load: GatewayReceiptSigner.load(configuration:))
            let owner = try Self(database: openedDatabase, configuration: configuration, requirement: requirement,
                signer: signer, expectedRequest: request.bytes, verifyCurrent: verifyPublication,
                release: { request.close(); scope.close() })
            database = nil
            return owner
        } catch { try? database?.close(); scope.close(); throw error }
    }

    static func loadReceiptSigner(database: GatewayDatabase, configuration: GatewayServiceConfiguration,
        verifyCurrent: () throws -> Void, load: (GatewayServiceConfiguration) throws -> GatewayReceiptSigner) throws -> GatewayReceiptSigner {
        try verifyCurrent()
        guard try database.updateHealthEvidence().registration == configuration.registration else {
            throw GatewayDatabaseError.wrongScope
        }
        try verifyCurrent()
        let signer = try load(configuration)
        try verifyCurrent()
        return signer
    }

    /// Owned SQLite and a disposable signer exercise ordering. They do not establish a native account or Root peer.
    static func openOwned(database: GatewayDatabase, configuration: GatewayServiceConfiguration, requirement: Requirement,
        signer: GatewayReceiptSigner, expectedRequest: Data? = nil, verifyCurrent: @escaping @Sendable () throws -> Void,
        release: @escaping @Sendable () -> Void = {}) throws -> MachineUpdateGatewayHealthOwner {
        try Self(database: database, configuration: configuration, requirement: requirement, signer: signer, expectedRequest: expectedRequest,
            verifyCurrent: verifyCurrent, release: release)
    }
    private init(database: GatewayDatabase, configuration: GatewayServiceConfiguration, requirement: Requirement,
        signer: GatewayReceiptSigner, expectedRequest: Data? = nil, verifyCurrent: @escaping @Sendable () throws -> Void,
        release: @escaping @Sendable () -> Void) throws {
        self.database = database; self.configuration = configuration; self.requirement = requirement; self.expectedRequest = expectedRequest
        self.signer = signer; self.verifyCurrent = verifyCurrent; self.release = release
        do {
            guard requirement.role == .notificationGateway, requirement.code.role == requirement.role,
                  requirement.code.active, requirement.binding.macID == configuration.registration.macID,
                  requirement.binding.accountID == configuration.registration.accountID,
                  requirement.executionUID == configuration.serviceUID,
                  requirement.publicKey == configuration.receiptPublicKey,
                  signer.publicKey == configuration.receiptPublicKey else {
                throw MachineUpdateRoleChallengeError.changedScope
            }
            if let expectedRequest {
                guard try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(expectedRequest) == requirement else {
                    throw MachineUpdateRoleChallengeError.changedScope
                }
            }
            _ = try validate()
        } catch { try? close(); throw error }
    }

    /// Root must reconcile this valid retained head with its own journal. This value alone does not prove the latest control revision.
    func headEvidence() throws -> GatewayHeadEvidence { try lock.withLock { try validate() } }

    func answer(_ bytes: Data) throws -> Data {
        try lock.withLock {
            guard !closed, !closing, !retired, !answering, let signer else { throw MachineUpdateRoleChallengeError.unavailable }
            answering = true; defer { answering = false }
            do {
                guard expectedRequest == nil || expectedRequest == bytes else { throw MachineUpdateRoleChallengeError.changedScope }
                _ = try validate()
                let reply = try MachineUpdateRoleChallengeSession.answer(bytes, expected: requirement,
                    verifyCurrent: { _ = try self.validate() }, sign: { try signer.sign($0) })
                _ = try validate(); return reply
            } catch { retired = true; self.signer = nil; throw error }
        }
    }
    /// The signed Gateway head uses a nonce derived from the complete update request. No token or provider credential is returned.
    func answerWithHead(_ bytes: Data) throws -> Data {
        try lock.withLock {
            guard !closed, !closing, !retired, !answering, let signer else { throw MachineUpdateRoleChallengeError.unavailable }
            answering = true; defer { answering = false }
            do {
                guard expectedRequest == nil || expectedRequest == bytes else { throw MachineUpdateRoleChallengeError.changedScope }
                _ = try validate()
                let role = try MachineUpdateRoleChallengeSession.answer(bytes, expected: requirement,
                    verifyCurrent: { _ = try self.validate() }, sign: { try signer.sign($0) })
                let query = try MachineUpdateGatewayHealthQuery.make(request: bytes, registration: configuration.registration,
                    gatewayPublicKey: configuration.receiptPublicKey)
                let reply = try database.headReply(canonicalQuery: query, sign: { try signer.sign($0) })
                _ = try validate()
                return try MachineUpdateConsumerHealthPacket(roleReply: role, gatewayHead: reply).encoded
            } catch { retired = true; self.signer = nil; throw error }
        }
    }
    private func validate() throws -> GatewayHeadEvidence {
        try lock.withLock {
            guard !closed, !closing, !retired else { throw MachineUpdateRoleChallengeError.unavailable }
            do {
                try verifyCurrent()
                let current = try database.updateHealthEvidence()
                guard current.registration == configuration.registration else { throw GatewayDatabaseError.wrongScope }
                if let head {
                    guard current.revision == head.revision,
                          current.receipt?.canonicalPayload == head.receipt?.canonicalPayload,
                          current.receipt?.signature == head.receipt?.signature else { throw GatewayDatabaseError.headMismatch }
                } else { head = current }
                try verifyCurrent()
                guard !closed, !closing, !retired else { throw MachineUpdateRoleChallengeError.unavailable }
                return current
            } catch { retired = true; signer = nil; throw error }
        }
    }
    func close() throws {
        try lock.withLock {
            guard !closed else { return }; closing = true; signer = nil
            try database.close()
            closed = true; release()
        }
    }
    deinit { try? close() }
}
