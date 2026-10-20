import Darwin
import Foundation
import Security

public enum AdministrativeSetupChannelError: Error, Equatable {
    case invalidConfiguration, wrongAccount, closed, busy, unsupportedVersion, invalidMessage, timedOut
}
enum SetupClientCall: Sendable {
    case hello, progress(Data), resume(SetupAccountProgress, Data)
    case gatewaySettingsHello, gatewaySettingsProgress, retainGatewaySettings(SetupGatewaySettingsProgress, GatewayRuntimeSettingsSelection, Data), resumeGatewaySettings(SetupGatewaySettingsProgress, Data)
    case gatewayActivationHello, gatewayActivationProgress, activateGateway(SetupGatewayActivationProgress, GatewayRuntimeActivationSettings, Data)
    case gatewayHello, gatewayProgress, prepareGateway(SetupGatewayProgress, GatewaySetupPreparationChoices, Data), resumeGatewayJournal(SetupGatewayProgress, Data)
    case activationHello, activationProgress, activateRuntime(SetupActivationProgress, Data)
    case runtimeHello, runtimeProgress, prepareRuntime(SetupRuntimeProgress, Bool, Data)
    case serviceAccountsHello, serviceAccountsProgress, prepareServiceAccounts(SetupServiceAccountProgress, Data)
    case enrollmentHello, enrollmentProgress, beginEnrollment(Data, Data), resumeEnrollment(SetupAccountEnrollmentProgress, Data)
    var handshake: Bool { switch self { case .hello, .enrollmentHello, .serviceAccountsHello, .runtimeHello, .activationHello, .gatewayHello, .gatewayActivationHello, .gatewaySettingsHello: true; default: false } }
}
enum SetupClientReply: Sendable { case version(UInt64), progress(Data?), failed }
protocol SetupClientDriver: Sendable {
    func start(closed: @escaping @Sendable () -> Void)
    func invoke(_ call: SetupClientCall, reply: @escaping @Sendable (SetupClientReply) -> Void)
    func close()
}
private final class NativeSetupClientDriver: SetupClientDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let policy: XPCPeerPolicy
    init(serviceName: String, policy: XPCPeerPolicy) {
        self.policy = policy
        connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: AdministrativeSetupXPCProtocol.self)
        policy.configure(connection)
    }
    func start(closed: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
    }
    func invoke(_ call: SetupClientCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
        // Hello discovers the peer. Every later send rechecks its kernel Root identity first.
        if !call.handshake {
            do { _ = try policy.verifyCredentials(connection) } catch { reply(.failed); return }
        }
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any AdministrativeSetupXPCProtocol else {
            reply(.failed); return
        }
        switch call {
        case .gatewaySettingsHello: proxy.gatewaySettingsHello { [self] in checked(.version($0), reply: reply) }
        case .gatewaySettingsProgress: proxy.gatewaySettingsProgress { [self] in checked(.progress($0), reply: reply) }
        case .retainGatewaySettings(let expected, let selection, let form):
            do { proxy.retainGatewaySettings(try expected.bytes, selection: try selection.bytes, authorization: form) { [self] in checked(.progress($0), reply: reply) } }
            catch { reply(.failed) }
        case .resumeGatewaySettings(let expected, let form):
            do { proxy.resumeGatewaySettings(try expected.bytes, authorization: form) { [self] in checked(.progress($0), reply: reply) } }
            catch { reply(.failed) }
        case .gatewayActivationHello: proxy.gatewayActivationHello { [self] in checked(.version($0), reply: reply) }
        case .gatewayActivationProgress: proxy.gatewayActivationProgress { [self] in checked(.progress($0), reply: reply) }
        case .activateGateway(let expected, let settings, let form):
            do { proxy.activateGateway(try expected.bytes, settings: try settings.bytes, authorization: form) { [self] in checked(.progress($0), reply: reply) } }
            catch { reply(.failed) }
        case .gatewayHello: proxy.gatewayHello { [self] in checked(.version($0), reply: reply) }
        case .gatewayProgress: proxy.gatewayProgress { [self] in checked(.progress($0), reply: reply) }
        case .prepareGateway(let expected, let choices, let form):
            do { proxy.prepareGateway(try expected.bytes, choices: try choices.bytes, authorization: form) { [self] in checked(.progress($0), reply: reply) } }
            catch { reply(.failed) }
        case .resumeGatewayJournal(let expected, let form):
            do { proxy.resumeGatewayJournal(try expected.bytes, authorization: form) { [self] in checked(.progress($0), reply: reply) } }
            catch { reply(.failed) }
        case .activationHello: proxy.activationHello { [self] in checked(.version($0), reply: reply) }
        case .activationProgress: proxy.activationProgress { [self] in checked(.progress($0), reply: reply) }
        case .activateRuntime(let expected, let form):
            do { proxy.activateRuntime(try expected.bytes, authorization: form) { [self] in checked(.progress($0), reply: reply) } }
            catch { reply(.failed) }
        case .runtimeHello: proxy.runtimeHello { [self] in checked(.version($0), reply: reply) }
        case .runtimeProgress: proxy.runtimeProgress { [self] in checked(.progress($0), reply: reply) }
        case .prepareRuntime(let expected, let accepted, let form):
            do { proxy.prepareRuntime(try expected.bytes, fileCustodyAccepted: accepted, authorization: form) { [self] in checked(.progress($0), reply: reply) } }
            catch { reply(.failed) }
        case .serviceAccountsHello: proxy.serviceAccountsHello { [self] in checked(.version($0), reply: reply) }
        case .serviceAccountsProgress: proxy.serviceAccountsProgress { [self] in checked(.progress($0), reply: reply) }
        case .prepareServiceAccounts(let expected, let form):
            do { proxy.prepareServiceAccounts(try expected.bytes, authorization: form) { [self] in checked(.progress($0), reply: reply) } }
            catch { reply(.failed) }
        case .enrollmentHello: proxy.enrollmentHello { [self] in checked(.version($0), reply: reply) }
        case .enrollmentProgress: proxy.accountEnrollmentProgress { [self] in checked(.progress($0), reply: reply) }
        case .beginEnrollment(let bytes, let form):
            proxy.beginAccountEnrollment(bytes, authorization: form) { [self] in checked(.progress($0), reply: reply) }
        case .resumeEnrollment(let expected, let form):
            proxy.resumeAccountEnrollment(expected.setupID, expectedRevision: expected.revision, authorization: form) { [self] in checked(.progress($0), reply: reply) }
        case .hello: proxy.hello { [self] in checked(.version($0), reply: reply) }
        case .progress(let account): proxy.accountStorageProgress(account) { [self] in checked(.progress($0), reply: reply) }
        case .resume(let progress, let authorization):
            proxy.resumeAccountStorage(progress.accountID, setupID: progress.setupID, expectedRevision: progress.revision,
                authorization: authorization) { [self] in checked(.progress($0), reply: reply) }
        }
    }
    private func checked(_ value: SetupClientReply, reply: @Sendable (SetupClientReply) -> Void) {
        do { _ = try policy.verifyCredentials(connection); reply(value) } catch { reply(.failed) }
    }
    func close() { connection.invalidate() }
    deinit { connection.invalidate() }
}
private final class SetupClientLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var closed = false
    func close() { lock.withLock { closed = true } }
    func ifOpen(_ body: () -> Void) -> Bool { lock.withLock { guard !closed else { return false }; body(); return true } }
}

/// App-to-Root setup connection. Inputs must come from verified, protected installation metadata.
/// Authenticate with start before exporting native administrator rights. A lost reply must be reconciled by reading progress.
public actor AdministrativeSetupChannel {
    private enum State { case new, opening, open, closed }
    private let driver: any SetupClientDriver
    private let accountID: Data?
    private let ownerUID: uid_t
    private let activation: Bool
    private let gateway: Bool
    private let gatewayActivation: Bool
    private let gatewaySettings: Bool
    private let gatewayOperationTimeout: UInt64
    private let runtime: Bool
    private let serviceAccounts: Bool
    private let timeout: UInt64
    private let verifyAccount: @Sendable () throws -> Void
    private let onClose: @Sendable () -> Void
    private let lifetime = SetupClientLifetime()
    private var state = State.new
    private var pending: (id: UUID, continuation: CheckedContinuation<SetupClientReply, any Error>)?
    private var timer: Task<Void, Never>?

    public init(serviceName: String, rootPolicy: XPCPeerPolicy, accountID: Data? = nil, ownerUID: uid_t, serviceAccounts: Bool = false, runtime: Bool = false, activation: Bool = false, gateway: Bool = false, gatewayActivation: Bool = false, gatewaySettings: Bool = false,
                gatewayOperationTimeoutMilliseconds: UInt64 = 60_000, timeoutMilliseconds: UInt64 = 5000, onClose: @escaping @Sendable () -> Void = {}) throws {
        guard serviceName.hasPrefix("dev.remozio."), (1...255).contains(serviceName.utf8.count),
              serviceName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45 }),
              (!(serviceAccounts || runtime || activation || gateway || gatewayActivation || gatewaySettings) || accountID == nil), rootPolicy.expectedUserID == 0, accountID == nil || accountID?.count == 16, ownerUID > 0, ownerUID < UInt32.max,
              (1...60_000).contains(timeoutMilliseconds), (1...300_000).contains(gatewayOperationTimeoutMilliseconds) else { throw AdministrativeSetupChannelError.invalidConfiguration }
        guard getuid() == ownerUID, geteuid() == ownerUID else { throw AdministrativeSetupChannelError.wrongAccount }
        let processID = getpid()
        driver = NativeSetupClientDriver(serviceName: serviceName, policy: rootPolicy)
        self.accountID = accountID; self.ownerUID = ownerUID; self.serviceAccounts = serviceAccounts || runtime || activation || gateway || gatewayActivation || gatewaySettings; self.runtime = runtime || activation || gateway || gatewayActivation || gatewaySettings; self.activation = activation || gateway || gatewayActivation || gatewaySettings; self.gateway = gateway || gatewayActivation || gatewaySettings; self.gatewayActivation = gatewayActivation || gatewaySettings; self.gatewaySettings = gatewaySettings; gatewayOperationTimeout = gatewayOperationTimeoutMilliseconds; timeout = timeoutMilliseconds; self.onClose = onClose
        verifyAccount = {
            guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else {
                throw AdministrativeSetupChannelError.wrongAccount
            }
        }
    }
    // Logical lifecycle controls do not prove native signing, service registration or administrator consent.
    init(driver: any SetupClientDriver, accountID: Data? = nil, ownerUID: uid_t = getuid(), serviceAccounts: Bool = false, runtime: Bool = false, activation: Bool = false, gateway: Bool = false, gatewayActivation: Bool = false, gatewaySettings: Bool = false, gatewayOperationTimeoutMilliseconds: UInt64 = 60_000, timeoutMilliseconds: UInt64 = 5000,
         verifyAccount: @escaping @Sendable () throws -> Void = {}, onClose: @escaping @Sendable () -> Void = {}) {
        self.driver = driver; self.accountID = accountID; self.ownerUID = ownerUID; self.serviceAccounts = serviceAccounts || runtime || activation || gateway || gatewayActivation || gatewaySettings; self.runtime = runtime || activation || gateway || gatewayActivation || gatewaySettings; self.activation = activation || gateway || gatewayActivation || gatewaySettings; self.gateway = gateway || gatewayActivation || gatewaySettings; self.gatewayActivation = gatewayActivation || gatewaySettings; self.gatewaySettings = gatewaySettings; gatewayOperationTimeout = gatewayOperationTimeoutMilliseconds; timeout = timeoutMilliseconds
        self.verifyAccount = verifyAccount; self.onClose = onClose
    }
    deinit { timer?.cancel(); driver.close() }
    public func start() async throws {
        guard state == .new else { throw AdministrativeSetupChannelError.closed }
        state = .opening
        do {
            let expected = gatewaySettings ? AdministrativeSetupInterface.gatewaySettingsVersion : gatewayActivation ? AdministrativeSetupInterface.gatewayActivationVersion : gateway ? AdministrativeSetupInterface.gatewayVersion : activation ? AdministrativeSetupInterface.activationVersion : runtime ? AdministrativeSetupInterface.runtimeVersion : serviceAccounts ? AdministrativeSetupInterface.serviceAccountsVersion :
                (accountID == nil ? AdministrativeSetupInterface.enrollmentVersion : AdministrativeSetupInterface.storageVersion)
            let call: SetupClientCall = gatewaySettings ? .gatewaySettingsHello : gatewayActivation ? .gatewayActivationHello : gateway ? .gatewayHello : activation ? .activationHello : runtime ? .runtimeHello : serviceAccounts ? .serviceAccountsHello : (accountID == nil ? .enrollmentHello : .hello)
            guard case .version(let version) = try await perform(call), version == expected else {
                throw AdministrativeSetupChannelError.unsupportedVersion
            }
            state = .open
        } catch { close(); throw error }
    }
    /// Empty progress means this account has no retained setup intent. It is not a runtime health result.
    public func progress() async throws -> SetupAccountProgress? {
        guard let accountID else { throw AdministrativeSetupChannelError.wrongAccount }
        return try decode(await perform(.progress(accountID)), expected: nil)
    }
    /// Supply only a freshly exported local administrator form after start succeeds. This method never prompts or retries.
    public func resume(_ expected: SetupAccountProgress, authorization: Data) async throws -> SetupAccountProgress {
        guard expected.accountID == accountID, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        guard let result = try decode(await perform(.resume(expected, authorization)), expected: expected) else {
            close(); throw AdministrativeSetupChannelError.invalidMessage
        }
        return result
    }
    public func enrollmentProgress() async throws -> SetupAccountEnrollmentProgress? {
        guard accountID == nil else { throw AdministrativeSetupChannelError.wrongAccount }
        return try decodeEnrollment(await perform(.enrollmentProgress), expected: nil)
    }
    public func beginEnrollment(_ choices: AccountEnrollmentRequest, authorization: Data) async throws -> SetupAccountEnrollmentProgress {
        guard accountID == nil, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        guard let result = try decodeEnrollment(await perform(.beginEnrollment(choices.bytes, authorization)), expected: nil),
              result.allowedTargetUIDs == choices.allowedTargetUIDs else {
            close(); throw AdministrativeSetupChannelError.invalidMessage
        }
        return result
    }
    public func resumeEnrollment(_ expected: SetupAccountEnrollmentProgress, authorization: Data) async throws -> SetupAccountEnrollmentProgress {
        guard accountID == nil, expected.ownerUID == ownerUID, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        guard let result = try decodeEnrollment(await perform(.resumeEnrollment(expected, authorization)), expected: expected) else {
            close(); throw AdministrativeSetupChannelError.invalidMessage
        }
        return result
    }
    public func serviceAccountsProgress() async throws -> SetupServiceAccountProgress? {
        guard serviceAccounts, accountID == nil else { throw AdministrativeSetupChannelError.unsupportedVersion }
        return try decodeServices(await perform(.serviceAccountsProgress), expected: nil)
    }
    public func prepareServiceAccounts(_ expected: SetupServiceAccountProgress, authorization: Data) async throws -> SetupServiceAccountProgress {
        guard serviceAccounts, accountID == nil, expected.ownerUID == ownerUID,
              authorization.count == MemoryLayout<AuthorizationExternalForm>.size else { throw AdministrativeSetupChannelError.invalidMessage }
        guard let result = try decodeServices(await perform(.prepareServiceAccounts(expected, authorization)), expected: expected) else {
            close(); throw AdministrativeSetupChannelError.invalidMessage
        }
        return result
    }
    public func gatewayProgress() async throws -> SetupGatewayProgress? {
        guard gateway, accountID == nil else { throw AdministrativeSetupChannelError.unsupportedVersion }
        return try decodeGateway(await perform(.gatewayProgress), expected: nil)
    }
    /// Resume the original setup. Completed progress does not apply new settings or provider choices.
    public func prepareGateway(_ expected: SetupGatewayProgress, choices: GatewaySetupPreparationChoices, authorization: Data) async throws -> SetupGatewayProgress {
        guard gateway, accountID == nil, expected.ownerUID == ownerUID,
              choices.fileWakeCustodyAccepted || expected.gatewayMaterialID != nil,
              authorization.count == MemoryLayout<AuthorizationExternalForm>.size else { throw AdministrativeSetupChannelError.invalidMessage }
        guard let value = try decodeGateway(await perform(.prepareGateway(expected, choices, authorization)), expected: expected) else {
            close(); throw AdministrativeSetupChannelError.invalidMessage
        }
        return value
    }
    public func resumeGatewayJournal(_ expected: SetupGatewayProgress, authorization: Data) async throws -> SetupGatewayJournalResult {
        guard gateway, accountID == nil, expected.ownerUID == ownerUID, expected.journalIntentDigest != nil,
              authorization.count == MemoryLayout<AuthorizationExternalForm>.size else { throw AdministrativeSetupChannelError.invalidMessage }
        do {
            let reply = try await perform(.resumeGatewayJournal(expected, authorization))
            guard case .progress(let bytes) = reply, let bytes, bytes.count <= 768 else { throw AdministrativeSetupChannelError.invalidMessage }
            let value = try SetupGatewayJournalResult.decode(bytes)
            guard value.progress.ownerUID == ownerUID else { throw AdministrativeSetupChannelError.invalidMessage }
            try value.progress.validateJournalCompletion(of: expected)
            return value
        } catch { close(); throw error }
    }
    private func decodeGateway(_ reply: SetupClientReply, expected: SetupGatewayProgress?) throws -> SetupGatewayProgress? {
        do {
            guard case .progress(let bytes) = reply, let bytes, bytes.count <= 640 else { throw AdministrativeSetupChannelError.invalidMessage }
            if bytes.isEmpty { guard expected == nil else { throw AdministrativeSetupChannelError.invalidMessage }; return nil }
            let value = try SetupGatewayProgress.decode(bytes)
            guard value.ownerUID == ownerUID else { throw AdministrativeSetupChannelError.invalidMessage }
            if let expected { try value.validatePreparation(of: expected) }
            return value
        } catch { finish(.invalidMessage); throw AdministrativeSetupChannelError.invalidMessage }
    }
    public func gatewayActivationProgress() async throws -> SetupGatewayActivationProgress? {
        guard gatewayActivation, accountID == nil else { throw AdministrativeSetupChannelError.unsupportedVersion }
        return try decodeGatewayActivation(await perform(.gatewayActivationProgress), expected: nil, settings: nil)
    }
    public func gatewaySettingsProgress() async throws -> SetupGatewaySettingsProgress? {
        guard gatewaySettings, accountID == nil else { throw AdministrativeSetupChannelError.unsupportedVersion }
        return try decodeGatewaySettings(await perform(.gatewaySettingsProgress))
    }

    public func retainGatewaySettings(_ expected: SetupGatewaySettingsProgress, selection: GatewayRuntimeSettingsSelection,
                                      authorization: Data) async throws -> SetupGatewaySettingsProgress {
        guard gatewaySettings, accountID == nil, expected.supportsSettingsChanges, expected.activation.setup.ownerUID == ownerUID,
              try expected.pending == nil, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        do {
            guard let value = try decodeGatewaySettings(await perform(.retainGatewaySettings(expected, selection, authorization))) else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            try value.validateRetention(of: expected, selection: selection); return value
        } catch { close(); throw error }
    }

    public func resumeGatewaySettings(_ expected: SetupGatewaySettingsProgress, authorization: Data) async throws -> SetupGatewaySettingsProgress {
        guard gatewaySettings, accountID == nil, expected.supportsSettingsChanges, expected.activation.setup.ownerUID == ownerUID,
              try expected.pending != nil, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        do {
            guard let value = try decodeGatewaySettings(await perform(.resumeGatewaySettings(expected, authorization))) else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            try value.validateCompletion(of: expected); return value
        } catch { close(); throw error }
    }

    private func decodeGatewaySettings(_ reply: SetupClientReply) throws -> SetupGatewaySettingsProgress? {
        do {
            guard case .progress(let bytes) = reply, let bytes, bytes.count <= SetupGatewaySettingsProgress.maximumByteCount else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            if bytes.isEmpty { return nil }
            let value = try SetupGatewaySettingsProgress.decode(bytes)
            guard value.activation.setup.ownerUID == ownerUID else { throw AdministrativeSetupChannelError.invalidMessage }
            return value
        } catch { finish(.invalidMessage); throw AdministrativeSetupChannelError.invalidMessage }
    }
    public func activateGateway(_ expected: SetupGatewayActivationProgress, settings: GatewayRuntimeActivationSettings,
                                authorization: Data) async throws -> SetupGatewayActivationProgress {
        guard gatewayActivation, accountID == nil, expected.setup.ownerUID == ownerUID, expected.setup.journalInitialized,
              expected.settings == nil || expected.settings == settings,
              authorization.count == MemoryLayout<AuthorizationExternalForm>.size else { throw AdministrativeSetupChannelError.invalidMessage }
        guard let value = try decodeGatewayActivation(await perform(.activateGateway(expected, settings, authorization)), expected: expected, settings: settings) else {
            close(); throw AdministrativeSetupChannelError.invalidMessage
        }
        return value
    }
    private func decodeGatewayActivation(_ reply: SetupClientReply, expected: SetupGatewayActivationProgress?,
                                         settings: GatewayRuntimeActivationSettings?) throws -> SetupGatewayActivationProgress? {
        do {
            guard case .progress(let bytes) = reply, let bytes, bytes.count <= 1280 else { throw AdministrativeSetupChannelError.invalidMessage }
            if bytes.isEmpty { guard expected == nil else { throw AdministrativeSetupChannelError.invalidMessage }; return nil }
            let value = try SetupGatewayActivationProgress.decode(bytes)
            guard value.setup.ownerUID == ownerUID else { throw AdministrativeSetupChannelError.invalidMessage }
            if let expected {
                guard let settings else { throw AdministrativeSetupChannelError.invalidMessage }
                try value.validateActivation(of: expected, selectedSettings: settings)
            }
            return value
        } catch { finish(.invalidMessage); throw AdministrativeSetupChannelError.invalidMessage }
    }
    public func activationProgress() async throws -> SetupActivationProgress? {
        guard activation, accountID == nil else { throw AdministrativeSetupChannelError.unsupportedVersion }
        return try decodeActivation(await perform(.activationProgress), expected: nil)
    }
    public func activateRuntime(_ expected: SetupActivationProgress, authorization: Data) async throws -> SetupActivationProgress {
        guard activation, accountID == nil, expected.ownerUID == ownerUID,
              authorization.count == MemoryLayout<AuthorizationExternalForm>.size else { throw AdministrativeSetupChannelError.invalidMessage }
        guard let value = try decodeActivation(await perform(.activateRuntime(expected, authorization)), expected: expected) else {
            close(); throw AdministrativeSetupChannelError.invalidMessage
        }
        return value
    }
    private func decodeActivation(_ reply: SetupClientReply, expected: SetupActivationProgress?) throws -> SetupActivationProgress? {
        do {
            guard case .progress(let bytes) = reply, let bytes, bytes.count <= 384 else { throw AdministrativeSetupChannelError.invalidMessage }
            if bytes.isEmpty {
                guard expected == nil else { throw AdministrativeSetupChannelError.invalidMessage }; return nil
            }
            let value = try SetupActivationProgress.decode(bytes)
            guard value.ownerUID == ownerUID else { throw AdministrativeSetupChannelError.invalidMessage }
            if let expected { try value.validateCompletion(of: expected) }
            return value
        } catch { finish(.invalidMessage); throw AdministrativeSetupChannelError.invalidMessage }
    }
    public func runtimeProgress() async throws -> SetupRuntimeProgress? {
        guard runtime, accountID == nil else { throw AdministrativeSetupChannelError.unsupportedVersion }
        return try decodeRuntime(await perform(.runtimeProgress), expected: nil)
    }
    public func prepareRuntime(_ expected: SetupRuntimeProgress, fileCustodyAccepted: Bool, authorization: Data) async throws -> SetupRuntimeProgress {
        guard runtime, accountID == nil, expected.ownerUID == ownerUID, fileCustodyAccepted,
              authorization.count == MemoryLayout<AuthorizationExternalForm>.size else { throw AdministrativeSetupChannelError.invalidMessage }
        guard let value = try decodeRuntime(await perform(.prepareRuntime(expected, fileCustodyAccepted, authorization)), expected: expected) else {
            close(); throw AdministrativeSetupChannelError.invalidMessage
        }
        return value
    }
    private func decodeRuntime(_ reply: SetupClientReply, expected: SetupRuntimeProgress?) throws -> SetupRuntimeProgress? {
        do {
            guard case .progress(let bytes) = reply, let bytes, bytes.count <= 384 else { throw AdministrativeSetupChannelError.invalidMessage }
            if bytes.isEmpty {
                guard expected == nil else { throw AdministrativeSetupChannelError.invalidMessage }; return nil
            }
            let value = try SetupRuntimeProgress.decode(bytes)
            guard value.ownerUID == ownerUID else { throw AdministrativeSetupChannelError.invalidMessage }
            if let expected { try value.validateCompletion(of: expected) }
            return value
        } catch { finish(.invalidMessage); throw AdministrativeSetupChannelError.invalidMessage }
    }
    private func decodeServices(_ reply: SetupClientReply, expected: SetupServiceAccountProgress?) throws -> SetupServiceAccountProgress? {
        do {
            guard case .progress(let bytes) = reply, let bytes, bytes.count <= 384 else { throw AdministrativeSetupChannelError.invalidMessage }
            if bytes.isEmpty {
                guard expected == nil else { throw AdministrativeSetupChannelError.invalidMessage }; return nil
            }
            let value = try SetupServiceAccountProgress.decode(bytes)
            guard value.ownerUID == ownerUID else { throw AdministrativeSetupChannelError.invalidMessage }
            if let expected { try value.validateCompletion(of: expected) }
            return value
        } catch { finish(.invalidMessage); throw AdministrativeSetupChannelError.invalidMessage }
    }
    private func decodeEnrollment(_ reply: SetupClientReply, expected: SetupAccountEnrollmentProgress?) throws -> SetupAccountEnrollmentProgress? {
        do {
            guard case .progress(let bytes) = reply, let bytes, bytes.count <= 1024 else { throw AdministrativeSetupChannelError.invalidMessage }
            if bytes.isEmpty {
                guard expected == nil else { throw AdministrativeSetupChannelError.invalidMessage }; return nil
            }
            let result = try SetupAccountEnrollmentProgress.decode(bytes)
            guard result.ownerUID == ownerUID else { throw AdministrativeSetupChannelError.invalidMessage }
            if let expected {
                guard result.macID == expected.macID, result.accountID == expected.accountID, result.setupID == expected.setupID,
                      result.allowedTargetUIDs == expected.allowedTargetUIDs, result.keyPrepared, result.storagePrepared,
                      (expected.storagePrepared ? result == expected : result.revision != expected.revision) else {
                    throw AdministrativeSetupChannelError.invalidMessage
                }
            }
            return result
        } catch { finish(.invalidMessage); throw AdministrativeSetupChannelError.invalidMessage }
    }
    public nonisolated func abort() { lifetime.close(); driver.close(); Task { await self.close() } }
    public func close() { finish(.closed) }
    private func decode(_ reply: SetupClientReply, expected: SetupAccountProgress?) throws -> SetupAccountProgress? {
        do {
            guard case .progress(let bytes) = reply, let bytes, bytes.count <= 256 else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            if bytes.isEmpty {
                guard expected == nil else { throw AdministrativeSetupChannelError.invalidMessage }; return nil
            }
            let value = try SetupAccountProgress.decode(bytes)
            guard value.accountID == accountID else { throw AdministrativeSetupChannelError.invalidMessage }
            if let expected {
                guard value.setupID == expected.setupID, value.complete, value.checkpointCaptured,
                      (expected.complete ? value == expected : value.revision != expected.revision) else { throw AdministrativeSetupChannelError.invalidMessage }
            }
            return value
        } catch { finish(.invalidMessage); throw AdministrativeSetupChannelError.invalidMessage }
    }
    private func perform(_ call: SetupClientCall) async throws -> SetupClientReply {
        do { try verifyAccount() } catch { close(); throw error }
        try Task.checkCancellation()
        switch call {
        case .hello, .enrollmentHello, .serviceAccountsHello, .runtimeHello, .activationHello, .gatewayHello, .gatewayActivationHello, .gatewaySettingsHello: guard state == .opening else { throw AdministrativeSetupChannelError.closed }
        case .gatewaySettingsProgress, .retainGatewaySettings, .resumeGatewaySettings, .gatewayActivationProgress, .activateGateway, .gatewayProgress, .prepareGateway, .resumeGatewayJournal, .progress, .resume, .enrollmentProgress, .beginEnrollment, .resumeEnrollment, .serviceAccountsProgress, .prepareServiceAccounts, .runtimeProgress, .prepareRuntime, .activationProgress, .activateRuntime: guard state == .open else { throw AdministrativeSetupChannelError.closed }
        }
        guard pending == nil else { throw AdministrativeSetupChannelError.busy }
        let requestTimeout: UInt64
        switch call { case .prepareGateway, .resumeGatewayJournal, .activateGateway, .retainGatewaySettings, .resumeGatewaySettings: requestTimeout = gatewayOperationTimeout; default: requestTimeout = timeout }
        let lifetime = lifetime, driver = driver, id = UUID()
        let value = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                timer = Task { [weak self, requestTimeout] in
                    do { try await Task.sleep(for: .milliseconds(requestTimeout)) } catch { return }
                    await self?.expire(id)
                }
                if call.handshake {
                    driver.start { [weak self] in lifetime.close(); Task { await self?.close() } }
                }
                guard lifetime.ifOpen({ driver.invoke(call) { [weak self] value in Task { await self?.complete(id, value: value) } } }) else {
                    close(); return
                }
            }
        } onCancel: { [weak self] in lifetime.close(); driver.close(); Task { await self?.close() } }
        try Task.checkCancellation()
        guard state != .closed, lifetime.ifOpen({}) else { close(); throw AdministrativeSetupChannelError.closed }
        return value
    }
    private func complete(_ id: UUID, value: SetupClientReply) {
        guard let previous = pending, previous.id == id else { return }
        guard lifetime.ifOpen({}) else { close(); return }
        if case .failed = value { finish(.closed); return }
        pending = nil; timer?.cancel(); timer = nil; previous.continuation.resume(returning: value)
    }
    private func expire(_ id: UUID) { if pending?.id == id { finish(.timedOut) } }
    private func finish(_ error: AdministrativeSetupChannelError) {
        guard state != .closed else { return }
        state = .closed; lifetime.close(); timer?.cancel(); timer = nil
        let previous = pending; pending = nil; driver.close(); onClose(); previous?.continuation.resume(throwing: error)
    }
}
