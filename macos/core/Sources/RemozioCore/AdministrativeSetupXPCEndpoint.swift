import Darwin
import Foundation
import Security

public enum AdministrativeSetupInterface {
    public static let storageVersion: UInt64 = 1
    public static let enrollmentVersion: UInt64 = 2
    public static let serviceAccountsVersion: UInt64 = 3
    public static let runtimeVersion: UInt64 = 4
    public static let activationVersion: UInt64 = 5
    public static let supportedVersions: Set<UInt64> = [storageVersion, enrollmentVersion, serviceAccountsVersion, runtimeVersion, activationVersion]
}

/// Versioned local setup interface. Authenticate the chosen hello before sending an external authorization form.
@objc public protocol AdministrativeSetupXPCProtocol {
    func activationHello(reply: @escaping @Sendable (UInt64) -> Void)
    func activationProgress(reply: @escaping @Sendable (Data?) -> Void)
    func activateRuntime(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
    func runtimeHello(reply: @escaping @Sendable (UInt64) -> Void)
    func runtimeProgress(reply: @escaping @Sendable (Data?) -> Void)
    func prepareRuntime(_ expected: Data, fileCustodyAccepted: Bool, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
    func hello(reply: @escaping @Sendable (UInt64) -> Void)
    func serviceAccountsHello(reply: @escaping @Sendable (UInt64) -> Void)
    func serviceAccountsProgress(reply: @escaping @Sendable (Data?) -> Void)
    func prepareServiceAccounts(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
    func enrollmentHello(reply: @escaping @Sendable (UInt64) -> Void)
    func accountEnrollmentProgress(reply: @escaping @Sendable (Data?) -> Void)
    func beginAccountEnrollment(_ request: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
    func resumeAccountEnrollment(_ setupID: Data, expectedRevision: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
    func accountStorageProgress(_ accountID: Data, reply: @escaping @Sendable (Data?) -> Void)
    func resumeAccountStorage(_ accountID: Data, setupID: Data, expectedRevision: Data, authorization: Data,
                              reply: @escaping @Sendable (Data?) -> Void)
}

/// One authenticated local app connection. A shared owner serializes every machine-store operation.
/// The listener must enforce this peer policy, retain the connection and activate it only after construction succeeds.
public final class AdministrativeSetupXPCEndpoint: NSObject, AdministrativeSetupXPCProtocol, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let owner: SetupAccountOwner
    private let verify: () throws -> uid_t
    private let authorize: (Data) throws -> Void
    private let invalidate: () -> Void
    private let onHandshake: @Sendable () -> Void
    private var ready = false
    private var enrollmentReady = false
    private var serviceAccountsReady = false
    private var activationReady = false
    private var runtimeReady = false
    private var closed = false
    private var busy = false

    public convenience init(connection: NSXPCConnection, peerPolicy: XPCPeerPolicy, owner: SetupAccountOwner,
                            onHandshake: @escaping @Sendable () -> Void = {}, onClose: @escaping @Sendable () -> Void = {}) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard peerPolicy.expectedUserID > 0, peerPolicy.expectedUserID < UInt32.max else {
            throw AdministrativeSetupError.invalidConfiguration
        }
        _ = try peerPolicy.verifyCredentials(connection)
        let invocation = XPCInvocationGuard(connection: connection, policy: peerPolicy)
        try owner.verifyCurrent()
        self.init(owner: owner, verify: { try invocation.verifyInvocation().userID },
            authorize: { try SetupAdministratorAuthorization.validate(externalForm: $0, invocation: invocation) },
            invalidate: { [weak connection] in connection?.invalidate(); onClose() }, onHandshake: onHandshake)
        peerPolicy.configure(connection)
        connection.exportedInterface = NSXPCInterface(with: AdministrativeSetupXPCProtocol.self)
        connection.exportedObject = self
        connection.interruptionHandler = { [weak self] in self?.close() }
        connection.invalidationHandler = { [weak self] in self?.close() }
    }
    // Fixtures prove sequencing and scoped storage only. Product callers cannot inject authorization or invocation checks.
    init(owner: SetupAccountOwner, verify: @escaping () throws -> uid_t,
         authorize: @escaping (Data) throws -> Void, invalidate: @escaping () -> Void,
         onHandshake: @escaping @Sendable () -> Void = {}) {
        self.owner = owner; self.verify = verify; self.authorize = authorize; self.invalidate = invalidate; self.onHandshake = onHandshake
    }
    public func close() {
        let changed = lock.withLock { if closed { return false }; closed = true; ready = false; return true }
        if changed { invalidate() }
    }
    public func hello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            try operation(handshake: true) { _ in try owner.verifyCurrent(); ready = true }
            onHandshake()
            send { reply(AdministrativeSetupInterface.storageVersion) }
        } catch { close(); reply(0) }
    }
    public func serviceAccountsHello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            try operation(handshake: true) { _ in
                try owner.verifyCurrent(); ready = true; enrollmentReady = true; serviceAccountsReady = true
            }
            onHandshake(); send { reply(AdministrativeSetupInterface.serviceAccountsVersion) }
        } catch { close(); reply(0) }
    }
    public func serviceAccountsProgress(reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let bytes = try operation { uid in
                guard serviceAccountsReady else { throw AdministrativeSetupError.unavailable }
                return try owner.serviceAccountsProgress(callerUID: uid).map { try $0.bytes } ?? Data()
            }
            send { reply(bytes) }
        } catch { close(); reply(nil) }
    }
    public func prepareServiceAccounts(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let bytes = try operation { uid in
                guard serviceAccountsReady, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.invalidConfiguration
                }
                let progress = try SetupServiceAccountProgress.decode(expected)
                guard progress.ownerUID == uid else { throw AdministrativeSetupError.wrongAccount }
                try authorize(authorization)
                return try owner.resumeServiceAccounts(callerUID: uid, expected: progress).bytes
            }
            send { reply(bytes) }
        } catch { close(); reply(nil) }
    }
    public func activationHello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            try operation(handshake: true) { _ in
                try owner.verifyCurrent(); ready = true; enrollmentReady = true; serviceAccountsReady = true
                runtimeReady = true; activationReady = true
            }
            onHandshake(); send { reply(AdministrativeSetupInterface.activationVersion) }
        } catch { close(); reply(0) }
    }
    public func activationProgress(reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let bytes = try operation { uid in
                guard activationReady else { throw AdministrativeSetupError.unavailable }
                return try owner.activationProgress(callerUID: uid).map { try $0.bytes } ?? Data()
            }
            send { reply(bytes) }
        } catch { close(); reply(nil) }
    }
    public func activateRuntime(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let bytes = try operation { uid in
                guard activationReady, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.invalidConfiguration
                }
                let progress = try SetupActivationProgress.decode(expected)
                guard progress.ownerUID == uid else { throw AdministrativeSetupError.wrongAccount }
                try authorize(authorization)
                return try owner.resumeActivation(callerUID: uid, expected: progress).bytes
            }
            send { reply(bytes) }
        } catch { close(); reply(nil) }
    }
    public func runtimeHello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            try operation(handshake: true) { _ in
                try owner.verifyCurrent(); ready = true; enrollmentReady = true; serviceAccountsReady = true; runtimeReady = true
            }
            onHandshake(); send { reply(AdministrativeSetupInterface.runtimeVersion) }
        } catch { close(); reply(0) }
    }
    public func runtimeProgress(reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let bytes = try operation { uid in
                guard runtimeReady else { throw AdministrativeSetupError.unavailable }
                return try owner.runtimeProgress(callerUID: uid).map { try $0.bytes } ?? Data()
            }
            send { reply(bytes) }
        } catch { close(); reply(nil) }
    }
    public func prepareRuntime(_ expected: Data, fileCustodyAccepted: Bool, authorization: Data,
                               reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let bytes = try operation { uid in
                guard runtimeReady, fileCustodyAccepted, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.invalidConfiguration
                }
                let progress = try SetupRuntimeProgress.decode(expected)
                guard progress.ownerUID == uid else { throw AdministrativeSetupError.wrongAccount }
                try authorize(authorization)
                return try owner.resumeRuntime(callerUID: uid, expected: progress, fileCustodyAccepted: fileCustodyAccepted).bytes
            }
            send { reply(bytes) }
        } catch { close(); reply(nil) }
    }
    public func enrollmentHello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            try operation(handshake: true) { _ in try owner.verifyCurrent(); ready = true; enrollmentReady = true }
            onHandshake(); send { reply(AdministrativeSetupInterface.enrollmentVersion) }
        } catch { close(); reply(0) }
    }
    public func accountEnrollmentProgress(reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let bytes = try operation { uid in
                guard enrollmentReady else { throw AdministrativeSetupError.unavailable }
                return try owner.enrollment(callerUID: uid).map { try SetupAccountEnrollmentProgress($0).bytes } ?? Data()
            }
            send { reply(bytes) }
        } catch { close(); reply(nil) }
    }
    public func beginAccountEnrollment(_ request: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let bytes = try operation { uid in
                guard enrollmentReady, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.invalidConfiguration
                }
                let choices = try AccountEnrollmentRequest.decode(request)
                try authorize(authorization)
                return try SetupAccountEnrollmentProgress(owner.beginEnrollment(callerUID: uid, allowedTargetUIDs: choices.allowedTargetUIDs,
                    disclosureAccepted: choices.independentPolicyDisclosureAccepted)).bytes
            }
            send { reply(bytes) }
        } catch { close(); reply(nil) }
    }
    public func resumeAccountEnrollment(_ setupID: Data, expectedRevision: Data, authorization: Data,
                                        reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let bytes = try operation { uid in
                guard enrollmentReady, setupID.count == 16, expectedRevision.count == 16,
                      authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.invalidConfiguration
                }
                try authorize(authorization)
                return try SetupAccountEnrollmentProgress(owner.resumeEnrollment(callerUID: uid, setupID: setupID,
                    expectedRevision: expectedRevision)).bytes
            }
            send { reply(bytes) }
        } catch { close(); reply(nil) }
    }
    public func accountStorageProgress(_ accountID: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let bytes = try operation { uid in
                guard accountID.count == 16 else { throw AdministrativeSetupError.invalidConfiguration }
                return try owner.progress(accountID: accountID, callerUID: uid).map { try SetupAccountProgress($0).bytes } ?? Data()
            }
            send { reply(bytes) }
        } catch { close(); reply(nil) }
    }
    public func resumeAccountStorage(_ accountID: Data, setupID: Data, expectedRevision: Data, authorization: Data,
                                     reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let bytes = try operation { uid in
                guard accountID.count == 16, setupID.count == 16, expectedRevision.count == 16,
                      authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.invalidConfiguration
                }
                // Import current native rights during this exported invocation. Never retain or forward the external form.
                try authorize(authorization)
                return try SetupAccountProgress(owner.resumeAccount(accountID: accountID, setupID: setupID,
                    expectedRevision: expectedRevision, callerUID: uid)).bytes
            }
            send { reply(bytes) }
        } catch { close(); reply(nil) }
    }
    private func operation<T>(handshake: Bool = false, _ body: (uid_t) throws -> T) throws -> T {
        let uid = try verify()
        return try lock.withLock {
            guard !closed, !busy, ready != handshake else { throw AdministrativeSetupError.unavailable }
            busy = true; defer { busy = false }
            return try body(uid)
        }
    }
    private func send(_ reply: () -> Void) { lock.withLock { if !closed { reply() } } }
}
