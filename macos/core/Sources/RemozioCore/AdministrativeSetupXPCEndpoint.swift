import Darwin
import Foundation
import Security

public enum AdministrativeSetupInterface {
    public static let formatName = "setup.local-ipc"
    public static let storageVersion: UInt64 = 1
    public static let enrollmentVersion: UInt64 = 2
    public static let serviceAccountsVersion: UInt64 = 3
    public static let runtimeVersion: UInt64 = 4
    public static let activationVersion: UInt64 = 5
    public static let gatewayVersion: UInt64 = 6
    public static let gatewayActivationVersion: UInt64 = 7
    public static let gatewaySettingsVersion: UInt64 = 8
    public static let supportedVersions: Set<UInt64> = [storageVersion, enrollmentVersion, serviceAccountsVersion, runtimeVersion, activationVersion, gatewayVersion, gatewayActivationVersion, gatewaySettingsVersion]
}

/// Versioned local setup interface. Authenticate the chosen hello before sending an external authorization form.
@objc public protocol AdministrativeSetupXPCProtocol {
    func gatewaySettingsHello(reply: @escaping @Sendable (UInt64) -> Void)
    func gatewaySettingsProgress(reply: @escaping @Sendable (Data?) -> Void)
    func retainGatewaySettings(_ expected: Data, selection: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
    func resumeGatewaySettings(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
    func gatewayActivationHello(reply: @escaping @Sendable (UInt64) -> Void)
    func gatewayActivationProgress(reply: @escaping @Sendable (Data?) -> Void)
    func activateGateway(_ expected: Data, settings: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
    func gatewayHello(reply: @escaping @Sendable (UInt64) -> Void)
    func gatewayProgress(reply: @escaping @Sendable (Data?) -> Void)
    func prepareGateway(_ expected: Data, choices: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
    func resumeGatewayJournal(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
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
    private var gatewayReady = false
    private var gatewayActivationReady = false
    private var gatewaySettingsReady = false
    private var asynchronousID: UUID?
    private var asynchronousTask: Task<Void, Never>?
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
        let changed = lock.withLock { () -> (Bool, Task<Void, Never>?) in
            if closed { return (false, nil) }; closed = true; ready = false; return (true, asynchronousTask)
        }
        changed.1?.cancel()
        if changed.0 { invalidate() }
    }
    public func gatewaySettingsHello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try operation(handshake: true) { _ in
                try owner.verifyCurrent(); ready = true; enrollmentReady = true; serviceAccountsReady = true
                runtimeReady = true; activationReady = true; gatewayReady = true; gatewayActivationReady = true; gatewaySettingsReady = true
            }
            defer { completed.activity?.close() }
            onHandshake(); send { reply(AdministrativeSetupInterface.gatewaySettingsVersion) }
        } catch { close(); reply(0) }
    }

    public func gatewaySettingsProgress(reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard gatewaySettingsReady else { throw AdministrativeSetupError.unavailable }
                return try owner.gatewaySettingsProgress(callerUID: uid).map { try $0.bytes } ?? Data()
            }
            defer { completed.activity?.close() }; send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }

    public func retainGatewaySettings(_ expected: Data, selection: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard gatewaySettingsReady, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.invalidConfiguration
                }
                let progress = try SetupGatewaySettingsProgress.decode(expected)
                let selection = try GatewayRuntimeSettingsSelection.decode(selection)
                guard progress.supportsSettingsChanges, progress.activation.setup.ownerUID == uid, try progress.pending == nil else {
                    throw AdministrativeSetupError.wrongAccount
                }
                try authorize(authorization)
                return try owner.retainGatewaySettings(callerUID: uid, expected: progress, selection: selection).bytes
            }
            defer { completed.activity?.close() }; send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }

    public func resumeGatewaySettings(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            // XPC invocation and native rights checks occur synchronously on this exported invocation.
            // The task captures only the authenticated UID, public progress and release activity.
            let uid = try verify()
            let reservation = try lock.withLock { () -> (uid: uid_t, progress: SetupGatewaySettingsProgress, id: UUID, activity: ReleaseActivityToken?, admission: SetupOwnerAsyncWork.Token) in
                guard !closed, !busy, ready, gatewaySettingsReady, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.unavailable
                }
                busy = true
                let admission: SetupOwnerAsyncWork.Token
                do { admission = try owner.acquireSetupReplyAdmission() } catch { busy = false; throw error }
                let activity: ReleaseActivityToken?
                do { activity = try owner.acquireReleaseActivity() } catch { busy = false; admission.close(); throw error }
                do {
                    let progress = try SetupGatewaySettingsProgress.decode(expected)
                    guard progress.supportsSettingsChanges, progress.activation.setup.ownerUID == uid, try progress.pending != nil else { throw AdministrativeSetupError.wrongAccount }
                    try authorize(authorization); try activity?.validate()
                    let id = UUID(); asynchronousID = id
                    return (uid, progress, id, activity, admission)
                } catch { busy = false; activity?.close(); admission.close(); throw error }
            }
            lock.withLock {
                guard !closed, asynchronousID == reservation.id else {
                    reservation.activity?.close(); reservation.admission.close(); busy = false; asynchronousID = nil; return
                }
                asynchronousTask = Task { [self, reservation, reply] in
                    defer {
                        lock.withLock {
                            if asynchronousID == reservation.id { asynchronousID = nil; asynchronousTask = nil; busy = false }
                        }
                        reservation.activity?.close(); reservation.admission.close()
                    }
                    do {
                        try Task.checkCancellation()
                        let result = try await owner.resumeGatewaySettings(callerUID: reservation.uid, expected: reservation.progress)
                        try Task.checkCancellation(); try reservation.activity?.validate()
                        let bytes = try result.bytes
                        try reservation.activity?.validate()
                        finishGatewayOperation(reservation.id, bytes: bytes, failed: false, reply: reply)
                    } catch { finishGatewayOperation(reservation.id, bytes: nil, failed: true, reply: reply) }
                }
            }
        } catch { close(); reply(nil) }
    }
    public func gatewayActivationHello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try operation(handshake: true) { _ in
                try owner.verifyCurrent(); ready = true; enrollmentReady = true; serviceAccountsReady = true
                runtimeReady = true; activationReady = true; gatewayReady = true; gatewayActivationReady = true
            }
            defer { completed.activity?.close() }
            onHandshake(); send { reply(AdministrativeSetupInterface.gatewayActivationVersion) }
        } catch { close(); reply(0) }
    }
    public func gatewayActivationProgress(reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard gatewayActivationReady else { throw AdministrativeSetupError.unavailable }
                return try owner.gatewayActivationProgress(callerUID: uid).map { try $0.bytes } ?? Data()
            }
            defer { completed.activity?.close() }; send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func gatewayHello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try operation(handshake: true) { _ in
                try owner.verifyCurrent(); ready = true; enrollmentReady = true; serviceAccountsReady = true
                runtimeReady = true; activationReady = true; gatewayReady = true
            }
            defer { completed.activity?.close() }
            onHandshake(); send { reply(AdministrativeSetupInterface.gatewayVersion) }
        } catch { close(); reply(0) }
    }
    public func gatewayProgress(reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard gatewayReady else { throw AdministrativeSetupError.unavailable }
                return try owner.gatewayProgress(callerUID: uid).map { try $0.bytes } ?? Data()
            }
            defer { completed.activity?.close() }; send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func prepareGateway(_ expected: Data, choices: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard gatewayReady, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.invalidConfiguration
                }
                let progress = try SetupGatewayProgress.decode(expected)
                guard progress.ownerUID == uid else { throw AdministrativeSetupError.wrongAccount }
                let choices = try GatewaySetupPreparationChoices.decode(choices)
                try authorize(authorization)
                return try owner.prepareGateway(callerUID: uid, expected: progress, choices: choices).bytes
            }
            defer { completed.activity?.close() }; send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func resumeGatewayJournal(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            // XPC invocation and native rights checks occur synchronously on this exported invocation.
            // The task captures only the authenticated UID, public progress and release activity.
            let uid = try verify()
            let reservation = try lock.withLock { () -> (uid: uid_t, progress: SetupGatewayProgress, id: UUID, activity: ReleaseActivityToken?, admission: SetupOwnerAsyncWork.Token) in
                guard !closed, !busy, ready, gatewayReady, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.unavailable
                }
                busy = true
                let admission: SetupOwnerAsyncWork.Token
                do { admission = try owner.acquireSetupReplyAdmission() } catch { busy = false; throw error }
                let activity: ReleaseActivityToken?
                do { activity = try owner.acquireReleaseActivity() } catch { busy = false; admission.close(); throw error }
                do {
                    let progress = try SetupGatewayProgress.decode(expected)
                    guard progress.ownerUID == uid, progress.journalIntentDigest != nil else { throw AdministrativeSetupError.wrongAccount }
                    try authorize(authorization); try activity?.validate()
                    let id = UUID(); asynchronousID = id
                    return (uid, progress, id, activity, admission)
                } catch { busy = false; activity?.close(); admission.close(); throw error }
            }
            lock.withLock {
                guard !closed, asynchronousID == reservation.id else {
                    reservation.activity?.close(); reservation.admission.close(); busy = false; asynchronousID = nil; return
                }
                asynchronousTask = Task { [self, reservation, reply] in
                    defer {
                        lock.withLock {
                            if asynchronousID == reservation.id { asynchronousID = nil; asynchronousTask = nil; busy = false }
                        }
                        reservation.activity?.close(); reservation.admission.close()
                    }
                    do {
                        try Task.checkCancellation()
                        let result = try await owner.resumeGatewayJournal(callerUID: reservation.uid, expected: reservation.progress)
                        try Task.checkCancellation(); try reservation.activity?.validate()
                        let bytes = try result.bytes
                        try reservation.activity?.validate()
                        finishGatewayOperation(reservation.id, bytes: bytes, failed: false, reply: reply)
                    } catch { finishGatewayOperation(reservation.id, bytes: nil, failed: true, reply: reply) }
                }
            }
        } catch { close(); reply(nil) }
    }
    public func activateGateway(_ expected: Data, settings: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            // XPC invocation and native rights checks occur synchronously on this exported invocation.
            // The task captures only the authenticated UID, public progress and release activity.
            let uid = try verify()
            let reservation = try lock.withLock { () -> (uid: uid_t, progress: SetupGatewayActivationProgress, settings: GatewayRuntimeActivationSettings, id: UUID, activity: ReleaseActivityToken?, admission: SetupOwnerAsyncWork.Token) in
                guard !closed, !busy, ready, gatewayActivationReady, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.unavailable
                }
                busy = true
                let admission: SetupOwnerAsyncWork.Token
                do { admission = try owner.acquireSetupReplyAdmission() } catch { busy = false; throw error }
                let activity: ReleaseActivityToken?
                do { activity = try owner.acquireReleaseActivity() } catch { busy = false; admission.close(); throw error }
                do {
                    let progress = try SetupGatewayActivationProgress.decode(expected)
                    let selected = try GatewayRuntimeActivationSettings.decode(settings)
                    guard progress.setup.ownerUID == uid, progress.setup.journalInitialized else { throw AdministrativeSetupError.wrongAccount }
                    try authorize(authorization); try activity?.validate()
                    let id = UUID(); asynchronousID = id
                    return (uid, progress, selected, id, activity, admission)
                } catch { busy = false; activity?.close(); admission.close(); throw error }
            }
            lock.withLock {
                guard !closed, asynchronousID == reservation.id else {
                    reservation.activity?.close(); reservation.admission.close(); busy = false; asynchronousID = nil; return
                }
                asynchronousTask = Task { [self, reservation, reply] in
                    defer {
                        lock.withLock {
                            if asynchronousID == reservation.id { asynchronousID = nil; asynchronousTask = nil; busy = false }
                        }
                        reservation.activity?.close(); reservation.admission.close()
                    }
                    do {
                        try Task.checkCancellation()
                        let result = try await owner.resumeGatewayActivation(callerUID: reservation.uid, expected: reservation.progress, settings: reservation.settings)
                        try Task.checkCancellation(); try reservation.activity?.validate()
                        let bytes = try result.bytes
                        try reservation.activity?.validate()
                        finishGatewayOperation(reservation.id, bytes: bytes, failed: false, reply: reply)
                    } catch { finishGatewayOperation(reservation.id, bytes: nil, failed: true, reply: reply) }
                }
            }
        } catch { close(); reply(nil) }
    }
    private func finishGatewayOperation(_ id: UUID, bytes: Data?, failed: Bool, reply: @Sendable (Data?) -> Void) {
        let terminate = lock.withLock {
            guard !closed, asynchronousID == id else { return false }
            asynchronousID = nil; asynchronousTask = nil; busy = false
            if failed { closed = true; ready = false }
            // Admission is released before a successful reply. A subsequent client call cannot race a stale busy flag.
            reply(bytes); return failed
        }
        if terminate { invalidate() }
    }
    public func hello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try operation(handshake: true) { _ in try owner.verifyCurrent(); ready = true }
            defer { completed.activity?.close() }
            onHandshake()
            send { reply(AdministrativeSetupInterface.storageVersion) }
        } catch { close(); reply(0) }
    }
    public func serviceAccountsHello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try operation(handshake: true) { _ in
                try owner.verifyCurrent(); ready = true; enrollmentReady = true; serviceAccountsReady = true
            }
            defer { completed.activity?.close() }
            onHandshake(); send { reply(AdministrativeSetupInterface.serviceAccountsVersion) }
        } catch { close(); reply(0) }
    }
    public func serviceAccountsProgress(reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard serviceAccountsReady else { throw AdministrativeSetupError.unavailable }
                return try owner.serviceAccountsProgress(callerUID: uid).map { try $0.bytes } ?? Data()
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func prepareServiceAccounts(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard serviceAccountsReady, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.invalidConfiguration
                }
                let progress = try SetupServiceAccountProgress.decode(expected)
                guard progress.ownerUID == uid else { throw AdministrativeSetupError.wrongAccount }
                try authorize(authorization)
                return try owner.resumeServiceAccounts(callerUID: uid, expected: progress).bytes
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func activationHello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try operation(handshake: true) { _ in
                try owner.verifyCurrent(); ready = true; enrollmentReady = true; serviceAccountsReady = true
                runtimeReady = true; activationReady = true
            }
            defer { completed.activity?.close() }
            onHandshake(); send { reply(AdministrativeSetupInterface.activationVersion) }
        } catch { close(); reply(0) }
    }
    public func activationProgress(reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard activationReady else { throw AdministrativeSetupError.unavailable }
                return try owner.activationProgress(callerUID: uid).map { try $0.bytes } ?? Data()
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func activateRuntime(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard activationReady, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.invalidConfiguration
                }
                let progress = try SetupActivationProgress.decode(expected)
                guard progress.ownerUID == uid else { throw AdministrativeSetupError.wrongAccount }
                try authorize(authorization)
                return try owner.resumeActivation(callerUID: uid, expected: progress).bytes
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func runtimeHello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try operation(handshake: true) { _ in
                try owner.verifyCurrent(); ready = true; enrollmentReady = true; serviceAccountsReady = true; runtimeReady = true
            }
            defer { completed.activity?.close() }
            onHandshake(); send { reply(AdministrativeSetupInterface.runtimeVersion) }
        } catch { close(); reply(0) }
    }
    public func runtimeProgress(reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard runtimeReady else { throw AdministrativeSetupError.unavailable }
                return try owner.runtimeProgress(callerUID: uid).map { try $0.bytes } ?? Data()
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func prepareRuntime(_ expected: Data, fileCustodyAccepted: Bool, authorization: Data,
                               reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard runtimeReady, fileCustodyAccepted, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.invalidConfiguration
                }
                let progress = try SetupRuntimeProgress.decode(expected)
                guard progress.ownerUID == uid else { throw AdministrativeSetupError.wrongAccount }
                try authorize(authorization)
                return try owner.resumeRuntime(callerUID: uid, expected: progress, fileCustodyAccepted: fileCustodyAccepted).bytes
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func enrollmentHello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try operation(handshake: true) { _ in try owner.verifyCurrent(); ready = true; enrollmentReady = true }
            defer { completed.activity?.close() }
            onHandshake(); send { reply(AdministrativeSetupInterface.enrollmentVersion) }
        } catch { close(); reply(0) }
    }
    public func accountEnrollmentProgress(reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard enrollmentReady else { throw AdministrativeSetupError.unavailable }
                return try owner.enrollment(callerUID: uid).map { try SetupAccountEnrollmentProgress($0).bytes } ?? Data()
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func beginAccountEnrollment(_ request: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard enrollmentReady, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.invalidConfiguration
                }
                let choices = try AccountEnrollmentRequest.decode(request)
                try authorize(authorization)
                return try SetupAccountEnrollmentProgress(owner.beginEnrollment(callerUID: uid, allowedTargetUIDs: choices.allowedTargetUIDs,
                    disclosureAccepted: choices.independentPolicyDisclosureAccepted)).bytes
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func resumeAccountEnrollment(_ setupID: Data, expectedRevision: Data, authorization: Data,
                                        reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard enrollmentReady, setupID.count == 16, expectedRevision.count == 16,
                      authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.invalidConfiguration
                }
                try authorize(authorization)
                return try SetupAccountEnrollmentProgress(owner.resumeEnrollment(callerUID: uid, setupID: setupID,
                    expectedRevision: expectedRevision)).bytes
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func accountStorageProgress(_ accountID: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard accountID.count == 16 else { throw AdministrativeSetupError.invalidConfiguration }
                return try owner.progress(accountID: accountID, callerUID: uid).map { try SetupAccountProgress($0).bytes } ?? Data()
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func resumeAccountStorage(_ accountID: Data, setupID: Data, expectedRevision: Data, authorization: Data,
                                     reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try operation { uid in
                guard accountID.count == 16, setupID.count == 16, expectedRevision.count == 16,
                      authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.invalidConfiguration
                }
                // Import current native rights during this exported invocation. Never retain or forward the external form.
                try authorize(authorization)
                return try SetupAccountProgress(owner.resumeAccount(accountID: accountID, setupID: setupID,
                    expectedRevision: expectedRevision, callerUID: uid)).bytes
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    private func operation<T>(handshake: Bool = false, _ body: (uid_t) throws -> T) throws -> (value: T, activity: ReleaseActivityToken?) {
        let uid = try verify()
        return try lock.withLock {
            guard !closed, !busy, ready != handshake else { throw AdministrativeSetupError.unavailable }
            busy = true; defer { busy = false }
            let activity = try owner.acquireReleaseActivity()
            var transferred = false
            defer { if !transferred { activity?.close() } }
            let value = try body(uid)
            try activity?.validate()
            transferred = true
            return (value, activity)
        }
    }
    private func send(_ reply: () -> Void) { lock.withLock { if !closed { reply() } } }
}
