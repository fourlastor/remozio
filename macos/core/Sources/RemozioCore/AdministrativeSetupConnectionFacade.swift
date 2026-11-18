import Darwin
import Foundation

/// The normal lane behind the facade: the unchanged endpoint, or a recording fixture.
protocol SetupNormalEndpoint: AnyObject, AdministrativeSetupMaintenanceXPCProtocol { func close() }
extension AdministrativeSetupXPCEndpoint: SetupNormalEndpoint {}

/// Exported object for one accepted Setup connection. It holds no mutation capability until a normal hello builds the
/// unchanged endpoint. Status first makes the connection status-only for its lifetime; status never reaches the owner lock.
final class AdministrativeSetupConnectionFacade: NSObject, AdministrativeSetupServiceXPCProtocol, @unchecked Sendable {
    enum State: Equatable { case undecided, statusOnly, openingNormal, normal, closed }
    private let lock = NSLock()
    private let verify: () throws -> XPCPeerCredentials
    private let select: (SetupConnectionSlots.Mode) -> Bool
    private let openNormal: (_ close: @escaping @Sendable () -> Void) throws -> any SetupNormalEndpoint
    private let normalAllowed: () -> Bool
    private let status: (XPCPeerCredentials) -> SetupRetainedInvocationStatus
    private let check: () -> SetupAccountOwner.StatusLaneCheck
    private let touch: () -> Void
    private let invalidate: () -> Void
    private var current = State.undecided
    private var endpoint: (any SetupNormalEndpoint)?
    private var statusInFlight = false
    private let now: () -> UInt64
    private var lastCheck: UInt64?
    /// Nanoseconds between store-backed installation checks on one status connection.
    static let checkInterval: UInt64 = 5_000_000_000

    /// Fixtures inject every capability. The native listener passes the accepted invocation guard, its slot and the shared owner.
    init(verify: @escaping () throws -> XPCPeerCredentials, select: @escaping (SetupConnectionSlots.Mode) -> Bool,
         openNormal: @escaping (_ close: @escaping @Sendable () -> Void) throws -> any SetupNormalEndpoint,
         status: @escaping (XPCPeerCredentials) -> SetupRetainedInvocationStatus,
         check: @escaping () -> SetupAccountOwner.StatusLaneCheck = { .verified }, touch: @escaping () -> Void = {},
         now: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }, normalAllowed: @escaping () -> Bool = { true },
         invalidate: @escaping () -> Void) {
        self.verify = verify; self.select = select; self.openNormal = openNormal; self.status = status
        self.check = check; self.touch = touch; self.now = now; self.normalAllowed = normalAllowed; self.invalidate = invalidate
    }
    /// Runs the owner check when none ran on this connection or the last one is older than `checkInterval`.
    /// Only drift or closure refuses; a busy owner or a held admission reuses no store result and is retried next time.
    private func checkInstallation() -> Bool {
        let time = now()
        let due = lock.withLock { lastCheck.map { time &- $0 >= Self.checkInterval } ?? true }
        guard due else { return true }
        switch check() {
        case .refused: return false
        case .verified: lock.withLock { lastCheck = time }; return true
        case .pinned, .busy: return true
        }
    }
    var state: State { lock.withLock { current } }

    func close() {
        let closing = lock.withLock { () -> (Bool, (any SetupNormalEndpoint)?) in
            guard current != .closed else { return (false, nil) }
            current = .closed
            defer { endpoint = nil }
            return (true, endpoint)
        }
        guard closing.0 else { return }
        closing.1?.close()
        invalidate()
    }

    // MARK: Status lane

    /// Status calls never close a normal connection: the call alone is refused, and in-flight normal work continues.
    /// Every other refusal replies nil and closes the connection, like the rest of this interface.
    func retainedInvocationStatus(_ request: Data, reply: @escaping @Sendable (Data?) -> Void) {
        // The exported call stack proves the peer before any owner access.
        guard let peer = try? verify() else { close(); reply(nil); return }
        let state = lock.withLock { current }
        if state == .normal || state == .openingNormal { reply(nil); return }
        guard state == .undecided || state == .statusOnly, request.count <= SetupRetainedStatusWire.maximumRequestBytes else {
            close(); reply(nil); return
        }
        // Installation and configuration drift are checked when status is selected, then at most every
        // `checkInterval` on this connection, so repeated status calls cannot keep mutations waiting on the owner lock.
        guard checkInstallation() else { close(); reply(nil); return }
        let admitted = lock.withLock { () -> Bool in
            guard !statusInFlight else { return false }
            switch current {
            case .undecided:
                guard select(.statusOnly) else { return false }
                current = .statusOnly
            case .statusOnly: break
            case .openingNormal, .normal, .closed: return false
            }
            statusInFlight = true
            return true
        }
        guard admitted else { close(); reply(nil); return }
        touch()
        defer { lock.withLock { statusInFlight = false }; touch() }
        do {
            let decoded = try SetupRetainedStatusWire.Request.decode(request)
            // Every check result answers with the in-memory projection only; nothing store-derived is reported.
            let bytes = try SetupRetainedStatusWire.reply(decoded, status(peer))
            // Recheck the same peer and connection lifetime before the reply leaves.
            guard (try? verify()) == peer, lock.withLock({ current == .statusOnly }) else { close(); reply(nil); return }
            reply(bytes)
        } catch { close(); reply(nil) }
    }

    // MARK: Normal routing

    /// A supported hello on an undecided connection is the only path that builds the mutation endpoint.
    private func hello(_ forward: (any SetupNormalEndpoint) -> Void, refuse: () -> Void) {
        // Prove the peer on the exported call stack before the owner is touched. The endpoint checks again per call.
        guard (try? verify()) != nil, normalAllowed() else { close(); refuse(); return }
        let decision = lock.withLock { () -> (open: Bool, existing: (any SetupNormalEndpoint)?) in
            switch current {
            case .undecided:
                guard select(.normal) else { return (false, nil) }
                current = .openingNormal
                return (true, nil)
            case .normal: return (false, endpoint)
            case .statusOnly, .openingNormal, .closed: return (false, nil)
            }
        }
        if let existing = decision.existing { forward(existing); return }
        guard decision.open else { close(); refuse(); return }
        let opened: any SetupNormalEndpoint
        do { opened = try openNormal({ [weak self] in self?.close() }) } catch { close(); refuse(); return }
        let installed = lock.withLock { () -> Bool in
            guard current == .openingNormal, normalAllowed() else { return false }
            current = .normal; endpoint = opened
            return true
        }
        guard installed else { opened.close(); close(); refuse(); return }
        forward(opened)
    }
    /// Every other normal selector requires the endpoint that only a successful normal hello can create.
    private func normal(_ forward: (any SetupNormalEndpoint) -> Void, refuse: () -> Void) {
        guard normalAllowed() else { close(); refuse(); return }
        let value = lock.withLock { current == .normal ? endpoint : nil }
        guard let value else { close(); refuse(); return }
        forward(value)
    }

    func auditUpgradeHello(reply: @escaping @Sendable (UInt64) -> Void) {
        hello({ $0.auditUpgradeHello(reply: reply) }, refuse: { reply(0) })
    }
    func auditUpgradeProgress(reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.auditUpgradeProgress(reply: reply) }, refuse: { reply(nil) })
    }
    func performAuditUpgrade(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.performAuditUpgrade(expected, authorization: authorization, reply: reply) }, refuse: { reply(nil) })
    }
    func portableImportRecoveryHello(reply: @escaping @Sendable (UInt64) -> Void) {
        hello({ $0.portableImportRecoveryHello(reply: reply) }, refuse: { reply(0) })
    }
    func portableImportRecovery(reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.portableImportRecovery(reply: reply) }, refuse: { reply(nil) })
    }
    func portableImportHello(reply: @escaping @Sendable (UInt64) -> Void) {
        hello({ $0.portableImportHello(reply: reply) }, refuse: { reply(0) })
    }
    func portableImportProgress(reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.portableImportProgress(reply: reply) }, refuse: { reply(nil) })
    }
    func performPortableImport(_ request: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.performPortableImport(request, authorization: authorization, reply: reply) }, refuse: { reply(nil) })
    }
    func gatewaySettingsHello(reply: @escaping @Sendable (UInt64) -> Void) {
        hello({ $0.gatewaySettingsHello(reply: reply) }, refuse: { reply(0) })
    }
    func gatewaySettingsProgress(reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.gatewaySettingsProgress(reply: reply) }, refuse: { reply(nil) })
    }
    func retainGatewaySettings(_ expected: Data, selection: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.retainGatewaySettings(expected, selection: selection, authorization: authorization, reply: reply) }, refuse: { reply(nil) })
    }
    func resumeGatewaySettings(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.resumeGatewaySettings(expected, authorization: authorization, reply: reply) }, refuse: { reply(nil) })
    }
    func gatewayActivationHello(reply: @escaping @Sendable (UInt64) -> Void) {
        hello({ $0.gatewayActivationHello(reply: reply) }, refuse: { reply(0) })
    }
    func gatewayActivationProgress(reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.gatewayActivationProgress(reply: reply) }, refuse: { reply(nil) })
    }
    func activateGateway(_ expected: Data, settings: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.activateGateway(expected, settings: settings, authorization: authorization, reply: reply) }, refuse: { reply(nil) })
    }
    func gatewayHello(reply: @escaping @Sendable (UInt64) -> Void) {
        hello({ $0.gatewayHello(reply: reply) }, refuse: { reply(0) })
    }
    func gatewayProgress(reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.gatewayProgress(reply: reply) }, refuse: { reply(nil) })
    }
    func prepareGateway(_ expected: Data, choices: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.prepareGateway(expected, choices: choices, authorization: authorization, reply: reply) }, refuse: { reply(nil) })
    }
    func resumeGatewayJournal(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.resumeGatewayJournal(expected, authorization: authorization, reply: reply) }, refuse: { reply(nil) })
    }
    func activationHello(reply: @escaping @Sendable (UInt64) -> Void) {
        hello({ $0.activationHello(reply: reply) }, refuse: { reply(0) })
    }
    func activationProgress(reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.activationProgress(reply: reply) }, refuse: { reply(nil) })
    }
    func activateRuntime(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.activateRuntime(expected, authorization: authorization, reply: reply) }, refuse: { reply(nil) })
    }
    func runtimeHello(reply: @escaping @Sendable (UInt64) -> Void) {
        hello({ $0.runtimeHello(reply: reply) }, refuse: { reply(0) })
    }
    func runtimeProgress(reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.runtimeProgress(reply: reply) }, refuse: { reply(nil) })
    }
    func prepareRuntime(_ expected: Data, fileCustodyAccepted: Bool, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.prepareRuntime(expected, fileCustodyAccepted: fileCustodyAccepted, authorization: authorization, reply: reply) },
            refuse: { reply(nil) })
    }
    func hello(reply: @escaping @Sendable (UInt64) -> Void) {
        hello({ $0.hello(reply: reply) }, refuse: { reply(0) })
    }
    func serviceAccountsHello(reply: @escaping @Sendable (UInt64) -> Void) {
        hello({ $0.serviceAccountsHello(reply: reply) }, refuse: { reply(0) })
    }
    func serviceAccountsProgress(reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.serviceAccountsProgress(reply: reply) }, refuse: { reply(nil) })
    }
    func prepareServiceAccounts(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.prepareServiceAccounts(expected, authorization: authorization, reply: reply) }, refuse: { reply(nil) })
    }
    func enrollmentHello(reply: @escaping @Sendable (UInt64) -> Void) {
        hello({ $0.enrollmentHello(reply: reply) }, refuse: { reply(0) })
    }
    func accountEnrollmentProgress(reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.accountEnrollmentProgress(reply: reply) }, refuse: { reply(nil) })
    }
    func beginAccountEnrollment(_ request: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.beginAccountEnrollment(request, authorization: authorization, reply: reply) }, refuse: { reply(nil) })
    }
    func resumeAccountEnrollment(_ setupID: Data, expectedRevision: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.resumeAccountEnrollment(setupID, expectedRevision: expectedRevision, authorization: authorization, reply: reply) },
            refuse: { reply(nil) })
    }
    func accountStorageProgress(_ accountID: Data, reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.accountStorageProgress(accountID, reply: reply) }, refuse: { reply(nil) })
    }
    func resumeAccountStorage(_ accountID: Data, setupID: Data, expectedRevision: Data, authorization: Data,
                              reply: @escaping @Sendable (Data?) -> Void) {
        normal({ $0.resumeAccountStorage(accountID, setupID: setupID, expectedRevision: expectedRevision, authorization: authorization, reply: reply) },
            refuse: { reply(nil) })
    }
}
