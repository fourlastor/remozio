import Darwin
import Foundation
import Security

/// Existing administrator rights bound to the authenticated invocation. No external form is retained or persisted.
final class SetupAuditUpgradeAuthorization: @unchecked Sendable, CustomStringConvertible, CustomReflectable {
    let callerUID: uid_t
    private let processOwner: uid_t
    private let processID = getpid()
    private let lock = NSLock()
    private let verifyRights: () throws -> Void
    private let cancellation: SetupAuditUpgradeCancellation
    var cancellationToken: SetupAuditUpgradeCancellation { cancellation }
    private let closeRights: () -> Void
    private var closed = false
    var description: String { "SetupAuditUpgradeAuthorization(redacted)" }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }

    /// Call on the exported invocation before dispatching work. The endpoint must also bind cancellation to its connection.
    static func open(externalForm: Data, invocation: XPCInvocationGuard,
                     cancellation: SetupAuditUpgradeCancellation = .init()) throws -> SetupAuditUpgradeAuthorization {
        guard getuid() == 0, geteuid() == 0 else { throw SetupAdministratorAuthorizationError.wrongProcess }
        let peer = try invocation.verifyInvocation()
        guard peer.userID > 0, peer.userID < UInt32.max else { throw SetupAdministratorAuthorizationError.wrongProcess }
        let reference = try SetupAdministratorNative.importCurrentRights(externalForm: externalForm)
        let value = SetupAuditUpgradeAuthorization(callerUID: peer.userID, processOwner: 0, cancellation: cancellation, verifyRights: {
            try SetupAdministratorNative.validatePolicy()
            try SetupAdministratorNative.copyRights(reference, flags: [])
            try SetupAdministratorNative.validatePolicy()
        }, closeRights: { _ = AuthorizationFree(reference, []) })
        do { try value.validate(); return value } catch { value.close(); throw error }
    }
    // Ordinary-owner lifecycle controls cannot import native Root rights or grant admission to a native factory.
    static func openOwned(callerUID: uid_t = getuid(), cancellation: SetupAuditUpgradeCancellation = .init(), verifyRights: @escaping () throws -> Void,
                          closeRights: @escaping () -> Void = {}) throws -> SetupAuditUpgradeAuthorization {
        guard getuid() > 0, getuid() == geteuid(), callerUID > 0, callerUID < UInt32.max else {
            throw SetupAdministratorAuthorizationError.wrongProcess
        }
        let value = SetupAuditUpgradeAuthorization(callerUID: callerUID, processOwner: getuid(), cancellation: cancellation,
            verifyRights: verifyRights, closeRights: closeRights)
        do { try value.validate(); return value } catch { value.close(); throw error }
    }
    private init(callerUID: uid_t, processOwner: uid_t, cancellation: SetupAuditUpgradeCancellation, verifyRights: @escaping () throws -> Void, closeRights: @escaping () -> Void) {
        self.callerUID = callerUID; self.processOwner = processOwner; self.cancellation = cancellation
        self.verifyRights = verifyRights; self.closeRights = closeRights
    }
    func validate() throws {
        guard getpid() == processID else { throw SetupAdministratorAuthorizationError.wrongProcess }
        try lock.withLock {
            guard !closed, getuid() == processOwner, geteuid() == processOwner else { throw SetupAdministratorAuthorizationError.closed }
            try cancellation.check(); try verifyRights(); try cancellation.check()
        }
    }
    func close() {
        guard getpid() == processID else { return }
        lock.withLock { guard !closed else { return }; closed = true; closeRights() }
    }
    deinit { close() }
}
