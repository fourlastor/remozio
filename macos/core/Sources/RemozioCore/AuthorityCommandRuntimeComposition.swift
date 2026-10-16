import Darwin
import Foundation
import RemozioProtocol

extension AuthorityWakeService {
    /// Compose command admission with the same request journal, clock, presence and wake owner.
    /// The installer must independently validate the registration before supplying a receive right.
    public static func open(configuration: AuthorityCommandStartupConfiguration,
        takingRegisteredReceiveRight: @escaping @Sendable () throws -> mach_port_t,
        releaseActivity: ReleaseActivityBarrier? = nil,
        reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
        onAdmission: @escaping @Sendable (Result<IssuedRequestPayload, any Error>) -> Void = { _ in },
        reportReceiver: @escaping @Sendable (AuthorityCommandReceiveWorker.Status) -> Void = { _ in },
        onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in },
        reportExecution: @escaping @Sendable (AuthorityCommandAuthorizationNotice, Result<Void, any Error>) -> Void = { _, _ in }) throws -> AuthorityWakeService {
        let factory = try configuration.receiverFactory(takingRegisteredReceiveRight: takingRegisteredReceiveRight,
            onAdmission: onAdmission, report: reportReceiver)
        let executionFactory = try configuration.executionFactory(report: reportExecution)
        return try open(configuration: configuration.presence, reconcileExpired: reconcileExpired,
            commandReceiverFactory: { journal, clock in
                if let releaseActivity { try journal.attachReleaseActivityBarrier(releaseActivity) }
                return try factory(journal, clock)
            }, commandExecutionFactory: executionFactory, onCommandAuthorized: onCommandAuthorized)
    }
}

extension AuthorityRuntimeRunner {
    /// Each startup attempt reloads protected inputs. Recovery never falls back to a request-only service.
    public init(commandConfigurationPath: String,
        takingRegisteredReceiveRight: @escaping @Sendable () throws -> mach_port_t,
        initialRetryMilliseconds: Int = 1000, maximumRetryMilliseconds: Int = 30_000,
        monitorMilliseconds: Int = 250,
        onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in },
        report: @escaping @Sendable (Status) -> Void) throws {
        try self.init(initialRetryMilliseconds: initialRetryMilliseconds,
            maximumRetryMilliseconds: maximumRetryMilliseconds, monitorMilliseconds: monitorMilliseconds, open: {
                let configuration = try AuthorityCommandStartupConfiguration.load(path: commandConfigurationPath)
                let service = try AuthorityWakeService.open(configuration: configuration,
                    takingRegisteredReceiveRight: takingRegisteredReceiveRight,
                    reconcileExpired: Self.reconcileCoordinatorExpiration, onCommandAuthorized: onCommandAuthorized)
                return AuthorityRuntimeInstance(start: { try await service.start() }, close: { try await service.close() },
                    retired: { await service.isRetired })
            }, report: report)
    }
}
