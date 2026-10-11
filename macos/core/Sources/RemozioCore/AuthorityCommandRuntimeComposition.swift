import Darwin
import Foundation
import RemozioProtocol

extension AuthorityWakeService {
    /// Compose command admission with the same request journal, clock, presence and wake owner.
    /// The installer must independently validate the registration before supplying a receive right.
    public static func open(configuration: AuthorityCommandStartupConfiguration,
        takingRegisteredReceiveRight: @escaping @Sendable () throws -> mach_port_t,
        reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
        onAdmission: @escaping @Sendable (Result<IssuedRequestPayload, any Error>) -> Void = { _ in },
        reportReceiver: @escaping @Sendable (AuthorityCommandReceiveWorker.Status) -> Void = { _ in }) throws -> AuthorityWakeService {
        let factory = try configuration.receiverFactory(takingRegisteredReceiveRight: takingRegisteredReceiveRight,
            onAdmission: onAdmission, report: reportReceiver)
        return try open(configuration: configuration.presence, reconcileExpired: reconcileExpired,
            commandReceiverFactory: factory)
    }
}

extension AuthorityRuntimeRunner {
    /// Each startup attempt reloads protected inputs. Recovery never falls back to a request-only service.
    public init(commandConfigurationPath: String,
        takingRegisteredReceiveRight: @escaping @Sendable () throws -> mach_port_t,
        initialRetryMilliseconds: Int = 1000, maximumRetryMilliseconds: Int = 30_000,
        monitorMilliseconds: Int = 250,
        report: @escaping @Sendable (Status) -> Void) throws {
        try self.init(initialRetryMilliseconds: initialRetryMilliseconds,
            maximumRetryMilliseconds: maximumRetryMilliseconds, monitorMilliseconds: monitorMilliseconds, open: {
                let configuration = try AuthorityCommandStartupConfiguration.load(path: commandConfigurationPath)
                let service = try AuthorityWakeService.open(configuration: configuration,
                    takingRegisteredReceiveRight: takingRegisteredReceiveRight,
                    reconcileExpired: Self.reconcileCoordinatorExpiration)
                return AuthorityRuntimeInstance(start: { try await service.start() }, close: { try await service.close() },
                    retired: { await service.isRetired })
            }, report: report)
    }
}
