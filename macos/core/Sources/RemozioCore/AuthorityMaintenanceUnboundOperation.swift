import Darwin
import Foundation

/// Library-only unbound commands. The existing XPC selectors do not dispatch these requests.
final class AuthorityMaintenanceUnboundOperation: Sendable {
    private let admission: AuthorityMaintenancePairingAdmission
    private let commands: AuthorityMaintenanceCommandExclusion
    private let hold: AuthorityMaintenanceAdmissionHold, boundary: UpdateAdmissionBoundary
    private let accountID: Data
    private let gateIdentity: PreparationFileIdentity
    private let read: @Sendable (AuthorityMaintenanceUnboundRequest, Data) throws -> RuntimeMaintenanceWindowRecord
    private let requireLive: @Sendable () throws -> Void
    private let processID = getpid(), ownerUID = getuid()

    private init(admission: AuthorityMaintenancePairingAdmission, commands: AuthorityMaintenanceCommandExclusion,
        hold: AuthorityMaintenanceAdmissionHold, boundary: UpdateAdmissionBoundary, accountID: Data, gateIdentity: PreparationFileIdentity,
        read: @escaping @Sendable (AuthorityMaintenanceUnboundRequest, Data) throws -> RuntimeMaintenanceWindowRecord,
        requireLive: @escaping @Sendable () throws -> Void) throws {
        try admission.requireAccount(accountID)
        try hold.bindUnboundAuthority(admission.liveIncarnation(accountID: accountID))
        self.admission = admission; self.commands = commands; self.hold = hold; self.boundary = boundary
        self.accountID = accountID; self.gateIdentity = gateIdentity; self.read = read; self.requireLive = requireLive
    }
    static func openOwned(admission: AuthorityMaintenancePairingAdmission, commands: AuthorityMaintenanceCommandExclusion,
        hold: AuthorityMaintenanceAdmissionHold, boundary: UpdateAdmissionBoundary, accountID: Data, gateIdentity: PreparationFileIdentity,
        read: @escaping @Sendable (AuthorityMaintenanceUnboundRequest, Data) throws -> RuntimeMaintenanceWindowRecord) throws -> Self {
        try RuntimeMaintenanceOwnedControl.require()
        return try .init(admission: admission, commands: commands, hold: hold, boundary: boundary,
            accountID: accountID, gateIdentity: gateIdentity, read: read, requireLive: { try RuntimeMaintenanceOwnedControl.require() })
    }
    static func openNative(service: AuthorityWakeService,
        registration: InstalledAuthorityCommandRegistration) async throws -> AuthorityMaintenanceUnboundOperation {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let (admission, _) = try await service.nativeMaintenanceScope()
        let command = try registration.maintenanceCommands.acquire(); defer { command.close() }
        try service.validateNativeMaintenanceIdentity()
        let account = try registration.captureMaintenanceAccount()
        guard let startup = registration.admissionStartup, let hold = startup.maintenanceHold,
              let gate = startup.registration.accounts.first(where: { $0.accountID == account.accountID }) else {
            throw RuntimePreparationError.changedScope
        }
        let result = try AuthorityMaintenanceUnboundOperation(admission: admission, commands: registration.maintenanceCommands,
            hold: hold, boundary: startup.boundary, accountID: account.accountID, gateIdentity: gate.identity,
            read: { request, incarnation in
                try service.validateNativeMaintenanceIdentity()
                let row = try registration.captureUnboundMaintenanceRecord(request, account: account, incarnation: incarnation)
                try service.validateNativeMaintenanceIdentity(); return row
            }, requireLive: { try service.validateNativeMaintenanceIdentity() })
        try command.validate(); return result
    }
    private func currentIncarnation(_ request: AuthorityMaintenanceUnboundRequest) throws -> Data {
        guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID,
              request.accountID == accountID, request.gate == gateIdentity else { throw RuntimePreparationError.changedScope }
        try requireLive()
        // The request is compared with the actual admission owner before any protected read or hold effect.
        let actual = try admission.liveUnboundIncarnation(accountID: accountID)
        guard request.authorityIncarnation == actual else { throw RuntimePreparationError.changedScope }
        try requireLive(); return actual
    }
    func release(_ request: AuthorityMaintenanceUnboundRequest) throws -> AuthorityMaintenanceUnboundReleaseResponse {
        guard request.kind == .release else { throw RuntimePreparationError.invalidRecord }
        let command: AuthorityMaintenanceCommandExclusion.Command
        do { command = try commands.acquire() }
        catch AuthorityMaintenanceCommandExclusion.AcquisitionError.busy {
            do { _ = try admission.liveUnboundIncarnation(accountID: accountID) }
            catch AuthorityMaintenancePairingAdmission.UnboundCommandError.stopping { return try .init(request: request, outcome: .refused) }
            return try .init(request: request, outcome: .busy)
        }
        catch AuthorityMaintenanceCommandExclusion.AcquisitionError.stopping { return try .init(request: request, outcome: .refused) }
        defer { command.close() }
        let actual: Data
        do { actual = try currentIncarnation(request) }
        catch AuthorityMaintenancePairingAdmission.UnboundCommandError.stopping { return try .init(request: request, outcome: .refused) }
        let before = try read(request, actual)
        try request.requireWindow(before, gateIdentity: gateIdentity)
        let outcome: AuthorityMaintenanceUnboundReleaseResponse.Outcome
        do { outcome = try hold.releaseUnbound(before, incarnation: actual, pairing: admission) }
        catch AuthorityMaintenancePairingAdmission.UnboundCommandError.busy { return try .init(request: request, outcome: .busy) }
        catch AuthorityMaintenancePairingAdmission.UnboundCommandError.stopping { return try .init(request: request, outcome: .refused) }
        guard try read(request, actual) == before else { throw RuntimePreparationError.changedScope }
        try command.validate(); _ = try currentIncarnation(request)
        return try .init(request: request, outcome: outcome)
    }
    func observeGate(_ request: AuthorityMaintenanceUnboundRequest) throws -> AuthorityMaintenanceUnboundGateResponse {
        guard request.kind == .gate else { throw RuntimePreparationError.invalidRecord }
        let command = try commands.acquire(); defer { command.close() }
        let actual = try currentIncarnation(request)
        let response = try AuthorityMaintenanceGateObservation.captureUnbound(request: request, incarnation: actual,
            hold: hold, boundary: boundary, gateIdentity: gateIdentity, read: { try self.read(request, actual) })
        try command.validate(); _ = try currentIncarnation(request)
        return response
    }
}
