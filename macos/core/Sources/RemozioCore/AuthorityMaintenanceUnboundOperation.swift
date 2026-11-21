import Darwin
import Foundation

/// Unbound commands retain the actual account, command owner and local hold.
final class AuthorityMaintenanceUnboundOperation: Sendable {
    private let admission: AuthorityMaintenancePairingAdmission
    private let commands: AuthorityMaintenanceCommandExclusion
    private let hold: AuthorityMaintenanceAdmissionHold, boundary: UpdateAdmissionBoundary
    private let accountID: Data
    private let gateIdentity: PreparationFileIdentity
    private let read: @Sendable (AuthorityMaintenanceUnboundRequest, Data) throws -> RuntimeMaintenanceWindowRecord
    private let requireLive: @Sendable () throws -> Void
    private let processID = getpid(), ownerUID = getuid()

    /// Root contexts capture their capabilities from the installed service. Only Owned contexts accept a test hook.
    struct Context: Sendable {
        let commands: AuthorityMaintenanceCommandExclusion
        private let admission: AuthorityMaintenancePairingAdmission
        private let verify: @Sendable (AuthorityMaintenanceUnboundRequest) throws -> Void
        private let beforeOpen: @Sendable () throws -> Void
        private let make: @Sendable (AuthorityMaintenanceCommandExclusion.Command) throws -> AuthorityMaintenanceUnboundOperation
        private let readBusy: @Sendable (AuthorityMaintenanceUnboundRequest) throws -> AuthorityMaintenanceUnboundGateResponse
        fileprivate init(admission: AuthorityMaintenancePairingAdmission, commands: AuthorityMaintenanceCommandExclusion,
            verify: @escaping @Sendable (AuthorityMaintenanceUnboundRequest) throws -> Void,
            make: @escaping @Sendable (AuthorityMaintenanceCommandExclusion.Command) throws -> AuthorityMaintenanceUnboundOperation,
            readBusy: @escaping @Sendable (AuthorityMaintenanceUnboundRequest) throws -> AuthorityMaintenanceUnboundGateResponse,
            beforeOpen: @escaping @Sendable () throws -> Void = {}) {
            self.admission = admission; self.commands = commands; self.verify = verify; self.make = make; self.readBusy = readBusy
            self.beforeOpen = beforeOpen
        }
        func requireAdmission(_ expected: AuthorityMaintenancePairingAdmission) throws {
            guard admission === expected else { throw RuntimePreparationError.changedScope }
        }
        func requireCurrent(_ request: AuthorityMaintenanceUnboundRequest) throws { try verify(request) }
        func prepareOperation(command: AuthorityMaintenanceCommandExclusion.Command) throws {
            try command.requireOwner(commands); try beforeOpen(); try command.requireOwner(commands)
        }
        func operation(command: AuthorityMaintenanceCommandExclusion.Command) throws -> AuthorityMaintenanceUnboundOperation {
            try command.requireOwner(commands); let result = try make(command); try command.requireOwner(commands); return result
        }
        func busyGate(_ request: AuthorityMaintenanceUnboundRequest) throws -> AuthorityMaintenanceUnboundGateResponse {
            try verify(request); let result = try readBusy(request); try verify(request); return result
        }
    }

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
        let context = try await captureNativeContext(service: service, registration: registration)
        let command = try context.commands.acquire(); defer { command.close() }
        return try context.operation(command: command)
    }
    /// Capture actor state before taking command ownership. Every operation checks that live scope again.
    static func captureNativeContext(service: AuthorityWakeService,
        registration: InstalledAuthorityCommandRegistration) async throws -> Context {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let (admission, _) = try await service.nativeMaintenanceScope()
        try service.validateNativeMaintenanceIdentity()
        let account = try registration.captureMaintenanceAccount()
        let startup = registration.admissionStartup, hold = startup?.maintenanceHold
        let gate = startup?.registration.accounts.first(where: { $0.accountID == account.accountID })?.identity
        let installationID = registration.configuration.installationID
        let verify: @Sendable (AuthorityMaintenanceUnboundRequest) throws -> Void = { request in
            try service.validateNativeMaintenanceIdentity()
            guard let gate, request.accountID == account.accountID, request.installationID == installationID,
                  request.gate == gate,
                  try admission.liveUnboundIncarnation(accountID: account.accountID) == request.authorityIncarnation else {
                throw RuntimePreparationError.changedScope
            }
            try service.validateNativeMaintenanceIdentity()
        }
        return .init(admission: admission, commands: registration.maintenanceCommands, verify: verify, make: { command in
            try command.requireOwner(registration.maintenanceCommands)
            try service.validateNativeMaintenanceIdentity()
            let current = try registration.captureMaintenanceAccount()
            guard current.accountID == account.accountID, let startup, let hold, let gate else {
                throw RuntimePreparationError.changedScope
            }
            let result = try AuthorityMaintenanceUnboundOperation(admission: admission, commands: registration.maintenanceCommands,
                hold: hold, boundary: startup.boundary, accountID: current.accountID, gateIdentity: gate,
                read: { request, incarnation in
                    try service.validateNativeMaintenanceIdentity()
                    let row = try registration.captureUnboundMaintenanceRecord(request, account: current, incarnation: incarnation)
                    try service.validateNativeMaintenanceIdentity(); return row
                }, requireLive: { try service.validateNativeMaintenanceIdentity() })
            try command.validate(); try service.validateNativeMaintenanceIdentity(); return result
        }, readBusy: { request in
            guard let hold else { throw RuntimePreparationError.changedScope }
            return try AuthorityMaintenanceUnboundOperation.busyResponse(request, hold: hold)
        })
    }
    func contextOwned(installationID: Data,
        beforeOpen: @escaping @Sendable () throws -> Void = {}) throws -> Context {
        try RuntimeMaintenanceOwnedControl.require()
        guard installationID.count == 16 else { throw RuntimePreparationError.invalidRecord }
        return .init(admission: admission, commands: commands, verify: { request in
            try RuntimeMaintenanceOwnedControl.require()
            guard request.installationID == installationID else { throw RuntimePreparationError.changedScope }
            _ = try self.currentIncarnation(request)
        }, make: { command in
            try RuntimeMaintenanceOwnedControl.require(); try command.requireOwner(self.commands)
            return self
        }, readBusy: { try self.observeBusyGate($0) }, beforeOpen: {
            try RuntimeMaintenanceOwnedControl.require(); try beforeOpen()
        })
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
        return try release(request, command: command)
    }
    func release(_ request: AuthorityMaintenanceUnboundRequest,
        command: AuthorityMaintenanceCommandExclusion.Command) throws -> AuthorityMaintenanceUnboundReleaseResponse {
        guard request.kind == .release else { throw RuntimePreparationError.invalidRecord }
        try command.requireOwner(commands)
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
        let command: AuthorityMaintenanceCommandExclusion.Command
        do { command = try commands.acquire() }
        catch AuthorityMaintenanceCommandExclusion.AcquisitionError.busy { return try observeBusyGate(request) }
        defer { command.close() }
        return try observeGate(request, command: command)
    }
    func observeGate(_ request: AuthorityMaintenanceUnboundRequest,
        command: AuthorityMaintenanceCommandExclusion.Command) throws -> AuthorityMaintenanceUnboundGateResponse {
        guard request.kind == .gate else { throw RuntimePreparationError.invalidRecord }
        try command.requireOwner(commands)
        let actual = try currentIncarnation(request)
        let response = try AuthorityMaintenanceGateObservation.captureUnbound(request: request, incarnation: actual,
            hold: hold, boundary: boundary, gateIdentity: gateIdentity, read: { try self.read(request, actual) })
        try command.validate(); _ = try currentIncarnation(request)
        return response
    }
    func observeBusyGate(_ request: AuthorityMaintenanceUnboundRequest) throws -> AuthorityMaintenanceUnboundGateResponse {
        guard request.kind == .gate else { throw RuntimePreparationError.invalidRecord }
        _ = try currentIncarnation(request)
        let result = try Self.busyResponse(request, hold: hold)
        _ = try currentIncarnation(request); return result
    }
    private static func busyResponse(_ request: AuthorityMaintenanceUnboundRequest,
        hold: AuthorityMaintenanceAdmissionHold) throws -> AuthorityMaintenanceUnboundGateResponse {
        guard request.kind == .gate else { throw RuntimePreparationError.invalidRecord }
        let observed: AuthorityMaintenanceUnboundGateResponse.Hold
        switch try hold.gateHold(attemptID: request.attemptID) {
        case .held: observed = .held
        case .released: observed = .released
        case .unknown: observed = .unknown
        }
        return try .init(request: request, hold: observed, admission: .busy)
    }
}
