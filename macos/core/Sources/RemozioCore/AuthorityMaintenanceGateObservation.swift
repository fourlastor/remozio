import Foundation

/// Observes existing owners and returns data only. The native caller supplies exact protected reads after closing each capture handle.
enum AuthorityMaintenanceGateObservation {
    static func capture(request: AuthorityMaintenanceGateRequest, incarnation: Data, hold: AuthorityMaintenanceAdmissionHold,
        boundary: UpdateAdmissionBoundary, read: () throws -> RuntimeMaintenanceWindowRecord) throws -> AuthorityMaintenanceGateResponse {
        let before = try read()
        guard before.id == request.attemptID, before.revision == request.revision, before.phase == .reopenPending,
              before.scope.authority.accountID == request.accountID, before.scope.installationID == request.installationID,
              before.shutdownBinding == request.target else { throw RuntimePreparationError.changedScope }
        let held = try hold.gateHold(attemptID: request.attemptID)
        if before.service == .notStopped {
            guard request.target.incarnation == incarnation else { throw RuntimePreparationError.changedScope }
        }
        var token: UpdateAdmissionLease?
        let admission: RuntimeMaintenanceWindowRecord.GateReadback.Admission
        do { token = try boundary.acquireAdmission(); try token?.validate(); admission = .available }
        catch UpdateAdmissionBarrierError.busy { admission = .busy }
        catch { admission = .unavailable }
        defer { token?.close() }
        guard try read() == before, try hold.gateHold(attemptID: request.attemptID) == held else { throw RuntimePreparationError.changedScope }
        try token?.validate()
        return try .init(request: request, authorityIncarnation: incarnation, hold: held, admission: admission)
    }
}
