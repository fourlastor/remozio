import Foundation

/// The probe has the effects of ordinary admission. It does not release the local hold.
/// The native caller supplies exact protected reads after closing each capture handle.
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
    /// Both protected reads close before returning. No store or hold lock crosses the ordinary admission probe.
    static func captureUnbound(request: AuthorityMaintenanceUnboundRequest, incarnation: Data,
        hold: AuthorityMaintenanceAdmissionHold,
        boundary: UpdateAdmissionBoundary, gateIdentity: PreparationFileIdentity,
        read: () throws -> RuntimeMaintenanceWindowRecord) throws -> AuthorityMaintenanceUnboundGateResponse {
        guard request.kind == .gate, request.authorityIncarnation == incarnation else {
            throw RuntimePreparationError.changedScope
        }
        let before = try read()
        try request.requireWindow(before, gateIdentity: gateIdentity)
        let held = try hold.unboundObservation(before, incarnation: incarnation)
        var token: UpdateAdmissionLease?
        let admission: RuntimeMaintenanceWindowRecord.GateReadback.Admission
        do { token = try boundary.acquireAdmission(); try token?.validate(); admission = .available }
        catch UpdateAdmissionBarrierError.busy { admission = .busy }
        catch { admission = .unavailable }
        defer { token?.close() }
        guard try read() == before,
              try hold.unboundObservation(before, incarnation: incarnation) == held else {
            throw RuntimePreparationError.changedScope
        }
        try token?.validate()
        return try .init(request: request, hold: held, admission: admission)
    }

}
