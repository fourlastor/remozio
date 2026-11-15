import Foundation
import Synchronization

/// Retains actual pairing endpoints through their operation and reply cleanup. Captures grant no idle proof.
final class AuthorityMaintenancePairingOwners: Sendable {
    let admission: AuthorityMaintenancePairingAdmission
    private let endpoints = Mutex<[UUID: AuthorityPairingXPCEndpoint]>([:])
    init(admission: AuthorityMaintenancePairingAdmission) { self.admission = admission }
    func retain(_ endpoint: AuthorityPairingXPCEndpoint, id: UUID) throws {
        try endpoint.requireMaintenanceAdmission(admission)
        endpoints.withLock {
            $0 = $0.filter { $0.value.retainedMaintenancePairingWork() != nil }; $0[id] = endpoint
        }
    }
    func capture() throws -> AuthorityMaintenancePairingWork {
        let values = endpoints.withLock { state in
            var values: [AuthorityMaintenancePairingWork] = []
            state = state.filter { if let value = $0.value.retainedMaintenancePairingWork() { values.append(value); return true }; return false }
            return values
        }
        return try .init(ready: values.allSatisfy { $0.ready }, stagedAttempts: admission.stagedReservations(),
            activityOwners: values.reduce(0) { $0 + $1.activityOwners }, operationActive: values.contains { $0.operationActive })
    }
}
