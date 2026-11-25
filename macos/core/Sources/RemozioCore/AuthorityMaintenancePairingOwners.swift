import Foundation
import Synchronization

/// Retains actual pairing endpoints through their operation and reply cleanup. Captures grant no idle proof.
final class AuthorityMaintenancePairingOwners: Sendable {
    let admission: AuthorityMaintenancePairingAdmission
    private let endpoints = Mutex<[UUID: AuthorityPairingXPCEndpoint]>([:])
    private let rendezvous = Mutex<[Data: AuthorityPairingRendezvous]>([:])

    func register(_ pending: AuthorityPairingRendezvous) {
        rendezvous.withLock { $0[pending.id] = pending }
    }

    func retire(_ pending: AuthorityPairingRendezvous) {
        pending.retire()
        rendezvous.withLock { _ = $0.removeValue(forKey: pending.id) }
    }

    func lookupRendezvous(_ id: Data) -> AuthorityPairingRendezvous? {
        rendezvous.withLock { $0[id] }
    }
    init(admission: AuthorityMaintenancePairingAdmission) { self.admission = admission }
    func retain(_ endpoint: AuthorityPairingXPCEndpoint, id: UUID) throws {
        try endpoint.requireMaintenanceAdmission(admission)
        endpoints.withLock {
            $0 = $0.filter { $0.value.retainedMaintenancePairingWork() != nil }; $0[id] = endpoint
        }
    }
    func proofReservations(windowID: Data, link: AuthorityPairingProofLink) throws -> AuthorityPairingProofReservations {
        guard windowID.count == 16 else { throw AuthorityPairingSetupError.wrongScope }
        let candidates = endpoints.withLock { Array($0.values) }.filter { $0.ownsProofWindow(windowID) }
        guard candidates.count == 1, let endpoint = candidates.first else {
            throw AuthorityPairingSetupError.unavailable
        }
        return try endpoint.proofReservations(windowID: windowID, link: link)
    }

    func capture() throws -> AuthorityMaintenancePairingWork {
        let values = endpoints.withLock { state in
            var values: [AuthorityMaintenancePairingWork] = []
            state = state.filter { if let value = $0.value.retainedMaintenancePairingWork() { values.append(value); return true }; return false }
            return values
        }
        // With no endpoints, ready is vacuously true. Idle decisions require the counts and actual arm outcome.
        return try .init(ready: values.allSatisfy { $0.ready }, stagedAttempts: admission.stagedReservations(),
            activityOwners: values.reduce(0) { $0 + $1.activityOwners }, operationActive: values.contains { $0.operationActive })
    }
}
