import Foundation
import OSLog
import Synchronization

/// Root-owned observations for one protected gateway registration. They never grant authority to the gateway.
public final class AuthorityGatewayRevocationState: Sendable {
    private struct State {
        var owner: UUID?
        var capability: (epoch: UUID, deadline: UInt64, supported: Bool)?
        var delivery: [Data: PhoneRevocationStatus] = [:]
        var grantHealth = GatewayRevocationHealth.clear
        var pushEnabled: Bool?
    }

    let registration: GatewayRegistrationIdentity
    private let state = Mutex(State())
    private let logger = Logger(subsystem: "dev.sebastiano.remozio.macos.authority", category: "gateway-revocation")

    init(registration: GatewayRegistrationIdentity) { self.registration = registration }

    func begin(_ owner: UUID, pushEnabled: Bool = true) {
        state.withLock { $0 = State(owner: owner, pushEnabled: pushEnabled) }
    }

    func setPushEnabled(_ enabled: Bool, owner: UUID) {
        state.withLock {
            guard $0.owner == owner else { return }
            $0.pushEnabled = enabled
            if !enabled {
                $0.capability = nil
                $0.grantHealth = .clear
            }
        }
    }

    func recordGrantHealth(_ health: GatewayRevocationHealth, owner: UUID) {
        state.withLock {
            if $0.owner == owner { $0.grantHealth = health }
        }
    }

    func health(_ enrollments: [StoredApprovalEnrollment], now: AuthorityMoment) -> GatewayRevocationHealth {
        state.withLock {
            GatewayRevocationHealth.read(enrollments, availability: Self.availability($0, now: now),
                registration: registration, pushEnabled: $0.pushEnabled, grantHealth: $0.grantHealth,
                hasBlockedRevocation: $0.delivery.values.contains(.gatewayBlocked))
        }
    }

    func publishCapability(_ supported: Bool, now: AuthorityMoment, deadline: UInt64, owner: UUID) {
        state.withLock {
            guard $0.owner == owner, deadline > now.milliseconds else { return }
            $0.capability = (now.epoch, deadline, supported)
        }
    }

    func close(_ owner: UUID) {
        state.withLock {
            guard $0.owner == owner else { return }
            $0 = State(pushEnabled: $0.pushEnabled)
        }
    }

    func availability(now: AuthorityMoment) -> PairedPhoneRevocationAvailability {
        state.withLock { Self.availability($0, now: now) }
    }

    private static func availability(_ state: State, now: AuthorityMoment) -> PairedPhoneRevocationAvailability {
        guard let capability = state.capability, capability.epoch == now.epoch, now.milliseconds < capability.deadline else {
            return .gatewayUnavailable
        }
        return capability.supported ? .available : .gatewayUnsupported
    }

    func deliveryStatus(_ operationID: Data) -> PhoneRevocationStatus {
        state.withLock { $0.delivery[operationID] ?? .gatewayPending }
    }

    func record(_ status: PhoneRevocationStatus, for operationID: Data, owner: UUID) {
        let becameBlocked = state.withLock { state in
            guard state.owner == owner else { return false }
            let prior = state.delivery[operationID]
            guard prior != .gatewayApplied else { return false }
            // At most one observation for each retained enrollment epoch.
            guard state.delivery.count < EnrollmentJournal.maximumRows || prior != nil else { return false }
            state.delivery[operationID] = status
            return prior != .gatewayBlocked && status == .gatewayBlocked
        }
        if becameBlocked { logger.error("Gateway phone revocation delivery is blocked") }
    }
}
