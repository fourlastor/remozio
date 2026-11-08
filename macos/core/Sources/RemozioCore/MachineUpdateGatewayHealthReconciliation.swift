import Foundation

/// Root supplies the current protected requirement and registration. Run this check inside its paired health journal read.
enum MachineUpdateGatewayHealthReconciliation {
    static func requireCurrent(_ proof: MachineUpdateConsumerHealthProof,
        expected: MachineUpdateRestartHealthPlan.Requirement, registration: GatewayRegistrationIdentity,
        transaction: JournalTransaction) throws {
        guard expected.role == .notificationGateway, proof.role.requirement == expected,
              let verified = proof.gatewayHead, verified.evidence.registration == registration,
              registration.macID == expected.binding.macID, registration.accountID == expected.binding.accountID else {
            throw MachineUpdateRoleChallengeError.changedScope
        }
        let local = try transaction.gatewayAuthorityHead(registration)
        guard verified.evidence.revision == local else { throw GatewayAuthorityError.headMismatch }
        let inspection = try transaction.inspectGatewayHead(verified)
        guard inspection.localRevision == local, inspection.reportedRevision == local,
              inspection.disposition == .recorded || inspection.disposition == .alreadyRecorded else {
            throw GatewayAuthorityError.corruptData
        }
    }
}
