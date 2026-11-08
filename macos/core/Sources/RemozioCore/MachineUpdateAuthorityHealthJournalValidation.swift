import Foundation
import RemozioProtocol

/// Shared read checks for paired Root journals. No request owner or writer is created.
enum MachineUpdateAuthorityHealthJournalValidation {
    static func requireCurrent(_ transaction: JournalTransaction, configuration: AuthorityServiceConfiguration,
        binding: RuntimeReleaseBinding, policy: AuthorityCodePolicySnapshot, requests: [ReleaseRequestContract]) throws {
        guard try transaction.codePolicy() == policy else { throw AuthorityCodePolicyError.staleRevision }
        let trust = try transaction.approvalTrustSnapshot()
        guard trust.macID == binding.macID, trust.accountID == binding.accountID,
              trust.allowedContracts.isSubset(of: Set(trust.authorityCapabilities.contracts.keys)) else {
            throw RuntimePreparationError.changedScope
        }
        for (contract, features) in trust.authorityCapabilities.contracts {
            let kind: UInt64
            switch contract.requestKind {
            case .command: kind = 0
            case .onePasswordAccess: kind = 1
            case .onePasswordUnlock: kind = 2
            case .littleSnitch: kind = 3
            }
            guard let declared = requests.first(where: {
                $0.kind == kind && $0.wireVersion == contract.wireVersion && $0.schemaVersion == contract.schemaVersion
            }), features.isSubset(of: declared.features) else { throw ReleaseCompatibilityError.invalidRequirements }
        }
        _ = try transaction.directApprovalTrust(maximumPayloadBytes: configuration.maximumPayloadBytes,
            minimumEnvelopeVersion: configuration.minimumEnvelopeVersion, auditVersions: configuration.auditVersions)
    }
}
