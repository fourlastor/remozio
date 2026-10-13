import Foundation
import RemozioProtocol

/// Root setup input after administrator, signed-code and fresh-installation checks.
/// This declaration is not evidence of those checks and grants no phone enrollment or command access.
public struct AuthorityJournalInitialization: Sendable {
    public let descriptor: AuditEpochDescriptor
    public let codePolicy: AuthorityCodePolicy
    public let capabilities: ContractCapabilities
    public let allowedContracts: Set<RequestContract>
    public let installCommandReplay: Bool

    public init(descriptor: AuditEpochDescriptor, codePolicy: AuthorityCodePolicy,
                capabilities: ContractCapabilities, allowedContracts: Set<RequestContract>, installCommandReplay: Bool = true) {
        self.descriptor = descriptor; self.codePolicy = codePolicy; self.capabilities = capabilities
        self.allowedContracts = allowedContracts; self.installCommandReplay = installCommandReplay
    }
    enum Stage { case epoch, approvalPolicy, codePolicy, commandReplay }
    func apply(_ transaction: JournalTransaction, didStage: (Stage) throws -> Void) throws {
        _ = try transaction.createEpoch(descriptor); try didStage(.epoch)
        _ = try transaction.configureApprovalAuthority(capabilities: capabilities, allowedContracts: allowedContracts)
        try didStage(.approvalPolicy)
        _ = try transaction.installCodePolicy(codePolicy, expectedRevision: nil); try didStage(.codePolicy)
        if installCommandReplay { try transaction.installCommandSubmissionReplay(); try didStage(.commandReplay) }
    }
}
