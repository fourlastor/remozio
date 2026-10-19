import Foundation

/// Inputs for a native settings transition. This value grants no authorization or runtime readiness.
struct AuthorityPhonePushSettingsChange: Equatable, Sendable {
    let revisionDigest: Data
    let previousCommitDigest: Data
    let selectedCommitDigest: Data

    init(revisionDigest: Data, previousCommitDigest: Data, selectedCommitDigest: Data) throws {
        guard revisionDigest.count == 32, previousCommitDigest.count == 32, selectedCommitDigest.count == 32,
              previousCommitDigest != selectedCommitDigest else { throw GatewayPreparationError.invalidRecord }
        self.revisionDigest = revisionDigest; self.previousCommitDigest = previousCommitDigest
        self.selectedCommitDigest = selectedCommitDigest
    }
    init(_ plan: GatewayRuntimeSettingsPublicationPlan) throws {
        guard let marker = plan.artifacts.last, case .gatewayRuntimeCommit = marker.file,
              let previous = marker.previous else { throw GatewayPreparationError.incomplete }
        let oldCommit = try GatewayRuntimeCommit.decode(previous)
        let selected = try GatewayRuntimeCommit.decode(marker.selected)
        guard oldCommit.intentID == selected.intentID, oldCommit.intentDigest == selected.intentDigest,
              oldCommit.foregroundDigest == selected.foregroundDigest,
              oldCommit.authorityDigest == selected.authorityDigest else { throw GatewayPreparationError.changedScope }
        try self.init(revisionDigest: plan.revision.digest, previousCommitDigest: oldCommit.observationDigest,
            selectedCommitDigest: selected.observationDigest)
    }
}
