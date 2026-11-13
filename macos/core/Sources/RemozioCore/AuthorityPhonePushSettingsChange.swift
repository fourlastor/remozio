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
    /// Reads installed release markers only. The ordinary entry keeps its version and byte limits.
    init(installed plan: GatewayRuntimeSettingsPublicationPlan) throws {
        guard let release = plan.commit.release, release.stage == .completion else { throw GatewayPreparationError.changedScope }
        guard let marker = plan.artifacts.last, case .gatewayRuntimeCommit = marker.file,
              let previous = marker.previous else { throw GatewayPreparationError.incomplete }
        let oldCommit = try GatewayRuntimeCommit.decodeForReleaseArchive(previous)
        let selected = try GatewayRuntimeCommit.decodeForReleaseArchive(marker.selected)
        try oldCommit.requireRelease(binding: release.binding, stage: .completion)
        try selected.requireRelease(binding: release.binding, stage: .completion)
        guard oldCommit.intentID == selected.intentID, oldCommit.intentDigest == selected.intentDigest,
              oldCommit.foregroundDigest == selected.foregroundDigest, oldCommit.authorityDigest == selected.authorityDigest,
              selected.settingsSequence == plan.revision.sequence, try selected.settingsRevisionDigest == plan.revision.digest,
              selected.activationDigest == plan.revision.activationDigest,
              try selected.encoded == plan.commit.encoded else { throw GatewayPreparationError.changedScope }
        try self.init(revisionDigest: plan.revision.digest, previousCommitDigest: oldCommit.observationDigest,
            selectedCommitDigest: selected.observationDigest)
    }
}
