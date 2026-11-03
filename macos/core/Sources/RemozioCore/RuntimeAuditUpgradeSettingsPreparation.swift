import Foundation
import RemozioProtocol

/// Retains both sides of a settings rebind. No value here grants file mutation, quiescence or consumer acceptance.
struct RuntimeAuditUpgradeSettingsPreparation: CustomStringConvertible, CustomDebugStringConvertible {
    struct Selection {
        let revision: GatewayRuntimeSettingsRevision?
        let gateway: GatewayServiceConfiguration
        let pair: GatewayRuntimeExtensions
        let commit: GatewayRuntimeCommit
    }
    let source: GatewayRuntimeSettingsState
    let target: GatewayRuntimeSettingsState
    let sourceActive: Selection
    let targetActive: Selection
    let sourcePending: GatewayRuntimeSettingsPublicationPlan?
    let targetPending: GatewayRuntimeSettingsPublicationPlan?
    private let services: ServiceAccountPlan
    private let upgradeID: Data
    var description: String { "RuntimeAuditUpgradeSettingsPreparation(redacted)" }
    var debugDescription: String { description }

    init(_ preparation: RuntimeAuditUpgradePreparation, state: GatewayRuntimeSettingsState,
         journal: GatewayJournalPreparationState, activation: GatewayRuntimeActivationPlan,
         gateway: RuntimeAuditUpgradePreparation.Gateway, inventory: InstallationInventory) throws {
        guard gateway.upgradeID == preparation.intent.id,
              try gateway.sourceActivationDigest == activation.digest,
              activation.extensions.authority.material.runtime == preparation.intent.source,
              gateway.material.runtime == preparation.intent.target,
              (state.pending == nil) == (state.phase == nil) else { throw GatewayPreparationError.changedScope }
        let oldActive = try Self.selection(state.active, activation: activation, journal: journal,
            foreground: preparation.source, inventory: inventory)
        if let active = state.active {
            guard active.sequence <= UInt64(Int64.max) else { throw GatewayPreparationError.exhausted }
            if active.sequence == 1 { try active.validateSuccessor(of: nil, activation: activation) }
        }
        let active: GatewayRuntimeSettingsRevision?
        if let retained = state.active {
            let previous = try retained.sequence == 1 ? gateway.activation.digest : retained.previousDigest
            active = try Self.rebind(retained, previousDigest: previous, activation: gateway.activation,
                journal: gateway.journal, foreground: preparation.target, inventory: inventory)
        } else { active = nil }
        let newActive = try Self.selection(active, activation: gateway.activation, journal: gateway.journal,
            foreground: preparation.target, inventory: inventory)
        try Self.requireSameOperationalValues(oldActive, newActive)
        let oldPending: GatewayRuntimeSettingsPublicationPlan?, newPending: GatewayRuntimeSettingsPublicationPlan?
        let pending: GatewayRuntimeSettingsRevision?
        if let retained = state.pending {
            guard retained.sequence <= UInt64(Int64.max) else { throw GatewayPreparationError.exhausted }
            try retained.validateSuccessor(of: state.active, activation: activation)
            let previous = try active?.digest ?? gateway.activation.digest
            let rebound = try Self.rebind(retained, previousDigest: previous, activation: gateway.activation,
                journal: gateway.journal, foreground: preparation.target, inventory: inventory)
            pending = rebound
            oldPending = try .init(revision: retained, previous: state.active, activation: activation,
                journal: journal, foreground: preparation.source, inventory: inventory)
            newPending = try .init(revision: rebound, previous: active, activation: gateway.activation,
                journal: gateway.journal, foreground: preparation.target, inventory: inventory)
            let oldSelection = try Self.selection(retained, activation: activation, journal: journal,
                foreground: preparation.source, inventory: inventory)
            let newSelection = try Self.selection(pending, activation: gateway.activation, journal: gateway.journal,
                foreground: preparation.target, inventory: inventory)
            try Self.requireSameOperationalValues(oldSelection, newSelection)
        } else { pending = nil; oldPending = nil; newPending = nil }
        source = state; target = .init(active: active, pending: pending, phase: state.phase)
        sourceActive = oldActive; targetActive = newActive
        sourcePending = oldPending; targetPending = newPending
        services = preparation.intent.source.services; upgradeID = preparation.intent.id
    }
    struct FenceBinding: CustomStringConvertible, CustomDebugStringConvertible {
        let source: GatewayRuntimeSettingsFence
        let target: GatewayRuntimeSettingsFence
        var description: String { "RuntimeAuditUpgradeSettingsPreparation.FenceBinding(redacted)" }
        var debugDescription: String { description }
    }
    /// The owner must durably retain both sides before publication. Every target requires fresh native barriers.
    func preparingFence(_ fence: GatewayRuntimeSettingsFence) throws -> FenceBinding {
        try fence.validate(services: services)
        if let sourcePending, let targetPending {
            guard fence.recoveryAttemptID == nil,
                  try fence.encoded == GatewayRuntimeSettingsFence(sourcePending).encoded else {
                throw GatewayPreparationError.changedScope
            }
            return try .init(source: fence, target: .init(targetPending))
        }
        guard let old = sourceActive.revision, let next = targetActive.revision,
              try fence.revision.encoded == old.encoded,
              try fence.selected.encoded == sourceActive.commit.encoded else { throw GatewayPreparationError.changedScope }
        if let attempt = fence.recoveryAttemptID {
            guard try fence.previous.encoded == sourceActive.commit.encoded else { throw GatewayPreparationError.changedScope }
            return try .init(source: fence, target: .init(recovering: next, commit: targetActive.commit,
                services: services, attemptID: attempt))
        }
        // A completed transition can retain its fence after losing the cleanup reply.
        return try .init(source: fence, target: .init(recovering: next, commit: targetActive.commit,
            services: services, attemptID: upgradeID))
    }
    private static func selection(_ revision: GatewayRuntimeSettingsRevision?, activation: GatewayRuntimeActivationPlan,
                                  journal: GatewayJournalPreparationState, foreground: RuntimeActivationPlan,
                                  inventory: InstallationInventory) throws -> Selection {
        let proposal: GatewayConfigurationBundle, pair: GatewayRuntimeExtensions, commit: GatewayRuntimeCommit
        if let revision {
            proposal = try revision.proposal(activation: activation, journal: journal, foreground: foreground, inventory: inventory)
            pair = try .init(settings: revision, activation: activation, journal: journal, foreground: foreground, inventory: inventory)
            commit = try .init(pair, settings: revision, gateway: proposal.gateway)
        } else {
            proposal = try activation.proposal(journal: journal, foreground: foreground, inventory: inventory)
            pair = activation.extensions; commit = try .init(pair)
        }
        return .init(revision: revision, gateway: proposal.gateway, pair: pair, commit: commit)
    }
    private static func requireSameOperationalValues(_ source: Selection, _ target: Selection) throws {
        guard source.gateway.canonicalBytes == target.gateway.canonicalBytes,
              source.pair.transport.wake?.canonicalBytes == target.pair.transport.wake?.canonicalBytes else {
            throw GatewayPreparationError.changedScope
        }
    }
    private static func rebind(_ revision: GatewayRuntimeSettingsRevision, previousDigest: Data,
                               activation: GatewayRuntimeActivationPlan, journal: GatewayJournalPreparationState,
                               foreground: RuntimeActivationPlan, inventory: InstallationInventory) throws -> GatewayRuntimeSettingsRevision {
        guard case .map(var fields) = try DeterministicCBOR.decode(revision.encoded, limits: limits) else {
            throw GatewayPreparationError.invalidRecord
        }
        fields[4] = .bytes(try activation.digest); fields[6] = .bytes(previousDigest)
        let value = try GatewayRuntimeSettingsRevision.decode(DeterministicCBOR.encode(.map(fields), limits: limits))
        _ = try value.proposal(activation: activation, journal: journal, foreground: foreground, inventory: inventory)
        return value
    }
    private static let limits = try! CBORLimits(maxBytes: 32768, maxDepth: 1, maxItems: 21)
}
