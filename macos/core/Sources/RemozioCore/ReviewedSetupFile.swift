import CryptoKit
import Foundation

/// Holds an authenticated proposal in memory and exposes its credential-free preview.
/// Closing releases this object's proposal and prevents new requests. Existing requests remain independent.
public final class ReviewedSetupFile: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let preview: SetupPreview
    private let lock = NSLock()
    private var proposal: PortableSetup?

    init(proposal: PortableSetup) {
        self.proposal = proposal
        preview = proposal.preview
    }

    public func operation(action: SetupPortableImportOperation.Action, expected: SetupPortableImportProgress,
                          fileCustodyAccepted: Bool = false) throws -> SetupPortableImportOperation {
        try lock.withLock {
            guard let proposal else { throw AdministrativeSetupChannelError.closed }
            return try SetupPortableImportOperation(action: action, expected: expected, proposal: proposal,
                fileCustodyAccepted: fileCustodyAccepted)
        }
    }

    /// Use only authenticated recovery metadata and an explicit local recovery action.
    /// This prepares a refused attempt; it does not authorize adoption or a provider creation.
    public func refusalRetryOperation(resource: SetupPortableImportRecovery.Resource, recovery: SetupPortableImportRecovery) throws -> SetupPortableImportOperation {
        try lock.withLock {
            guard let proposal else { throw AdministrativeSetupChannelError.closed }
            guard let record = recovery.rejectedRecord(for: resource) else { throw AdministrativeSetupChannelError.invalidMessage }
            let action: SetupPortableImportOperation.Action
            switch resource {
            case .tunnel: action = .prepareRefusedTunnelRetry
            case .accessApplication: action = .prepareRefusedAccessRetry
            case .dnsRecord: action = .prepareRefusedDNSRetry
            }
            return try .init(action: action, expected: recovery.progress, proposal: proposal, expectedRejectedRecordDigest: record.recordDigest)
        }
    }

    public func custodyRequirements(expected: SetupPortableImportProgress) throws -> Set<SetupPortableImportCustodyRequirement> {
        requirements(for: try plannedActions(expected: expected))
    }

    /// The caller must authenticate completion and read/apply these values without suspension.
    /// This method returns imported app preferences only; it does not write or assert live readiness.
    public func appPreferenceValues(completed: SetupPortableImportProgress, readExisting: (String) -> Any?) throws -> [String: Any] {
        try lock.withLock {
            guard let proposal else { throw AdministrativeSetupChannelError.closed }
            guard completed.phase == .rootComplete else { throw SharedSetupImportCompletionValidation.Failure.incomplete }
            try validateProposal(proposal, expected: completed)
            return try proposal.appPreferences?.applicationValues(readExisting: readExisting) ?? [:]
        }
    }

    func actions(expected: SetupPortableImportProgress, custody: SetupPortableImportCustodyChoices) throws -> [SetupPortableImportOperation.Action] {
        let actions = try plannedActions(expected: expected)
        guard custody.satisfies(requirements(for: actions)) else { throw SetupPortableImportFlowError.custodyNotAccepted }
        return actions
    }
    private func requirements(for actions: [SetupPortableImportOperation.Action]) -> Set<SetupPortableImportCustodyRequirement> {
        var result = Set<SetupPortableImportCustodyRequirement>()
        if actions.contains(.prepareRuntime) { result.insert(.runtimeFiles) }
        if actions.contains(.prepareGateway), preview.firebaseProject != nil { result.insert(.pushCredentials) }
        if actions.contains(.prepareRunCredential) { result.insert(.relayCredential) }
        return result
    }
    private func validateProposal(_ proposal: PortableSetup, expected: SetupPortableImportProgress) throws {
        let digest = Data(SHA256.hash(data: try proposal.canonicalBytes()))
        guard expected.proposalDigest == nil || expected.proposalDigest == digest else { throw SetupPortableImportFlowError.differentProposal }
        _ = try SetupPortableImportOperation(action: .retain, expected: expected, proposal: proposal)
    }
    private func plannedActions(expected: SetupPortableImportProgress) throws -> [SetupPortableImportOperation.Action] {
        try lock.withLock {
            guard let proposal else { throw AdministrativeSetupChannelError.closed }
            try validateProposal(proposal, expected: expected)
            let gateway = proposal.fcm != nil || proposal.pushClient != nil
            if gateway { _ = try proposal.gatewayPreparationChoices(fileWakeCustodyAccepted: false) }
            if expected.phase == .rootComplete || expected.phase == .relayPrepared { return [.complete] }
            var actions: [SetupPortableImportOperation.Action] = [.retain]
            if expected.phase == nil || expected.phase == .retained {
                if proposal.cloudflare != nil { actions.append(.prepareRelayPlan) }
                actions.append(.prepareRuntime)
            } else if expected.phase == .runtimePublished, proposal.cloudflare != nil { actions.append(.prepareRelayPlan) }
            if expected.phase != .gatewayPrepared { actions += [.activateRuntime, .prepareGateway] }
            if gateway { actions.append(.activateGateway) }
            if proposal.cloudflare != nil {
                actions += [.createTunnel, .applyIngress, .prepareRunCredential, .createAccess, .createDNS, .publishConnector]
            }
            actions.append(.complete)
            return actions
        }
    }

    public func close() { lock.withLock { proposal = nil } }
    public var description: String { "ReviewedSetupFile(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
}
