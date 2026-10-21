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

    func actions(expected: SetupPortableImportProgress, custody: SetupPortableImportCustodyChoices) throws -> [SetupPortableImportOperation.Action] {
        try lock.withLock {
            guard let proposal else { throw AdministrativeSetupChannelError.closed }
            _ = try SetupPortableImportOperation(action: .retain, expected: expected, proposal: proposal)
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
            guard !actions.contains(.prepareRuntime) || custody.runtimeFiles,
                  !actions.contains(.prepareGateway) || !gateway || custody.pushCredentials,
                  !actions.contains(.prepareRunCredential) || custody.relayCredential else {
                throw SetupPortableImportFlowError.custodyNotAccepted
            }
            return actions
        }
    }

    public func close() { lock.withLock { proposal = nil } }
    public var description: String { "ReviewedSetupFile(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
}
