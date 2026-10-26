import CryptoKit
import Foundation
import RemozioProtocol

/// One reviewed setup step. This request can contain provider credentials and must never be logged or persisted.
public struct SetupPortableImportOperation: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public enum Action: UInt64, CaseIterable, Sendable {
        case retain = 0, prepareRelayPlan, prepareRuntime, activateRuntime, prepareGateway, activateGateway
        case createTunnel, applyIngress, prepareRunCredential, createAccess, createDNS, publishConnector, complete
        var usesCloudflare: Bool { [.prepareRelayPlan, .createTunnel, .applyIngress, .prepareRunCredential, .createAccess, .createDNS, .publishConnector].contains(self) }
        var needsCustody: Bool { [.prepareRuntime, .prepareGateway, .prepareRunCredential].contains(self) }
    }
    public static let maximumBytes = 70_000
    static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 13)
    public let action: Action
    public let expected: SetupPortableImportProgress
    let proposal: PortableSetup
    public let fileCustodyAccepted: Bool
    public var description: String { "SetupPortableImportOperation(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
    init(action: Action, expected: SetupPortableImportProgress, proposal: PortableSetup, fileCustodyAccepted: Bool = false) throws {
        guard !action.usesCloudflare || proposal.cloudflare != nil,
              !fileCustodyAccepted || action.needsCustody,
              action != .activateGateway || (proposal.fcm != nil && proposal.pushClient != nil),
              expected.operationID != nil || action == .retain else { throw AdministrativeSetupChannelError.invalidMessage }
        let digest = Data(SHA256.hash(data: try proposal.canonicalBytes()))
        guard expected.proposalDigest == nil || expected.proposalDigest == digest else { throw AdministrativeSetupChannelError.invalidMessage }
        self.action = action; self.expected = expected; self.proposal = proposal; self.fileCustodyAccepted = fileCustodyAccepted
        _ = try bytes
    }
    var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-portable-import-operation"),
            2: .unsigned(action.rawValue), 3: .bytes(try expected.bytes), 4: .bytes(try proposal.canonicalBytes()),
            5: .boolean(fileCustodyAccepted)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...5),
              f[0] == .unsigned(1), f[1] == .text("remozio-portable-import-operation"),
              case .unsigned(let raw) = f[2], let action = Action(rawValue: raw),
              case .bytes(let expected) = f[3], case .bytes(let proposal) = f[4], case .boolean(let accepted) = f[5] else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        let result = try Self(action: action, expected: .decode(expected), proposal: .init(canonicalBytes: proposal), fileCustodyAccepted: accepted)
        guard try result.bytes == bytes else { throw AdministrativeSetupChannelError.invalidMessage }; return result
    }
}

/// An action result contains public progress only. Applied setup does not assert runtime or provider readiness.
public struct SetupPortableImportOperationResult: Equatable, Sendable {
    public enum Status: UInt64, Sendable { case applied = 0, waitingForCleanup, requiresReconciliation, providerRejected }
    public static let maximumBytes = 1536
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 13)
    public let action: SetupPortableImportOperation.Action
    public let progress: SetupPortableImportProgress
    public let status: Status
    private let requestDigest: Data
    init(request: SetupPortableImportOperation, progress: SetupPortableImportProgress, status: Status) throws {
        action = request.action; self.progress = progress; self.status = status
        requestDigest = Data(SHA256.hash(data: try request.bytes)); try validate(request)
    }
    func validate(_ request: SetupPortableImportOperation) throws {
        let before = request.expected, now = progress, a = before.runtime, b = now.runtime
        guard action == request.action, requestDigest == Data(SHA256.hash(data: try request.bytes)),
              a.macID == b.macID, a.accountID == b.accountID, a.setupID == b.setupID, a.accountRevision == b.accountRevision,
              a.ownerUID == b.ownerUID, a.servicePlanID == b.servicePlanID,
              a.materialID == nil || a.materialID == b.materialID, !a.configurationPublished || b.configurationPublished,
              before.installationID == now.installationID, before.releaseDigest == now.releaseDigest,
              now.proposalDigest == Data(SHA256.hash(data: try request.proposal.canonicalBytes())),
              now.operationID != nil,
              before.operationID == nil || (now.operationID == before.operationID && now.phase!.rawValue >= before.phase!.rawValue),
              status != .waitingForCleanup || action == .activateGateway,
              ![.requiresReconciliation, .providerRejected].contains(status) || [.createTunnel, .createAccess, .createDNS].contains(action),
              action != .prepareRuntime || (status == .applied && b.configurationPublished && b.materialID != nil &&
                now.phase!.rawValue >= SetupPortableImportProgress.Phase.runtimePublished.rawValue),
              action != .prepareGateway || (status == .applied && now.phase!.rawValue >= SetupPortableImportProgress.Phase.gatewayPrepared.rawValue),
              action != .complete || (status == .applied && now.phase == .rootComplete) else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        if action == .retain { try now.validateRetention(of: before, proposalDigest: now.proposalDigest!) }
    }
    var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-portable-import-result"),
            2: .bytes(requestDigest), 3: .unsigned(action.rawValue), 4: .bytes(try progress.bytes), 5: .unsigned(status.rawValue)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data, request: SetupPortableImportOperation) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...5),
              f[0] == .unsigned(1), f[1] == .text("remozio-portable-import-result"), case .bytes(let digest) = f[2],
              case .unsigned(let action) = f[3], action == request.action.rawValue, case .bytes(let progress) = f[4],
              case .unsigned(let rawStatus) = f[5], let status = Status(rawValue: rawStatus) else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        let result = try Self(request: request, progress: .decode(progress), status: status)
        guard digest == result.requestDigest, try result.bytes == bytes else { throw AdministrativeSetupChannelError.invalidMessage }; return result
    }
}
