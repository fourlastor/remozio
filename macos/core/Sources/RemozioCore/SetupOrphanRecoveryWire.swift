import Foundation
import RemozioProtocol

@objc public protocol RetainedSetupRecoveryXPCProtocol {
    func recoveryHello(reply: @escaping @Sendable (UInt64) -> Void)
    func startRecovery(_ request: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
    func recoveryProgress(_ request: Data, reply: @escaping @Sendable (Data?) -> Void)
}

/// Bounded messages for the selected Setup recovery lane.
enum SetupOrphanRecoveryWire {
    static let version: UInt64 = 1
    static let ipcVersion: UInt64 = 13
    static func requireFormats(_ candidate: SignedReleaseEvidence) throws {
        for role in [AuthorityCodeRole.app, .setupController] {
            guard let component = candidate.manifest.components.first(where: { $0.role == role }),
                  let format = component.formats.first(where: { $0.name == "setup.local-ipc" }),
                  format.readers.contains(ipcVersion), format.writers.contains(ipcVersion) else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }
    static let maximumBytes = 1024
    static let requestName = "setup.orphan-recovery.request"
    static let progressName = "setup.orphan-recovery.progress"
    static let replyName = "setup.orphan-recovery.reply"
    enum Action: UInt64, CaseIterable, Sendable { case restore = 1, adoptRecordedCompletion = 2, releaseWindowFree = 3 }
    enum Code: UInt64, CaseIterable, Sendable {
        case requestRecorded = 0, refusedUnavailable, pending, released, restored, repairRequired, notApplicable
        case failedAuthorization, failedDeadline, failedJoin, failedOperation
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 3, maxItems: 20) } }
    private static func invalid() -> AdministrativeSetupChannelError { .invalidMessage }
    private static func uuidBytes(_ id: UUID) -> Data {
        var value = id.uuid
        return withUnsafeBytes(of: &value) { Data($0) }
    }
    private static func uuid(_ bytes: Data) throws -> UUID {
        guard bytes.count == 16 else { throw invalid() }
        return bytes.withUnsafeBytes { NSUUID(uuidBytes: $0.bindMemory(to: UInt8.self).baseAddress!) as UUID }
    }
    struct Request: Equatable, Sendable {
        let requestID: Data, action: Action
        let identity: SetupRetainedInvocationStatus.Identity?
        init(requestID: Data, action: Action, identity: SetupRetainedInvocationStatus.Identity? = nil) throws {
            guard requestID.count == 16 else { throw invalid() }
            self.requestID = requestID; self.action = action; self.identity = identity
        }
        var bytes: Data {
            get throws {
                let target: CBORValue = identity.map { .array([.bytes(uuidBytes($0.reservationID)), .bytes(uuidBytes($0.incarnation))]) } ?? .null
                return try DeterministicCBOR.encode(.map([0: .unsigned(version), 1: .text(requestName),
                    2: .bytes(requestID), 3: .unsigned(action.rawValue), 4: target]), limits: limits)
            }
        }
        static func decode(_ bytes: Data) throws -> Self {
            guard bytes.count <= maximumBytes,
                  case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == [0, 1, 2, 3, 4],
                  f[0] == .unsigned(version), f[1] == .text(requestName), case .bytes(let id) = f[2],
                  case .unsigned(let value) = f[3], let action = Action(rawValue: value) else { throw invalid() }
            let identity: SetupRetainedInvocationStatus.Identity?
            switch f[4] {
            case .null: identity = nil
            case .array(let pair):
                guard pair.count == 2, case .bytes(let reservation) = pair[0], case .bytes(let incarnation) = pair[1] else { throw invalid() }
                identity = try .init(reservationID: uuid(reservation), incarnation: uuid(incarnation))
            default: throw invalid()
            }
            let result = try Self(requestID: id, action: action, identity: identity)
            guard try result.bytes == bytes else { throw invalid() }
            return result
        }
    }
    struct Progress: Equatable, Sendable {
        let requestID: Data
        init(requestID: Data) throws {
            guard requestID.count == 16 else { throw invalid() }; self.requestID = requestID
        }
        var bytes: Data { get throws {
            try DeterministicCBOR.encode(.map([0: .unsigned(version), 1: .text(progressName), 2: .bytes(requestID)]), limits: limits)
        } }
        static func decode(_ bytes: Data) throws -> Self {
            guard bytes.count <= maximumBytes, case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits),
                  Set(f.keys) == [0, 1, 2], f[0] == .unsigned(version), f[1] == .text(progressName),
                  case .bytes(let id) = f[2] else { throw invalid() }
            let result = try Self(requestID: id)
            guard try result.bytes == bytes else { throw invalid() }; return result
        }
    }
    struct Reply: Equatable, Sendable {
        let requestID: Data, code: Code
        init(requestID: Data, code: Code) throws {
            guard requestID.count == 16 else { throw invalid() }; self.requestID = requestID; self.code = code
        }
        var bytes: Data { get throws {
            try DeterministicCBOR.encode(.map([0: .unsigned(version), 1: .text(replyName),
                2: .bytes(requestID), 3: .unsigned(code.rawValue)]), limits: limits)
        } }
        static func decode(_ bytes: Data) throws -> Self {
            guard bytes.count <= maximumBytes, case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits),
                  Set(f.keys) == [0, 1, 2, 3], f[0] == .unsigned(version), f[1] == .text(replyName),
                  case .bytes(let id) = f[2], case .unsigned(let raw) = f[3], let code = Code(rawValue: raw) else { throw invalid() }
            let result = try Self(requestID: id, code: code)
            guard try result.bytes == bytes else { throw invalid() }; return result
        }
    }
}
