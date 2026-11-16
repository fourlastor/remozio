import Foundation
import RemozioProtocol

/// Status lane selector. A connection that calls it before a normal hello stays status-only for its lifetime.
@objc public protocol RetainedSetupStatusXPCProtocol {
    func retainedInvocationStatus(_ request: Data, reply: @escaping @Sendable (Data?) -> Void)
}

/// The daemon exports one fixed interface: every existing normal selector plus the status lane.
@objc public protocol AdministrativeSetupServiceXPCProtocol: AdministrativeSetupMaintenanceXPCProtocol, RetainedSetupStatusXPCProtocol {}

/// Bounded status codec. It carries captured facts only. Rights, code requirements, paths, account bindings and error text never cross it.
enum SetupRetainedStatusWire {
    static let version: UInt64 = 1
    static let maximumRequestBytes = 1024
    static let maximumReplyBytes = 16 * 1024
    static let requestName = "setup.retained-status.request"
    static let replyName = "setup.retained-status.reply"
    private static var requestLimits: CBORLimits { get throws { try .init(maxBytes: maximumRequestBytes, maxDepth: 2, maxItems: 8) } }
    private static var replyLimits: CBORLimits { get throws { try .init(maxBytes: maximumReplyBytes, maxDepth: 4, maxItems: 64) } }

    struct Request: Equatable, Sendable {
        let requestID: Data
        init(requestID: Data) throws {
            guard requestID.count == 16 else { throw AdministrativeSetupChannelError.invalidMessage }
            self.requestID = requestID
        }
        var bytes: Data {
            get throws {
                try DeterministicCBOR.encode(.map([0: .unsigned(version), 1: .text(requestName), 2: .bytes(requestID)]), limits: requestLimits)
            }
        }
        static func decode(_ bytes: Data) throws -> Request {
            guard bytes.count <= maximumRequestBytes,
                  case .map(let f) = try DeterministicCBOR.decode(bytes, limits: requestLimits), Set(f.keys) == [0, 1, 2],
                  f[0] == .unsigned(version), f[1] == .text(requestName), case .bytes(let id) = f[2] else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            let value = try Request(requestID: id)
            guard try value.bytes == bytes else { throw AdministrativeSetupChannelError.invalidMessage }
            return value
        }
    }

    /// Unavailable facts encode as null. A decoder never turns null into a terminal outcome.
    /// The status lane reports only the in-memory projection, so fields 5 (window), 6 (operation), 7 (restoration) and
    /// 10 (supervisor) are always null until a later cut adds a bounded durable read or a supervisor observation.
    static func reply(_ request: Request, _ status: SetupRetainedInvocationStatus) throws -> Data {
        func fact<V: Equatable & Sendable>(_ value: SetupRetainedInvocationStatus.Fact<V>, _ encode: (V) -> CBORValue) -> CBORValue {
            if case .observed(let observed) = value { return encode(observed) }
            return .null
        }
        let fields: [UInt64: CBORValue] = [
            0: .unsigned(version), 1: .text(replyName), 2: .bytes(request.requestID),
            3: fact(status.reservation) { .unsigned(code($0)) },
            4: fact(status.identity) { identity in
                var reservation = identity.reservationID.uuid, incarnation = identity.incarnation.uuid
                return .array([.bytes(withUnsafeBytes(of: &reservation) { Data($0) }), .bytes(withUnsafeBytes(of: &incarnation) { Data($0) })])
            },
            5: fact(status.window) { .array([.bytes($0.id), .bytes($0.revision), .unsigned($0.purpose.rawValue)]) },
            6: fact(status.operation) { .unsigned($0.rawValue) },
            7: fact(status.restoration) { .array([.unsigned($0.phase.rawValue), .unsigned($0.service.rawValue), $0.failure.map { .unsigned($0.rawValue) } ?? .null]) },
            8: fact(status.worker) { .unsigned(code($0)) },
            9: fact(status.cleanup) { .unsigned(code($0)) },
            10: fact(status.supervisor) { supervisor($0) },
        ]
        let bytes = try DeterministicCBOR.encode(.map(fields), limits: replyLimits)
        guard bytes.count <= maximumReplyBytes else { throw AdministrativeSetupChannelError.invalidMessage }
        return bytes
    }

    static func code(_ value: SetupRetainedInvocationStatus.Reservation) -> UInt64 {
        switch value { case .absent: 1; case .reserved: 2; case .attached: 3; case .orphan: 4; case .recovering: 5; case .settled: 6 }
    }
    static func code(_ value: SetupRetainedInvocationStatus.Worker) -> UInt64 {
        switch value { case .idle: 1; case .running: 2; case .registered: 3 }
    }
    static func code(_ value: SetupRetainedInvocationStatus.Cleanup) -> UInt64 {
        switch value { case .noneRegistered: 1; case .pending: 2; case .joining: 3; case .joinFailed: 4; case .joined: 5; case .settled: 6 }
    }
    static func supervisor(_ value: SetupRetainedInvocationStatus.Supervisor) -> CBORValue {
        switch value {
        case .recovering: .array([.unsigned(1)])
        case .joining: .array([.unsigned(2)])
        case .busy: .array([.unsigned(3)])
        case .cancelled: .array([.unsigned(4)])
        case .retired: .array([.unsigned(5)])
        case .noWindow: .array([.unsigned(6)])
        case .phase(let phase): .array([.unsigned(7), .unsigned(phase.rawValue)])
        case .failed(let failure): .array([.unsigned(8), .unsigned(failure.rawValue)])
        }
    }
}
