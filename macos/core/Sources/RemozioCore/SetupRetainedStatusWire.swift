import Foundation
import RemozioProtocol

/// Status lane selector. A connection that calls it before a normal hello stays status-only for its lifetime.
@objc public protocol RetainedSetupStatusXPCProtocol {
    func retainedInvocationStatus(_ request: Data, reply: @escaping @Sendable (Data?) -> Void)
}

/// The daemon exports one fixed interface: every existing normal selector plus the status lane.
@objc public protocol AdministrativeSetupServiceXPCProtocol: AdministrativeSetupMaintenanceXPCProtocol, RetainedSetupStatusXPCProtocol, RetainedSetupRecoveryXPCProtocol {}

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
    /// Fields 5, 6 and 7 contain only a captured protected row. Field 10 contains a separate supervisor observation.
    /// An unavailable capture remains null. A status request never opens a store or waits for recovery.
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

extension SetupRetainedStatusWire {
    /// Public wire facts cannot reconstruct the protected setup scope.
    struct Observation: Equatable, Sendable, CustomReflectable {
        struct Window: Equatable, Sendable {
            let id: Data
            let revision: Data
            let purpose: RuntimeMaintenanceWindowRecord.Purpose
        }

        let reservation: SetupRetainedInvocationStatus.Reservation?
        let identity: SetupRetainedInvocationStatus.Identity?
        let window: Window?
        let operation: RuntimeMaintenanceWindowRecord.OperationOutcome?
        let restoration: SetupRetainedInvocationStatus.Restoration?
        let worker: SetupRetainedInvocationStatus.Worker?
        let cleanup: SetupRetainedInvocationStatus.Cleanup?
        let supervisor: SetupRetainedInvocationStatus.Supervisor?
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
    }

    static func decodeReply(_ bytes: Data, matching request: Request) throws -> Observation {
        let invalid = AdministrativeSetupChannelError.invalidMessage
        guard bytes.count <= maximumReplyBytes,
              case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: replyLimits),
              Set(fields.keys) == Set(UInt64(0)...10), fields[0] == .unsigned(version),
              fields[1] == .text(replyName), fields[2] == .bytes(request.requestID),
              try DeterministicCBOR.encode(.map(fields), limits: replyLimits) == bytes else { throw invalid }

        func fact<Value>(_ key: UInt64, _ decode: (CBORValue) throws -> Value) throws -> Value? {
            guard let field = fields[key], field != .null else { return nil }
            return try decode(field)
        }
        func number(_ value: CBORValue) throws -> UInt64 {
            guard case .unsigned(let raw) = value else { throw invalid }
            return raw
        }
        func coded<Value>(_ value: CBORValue, _ choices: [Value], _ code: (Value) -> UInt64) throws -> Value {
            let raw = try number(value)
            guard let result = choices.first(where: { code($0) == raw }) else { throw invalid }
            return result
        }
        func tuple(_ value: CBORValue, count: Int) throws -> [CBORValue] {
            guard case .array(let items) = value, items.count == count else { throw invalid }
            return items
        }
        func identifier(_ value: CBORValue) throws -> Data {
            guard case .bytes(let data) = value, data.count == 16 else { throw invalid }
            return data
        }
        func uuid(_ value: CBORValue) throws -> UUID {
            let data = try identifier(value)
            return data.withUnsafeBytes { NSUUID(uuidBytes: $0.bindMemory(to: UInt8.self).baseAddress!) as UUID }
        }

        typealias Status = SetupRetainedInvocationStatus
        typealias Record = RuntimeMaintenanceWindowRecord
        let supervisors: [Status.Supervisor] = [.recovering, .joining, .busy, .cancelled, .retired, .noWindow]
            + Record.Phase.allCases.map(Status.Supervisor.phase) + Record.Failure.allCases.map(Status.Supervisor.failed)
        return Observation(
            reservation: try fact(3) { try coded($0, [Status.Reservation.absent, .reserved, .attached, .orphan, .recovering, .settled], code) },
            identity: try fact(4) { value in
                let items = try tuple(value, count: 2)
                return try .init(reservationID: uuid(items[0]), incarnation: uuid(items[1]))
            },
            window: try fact(5) { value in
                let items = try tuple(value, count: 3)
                return try .init(id: identifier(items[0]), revision: identifier(items[1]),
                    purpose: coded(items[2], Record.Purpose.allCases, \.rawValue))
            },
            operation: try fact(6) { try coded($0, Record.OperationOutcome.allCases, \.rawValue) },
            restoration: try fact(7) { value in
                let items = try tuple(value, count: 3)
                return try .init(phase: coded(items[0], Record.Phase.allCases, \.rawValue),
                    service: coded(items[1], Record.ServiceOutcome.allCases, \.rawValue),
                    failure: items[2] == .null ? nil : coded(items[2], Record.Failure.allCases, \.rawValue))
            },
            worker: try fact(8) { try coded($0, [Status.Worker.idle, .running, .registered], code) },
            cleanup: try fact(9) { try coded($0, [Status.Cleanup.noneRegistered, .pending, .joining, .joinFailed, .joined, .settled], code) },
            supervisor: try fact(10) { value in
                guard let result = supervisors.first(where: { supervisor($0) == value }) else { throw invalid }
                return result
            })
    }
}
