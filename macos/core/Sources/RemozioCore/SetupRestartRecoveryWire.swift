import Foundation
import RemozioProtocol

/// A separate library protocol. No production XPC interface exports these messages.
enum SetupRestartRecoveryWire {
    static let version: UInt64 = 1
    static let maximumBytes = 1024
    static let requestName = "setup.restart-recovery.request"
    static let progressName = "setup.restart-recovery.progress"
    static let replyName = "setup.restart-recovery.reply"
    enum Action: UInt64, CaseIterable, Sendable { case restore = 1, adoptRecordedCompletion = 2, releaseIdleSlot = 3 }
    /// Before claim, every refusal is 1. After claim, rights loss is 7; an unsafe writer or window requires 5.
    /// Routing, no window, pending adoption or forward effects require 6. Other idle release failures use 9.
    /// A release awaiting actual work remains 2; a deadline cannot turn it into a terminal outcome.
    enum Code: UInt64, CaseIterable, Sendable {
        case requestRecorded = 0, refusedUnavailable, pending, released, restored, repairRequired, notApplicable
        case failedAuthorization, failedDeadline, failedOperation
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 2, maxItems: 10) } }
    private static func encode(_ name: String, _ id: Data, _ code: UInt64? = nil) throws -> Data {
        guard id.count == 16 else { throw AdministrativeSetupChannelError.invalidMessage }
        var fields: [UInt64: CBORValue] = [0: .unsigned(version), 1: .text(name), 2: .bytes(id)]
        if let code { fields[3] = .unsigned(code) }
        return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    private static func decode(_ bytes: Data, name: String, coded: Bool) throws -> (Data, UInt64?) {
        guard bytes.count <= maximumBytes,
              case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == (coded ? Set([0, 1, 2, 3]) : Set([0, 1, 2])),
              fields[0] == .unsigned(version), fields[1] == .text(name),
              case .bytes(let id) = fields[2], id.count == 16 else { throw AdministrativeSetupChannelError.invalidMessage }
        let code: UInt64?
        if coded {
            guard case .unsigned(let value) = fields[3] else { throw AdministrativeSetupChannelError.invalidMessage }
            code = value
        } else { code = nil }
        guard try encode(name, id, code) == bytes else { throw AdministrativeSetupChannelError.invalidMessage }
        return (id, code)
    }
    struct Request: Equatable, Sendable {
        let requestID: Data, action: Action
        init(requestID: Data, action: Action) throws {
            guard requestID.count == 16 else { throw AdministrativeSetupChannelError.invalidMessage }
            self.requestID = requestID; self.action = action
        }
        var bytes: Data { get throws { try encode(requestName, requestID, action.rawValue) } }
        static func decode(_ bytes: Data) throws -> Self {
            let (id, raw) = try SetupRestartRecoveryWire.decode(bytes, name: requestName, coded: true)
            guard let raw, let action = Action(rawValue: raw) else { throw AdministrativeSetupChannelError.invalidMessage }
            return try .init(requestID: id, action: action)
        }
    }
    struct Progress: Equatable, Sendable {
        let requestID: Data
        init(requestID: Data) throws {
            guard requestID.count == 16 else { throw AdministrativeSetupChannelError.invalidMessage }
            self.requestID = requestID
        }
        var bytes: Data { get throws { try encode(progressName, requestID) } }
        static func decode(_ bytes: Data) throws -> Self {
            let (id, _) = try SetupRestartRecoveryWire.decode(bytes, name: progressName, coded: false)
            return try .init(requestID: id)
        }
    }
    struct Reply: Equatable, Sendable {
        let requestID: Data, code: Code
        init(requestID: Data, code: Code) throws {
            guard requestID.count == 16 else { throw AdministrativeSetupChannelError.invalidMessage }
            self.requestID = requestID; self.code = code
        }
        var bytes: Data { get throws { try encode(replyName, requestID, code.rawValue) } }
        static func decode(_ bytes: Data) throws -> Self {
            let (id, raw) = try SetupRestartRecoveryWire.decode(bytes, name: replyName, coded: true)
            guard let raw, let code = Code(rawValue: raw) else { throw AdministrativeSetupChannelError.invalidMessage }
            return try .init(requestID: id, code: code)
        }
    }
}
