import Foundation
import RemozioProtocol

/// Library-only status v2. The producer slice owns negotiation on the existing status selector.
enum SetupRetainedStatusV2Wire {
    static let version: UInt64 = 2
    static let maximumRequestBytes = 1024, maximumReplyBytes = 16 * 1024
    private static var requestLimits: CBORLimits { get throws { try .init(maxBytes: maximumRequestBytes, maxDepth: 2, maxItems: 8) } }
    private static var replyLimits: CBORLimits { get throws { try .init(maxBytes: maximumReplyBytes, maxDepth: 4, maxItems: 96) } }
    struct Request: Equatable, Sendable {
        let requestID: Data
        init(requestID: Data) throws {
            guard requestID.count == 16 else { throw AdministrativeSetupChannelError.invalidMessage }; self.requestID = requestID
        }
        var bytes: Data { get throws {
            try DeterministicCBOR.encode(.map([0: .unsigned(version), 1: .text(SetupRetainedStatusWire.requestName), 2: .bytes(requestID)]), limits: requestLimits)
        } }
        static func decode(_ bytes: Data) throws -> Self {
            guard bytes.count <= maximumRequestBytes, case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: requestLimits),
                  Set(fields.keys) == [0, 1, 2], fields[0] == .unsigned(version), fields[1] == .text(SetupRetainedStatusWire.requestName),
                  case .bytes(let id) = fields[2] else { throw AdministrativeSetupChannelError.invalidMessage }
            let request = try Self(requestID: id)
            guard try request.bytes == bytes else { throw AdministrativeSetupChannelError.invalidMessage }; return request
        }
    }
    /// Restart keys 6–8 carry only the last confirmed row. They are not refreshed after release and do not prove completion.
    static func reply(_ request: Request, _ projection: SetupRetainedStatusProjection) throws -> Data {
        let legacy = try SetupRetainedStatusWire.reply(.init(requestID: request.requestID), projection.retained)
        guard case .map(let old) = try DeterministicCBOR.decode(legacy, limits: replyLimits) else { throw AdministrativeSetupChannelError.invalidMessage }
        var fields: [UInt64: CBORValue] = [0: .unsigned(version), 1: .text(SetupRetainedStatusWire.replyName), 2: .bytes(request.requestID)]
        for key in UInt64(4)...11 { fields[key] = old[key - 1] }
        fields[3] = .null; fields[12] = .null
        if case .observed = projection.retained.reservation { fields[3] = .unsigned(1) }
        else if case .observed = projection.retained.window { fields[3] = .unsigned(3) }
        if let restart = projection.restart {
            fields[3] = .unsigned(2)
            for key in UInt64(4)...11 { fields[key] = .null }
            if let row = restart.row {
                fields[6] = .array([.bytes(row.window.id), .bytes(row.window.revision), .unsigned(row.window.purpose.rawValue)])
                fields[7] = .unsigned(row.operation.rawValue)
                fields[8] = .array([.unsigned(row.restoration.phase.rawValue), .unsigned(row.restoration.service.rawValue),
                    row.restoration.failure.map { .unsigned($0.rawValue) } ?? .null])
            }
            fields[12] = .array([.unsigned(restart.slot.rawValue), .unsigned(restart.claim.rawValue), .unsigned(restart.task.rawValue),
                restart.custody.map { .unsigned($0.rawValue) } ?? .null, restart.writer.map { .unsigned($0.rawValue) } ?? .null])
        }
        let bytes = try DeterministicCBOR.encode(.map(fields), limits: replyLimits)
        _ = try decodeReply(bytes)
        return bytes
    }
    /// Validate the redacted wire projection without inventing a protected binding from public bytes.
    static func decodeReply(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard bytes.count <= maximumReplyBytes, case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: replyLimits),
              Set(fields.keys) == Set(UInt64(0)...12), fields[0] == .unsigned(version), fields[1] == .text(SetupRetainedStatusWire.replyName),
              case .bytes(let id) = fields[2], id.count == 16 else { throw AdministrativeSetupChannelError.invalidMessage }
        func valid(_ value: CBORValue?, _ allowed: ClosedRange<UInt64>) -> Bool {
            if value == .null { return true }
            if case .unsigned(let code) = value { return allowed.contains(code) }; return false
        }
        func data(_ value: CBORValue?, size: Int) -> Bool {
            if case .bytes(let bytes) = value { return bytes.count == size }; return false
        }
        func array(_ value: CBORValue?, count: Int) -> [CBORValue]? {
            if case .array(let values) = value, values.count == count { return values }; return nil
        }
        guard valid(fields[3], 1...3), valid(fields[4], 1...6), valid(fields[7], 1...4), valid(fields[9], 1...3), valid(fields[10], 1...6) else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        if fields[5] != .null {
            guard let pair = array(fields[5], count: 2), pair.allSatisfy({ data($0, size: 16) }) else { throw AdministrativeSetupChannelError.invalidMessage }
        }
        if fields[6] != .null {
            guard let row = array(fields[6], count: 3), data(row[0], size: 16), data(row[1], size: 16), valid(row[2], 1...3), row[2] != .null else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
        }
        if fields[8] != .null {
            guard let row = array(fields[8], count: 3), valid(row[0], 1...10), valid(row[1], 1...7), valid(row[2], 1...8),
                  row[0] != .null, row[1] != .null else { throw AdministrativeSetupChannelError.invalidMessage }
        }
        if fields[11] != .null {
            guard case .array(let observation) = fields[11], let first = observation.first, case .unsigned(let code) = first else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            switch code {
            case 1...6: guard observation.count == 1 else { throw AdministrativeSetupChannelError.invalidMessage }
            case 7: guard observation.count == 2, valid(observation[1], 1...10), observation[1] != .null else { throw AdministrativeSetupChannelError.invalidMessage }
            case 8: guard observation.count == 2, valid(observation[1], 1...8), observation[1] != .null else { throw AdministrativeSetupChannelError.invalidMessage }
            default: throw AdministrativeSetupChannelError.invalidMessage
            }
        }
        if fields[3] == .unsigned(2) {
            guard let tuple = array(fields[12], count: 5), valid(tuple[0], 1...2), valid(tuple[1], 1...2), valid(tuple[2], 1...6),
                  valid(tuple[3], 1...3), valid(tuple[4], 1...2), fields[4] == .null, fields[5] == .null,
                  fields[9] == .null, fields[10] == .null, fields[11] == .null,
                  (tuple[3] != .unsigned(2) && tuple[3] != .null) || tuple[4] == .null else { throw AdministrativeSetupChannelError.invalidMessage }
        } else if fields[12] != .null { throw AdministrativeSetupChannelError.invalidMessage }
        guard try DeterministicCBOR.encode(.map(fields), limits: replyLimits) == bytes else { throw AdministrativeSetupChannelError.invalidMessage }
        return fields
    }
}
