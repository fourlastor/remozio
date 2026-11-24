import Darwin
import Foundation
import RemozioProtocol

/// An IO binding identifies the original admitted request. It grants no execution or retry permission.
struct CommandStreamBinding: Equatable, Sendable {
    let profile: CommandHandshakeProfile
    let submission: CapturedSubmission
    let submissionDigest: Data
    let request: CommandAdmittedRequest

    var fields: CBORValue { .map([0: profile.fields,
        1: .map([0: .bytes(submission.id), 1: .bytes(submission.nonce), 2: .bytes(submission.callerBinding)]),
        2: .bytes(submissionDigest),
        3: .map([0: .bytes(request.requestID), 1: .bytes(request.requestToken), 2: .bytes(request.challenge)])]) }
    func validate() throws {
        guard profile.supportsExecutionControls, profile.callerBinding.count == 16, profile.macID.count == 16, profile.accountID.count == 16,
              submission.callerBinding == profile.callerBinding,
              submission.id.count == 16, submission.nonce.count == 32, submissionDigest.count == 32,
              request.requestID.count == 16, request.requestToken.count == 32, request.challenge.count == 32 else {
            throw CommandStreamError.binding
        }
    }
}

public enum CommandStreamError: Error, Equatable { case binding, malformed, sequence, closed, capacity }

/// The private command channel carries bounded bytes and controls. Sender authentication is a separate required gate.
struct CommandStreamFrame: Equatable {
    static let maximumBytes = 8192
    static let maximumChunk = 4096
    static let inputWindow = 32768
    enum Direction { case toAuthority, toFrontend }
    enum Body: Equatable {
        case opened, output(Data), outputEnd, inputCredit(UInt32), jobState(CommandJobStatePayload)
        case input(Data), inputEnd, signal(UInt32), resize(UInt16, UInt16, UInt16, UInt16), cancel, outputDrained
        case currentJob(CommandCurrentJobPayload), queryCurrentJob(Data)
    }
    let sequence: UInt64
    let body: Body

    var direction: Direction {
        switch body {
        case .opened, .output, .outputEnd, .inputCredit, .jobState, .currentJob: .toFrontend
        case .input, .inputEnd, .signal, .resize, .cancel, .outputDrained, .queryCurrentJob: .toAuthority
        }
    }
    static func limits() throws -> CBORLimits { try .init(maxBytes: maximumBytes, maxDepth: 7, maxItems: 128) }
    func encode(binding: CommandStreamBinding) throws -> Data {
        try binding.validate()
        guard sequence < UInt64.max else { throw CommandStreamError.sequence }
        if case .jobState = body, !binding.profile.supportsJobState { throw CommandStreamError.malformed }
        switch body {
        case .currentJob, .queryCurrentJob:
            guard binding.profile.supportsCurrentJob else { throw CommandStreamError.malformed }
        default: break
        }
        if binding.profile.supportsPipeExecutionControls {
            switch body {
            case .opened, .signal, .cancel, .jobState, .currentJob, .queryCurrentJob: break
            default: throw CommandStreamError.malformed
            }
        }
        let tag: UInt64, value: CBORValue
        switch body {
        case .opened: tag = 1; value = binding.profile.supportsPipeExecutionControls ? .null : .unsigned(UInt64(Self.inputWindow))
        case .output(let bytes): tag = 2; value = try Self.chunk(bytes)
        case .outputEnd: tag = 3; value = .null
        case .inputCredit(let count):
            guard (1...UInt32(Self.inputWindow)).contains(count) else { throw CommandStreamError.capacity }
            tag = 4; value = .unsigned(UInt64(count))
        case .jobState(let observation): tag = 5; value = try observation.fields
        case .currentJob(let observation): tag = 6; value = try observation.fields
        case .queryCurrentJob(let nonce):
            guard nonce.count == 32 else { throw CommandStreamError.binding }
            tag = 16; value = .bytes(nonce)
        case .input(let bytes): tag = 10; value = try Self.chunk(bytes)
        case .inputEnd: tag = 11; value = .null
        case .signal(let signal):
            guard signal > 0, signal < UInt32(NSIG) else { throw CommandStreamError.malformed }
            tag = 12; value = .unsigned(UInt64(signal))
        case .resize(let rows, let columns, let width, let height):
            tag = 13; value = .array([rows, columns, width, height].map { .unsigned(UInt64($0)) })
        case .cancel: tag = 14; value = .null
        case .outputDrained: tag = 15; value = .null
        }
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: binding.fields,
            2: .unsigned(sequence), 3: .unsigned(tag), 4: value]), limits: Self.limits())
    }
    static func decode(_ bytes: Data, binding: CommandStreamBinding, direction: Direction) throws -> Self {
        try binding.validate()
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
              Set(fields.keys) == [0, 1, 2, 3, 4], fields[0] == .unsigned(1),
              fields[1] == binding.fields, case .unsigned(let sequence) = fields[2], sequence < UInt64.max,
              case .unsigned(let tag) = fields[3], let value = fields[4] else { throw CommandStreamError.binding }
        let body: Body
        switch tag {
        case 1:
            guard value == (binding.profile.supportsPipeExecutionControls ? .null : .unsigned(UInt64(inputWindow))) else { throw CommandStreamError.capacity }
            body = .opened
        case 2, 10:
            guard case .bytes(let chunk) = value else { throw CommandStreamError.malformed }
            _ = try Self.chunk(chunk)
            body = tag == 2 ? .output(chunk) : .input(chunk)
        case 3, 11, 14, 15:
            guard value == .null else { throw CommandStreamError.malformed }
            body = tag == 3 ? .outputEnd : (tag == 11 ? .inputEnd : (tag == 14 ? .cancel : .outputDrained))
        case 4:
            guard case .unsigned(let count) = value, count > 0, count <= UInt64(inputWindow) else { throw CommandStreamError.capacity }
            body = .inputCredit(UInt32(count))
        case 5: body = .jobState(try CommandJobStatePayload.decode(value))
        case 6: body = .currentJob(try CommandCurrentJobPayload.decode(value))
        case 16:
            guard case .bytes(let nonce) = value, nonce.count == 32 else { throw CommandStreamError.binding }
            body = .queryCurrentJob(nonce)
        case 12:
            guard case .unsigned(let signal) = value, signal > 0, signal < UInt64(NSIG) else { throw CommandStreamError.malformed }
            body = .signal(UInt32(signal))
        case 13:
            guard case .array(let raw) = value, raw.count == 4 else { throw CommandStreamError.malformed }
            let dimensions = try raw.map { raw -> UInt16 in
                guard case .unsigned(let number) = raw, let value = UInt16(exactly: number) else { throw CommandStreamError.malformed }
                return value
            }
            body = .resize(dimensions[0], dimensions[1], dimensions[2], dimensions[3])
        default: throw CommandStreamError.malformed
        }
        let frame = Self(sequence: sequence, body: body)
        guard frame.direction == direction, try frame.encode(binding: binding) == bytes else { throw CommandStreamError.malformed }
        return frame
    }
    private static func chunk(_ bytes: Data) throws -> CBORValue {
        guard (1...maximumChunk).contains(bytes.count) else { throw CommandStreamError.capacity }
        return .bytes(bytes)
    }
}

/// A receiver advances only after the authenticated frame is retained or its control is accepted by its owner.
struct CommandStreamReceiveSequence {
    private(set) var next: UInt64 = 0
    private(set) var ended = false
    let direction: CommandStreamFrame.Direction
    func check(_ frame: CommandStreamFrame) throws {
        guard frame.direction == direction, frame.sequence == next, next < UInt64.max else { throw CommandStreamError.sequence }
        switch direction {
        case .toFrontend:
            if ended {
                switch frame.body {
                case .jobState, .currentJob: break
                default: throw CommandStreamError.closed
                }
            }
            guard (next == 0) == (frame.body == .opened) else { throw CommandStreamError.closed }
        case .toAuthority:
            if ended, case .input = frame.body { throw CommandStreamError.closed }
            if ended, frame.body == .inputEnd { throw CommandStreamError.closed }
        }
    }
    mutating func accept(_ frame: CommandStreamFrame) throws {
        try check(frame)
        if frame.body == .outputEnd || frame.body == .inputEnd { ended = true }
        next += 1
    }
}
