import Darwin
import Dispatch
import Foundation
import RemozioMach
import RemozioProtocol
import Security

/// The registered receive owner routes both message kinds without another port consumer.
public enum ReceivedMachCommandMessage {
    case hello(MachCommandHello)
    case input(ReceivedMachCommandInputSubmission)
}

public enum MachCommandCallerError: Error, Equatable {
    case configuration, malformed, version, timeout, retired, wrongPeer, unavailable
    case mach(Int32), security(OSStatus)
}

enum MachCommandReceiveTimeoutStage: Sendable, Equatable { case previewWait, authenticatedPreview, packetReceive }

/// Receives untrusted submission bytes and authenticates their actual sender. This grants no command authority.
/// This receiver is the port's sole consumer. The owner supplies the borrowed right, serializes access, and owns its lifetime.
public final class MachCommandCallerReceiver {
    public static let messageID: mach_msg_id_t = 0x524d0401
    public static let carrierVersion: UInt32 = 1
    public static let inputMessageID: mach_msg_id_t = 0x524d0402
    public static let inputCarrierVersion: UInt32 = 2
    public static let helloMessageID: mach_msg_id_t = 0x524d0403
    public static let helloReplyMessageID: mach_msg_id_t = 0x524d0404
    public static let handshakeCarrierVersion: UInt32 = 1
    public static let admissionInputMessageID: mach_msg_id_t = 0x524d0405
    public static let admissionInputCarrierVersion: UInt32 = 3
    public static let admissionReplyMessageID: mach_msg_id_t = 0x524d0406
    public static let admissionReplyCarrierVersion: UInt32 = 1
    public static let ioInputMessageID: mach_msg_id_t = 0x524d0407
    public static let ioInputCarrierVersion: UInt32 = 4
    static let mappedIOInputMessageID: mach_msg_id_t = 0x524d040c
    static let mappedIOInputCarrierVersion: UInt32 = 5
    public static let terminalReplyMessageID: mach_msg_id_t = 0x524d0408
    static let streamOutputMessageID: mach_msg_id_t = 0x524d0409
    static let streamOpenedMessageID: mach_msg_id_t = 0x524d040a
    static let streamControlMessageID: mach_msg_id_t = 0x524d040b
    private let port: mach_port_t
    private let maxPayloadBytes: Int
    private let expression: String
    private let userID: uid_t
    private let auditSessionID: au_asid_t?
    private let observeTimeout: (@Sendable (MachCommandReceiveTimeoutStage) -> Void)?
    private let uptimeNanoseconds: () -> UInt64

    public convenience init(receivePort: mach_port_t, policy: XPCPeerPolicy, maxPayloadBytes: Int) throws {
        try self.init(receivePort: receivePort, expression: policy.requirement, userID: policy.expectedUserID,
            auditSessionID: policy.expectedAuditSessionID, maxPayloadBytes: maxPayloadBytes)
    }

    // Internal fixture policy does not expose an ad-hoc option to product callers.
    init(receivePort: mach_port_t, expression: String, userID: uid_t, auditSessionID: au_asid_t?, maxPayloadBytes: Int,
         observeTimeout: (@Sendable (MachCommandReceiveTimeoutStage) -> Void)? = nil,
         uptimeNanoseconds: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }) throws {
        guard receivePort != MACH_PORT_NULL, receivePort != UInt32.max, maxPayloadBytes > 0,
              maxPayloadBytes <= Int(UInt32.max) - 1024 else { throw MachCommandCallerError.configuration }
        self.port = receivePort; self.maxPayloadBytes = maxPayloadBytes
        _ = try Self.compile(expression)
        self.expression = expression
        self.userID = userID; self.auditSessionID = auditSessionID
        self.observeTimeout = observeTimeout; self.uptimeNanoseconds = uptimeNanoseconds
    }

    /// A finite timeout keeps receive loops cancellable. Oversized and malformed packets fail without truncation.
    public func receive(timeoutMilliseconds: UInt32) throws -> sending ReceivedMachCommandSubmission {
        let packet = try receivePacket(timeoutMilliseconds: timeoutMilliseconds, kind: .submission)
        return ReceivedMachCommandSubmission(payload: packet.payload, caller: packet.caller)
    }

    /// Imports one actual input fileport from the verified sender without reading its input.
    public func receiveInput(timeoutMilliseconds: UInt32) throws -> sending ReceivedMachCommandInputSubmission {
        let packet = try receivePacket(timeoutMilliseconds: timeoutMilliseconds, kind: .input)
        guard let input = packet.input else { throw MachCommandCallerError.malformed }
        return ReceivedMachCommandInputSubmission(payload: packet.payload, caller: packet.caller, input: input, carrierVersion: Self.inputCarrierVersion, reply: nil)
    }

    /// Imports the original input and one private reply right from the same verified sender. No input is read.
    public func receiveAdmissionInput(timeoutMilliseconds: UInt32) throws -> sending ReceivedMachCommandInputSubmission {
        let packet = try receivePacket(timeoutMilliseconds: timeoutMilliseconds, kind: .admissionInput)
        guard let input = packet.input, let reply = packet.reply else { throw MachCommandCallerError.malformed }
        return ReceivedMachCommandInputSubmission(payload: packet.payload, caller: packet.caller, input: input,
            carrierVersion: Self.admissionInputCarrierVersion, reply: reply)
    }

    func receiveIOInput(timeoutMilliseconds: UInt32) throws -> sending ReceivedMachCommandInputSubmission {
        let packet = try receivePacket(timeoutMilliseconds: timeoutMilliseconds, kind: .ioInput)
        guard let input = packet.input, let reply = packet.reply, let outputs = packet.outputs else {
            packet.caller.close(); packet.input?.close(); packet.reply?.close(); packet.outputs?.close(); packet.controlTerminal?.close()
            throw MachCommandCallerError.malformed
        }
        return ReceivedMachCommandInputSubmission(payload: packet.payload, caller: packet.caller, input: input,
            carrierVersion: Self.ioInputCarrierVersion, reply: reply, outputs: outputs)
    }

    func receiveMappedIOInput(timeoutMilliseconds: UInt32) throws -> sending ReceivedMachCommandInputSubmission {
        let packet = try receivePacket(timeoutMilliseconds: timeoutMilliseconds, kind: .mappedIOInput)
        guard let input = packet.input, let reply = packet.reply, let outputs = packet.outputs else {
            packet.caller.close(); packet.input?.close(); packet.reply?.close(); packet.outputs?.close(); packet.controlTerminal?.close()
            throw MachCommandCallerError.malformed
        }
        return ReceivedMachCommandInputSubmission(payload: packet.payload, caller: packet.caller, input: input,
            carrierVersion: Self.mappedIOInputCarrierVersion, reply: reply, outputs: outputs, controlTerminal: packet.controlTerminal)
    }

    func receiveAdmissionReply(timeoutMilliseconds: UInt32, previewTimeoutMilliseconds: UInt32? = nil) throws -> sending ReceivedMachCommandSubmission {
        let packet = try receivePacket(timeoutMilliseconds: timeoutMilliseconds, kind: .admissionReply, previewTimeoutMilliseconds: previewTimeoutMilliseconds)
        return ReceivedMachCommandSubmission(payload: packet.payload, caller: packet.caller)
    }

    func receiveTerminalReply(timeoutMilliseconds: UInt32) throws -> sending ReceivedMachCommandSubmission {
        let packet = try receivePacket(timeoutMilliseconds: timeoutMilliseconds, kind: .terminalReply)
        return ReceivedMachCommandSubmission(payload: packet.payload, caller: packet.caller)
    }

    func receiveStreamControl() throws -> sending ReceivedMachCommandSubmission {
        let packet = try receivePacket(timeoutMilliseconds: 0, kind: .streamControl)
        return ReceivedMachCommandSubmission(payload: packet.payload, caller: packet.caller)
    }
    func receiveExecutionEvent(timeoutMilliseconds: UInt32, nonblocking: Bool = false) throws -> sending ReceivedMachCommandExecutionEvent {
        let packet = try receivePacket(timeoutMilliseconds: timeoutMilliseconds, kind: nil,
            previewTimeoutMilliseconds: nonblocking ? 0 : nil, allowNonblockingPreview: nonblocking)
        switch packet.kind {
        case .streamOpened: return .stream(ReceivedMachCommandSubmission(payload: packet.payload, caller: packet.caller), packet.reply)
        case .streamOutput: return .stream(ReceivedMachCommandSubmission(payload: packet.payload, caller: packet.caller), nil)
        case .terminalReply: return .terminal(ReceivedMachCommandSubmission(payload: packet.payload, caller: packet.caller))
        default:
            packet.caller.close(); packet.input?.close(); packet.reply?.close(); packet.outputs?.close(); packet.controlTerminal?.close()
            throw MachCommandCallerError.malformed
        }
    }

    /// Receives protocol metadata and a private reply right from the actual frontend process.
    /// The listener must still reserve capacity and validate its current protected role before retaining a session.
    public func receiveHello(timeoutMilliseconds: UInt32) throws -> sending MachCommandHello {
        let packet = try receivePacket(timeoutMilliseconds: timeoutMilliseconds, kind: .hello)
        guard let reply = packet.reply else { packet.caller.close(); throw MachCommandCallerError.malformed }
        return MachCommandHello(payload: packet.payload, caller: packet.caller, reply: reply)
    }

    func receiveHelloReply(timeoutMilliseconds: UInt32, previewTimeoutMilliseconds: UInt32? = nil) throws -> sending ReceivedMachCommandSubmission {
        let packet = try receivePacket(timeoutMilliseconds: timeoutMilliseconds, kind: .helloReply, previewTimeoutMilliseconds: previewTimeoutMilliseconds)
        return ReceivedMachCommandSubmission(payload: packet.payload, caller: packet.caller)
    }

    /// Select from the actual queue preview, then authenticate and receive through the same parser.
    /// Only hello and original-input submission carriers belong on a command listener.
    /// The timeout bounds queue waiting. Authentication may finish a queued packet through a nonblocking receive.
    public func receiveNext(timeoutMilliseconds: UInt32) throws -> sending ReceivedMachCommandMessage {
        let packet = try receivePacket(timeoutMilliseconds: timeoutMilliseconds, kind: nil, finishQueuedListenerPacket: true)
        switch packet.kind {
        case .hello:
            guard let reply = packet.reply else { packet.caller.close(); throw MachCommandCallerError.malformed }
            return .hello(MachCommandHello(payload: packet.payload, caller: packet.caller, reply: reply))
        case .input, .admissionInput, .ioInput, .mappedIOInput:
            guard let input = packet.input else {
                packet.caller.close(); packet.reply?.close(); packet.outputs?.close(); packet.controlTerminal?.close()
                throw MachCommandCallerError.malformed
            }
            return .input(ReceivedMachCommandInputSubmission(payload: packet.payload, caller: packet.caller, input: input,
                carrierVersion: packet.kind == .input ? Self.inputCarrierVersion :
                    (packet.kind == .mappedIOInput ? Self.mappedIOInputCarrierVersion :
                        (packet.kind == .ioInput ? Self.ioInputCarrierVersion : Self.admissionInputCarrierVersion)),
                reply: packet.reply, outputs: packet.outputs, controlTerminal: packet.controlTerminal))
        default:
            packet.caller.close(); packet.input?.close(); packet.reply?.close(); packet.outputs?.close(); packet.controlTerminal?.close()
            throw MachCommandCallerError.malformed
        }
    }

    private enum PacketKind { case submission, input, hello, helloReply, admissionInput, admissionReply, ioInput, mappedIOInput, terminalReply, streamOutput, streamOpened, streamControl }

    private struct Packet {
        let kind: PacketKind
        let payload: Data
        let caller: RetainedCommandCaller
        let input: RetainedCommandInputDescriptor?
        let reply: MachCommandReplyRight?
        let outputs: RetainedCommandOutputChannels?
        let controlTerminal: RetainedCommandInputDescriptor?
    }

    private func receivePacket(timeoutMilliseconds: UInt32, kind requestedKind: PacketKind?, previewTimeoutMilliseconds: UInt32? = nil,
                               allowNonblockingPreview: Bool = false, finishQueuedListenerPacket: Bool = false) throws -> sending Packet {
        let previewWait = previewTimeoutMilliseconds ?? timeoutMilliseconds
        guard (timeoutMilliseconds > 0 || requestedKind == .streamControl),
              (previewWait > 0 || requestedKind == .streamControl || allowNonblockingPreview),
              previewWait <= timeoutMilliseconds else { throw MachCommandCallerError.configuration }
        let started = uptimeNanoseconds()
        var preview = remozio_mach_preview_t()
        let previewResult = remozio_preview_audit(port, previewWait, &preview)
        if previewResult == MACH_RCV_TIMED_OUT {
            observeTimeout?(.previewWait)
            throw MachCommandCallerError.timeout
        }
        guard previewResult == KERN_SUCCESS else { throw MachCommandCallerError.mach(previewResult) }
        let kind: PacketKind
        if let requestedKind { kind = requestedKind }
        else {
            switch preview.identifier {
            case Self.helloMessageID: kind = .hello
            case Self.inputMessageID: kind = .input
            case Self.admissionInputMessageID: kind = .admissionInput
            case Self.ioInputMessageID: kind = .ioInput
            case Self.mappedIOInputMessageID: kind = .mappedIOInput
            case Self.streamOutputMessageID: kind = .streamOutput
            case Self.streamOpenedMessageID: kind = .streamOpened
            case Self.terminalReplyMessageID: kind = .terminalReply
            default: try discardQueueHead(); throw MachCommandCallerError.malformed
            }
        }
        let isIO = kind == .ioInput || kind == .mappedIOInput
        let hasInput = kind == .input || kind == .admissionInput || isIO
        let hasPort = hasInput || kind == .hello || kind == .streamOpened
        let isStream = [.streamOutput, .streamOpened, .streamControl].contains(kind)
        let payloadLimit = isStream ? min(maxPayloadBytes, CommandStreamFrame.maximumBytes) : kind == .hello || kind == .helloReply || (kind == .admissionReply || kind == .terminalReply) ? min(maxPayloadBytes, CommandHandshakeOffer.maximumBytes) : maxPayloadBytes
        let headerBytes = MemoryLayout<mach_msg_header_t>.size
        let descriptorCount = kind == .mappedIOInput ? 6 : kind == .ioInput ? 5 : (kind == .admissionInput ? 2 : (hasPort ? 1 : 0))
        let descriptorBytes = hasPort ? MemoryLayout<mach_msg_body_t>.size + descriptorCount * MemoryLayout<mach_msg_port_descriptor_t>.size : 0
        let metadataOffset = headerBytes + descriptorBytes
        let prefixBytes = metadataOffset + 8
        let identifier: mach_msg_id_t
        let carrierVersion: UInt32
        switch kind {
        case .submission: identifier = Self.messageID; carrierVersion = Self.carrierVersion
        case .input: identifier = Self.inputMessageID; carrierVersion = Self.inputCarrierVersion
        case .hello: identifier = Self.helloMessageID; carrierVersion = Self.handshakeCarrierVersion
        case .helloReply: identifier = Self.helloReplyMessageID; carrierVersion = Self.handshakeCarrierVersion
        case .admissionInput: identifier = Self.admissionInputMessageID; carrierVersion = Self.admissionInputCarrierVersion
        case .admissionReply: identifier = Self.admissionReplyMessageID; carrierVersion = Self.admissionReplyCarrierVersion
        case .ioInput: identifier = Self.ioInputMessageID; carrierVersion = Self.ioInputCarrierVersion
        case .mappedIOInput: identifier = Self.mappedIOInputMessageID; carrierVersion = Self.mappedIOInputCarrierVersion
        case .terminalReply: identifier = Self.terminalReplyMessageID; carrierVersion = Self.admissionReplyCarrierVersion
        case .streamOutput: identifier = Self.streamOutputMessageID; carrierVersion = Self.handshakeCarrierVersion
        case .streamOpened: identifier = Self.streamOpenedMessageID; carrierVersion = Self.handshakeCarrierVersion
        case .streamControl: identifier = Self.streamControlMessageID; carrierVersion = Self.handshakeCarrierVersion
        }
        let maximumMessage = (prefixBytes + payloadLimit + 3) & ~3
        guard preview.identifier == identifier, preview.size >= prefixBytes, preview.size <= maximumMessage else {
            try discardQueueHead()
            throw MachCommandCallerError.malformed
        }
        // Keep each packet's Security references in its own ownership region.
        let requirement: SecRequirement
        let caller: RetainedCommandCaller
        do {
            requirement = try Self.compile(expression)
            caller = try RetainedCommandCaller(token: preview.token, requirement: requirement,
                userID: userID, auditSessionID: auditSessionID)
        } catch {
            try discardQueueHead()
            throw error
        }
        var completed = false
        defer { if !completed { caller.close() } }
        let elapsed = uptimeNanoseconds() - started
        let budget = UInt64(timeoutMilliseconds) * 1_000_000
        let expired = budget != 0 && elapsed >= budget
        let queuedListenerPacket = finishQueuedListenerPacket && [.hello, .input, .admissionInput, .ioInput, .mappedIOInput].contains(kind)
        if expired && !queuedListenerPacket {
            try discardQueueHead()
            observeTimeout?(.authenticatedPreview)
            if kind == .terminalReply { throw CommandTerminalResultError.deadlineExceeded }
            throw MachCommandCallerError.timeout
        }
        let remaining = budget == 0 || expired ? 0 : UInt32((budget - elapsed + 999_999) / 1_000_000)
        let capacity = maximumMessage + MemoryLayout<mach_msg_audit_trailer_t>.size
        let storage = UnsafeMutableRawPointer.allocate(byteCount: capacity,
            alignment: max(MemoryLayout<mach_msg_header_t>.alignment, MemoryLayout<mach_msg_audit_trailer_t>.alignment))
        defer { storage.deallocate() }
        storage.initializeMemory(as: UInt8.self, repeating: 0, count: capacity)
        let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
        let result = remozio_receive_audit(header, UInt32(capacity), port, remaining)
        if result == MACH_RCV_TIMED_OUT {
            observeTimeout?(.packetReceive)
            if kind == .terminalReply { throw CommandTerminalResultError.deadlineExceeded }
            throw MachCommandCallerError.timeout
        }
        guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        defer { mach_msg_destroy(header) }
        let value = header.pointee
        guard (value.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0) == hasPort, value.msgh_remote_port == MACH_PORT_NULL,
              value.msgh_voucher_port == MACH_PORT_NULL, value.msgh_local_port == port,
              value.msgh_id == identifier, value.msgh_size >= prefixBytes,
              value.msgh_size <= maximumMessage else { throw MachCommandCallerError.malformed }
        let size = Int(value.msgh_size)
        let trailerOffset = (size + 3) & ~3
        guard trailerOffset <= capacity - MemoryLayout<mach_msg_audit_trailer_t>.size else {
            throw MachCommandCallerError.malformed
        }
        let trailer = storage.loadUnaligned(fromByteOffset: trailerOffset, as: mach_msg_audit_trailer_t.self)
        guard trailer.msgh_trailer_type == MACH_MSG_TRAILER_FORMAT_0,
              trailer.msgh_trailer_size == MemoryLayout<mach_msg_audit_trailer_t>.size,
              trailer.msgh_seqno == preview.sequence, value.msgh_size == preview.size, value.msgh_id == preview.identifier,
              Self.sameToken(trailer.msgh_audit, preview.token) else {
            throw MachCommandCallerError.malformed
        }
        var carriedPorts: [mach_port_t] = []
        if hasPort {
            let body = storage.loadUnaligned(fromByteOffset: headerBytes, as: mach_msg_body_t.self)
            guard body.msgh_descriptor_count == descriptorCount else { throw MachCommandCallerError.malformed }
            for index in 0..<descriptorCount {
                let descriptor = storage.loadUnaligned(fromByteOffset: headerBytes + MemoryLayout<mach_msg_body_t>.size +
                    index * MemoryLayout<mach_msg_port_descriptor_t>.size, as: mach_msg_port_descriptor_t.self)
                guard descriptor.type == UInt32(MACH_MSG_PORT_DESCRIPTOR),
                      descriptor.disposition == UInt32(MACH_MSG_TYPE_PORT_SEND),
                      (descriptor.name != MACH_PORT_NULL || (kind == .mappedIOInput && index == 3)),
                      descriptor.name != UInt32.max else {
                    throw MachCommandCallerError.malformed
                }
                carriedPorts.append(descriptor.name)
            }
        }
        let version = UInt32(bigEndian: storage.loadUnaligned(fromByteOffset: metadataOffset, as: UInt32.self))
        guard version == carrierVersion else { throw MachCommandCallerError.version }
        let count = Int(UInt32(bigEndian: storage.loadUnaligned(fromByteOffset: metadataOffset + 4, as: UInt32.self)))
        guard count > 0, count <= payloadLimit, (prefixBytes + count + 3) & ~3 == size else {
            throw MachCommandCallerError.malformed
        }
        for offset in (prefixBytes + count)..<size where storage.load(fromByteOffset: offset, as: UInt8.self) != 0 {
            throw MachCommandCallerError.malformed
        }
        try caller.recheck(requirement: requirement, userID: userID, auditSessionID: auditSessionID)
        let input = hasInput ? try RetainedCommandInputDescriptor(fileport: carriedPorts[0]) : nil
        func takeReply(_ index: Int, identifier: mach_msg_id_t) -> MachCommandReplyRight {
            let right = MachCommandReplyRight(taking: carriedPorts[index], identifier: identifier)
            let offset = headerBytes + MemoryLayout<mach_msg_body_t>.size + index * MemoryLayout<mach_msg_port_descriptor_t>.size
            var descriptor = storage.loadUnaligned(fromByteOffset: offset, as: mach_msg_port_descriptor_t.self)
            descriptor.name = 0
            storage.storeBytes(of: descriptor, toByteOffset: offset, as: mach_msg_port_descriptor_t.self)
            return right
        }
        let controlTerminal: RetainedCommandInputDescriptor?
        if kind == .mappedIOInput, carriedPorts[3] != MACH_PORT_NULL {
            let terminal = try RetainedCommandInputDescriptor(fileport: carriedPorts[3])
            try terminal.withBorrowedDescriptor { fd in
                let flags = fcntl(fd, F_GETFL)
                guard flags >= 0 else { throw RetainedCommandInputError.system(errno) }
                guard flags & O_ACCMODE == O_RDWR, flags & O_EVTONLY == 0, isatty(fd) == 1 else {
                    throw MachCommandCallerError.malformed
                }
            }
            controlTerminal = terminal
        } else { controlTerminal = nil }
        let outputs: RetainedCommandOutputChannels?
        if isIO {
            let output = try RetainedCommandOutputDescriptor(fileport: carriedPorts[1])
            let error = try RetainedCommandOutputDescriptor(fileport: carriedPorts[2])
            outputs = RetainedCommandOutputChannels(output: output, error: error,
                result: takeReply(kind == .mappedIOInput ? 5 : 4, identifier: Self.terminalReplyMessageID))
        } else { outputs = nil }
        let reply: MachCommandReplyRight?
        if kind == .hello || kind == .admissionInput || isIO {
            let index = kind == .hello ? 0 : (kind == .mappedIOInput ? 4 : (kind == .ioInput ? 3 : 1))
            reply = takeReply(index, identifier: kind == .hello ? Self.helloReplyMessageID : Self.admissionReplyMessageID)
        } else if kind == .streamOpened {
            reply = takeReply(0, identifier: Self.streamControlMessageID)
        } else { reply = nil }
        completed = true
        return Packet(kind: kind, payload: Data(bytes: storage.advanced(by: prefixBytes), count: count), caller: caller, input: input, reply: reply, outputs: outputs, controlTerminal: controlTerminal)
    }

    private func discardQueueHead() throws {
        let result = remozio_discard_message(port)
        guard result == MACH_MSG_SUCCESS || result == MACH_RCV_TOO_LARGE else {
            throw MachCommandCallerError.mach(result)
        }
    }

    private static func sameToken(_ first: audit_token_t, _ second: audit_token_t) -> Bool {
        var first = first, second = second
        return withUnsafeBytes(of: &first) { a in withUnsafeBytes(of: &second) { b in a.elementsEqual(b) } }
    }

    fileprivate static func compile(_ expression: String) throws -> SecRequirement {
        var requirement: SecRequirement?
        let status = SecRequirementCreateWithString(expression as CFString, [], &requirement)
        guard status == errSecSuccess, let requirement else { throw MachCommandCallerError.security(status) }
        return requirement
    }
}

enum ReceivedMachCommandExecutionEvent {
    case stream(ReceivedMachCommandSubmission, MachCommandReplyRight?)
    case terminal(ReceivedMachCommandSubmission)
}

/// Payload fields remain untrusted. Only the receiver can construct this sender binding.
public struct ReceivedMachCommandSubmission {
    public let payload: Data
    public let caller: RetainedCommandCaller
    fileprivate init(payload: Data, caller: RetainedCommandCaller) { self.payload = payload; self.caller = caller }
}

/// The input remains caller-controlled. Holding its descriptor grants no execution authority.
public struct ReceivedMachCommandInputSubmission {
    public let payload: Data
    public let caller: RetainedCommandCaller
    public let input: RetainedCommandInputDescriptor
    public let carrierVersion: UInt32
    let reply: MachCommandReplyRight?
    let outputs: RetainedCommandOutputChannels?
    let controlTerminal: RetainedCommandInputDescriptor?
    private let ownership = InputSubmissionOwnership()
    fileprivate init(payload: Data, caller: RetainedCommandCaller, input: RetainedCommandInputDescriptor,
                     carrierVersion: UInt32, reply: MachCommandReplyRight?, outputs: RetainedCommandOutputChannels? = nil,
                     controlTerminal: RetainedCommandInputDescriptor? = nil) {
        self.payload = payload; self.caller = caller; self.input = input
        self.carrierVersion = carrierVersion; self.reply = reply; self.outputs = outputs; self.controlTerminal = controlTerminal
    }
    /// Sends one opaque control reply before input transfer. It is not a no-admission proof or retry grant.
    public func sendAdmissionReply(_ bytes: Data, timeoutMilliseconds: UInt32 = 5000) throws {
        guard !ownership.claimed, [MachCommandCallerReceiver.admissionInputCarrierVersion, MachCommandCallerReceiver.ioInputCarrierVersion,
                   MachCommandCallerReceiver.mappedIOInputCarrierVersion].contains(carrierVersion),
              let reply else { throw MachCommandHandshakeError.retired }
        try reply.send(bytes, timeoutMilliseconds: timeoutMilliseconds)
    }
    /// Copies share this claim. A repeated transfer cannot close objects already held by a capture.
    func claimForCaptureOwner() throws {
        guard !ownership.claimed else { throw RetainedCommandCaptureError.alreadyOwned }
        ownership.claimed = true
    }
    /// The original claim protects aliases. The new receipt owns the same kernel objects but no reply right.
    func takeForAdmissionAttempt() throws -> (ReceivedMachCommandInputSubmission, MachCommandReplyRight) {
        guard !ownership.claimed else { throw RetainedCommandCaptureError.alreadyOwned }
        guard [MachCommandCallerReceiver.admissionInputCarrierVersion, MachCommandCallerReceiver.ioInputCarrierVersion,
                   MachCommandCallerReceiver.mappedIOInputCarrierVersion].contains(carrierVersion), let reply else {
            closeIfUnclaimed(); throw MachCommandHandshakeError.incompatible
        }
        ownership.claimed = true
        return (ReceivedMachCommandInputSubmission(payload: payload, caller: caller, input: input,
            carrierVersion: carrierVersion, reply: nil, outputs: outputs, controlTerminal: controlTerminal), reply)
    }
    func closeIfUnclaimed() {
        if !ownership.claimed { ownership.claimed = true; caller.close(); input.close(); reply?.close(); outputs?.close(); controlTerminal?.close() }
    }
}

private final class InputSubmissionOwnership { var claimed = false }

public enum RetainedCommandInputError: Error, Equatable {
    case closed, invalidBinding, notReadable
    case system(Int32)
}

/// Owns an imported descriptor without reading input or changing shared open-file flags.
/// The owner serializes access and closes it when the request retires.
public final class RetainedCommandInputDescriptor {
    private var descriptor: Int32

    fileprivate init(fileport: mach_port_t) throws {
        let imported = fileport_makefd(fileport)
        guard imported >= 0 else { throw RetainedCommandInputError.system(errno) }
        do { try CommandStreamSource.rejectTerminalAlias(imported) }
        catch { _ = Darwin.close(imported); throw error }
        let flags = fcntl(imported, F_GETFD)
        guard flags >= 0, fcntl(imported, F_SETFD, flags | FD_CLOEXEC) == 0 else {
            let error = errno
            _ = Darwin.close(imported)
            throw RetainedCommandInputError.system(error)
        }
        descriptor = imported
    }

    deinit { close() }

    /// Borrow only for this call. Do not close, retain, or pass this descriptor to another thread.
    public func withBorrowedDescriptor<T>(_ body: (Int32) throws -> T) throws -> T {
        guard descriptor >= 0 else { throw RetainedCommandInputError.closed }
        return try body(descriptor)
    }

    /// Observes this retained object. The authority supplies and retains the stream binding; this method reads no source bytes.
    public func capture(streamBinding: Data) throws -> CapturedCommandInput {
        guard streamBinding.count == 16 else { throw RetainedCommandInputError.invalidBinding }
        return try withBorrowedDescriptor { fd in
            let flags = fcntl(fd, F_GETFL)
            guard flags >= 0 else { throw RetainedCommandInputError.system(errno) }
            guard flags & O_ACCMODE != O_WRONLY, flags & O_EVTONLY == 0 else { throw RetainedCommandInputError.notReadable }
            var information = stat()
            guard fstat(fd, &information) == 0 else { throw RetainedCommandInputError.system(errno) }
            let type = information.st_mode & S_IFMT
            if type == S_IFCHR {
                var null = stat()
                if fstatat(AT_FDCWD, "/dev/null", &null, AT_SYMLINK_NOFOLLOW) == 0,
                   null.st_mode & S_IFMT == S_IFCHR, null.st_rdev == information.st_rdev {
                    return CapturedCommandInput(kind: .null, streamBinding: nil, observedPath: nil, identity: nil)
                }
            }
            let kind: CommandInputKind
            switch type {
            case S_IFREG: kind = .file
            case S_IFDIR: kind = .directory
            case S_IFIFO: kind = .pipe
            case S_IFSOCK: kind = .socket
            case S_IFCHR: kind = isatty(fd) == 1 ? .tty : .device
            case S_IFBLK: kind = .device
            default: kind = .other
            }
            var path = [CChar](repeating: 0, count: Int(PATH_MAX))
            let result = path.withUnsafeMutableBufferPointer { fcntl(fd, F_GETPATH, $0.baseAddress!) }
            let observedPath: Data?
            if result == 0, path.first == 0x2f, let end = path.firstIndex(of: 0) {
                observedPath = Data(path[..<end].map { UInt8(bitPattern: $0) })
            } else { observedPath = nil }
            return CapturedCommandInput(kind: kind, streamBinding: streamBinding, observedPath: observedPath,
                identity: CapturedFileIdentity(device: UInt64(UInt32(bitPattern: information.st_dev)), inode: information.st_ino))
        }
    }

    public func close() {
        if descriptor >= 0 { _ = Darwin.close(descriptor); descriptor = -1 }
    }
}

/// Retains an OS process incarnation and dynamic code reference. It is not user consent or an execution permit.
/// The owner serializes access, closes this record on retirement, and supplies current protected policy at dispatch.
public final class RetainedCommandCaller {
    public let requester: CapturedRequester
    public let auditSessionID: au_asid_t
    private var token: audit_token_t
    private var code: SecCode?
    private var lifetimeObserver: OpaquePointer?
    private(set) var requesterExitObserved = false

    fileprivate init(token: audit_token_t, requirement: SecRequirement, userID: uid_t, auditSessionID: au_asid_t?) throws {
        try Self.credentials(token, userID: userID, auditSessionID: auditSessionID)
        let code = try Self.code(token)
        try Self.valid(code, requirement: requirement)
        let path = try Self.path(token)
        var information: CFDictionary?
        let status = remozio_copy_dynamic_signing_information(code, &information)
        guard status == errSecSuccess, let values = information as? [String: Any],
              let identifier = values[kSecCodeInfoIdentifier as String] as? String,
              let hash = values[kSecCodeInfoUnique as String] as? Data, hash.count == 20,
              let flags = values[kSecCodeInfoFlags as String] as? NSNumber else { throw MachCommandCallerError.unavailable }
        let session = getsid(audit_token_to_pid(token))
        try Self.valid(code, requirement: requirement)
        guard try Self.path(token) == path else { throw MachCommandCallerError.wrongPeer }
        self.token = token; self.code = code; self.auditSessionID = audit_token_to_asid(token)
        requester = CapturedRequester(executablePath: path, realUID: audit_token_to_ruid(token),
            effectiveUID: audit_token_to_euid(token), pid: UInt32(audit_token_to_pid(token)),
            pidVersion: UInt32(bitPattern: audit_token_to_pidversion(token)),
            signing: CapturedSigningIdentity(status: remozio_code_is_adhoc(flags.uint32Value) ? .adHoc : .validated,
                identifier: identifier, team: values[kSecCodeInfoTeamIdentifier as String] as? String, cdHash: hash),
            sessionID: session > 0 ? UInt32(session) : nil, ttyPath: nil)
        // Missing observation support leaves the existing dynamic code validation in force.
        _ = remozio_command_caller_observer_create(&self.token, &lifetimeObserver)
    }
    deinit { close() }

    /// Rechecking a failed or closed record never recaptures a replacement process.
    public func recheck(currentPolicy: XPCPeerPolicy) throws {
        try recheck(expression: currentPolicy.requirement, userID: currentPolicy.expectedUserID,
            auditSessionID: currentPolicy.expectedAuditSessionID)
    }

    func recheck(expression: String, userID: uid_t, auditSessionID: au_asid_t?) throws {
        guard code != nil else { throw MachCommandCallerError.retired }
        do {
            let requirement = try MachCommandCallerReceiver.compile(expression)
            try recheck(requirement: requirement, userID: userID, auditSessionID: auditSessionID)
        } catch { close(); throw error }
    }

    fileprivate func recheck(requirement: SecRequirement, userID: uid_t, auditSessionID: au_asid_t?) throws {
        guard let code else { throw MachCommandCallerError.retired }
        do {
            observeLifetime()
            if requesterExitObserved { throw MachCommandCallerError.unavailable }
            try Self.credentials(token, userID: userID, auditSessionID: auditSessionID)
            try Self.valid(code, requirement: requirement)
            guard try Self.path(token) == requester.executablePath else { throw MachCommandCallerError.wrongPeer }
        } catch { close(); throw error }
    }

    /// Only a new terminal-layout capture requests this observation. Legacy profiles retain their existing behavior.
    func captureTerminalContext(expression: String, userID: uid_t, auditSessionID: au_asid_t?) throws -> CommandCallerTerminalContext {
        try recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        let context = try CommandCallerTerminalContext(originalAuditToken: token)
        try recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        return context
    }

    /// Recheck the same caller record and terminal context. This never observes a replacement caller as the original.
    func recheckTerminalContext(_ context: CommandCallerTerminalContext, expression: String, userID: uid_t, auditSessionID: au_asid_t?) throws {
        try recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        try context.recheck(originalAuditToken: token)
        try recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
    }

    /// Observes parent links with kernel process incarnations. Ancestors are observations, not trusted initiators or consent.
    public func captureAncestry(currentPolicy: XPCPeerPolicy, maximumEntries: Int = 16,
                               checkCancellation: () throws -> Void = {}) throws -> CapturedAncestry {
        try captureAncestry(expression: currentPolicy.requirement, userID: currentPolicy.expectedUserID,
            auditSessionID: currentPolicy.expectedAuditSessionID, maximumEntries: maximumEntries, checkCancellation: checkCancellation)
    }

    func captureAncestry(expression: String, userID: uid_t, auditSessionID: au_asid_t?, maximumEntries: Int = 16,
                        checkCancellation: () throws -> Void = {}) throws -> CapturedAncestry {
        guard (0...64).contains(maximumEntries) else { throw MachCommandCallerError.configuration }
        try recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        do {
            let result = try CommandAncestryObservation.capture(source: token, maximumEntries: maximumEntries,
                checkCancellation: checkCancellation)
            try recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
            return result
        } catch let failure as MachCommandCallerError { close(); throw failure }
    }

    /// Read-only kernel binding values do not connect the ownership regions of two retained callers.
    var retainedAuditBinding: Data? {
        guard code != nil else { return nil }
        var value = token
        return withUnsafeBytes(of: &value) { Data($0) }
    }
    func hasSameAuditBinding(as other: RetainedCommandCaller) -> Bool {
        guard let first = retainedAuditBinding, let second = other.retainedAuditBinding else { return false }
        return first == second
    }

    private func observeLifetime() {
        guard let lifetimeObserver else { return }
        var observation = REMOZIO_CALLER_UNAVAILABLE
        _ = remozio_command_caller_observer_poll(lifetimeObserver, &observation)
        if observation == REMOZIO_CALLER_EXITED { requesterExitObserved = true }
    }

    public func close() {
        code = nil
        remozio_command_caller_observer_close(lifetimeObserver); lifetimeObserver = nil
    }

    private static func credentials(_ token: audit_token_t, userID: uid_t, auditSessionID: au_asid_t?) throws {
        guard audit_token_to_pid(token) > 0, audit_token_to_euid(token) == userID,
              auditSessionID == nil || audit_token_to_asid(token) == auditSessionID else { throw MachCommandCallerError.wrongPeer }
    }

    private static func code(_ token: audit_token_t) throws -> SecCode {
        var token = token
        let data = withUnsafeBytes(of: &token) { Data($0) }
        var code: SecCode?
        let status = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: data] as CFDictionary, [], &code)
        guard status == errSecSuccess, let code else { throw MachCommandCallerError.security(status) }
        return code
    }

    private static func valid(_ code: SecCode, requirement: SecRequirement) throws {
        let status = SecCodeCheckValidity(code, [], requirement)
        guard status == errSecSuccess else { throw MachCommandCallerError.security(status) }
    }

    private static func path(_ token: audit_token_t) throws -> Data {
        var token = token, bytes = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let count = proc_pidpath_audittoken(&token, &bytes, UInt32(bytes.count))
        guard count > 0, let end = bytes.firstIndex(of: 0), end > 0, bytes[0] == 0x2f else {
            throw MachCommandCallerError.unavailable
        }
        return Data(bytes[..<end].map { UInt8(bitPattern: $0) })
    }
}
