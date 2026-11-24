import Darwin
import Dispatch
import Foundation
import RemozioProtocol
import Security

public enum MachCommandHandshakeError: Error, Equatable { case invalidConfiguration, invalidMessage, incompatible, wrongBinding, retired }

/// Local component support. These declarations grant no command or retry authority.
public struct CommandHandshakeCapabilities: Equatable, Sendable {
    public let wireVersions: Set<UInt64>
    public let submissionSchemaVersions: Set<UInt64>
    public let inputCarrierVersions: Set<UInt64>
    public static let current = CommandHandshakeCapabilities(knownWire: [1], submission: CommandSubmission.supportedSchemaVersions,
        input: [UInt64(MachCommandCallerReceiver.inputCarrierVersion)])
    /// Explicit carrier support. The serial host keeps its legacy default until its reply controller is integrated.
    public static let admissionReplies = CommandHandshakeCapabilities(knownWire: [1], submission: CommandSubmission.supportedSchemaVersions,
        input: [UInt64(MachCommandCallerReceiver.admissionInputCarrierVersion)])
    /// Explicit typed result contract. Legacy profiles cannot acquire these meanings.
    public static let admissionResults = CommandHandshakeCapabilities(knownWire: [2], submission: CommandSubmission.supportedSchemaVersions,
        input: [UInt64(MachCommandCallerReceiver.admissionInputCarrierVersion)])
    public static let executionChannels = CommandHandshakeCapabilities(knownWire: [3], submission: CommandSubmission.supportedSchemaVersions,
        input: [UInt64(MachCommandCallerReceiver.ioInputCarrierVersion)])
    public static let streamingExecution = CommandHandshakeCapabilities(knownWire: [4], submission: CommandSubmission.supportedSchemaVersions,
        input: [UInt64(MachCommandCallerReceiver.ioInputCarrierVersion)])
    /// Separate stdio fileports with private signal and cancellation controls. No PTY stream is negotiated.
    public static let pipeExecutionControls = CommandHandshakeCapabilities(knownWire: [5], submission: CommandSubmission.supportedSchemaVersions,
        input: [UInt64(MachCommandCallerReceiver.ioInputCarrierVersion)])
    /// Explicit PTY streaming with native target job-state observations.
    public static let streamingJobExecution = CommandHandshakeCapabilities(knownWire: [6], submission: CommandSubmission.supportedSchemaVersions,
        input: [UInt64(MachCommandCallerReceiver.ioInputCarrierVersion)])
    /// Explicit separate stdio and controls with native target job-state observations.
    public static let pipeJobExecutionControls = CommandHandshakeCapabilities(knownWire: [7], submission: CommandSubmission.supportedSchemaVersions,
        input: [UInt64(MachCommandCallerReceiver.ioInputCarrierVersion)])
    /// Explicit schema-3 terminal routing with a separate caller terminal and target job state.
    public static let mappedTerminalJobExecution = CommandHandshakeCapabilities(knownWire: [8], submission: CommandSubmission.supportedSchemaVersions,
        input: [UInt64(MachCommandCallerReceiver.mappedIOInputCarrierVersion)])
    /// Explicit schema-3 direct streams with private controls and target job state.
    public static let mappedPipeJobExecutionControls = CommandHandshakeCapabilities(knownWire: [9], submission: CommandSubmission.supportedSchemaVersions,
        input: [UInt64(MachCommandCallerReceiver.mappedIOInputCarrierVersion)])
    /// Mapped PTY routing with nonce-bound current job queries. Historical profiles keep their original meanings.
    public static let mappedTerminalCurrentJobExecution = CommandHandshakeCapabilities(knownWire: [10], submission: CommandSubmission.supportedSchemaVersions,
        input: [UInt64(MachCommandCallerReceiver.mappedIOInputCarrierVersion)])
    /// Separate stdio controls with nonce-bound current job queries.
    public static let mappedPipeCurrentJobExecutionControls = CommandHandshakeCapabilities(knownWire: [11], submission: CommandSubmission.supportedSchemaVersions,
        input: [UInt64(MachCommandCallerReceiver.mappedIOInputCarrierVersion)])
    fileprivate static let implemented = CommandHandshakeCapabilities(knownWire: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], submission: CommandSubmission.supportedSchemaVersions,
        input: [UInt64(MachCommandCallerReceiver.inputCarrierVersion), UInt64(MachCommandCallerReceiver.admissionInputCarrierVersion), UInt64(MachCommandCallerReceiver.ioInputCarrierVersion), UInt64(MachCommandCallerReceiver.mappedIOInputCarrierVersion)])
    private init(knownWire: Set<UInt64>, submission: Set<UInt64>, input: Set<UInt64>) {
        wireVersions = knownWire; submissionSchemaVersions = submission; inputCarrierVersions = input
    }
    public init(wireVersions: Set<UInt64>, submissionSchemaVersions: Set<UInt64>, inputCarrierVersions: Set<UInt64>) throws {
        for values in [wireVersions, submissionSchemaVersions, inputCarrierVersions] {
            guard (1...16).contains(values.count), values.allSatisfy({ (1...65535).contains($0) }) else {
                throw MachCommandHandshakeError.invalidConfiguration
            }
        }
        self.init(knownWire: wireVersions, submission: submissionSchemaVersions, input: inputCarrierVersions)
    }
    var fields: CBORValue { .map([0: .array(wireVersions.sorted().map(CBORValue.unsigned)),
        1: .array(submissionSchemaVersions.sorted().map(CBORValue.unsigned)),
        2: .array(inputCarrierVersions.sorted().map(CBORValue.unsigned))]) }
    static func decode(_ raw: CBORValue) throws -> Self {
        guard case .map(let fields) = raw, Set(fields.keys) == [0, 1, 2] else { throw MachCommandHandshakeError.invalidMessage }
        func versions(_ key: UInt64) throws -> Set<UInt64> {
            guard case .array(let values) = fields[key] else { throw MachCommandHandshakeError.invalidMessage }
            var result: [UInt64] = []
            for value in values {
                guard case .unsigned(let number) = value, result.last == nil || result.last! < number else {
                    throw MachCommandHandshakeError.invalidMessage
                }
                result.append(number)
            }
            return Set(result)
        }
        return try Self(wireVersions: versions(0), submissionSchemaVersions: versions(1), inputCarrierVersions: versions(2))
    }
}

/// Harmless protocol metadata. It contains no scope, command, input, rationale, or credential.
public struct CommandHandshakeOffer: Equatable, Sendable {
    public static let maximumBytes = 4096
    public let nonce: Data
    public let capabilities: CommandHandshakeCapabilities
    public init(nonce: Data, capabilities: CommandHandshakeCapabilities = .current) throws {
        guard nonce.count == 32 else { throw MachCommandHandshakeError.invalidConfiguration }
        self.nonce = nonce; self.capabilities = capabilities
    }
    public var canonicalBytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(nonce), 2: capabilities.fields]), limits: Self.limits())
    } }
    public init(canonicalBytes: Data) throws {
        guard case .map(let fields) = try DeterministicCBOR.decode(canonicalBytes, limits: Self.limits()),
              Set(fields.keys) == [0, 1, 2], fields[0] == .unsigned(1), case .bytes(let nonce) = fields[1],
              let capabilities = fields[2] else { throw MachCommandHandshakeError.invalidMessage }
        try self.init(nonce: nonce, capabilities: CommandHandshakeCapabilities.decode(capabilities))
        guard try self.canonicalBytes == canonicalBytes else { throw MachCommandHandshakeError.invalidMessage }
    }
    static func limits() throws -> CBORLimits { try CBORLimits(maxBytes: maximumBytes, maxDepth: 5, maxItems: 128) }
}

/// A current local protocol selection. The binding alone grants neither admission nor execution authority.
public struct CommandHandshakeProfile: Equatable, Sendable {
    public let wireVersion: UInt64
    public let submissionSchemaVersion: UInt64
    public let inputCarrierVersion: UInt64
    public let callerBinding: Data
    public let macID: Data
    public let accountID: Data
    var fields: CBORValue { .map([0: .unsigned(wireVersion), 1: .unsigned(submissionSchemaVersion),
        2: .unsigned(inputCarrierVersion), 3: .bytes(callerBinding), 4: .bytes(macID), 5: .bytes(accountID)]) }
    static func decode(_ raw: CBORValue) throws -> Self {
        guard case .map(let fields) = raw, Set(fields.keys) == Set((0...5).map(UInt64.init)),
              case .unsigned(let wire) = fields[0], case .unsigned(let submission) = fields[1], case .unsigned(let input) = fields[2],
              case .bytes(let binding) = fields[3], binding.count == 16, case .bytes(let mac) = fields[4], mac.count == 16,
              case .bytes(let account) = fields[5], account.count == 16 else { throw MachCommandHandshakeError.invalidMessage }
        return Self(wireVersion: wire, submissionSchemaVersion: submission, inputCarrierVersion: input,
            callerBinding: binding, macID: mac, accountID: account)
    }
    var supportsMappedLayout: Bool { [8, 9, 10, 11].contains(wireVersion) && submissionSchemaVersion == 1 && inputCarrierVersion == 5 }
    var supportsAdmissionResults: Bool { supportsMappedLayout || submissionSchemaVersion == 1 &&
        ((wireVersion == 2 && inputCarrierVersion == 3) || ([3, 4, 5, 6, 7].contains(wireVersion) && inputCarrierVersion == 4)) }
    var supportsExecutionChannels: Bool { supportsMappedLayout || [3, 4, 5, 6, 7].contains(wireVersion) && submissionSchemaVersion == 1 && inputCarrierVersion == 4 }
    var supportsStreamingExecution: Bool { supportsMappedLayout && [8, 10].contains(wireVersion) ||
        [4, 6].contains(wireVersion) && submissionSchemaVersion == 1 && inputCarrierVersion == 4 }
    var supportsPipeExecutionControls: Bool { supportsMappedLayout && [9, 11].contains(wireVersion) ||
        [5, 7].contains(wireVersion) && submissionSchemaVersion == 1 && inputCarrierVersion == 4 }
    var supportsJobState: Bool { supportsMappedLayout || [6, 7].contains(wireVersion) && submissionSchemaVersion == 1 && inputCarrierVersion == 4 }
    var supportsCurrentJob: Bool { supportsMappedLayout && [10, 11].contains(wireVersion) }
    var supportsExecutionControls: Bool { supportsStreamingExecution || supportsPipeExecutionControls }
    func supported(by capabilities: CommandHandshakeCapabilities) -> Bool {
        let understood = (wireVersion == 1 && submissionSchemaVersion == 1 && [2, 3].contains(inputCarrierVersion)) || supportsAdmissionResults
        return understood && capabilities.wireVersions.contains(wireVersion) && capabilities.submissionSchemaVersions.contains(submissionSchemaVersion)
            && capabilities.inputCarrierVersions.contains(inputCarrierVersion)
    }
}

struct CommandHandshakeReply {
    let nonce: Data
    let profile: CommandHandshakeProfile?
    var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(nonce), 2: .unsigned(profile == nil ? 2 : 1),
            3: profile?.fields ?? .null]), limits: CommandHandshakeOffer.limits())
    } }
    static func decode(_ bytes: Data, offer: CommandHandshakeOffer, macID: Data, accountID: Data) throws -> CommandHandshakeProfile {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: CommandHandshakeOffer.limits()),
              Set(fields.keys) == [0, 1, 2, 3], fields[0] == .unsigned(1), fields[1] == .bytes(offer.nonce) else {
            throw MachCommandHandshakeError.invalidMessage
        }
        if fields[2] == .unsigned(2), fields[3] == .null { throw MachCommandHandshakeError.incompatible }
        guard fields[2] == .unsigned(1), let raw = fields[3] else { throw MachCommandHandshakeError.invalidMessage }
        let profile = try CommandHandshakeProfile.decode(raw)
        guard profile.macID == macID, profile.accountID == accountID else { throw MachCommandHandshakeError.wrongBinding }
        guard profile.supported(by: offer.capabilities), profile.supported(by: .implemented) else {
            throw MachCommandHandshakeError.incompatible
        }
        return profile
    }
}

/// Owns the imported private reply right and verified hello sender until negotiation consumes them.
public final class MachCommandHello {
    public let payload: Data
    private var caller: RetainedCommandCaller?
    private var reply: MachCommandReplyRight?
    init(payload: Data, caller: RetainedCommandCaller, reply: MachCommandReplyRight) {
        self.payload = payload; self.caller = caller; self.reply = reply
    }
    func take() throws -> (RetainedCommandCaller, MachCommandReplyRight) {
        guard let caller, let reply else { throw MachCommandHandshakeError.retired }
        self.caller = nil; self.reply = nil
        return (caller, reply)
    }
    public func close() { caller?.close(); caller = nil; reply?.close(); reply = nil }
    deinit { close() }
}

/// Root-side ownership of one verified frontend incarnation. The host serializes access and bounds retained sessions.
/// Construct only after protected deployment, current code-role validation, and a session-capacity reservation.
public final class RetainedCommandHandshake {
    public let profile: CommandHandshakeProfile
    private let caller: RetainedCommandCaller
    private var closed = false
    public convenience init(hello: sending MachCommandHello, capabilities: CommandHandshakeCapabilities = .current,
                macID: Data, accountID: Data, currentPolicy: XPCPeerPolicy, timeoutMilliseconds: UInt32 = 5000) throws {
        try self.init(hello: hello, capabilities: capabilities, macID: macID, accountID: accountID,
            expression: currentPolicy.requirement, userID: currentPolicy.expectedUserID,
            auditSessionID: currentPolicy.expectedAuditSessionID, timeoutMilliseconds: timeoutMilliseconds)
    }
    init(hello: MachCommandHello, capabilities: CommandHandshakeCapabilities = .current, macID: Data, accountID: Data,
         expression: String, userID: uid_t, auditSessionID: au_asid_t?, timeoutMilliseconds: UInt32 = 5000) throws {
        let (caller, reply) = try hello.take()
        var completed = false
        defer { reply.close(); if !completed { caller.close() } }
        guard macID.count == 16, accountID.count == 16, (1...60_000).contains(timeoutMilliseconds),
              capabilities.wireVersions.isSubset(of: CommandHandshakeCapabilities.implemented.wireVersions),
              capabilities.submissionSchemaVersions.isSubset(of: CommandHandshakeCapabilities.implemented.submissionSchemaVersions),
              capabilities.inputCarrierVersions.isSubset(of: CommandHandshakeCapabilities.implemented.inputCarrierVersions) else {
            throw MachCommandHandshakeError.invalidConfiguration
        }
        try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        let offer = try CommandHandshakeOffer(canonicalBytes: hello.payload)
        let wires = offer.capabilities.wireVersions.intersection(capabilities.wireVersions).sorted(by: >)
        let inputs = offer.capabilities.inputCarrierVersions.intersection(capabilities.inputCarrierVersions).sorted(by: >)
        let selected = wires.flatMap { wire in inputs.compactMap { input -> (UInt64, UInt64)? in
            (wire == 1 && [2, 3].contains(input)) || (wire == 2 && input == 3) ||
                ([3, 4, 5, 6, 7].contains(wire) && input == 4) || ([8, 9, 10, 11].contains(wire) && input == 5) ? (wire, input) : nil
        } }.first
        guard let (wire, input) = selected,
              let submission = offer.capabilities.submissionSchemaVersions.intersection(capabilities.submissionSchemaVersions).max() else {
            try reply.send(CommandHandshakeReply(nonce: offer.nonce, profile: nil).bytes, timeoutMilliseconds: timeoutMilliseconds)
            throw MachCommandHandshakeError.incompatible
        }
        let profile = CommandHandshakeProfile(wireVersion: wire, submissionSchemaVersion: submission, inputCarrierVersion: input,
            callerBinding: try MachCommandWire.random(16), macID: macID, accountID: accountID)
        guard profile.supported(by: .implemented) else {
            try reply.send(CommandHandshakeReply(nonce: offer.nonce, profile: nil).bytes, timeoutMilliseconds: timeoutMilliseconds)
            throw MachCommandHandshakeError.incompatible
        }
        try reply.send(CommandHandshakeReply(nonce: offer.nonce, profile: profile).bytes, timeoutMilliseconds: timeoutMilliseconds)
        try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        self.profile = profile; self.caller = caller; completed = true
    }
    /// Match the actual kernel sender before constructing the capture. Policy and submission replay remain host gates.
    /// The authority supplies the stream binding, resolved target, environment, and negotiated phone capture schema.
    public func assemble(received: sending ReceivedMachCommandInputSubmission, currentPolicy: XPCPeerPolicy,
                         captureSchemaVersion: UInt64, resolvedTarget: CommandTarget, minimalEnvironment: [CapturedEnvironmentEntry],
                         streamBinding: Data, submissionLimits: CBORLimits, captureLimits: CBORLimits,
                         maximumAncestryEntries: Int = 16, checkCancellation: @Sendable () throws -> Void = {}) throws -> sending RetainedCommandCapture {
        try assemble(received: received, expression: currentPolicy.requirement, userID: currentPolicy.expectedUserID,
            auditSessionID: currentPolicy.expectedAuditSessionID, captureSchemaVersion: captureSchemaVersion,
            resolvedTarget: resolvedTarget, minimalEnvironment: minimalEnvironment, streamBinding: streamBinding,
            submissionLimits: submissionLimits, captureLimits: captureLimits, maximumAncestryEntries: maximumAncestryEntries,
            checkCancellation: checkCancellation)
    }
    func assemble(received: sending ReceivedMachCommandInputSubmission, expression: String, userID: uid_t, auditSessionID: au_asid_t?,
                  captureSchemaVersion: UInt64, resolvedTarget: CommandTarget, minimalEnvironment: [CapturedEnvironmentEntry],
                  streamBinding: Data, submissionLimits: CBORLimits, captureLimits: CBORLimits, maximumAncestryEntries: Int = 16,
                  checkCancellation: @Sendable () throws -> Void = {}) throws -> sending RetainedCommandCapture {
        do {
            guard !closed else { throw MachCommandHandshakeError.retired }
            guard UInt64(received.carrierVersion) == profile.inputCarrierVersion else { throw MachCommandHandshakeError.incompatible }
            try checkCancellation()
            try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
            try received.caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
            guard let expected = caller.retainedAuditBinding, let actual = received.caller.retainedAuditBinding,
                  expected == actual else { throw MachCommandHandshakeError.wrongBinding }
        } catch { received.closeIfUnclaimed(); throw error }
        // Capture construction owns cleanup after this transfer, including failure.
        return try RetainedCommandCapture(received: received, expectedCallerBinding: profile.callerBinding,
            submissionSchemaVersion: profile.submissionSchemaVersion, captureSchemaVersion: captureSchemaVersion,
            expression: expression, userID: userID, auditSessionID: auditSessionID, resolvedTarget: resolvedTarget,
            minimalEnvironment: minimalEnvironment, streamBinding: streamBinding, submissionLimits: submissionLimits,
            captureLimits: captureLimits, maximumAncestryEntries: maximumAncestryEntries, checkCancellation: checkCancellation, admissionProfile: profile)
    }
    /// Own the original input and reply before filesystem capture. This authenticates no elevation policy.
    public func prepareAdmission(received: sending ReceivedMachCommandInputSubmission, currentPolicy: XPCPeerPolicy,
                                 submissionLimits: CBORLimits) throws -> sending RetainedCommandAdmissionAttempt {
        try prepareAdmission(received: received, expression: currentPolicy.requirement, userID: currentPolicy.expectedUserID,
            auditSessionID: currentPolicy.expectedAuditSessionID, submissionLimits: submissionLimits)
    }

    func prepareAdmission(received: sending ReceivedMachCommandInputSubmission, expression: String, userID: uid_t,
                          auditSessionID: au_asid_t?, submissionLimits: CBORLimits) throws -> sending RetainedCommandAdmissionAttempt {
        do {
            let expected = try admissionPeerBinding(carrierVersion: received.carrierVersion, expression: expression,
                userID: userID, auditSessionID: auditSessionID)
            try received.caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
            guard received.caller.retainedAuditBinding == expected else { throw MachCommandHandshakeError.wrongBinding }
        } catch { received.closeIfUnclaimed(); throw error }
        return try RetainedCommandAdmissionAttempt(received: received, profile: profile, userID: userID,
            auditSessionID: auditSessionID, submissionLimits: submissionLimits)
    }

    func admissionPeerBinding(carrierVersion: UInt32, expression: String,
                              userID: uid_t, auditSessionID: au_asid_t?) throws -> Data {
        guard !closed else { throw MachCommandHandshakeError.retired }
        guard profile.supportsAdmissionResults, UInt64(carrierVersion) == profile.inputCarrierVersion else {
            throw MachCommandHandshakeError.incompatible
        }
        try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        guard let expected = caller.retainedAuditBinding else { throw MachCommandHandshakeError.wrongBinding }
        return expected
    }

    /// The registry uses current protected policy and retires a failed retained identity.
    func recheck(expression: String, userID: uid_t, auditSessionID: au_asid_t?) throws {
        guard !closed else { throw MachCommandHandshakeError.retired }
        do { try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID) }
        catch { close(); throw error }
    }
    public func close() { if !closed { closed = true; caller.close() } }
    deinit { close() }
}

/// Client observation of a reply from the configured signed Root process. It is not an admission acknowledgment.
public final class VerifiedCommandHandshake {
    public let profile: CommandHandshakeProfile
    private let authority: RetainedCommandCaller
    private let destination: MachCommandAuthorityPort
    init(profile: CommandHandshakeProfile, authority: RetainedCommandCaller, destination: MachCommandAuthorityPort) {
        self.profile = profile; self.authority = authority; self.destination = destination
    }
    func borrowedAuthorityPort() throws -> mach_port_t { try destination.borrowed() }
    public func recheck(currentPolicy: XPCPeerPolicy) throws {
        guard currentPolicy.expectedUserID == 0 else { throw MachCommandHandshakeError.invalidConfiguration }
        try authority.recheck(currentPolicy: currentPolicy)
    }
    func authenticateReplyAuthority(expression: String, userID: uid_t, auditSessionID: au_asid_t?) throws {
        try authority.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
    }
    func authenticateReply(_ caller: RetainedCommandCaller, expression: String, userID: uid_t, auditSessionID: au_asid_t?) throws {
        try authority.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        guard authority.hasSameAuditBinding(as: caller) else { throw MachCommandHandshakeError.wrongBinding }
    }
    public func close() { authority.close(); destination.close() }
    deinit { close() }
}

public enum MachCommandHandshakeClient {
    /// Borrow the configured authority send right. The first message contains only harmless protocol metadata.
    /// Authentication precedes scope decoding. A fresh private reply port and nonce prevent cross-attempt replies.
    /// This method submits no command, passes no input, and implements no automatic command retry.
    public static func negotiate(authorityPort: mach_port_t, authorityPolicy: XPCPeerPolicy, macID: Data, accountID: Data,
                                 capabilities: CommandHandshakeCapabilities = .current, timeoutMilliseconds: UInt32 = 5000,
                                 checkCancellation: () throws -> Void = {}) throws -> sending VerifiedCommandHandshake {
        guard authorityPolicy.expectedUserID == 0 else { throw MachCommandHandshakeError.invalidConfiguration }
        return try negotiate(authorityPort: authorityPort, expression: authorityPolicy.requirement, userID: 0,
            auditSessionID: authorityPolicy.expectedAuditSessionID, macID: macID, accountID: accountID,
            capabilities: capabilities, timeoutMilliseconds: timeoutMilliseconds, checkCancellation: checkCancellation)
    }
    static func negotiate(authorityPort: mach_port_t, expression: String, userID: uid_t, auditSessionID: au_asid_t?,
                          macID: Data, accountID: Data, capabilities: CommandHandshakeCapabilities = .current,
                          timeoutMilliseconds: UInt32 = 5000, checkCancellation: () throws -> Void = {}) throws -> sending VerifiedCommandHandshake {
        guard authorityPort != MACH_PORT_NULL, authorityPort != UInt32.max, macID.count == 16, accountID.count == 16,
              (1...60_000).contains(timeoutMilliseconds) else { throw MachCommandHandshakeError.invalidConfiguration }
        try checkCancellation()
        let destination = try MachCommandAuthorityPort(copying: authorityPort)
        do {
            let clock = try AuthorityClock(), started = try clock.now().milliseconds
            func remaining() throws -> UInt32 {
                let current = try clock.now().milliseconds
                guard current >= started, current - started < UInt64(timeoutMilliseconds) else { throw MachCommandCallerError.timeout }
                return UInt32(UInt64(timeoutMilliseconds) - (current - started))
            }
            let endpoint = try MachCommandPrivateReplyPort()
            defer { endpoint.close() }
            let offer = try CommandHandshakeOffer(nonce: MachCommandWire.random(32), capabilities: capabilities)
            let receiver = try MachCommandCallerReceiver(receivePort: endpoint.port, expression: expression,
                userID: userID, auditSessionID: auditSessionID, maxPayloadBytes: CommandHandshakeOffer.maximumBytes)
            try MachCommandWire.send(offer.canonicalBytes, destination: authorityPort, replyPort: endpoint.port,
                identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: remaining())
            try checkCancellation()
            func receiveReply() throws -> sending ReceivedMachCommandSubmission {
                while true {
                    try checkCancellation()
                    let budget = try remaining()
                    do { return try receiver.receiveHelloReply(timeoutMilliseconds: budget, previewTimeoutMilliseconds: min(budget, 250)) }
                    catch MachCommandCallerError.timeout { _ = try remaining() }
                }
            }
            let response = try receiveReply()
            do {
                try checkCancellation()
                _ = try remaining()
                let profile = try CommandHandshakeReply.decode(response.payload, offer: offer, macID: macID, accountID: accountID)
                try response.caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
                try checkCancellation()
                _ = try remaining()
                return VerifiedCommandHandshake(profile: profile, authority: response.caller, destination: destination)
            } catch { response.caller.close(); throw error }
        } catch { destination.close(); throw error }
    }
}

final class MachCommandReplyRight {
    private var port: mach_port_t
    private let identifier: mach_msg_id_t
    init(taking port: mach_port_t, identifier: mach_msg_id_t = MachCommandCallerReceiver.helloReplyMessageID) {
        self.port = port; self.identifier = identifier
    }
    func recheck() throws {
        guard port != MACH_PORT_NULL else { throw MachCommandHandshakeError.retired }
        var references: mach_port_urefs_t = 0
        let result = mach_port_get_refs(mach_task_self_, port, MACH_PORT_RIGHT_SEND, &references)
        guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        guard references > 0 else {
            throw MachCommandHandshakeError.retired
        }
    }
    func send(_ bytes: Data, timeoutMilliseconds: UInt32) throws {
        guard port != MACH_PORT_NULL else { throw MachCommandHandshakeError.retired }
        defer { close() }
        try MachCommandWire.send(bytes, destination: port, replyPort: nil,
            identifier: identifier, timeoutMilliseconds: timeoutMilliseconds)
    }
    func sendTerminalNonblocking(_ bytes: Data) throws {
        guard port != MACH_PORT_NULL else { throw MachCommandHandshakeError.retired }
        guard identifier == MachCommandCallerReceiver.terminalReplyMessageID else { throw MachCommandHandshakeError.invalidConfiguration }
        defer { close() }
        try MachCommandWire.sendTerminalNonblocking(bytes, destination: port)
    }
    /// A timeout or send interruption queued nothing. Keep this original right for a later bounded delivery turn.
    func queueTerminalNonblocking(_ bytes: Data) throws -> Bool {
        guard port != MACH_PORT_NULL else { throw MachCommandHandshakeError.retired }
        guard identifier == MachCommandCallerReceiver.terminalReplyMessageID else { throw MachCommandHandshakeError.invalidConfiguration }
        do {
            try MachCommandWire.sendTerminalNonblocking(bytes, destination: port)
            close(); return true
        } catch MachCommandCallerError.mach(let result) {
            let code = result & ~MACH_MSG_MASK
            if code == MACH_SEND_TIMED_OUT || code == MACH_SEND_INTERRUPTED { return false }
            close(); throw MachCommandCallerError.mach(result)
        } catch { close(); throw error }
    }
    func copyStreamRight() throws -> MachCommandAuthorityPort {
        guard identifier == MachCommandCallerReceiver.terminalReplyMessageID else { throw MachCommandHandshakeError.invalidConfiguration }
        try recheck()
        return try MachCommandAuthorityPort(copying: port)
    }
    func takeControlRight() throws -> MachCommandAuthorityPort {
        guard identifier == MachCommandCallerReceiver.streamControlMessageID else { throw MachCommandHandshakeError.invalidConfiguration }
        try recheck()
        let copied = try MachCommandAuthorityPort(copying: port)
        close()
        return copied
    }
    func close() { if port != MACH_PORT_NULL { _ = mach_port_deallocate(mach_task_self_, port); port = 0 } }
    deinit { close() }
}

/// Keeps the negotiated send right alive. An unrelated port or recycled name cannot replace it during submission.
final class MachCommandAuthorityPort {
    private var port: mach_port_t
    init(copying port: mach_port_t) throws {
        guard port != MACH_PORT_NULL, port != UInt32.max else { throw MachCommandHandshakeError.invalidConfiguration }
        let result = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_SEND, 1)
        guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        self.port = port
    }
    func borrowed() throws -> mach_port_t {
        guard port != MACH_PORT_NULL else { throw MachCommandHandshakeError.retired }
        return port
    }
    func close() { if port != MACH_PORT_NULL { _ = mach_port_deallocate(mach_task_self_, port); port = 0 } }
    deinit { close() }
}

final class MachCommandPrivateReplyPort {
    var port: mach_port_t = 0
    private var localSendReleased = false
    init(queueLimit: UInt32? = nil) throws {
        if let queueLimit, !(1...64).contains(queueLimit) { throw MachCommandHandshakeError.invalidConfiguration }
        let result = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &port)
        guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        let inserted = mach_port_insert_right(mach_task_self_, port, port, UInt32(MACH_MSG_TYPE_MAKE_SEND))
        guard inserted == KERN_SUCCESS else {
            _ = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1)
            port = 0; throw MachCommandCallerError.mach(inserted)
        }
        if let queueLimit {
            var limits = mach_port_limits_t(mpl_qlimit: queueLimit)
            let count = MemoryLayout<mach_port_limits_t>.size / MemoryLayout<natural_t>.size
            let result = withUnsafeMutablePointer(to: &limits) {
                $0.withMemoryRebound(to: Int32.self, capacity: count) {
                    mach_port_set_attributes(mach_task_self_, port, MACH_PORT_LIMITS_INFO, $0, mach_msg_type_number_t(count))
                }
            }
            if result != KERN_SUCCESS { close(); throw MachCommandCallerError.mach(result) }
        }
    }
    /// Release only the grant's local send reference. The receive right remains owned by this endpoint.
    func releaseLocalSendRight() throws {
        guard port != MACH_PORT_NULL, !localSendReleased else { throw MachCommandHandshakeError.retired }
        let result = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_SEND, -1)
        guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        localSendReleased = true
    }
    /// Includes a send right in a queued grant. Zero means the peer closed all controls, even if its process remains alive.
    func hasSenders() throws -> Bool {
        guard port != MACH_PORT_NULL else { throw MachCommandHandshakeError.retired }
        var status = mach_port_status_t()
        let capacity = MemoryLayout<mach_port_status_t>.size / MemoryLayout<natural_t>.size
        var count = mach_msg_type_number_t(capacity)
        let result = withUnsafeMutablePointer(to: &status) {
            $0.withMemoryRebound(to: Int32.self, capacity: capacity) {
                mach_port_get_attributes(mach_task_self_, port, MACH_PORT_RECEIVE_STATUS, $0, &count)
            }
        }
        guard result == KERN_SUCCESS, count == capacity else { throw MachCommandCallerError.mach(result) }
        return status.mps_srights > 0
    }
    func close() {
        if port != MACH_PORT_NULL {
            _ = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1)
            if !localSendReleased { _ = mach_port_deallocate(mach_task_self_, port) }
            port = 0
        }
    }
    deinit { close() }
}

enum MachCommandWire {
    static func random(_ count: Int) throws -> Data {
        var bytes = Data(count: count)
        guard bytes.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }) == errSecSuccess else {
            throw MachCommandCallerError.unavailable
        }
        return bytes
    }
    static func send(_ bytes: Data, destination: mach_port_t, replyPort: mach_port_t?, identifier: mach_msg_id_t,
                     timeoutMilliseconds: UInt32) throws {
        guard (1...60_000).contains(timeoutMilliseconds) else { throw MachCommandHandshakeError.invalidConfiguration }
        try sendPacket(bytes, destination: destination, replyPort: replyPort, identifier: identifier, timeoutMilliseconds: timeoutMilliseconds)
    }
    static func sendTerminalNonblocking(_ bytes: Data, destination: mach_port_t) throws {
        try sendPacket(bytes, destination: destination, replyPort: nil,
            identifier: MachCommandCallerReceiver.terminalReplyMessageID, timeoutMilliseconds: 0)
    }
    static func sendStream(_ bytes: Data, destination: mach_port_t, openedControl: mach_port_t? = nil,
                           toAuthority: Bool = false) throws -> Bool {
        guard !toAuthority || openedControl == nil else { throw MachCommandHandshakeError.invalidConfiguration }
        let identifier = toAuthority ? MachCommandCallerReceiver.streamControlMessageID :
            (openedControl == nil ? MachCommandCallerReceiver.streamOutputMessageID : MachCommandCallerReceiver.streamOpenedMessageID)
        do {
            try sendPacket(bytes, destination: destination, replyPort: openedControl, identifier: identifier,
                timeoutMilliseconds: 0, maximumPayloadBytes: CommandStreamFrame.maximumBytes)
            return true
        } catch MachCommandCallerError.mach(let result) {
            let code = result & ~MACH_MSG_MASK
            if code == MACH_SEND_TIMED_OUT || code == MACH_SEND_INTERRUPTED { return false }
            throw MachCommandCallerError.mach(result)
        }
    }
    private static func sendPacket(_ bytes: Data, destination: mach_port_t, replyPort: mach_port_t?, identifier: mach_msg_id_t,
                                   timeoutMilliseconds: UInt32, maximumPayloadBytes: Int = CommandHandshakeOffer.maximumBytes) throws {
        guard destination != MACH_PORT_NULL, destination != UInt32.max, !bytes.isEmpty, bytes.count <= maximumPayloadBytes else { throw MachCommandHandshakeError.invalidConfiguration }
        let headerBytes = MemoryLayout<mach_msg_header_t>.size
        let metadata = headerBytes + (replyPort == nil ? 0 : MemoryLayout<mach_msg_body_t>.size + MemoryLayout<mach_msg_port_descriptor_t>.size)
        let size = (metadata + 8 + bytes.count + 3) & ~3
        let storage = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: 8)
        defer { storage.deallocate() }
        storage.initializeMemory(as: UInt8.self, repeating: 0, count: size)
        let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
        header.pointee.msgh_bits = UInt32(MACH_MSG_TYPE_COPY_SEND) | (replyPort == nil ? 0 : MACH_MSGH_BITS_COMPLEX)
        header.pointee.msgh_size = UInt32(size); header.pointee.msgh_remote_port = destination; header.pointee.msgh_id = identifier
        if let replyPort {
            storage.storeBytes(of: mach_msg_body_t(msgh_descriptor_count: 1), toByteOffset: headerBytes, as: mach_msg_body_t.self)
            var descriptor = mach_msg_port_descriptor_t()
            descriptor.name = replyPort; descriptor.disposition = UInt32(MACH_MSG_TYPE_COPY_SEND); descriptor.type = UInt32(MACH_MSG_PORT_DESCRIPTOR)
            storage.storeBytes(of: descriptor, toByteOffset: headerBytes + MemoryLayout<mach_msg_body_t>.size, as: mach_msg_port_descriptor_t.self)
        }
        storage.storeBytes(of: MachCommandCallerReceiver.handshakeCarrierVersion.bigEndian, toByteOffset: metadata, as: UInt32.self)
        storage.storeBytes(of: UInt32(bytes.count).bigEndian, toByteOffset: metadata + 4, as: UInt32.self)
        bytes.withUnsafeBytes { raw in storage.advanced(by: metadata + 8).copyMemory(from: raw.baseAddress!, byteCount: raw.count) }
        let result = mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT | MACH_SEND_INTERRUPT, UInt32(size), 0, 0, timeoutMilliseconds, 0)
        guard result == KERN_SUCCESS else {
            let code = result & ~MACH_MSG_MASK
            if code == MACH_SEND_TIMED_OUT || code == MACH_SEND_INTERRUPTED || code == MACH_SEND_INVALID_DEST {
                mach_msg_destroy(header)
            }
            throw MachCommandCallerError.mach(result)
        }
    }
}
