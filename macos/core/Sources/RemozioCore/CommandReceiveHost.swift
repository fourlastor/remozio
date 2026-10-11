import Darwin
import Foundation
import RemozioProtocol
import os

public enum CommandReceiveHostError: Error, Equatable { case invalidConfiguration, stopped, operationActive }
public enum CommandReceiveRejection: Sendable, Equatable { case malformed, wrongPeer, incompatible, capacity, replyFailure }

/// These outcomes describe local receipt handling. They grant no admission, retry, or execution authority.
public enum CommandReceiveEvent: Sendable, Equatable {
    case idle
    case hello(CommandHandshakeProfile)
    case inputHandled
    case rejected(CommandReceiveRejection)
}

/// A thread-safe stop signal. It never disposes resources from another thread.
public struct CommandReceiveStop: Sendable {
    fileprivate let state = OSAllocatedUnfairLock(initialState: false)
    public func requestStop() { state.withLock { $0 = true } }
    fileprivate var requested: Bool { state.withLock { $0 } }
    fileprivate func check() throws { if requested { throw CommandReceiveHostError.stopped } }
}

/// Owns one receive right and serial command session lifetime. No service is registered by this owner.
/// The caller serializes poll, assemble, run, and close. Only stop.requestStop() may run on another thread.
public final class CommandReceiveHost {
    public let stop = CommandReceiveStop()
    public let receiveWaitMilliseconds: UInt32
    private var port: mach_port_t
    private let registry: CommandSessionRegistry
    private let loadContext: () throws -> CommandSessionRegistry.Context
    private let userID: uid_t
    private let auditSessionID: au_asid_t?
    private let maximumPayloadBytes: Int
    private let replyTimeoutMilliseconds: UInt32
    private var busy = false
    private var running = false
    private var delivering = false
    private var activeInput: ObjectIdentifier?
    public var retainedSessionCount: Int { registry.retainedSessionCount }

    /// Transfer the actual receive right, including failure. Do not retain another consumer or destroy its borrowed name.
    /// The journal must already own validated protected storage. No cached policy fallback is used.
    public convenience init(takingReceiveRight: mach_port_t, journal: AuthorityJournal, macID: Data, accountID: Data,
                            userID: uid_t, auditSessionID: au_asid_t? = nil, maximumSessions: Int,
                            maximumPayloadBytes: Int, receiveWaitMilliseconds: UInt32 = 250,
                            replyTimeoutMilliseconds: UInt32 = 5000,
                            capabilities: CommandHandshakeCapabilities = .current) throws {
        try self.init(takingReceiveRight: takingReceiveRight, macID: macID, accountID: accountID,
            userID: userID, auditSessionID: auditSessionID, maximumSessions: maximumSessions,
            maximumPayloadBytes: maximumPayloadBytes, receiveWaitMilliseconds: receiveWaitMilliseconds,
            replyTimeoutMilliseconds: replyTimeoutMilliseconds, capabilities: capabilities, context: { registry in
                guard geteuid() == 0 else { throw JournalLeaseError.rootRequired }
                let snapshot = try journal.read { transaction in
                    try AuthoritySelfValidation.validate(transaction: transaction)
                    let trust = try transaction.directApprovalTrust(maximumPayloadBytes: maximumPayloadBytes)
                    guard trust.macID == macID, trust.accountID == accountID else { throw JournalDatabaseError.wrongScope }
                    guard let snapshot = try transaction.codePolicy() else { throw CommandSessionRegistryError.invalidCodePolicy }
                    return snapshot
                }
                return try registry.context(snapshot)
            })
    }

    /// Fixture policy seam. Product construction always reads the current protected journal.
    init(takingReceiveRight: mach_port_t, macID: Data, accountID: Data, userID: uid_t, auditSessionID: au_asid_t?,
         maximumSessions: Int, maximumPayloadBytes: Int, receiveWaitMilliseconds: UInt32 = 250,
         replyTimeoutMilliseconds: UInt32 = 5000, capabilities: CommandHandshakeCapabilities = .current,
         context: @escaping (CommandSessionRegistry) throws -> CommandSessionRegistry.Context) throws {
        var references: mach_port_urefs_t = 0
        guard takingReceiveRight != MACH_PORT_NULL, takingReceiveRight != UInt32.max,
              mach_port_get_refs(mach_task_self_, takingReceiveRight, MACH_PORT_RIGHT_RECEIVE, &references) == KERN_SUCCESS,
              references == 1 else { throw CommandReceiveHostError.invalidConfiguration }
        var transferred = false
        defer { if !transferred { _ = mach_port_mod_refs(mach_task_self_, takingReceiveRight, MACH_PORT_RIGHT_RECEIVE, -1) } }
        guard (1...60_000).contains(receiveWaitMilliseconds), (1...60_000).contains(replyTimeoutMilliseconds),
              maximumPayloadBytes > 0, maximumPayloadBytes <= Int(UInt32.max) - 1024 else {
            throw CommandReceiveHostError.invalidConfiguration
        }
        let registry = try CommandSessionRegistry(macID: macID, accountID: accountID, userID: userID,
            auditSessionID: auditSessionID, maximumSessions: maximumSessions, capabilities: capabilities)
        self.registry = registry; self.loadContext = { try context(registry) }
        self.port = takingReceiveRight; self.userID = userID; self.auditSessionID = auditSessionID
        self.maximumPayloadBytes = maximumPayloadBytes; self.receiveWaitMilliseconds = receiveWaitMilliseconds
        self.replyTimeoutMilliseconds = replyTimeoutMilliseconds; transferred = true
    }

    deinit { close() }

    /// The queue owner validates current policy before reporting readiness. This does not receive a message.
    func validateStartupContext() throws {
        guard !running, !delivering else { throw CommandReceiveHostError.operationActive }
        try begin(); defer { end() }
        _ = try currentContext()
    }

    /// One bounded receive turn also prunes while idle or under continuous invalid traffic.
    /// The synchronous handler receives input ownership and must complete every separate admission gate.
    public func poll(handleInput: (sending ReceivedMachCommandInputSubmission) throws -> Void) throws -> CommandReceiveEvent {
        guard !running, !delivering else { throw CommandReceiveHostError.operationActive }
        return try receiveTurn(handleInput: handleInput)
    }

    /// Runs the sole receive loop. The synchronous handler may assemble its input but must not poll or reenter run.
    /// The handler owns input cleanup and handles request-local rejection. An escaping error retires this lifetime.
    public func run(handleInput: (sending ReceivedMachCommandInputSubmission) throws -> Void) throws {
        guard !running, !busy, !delivering else { throw CommandReceiveHostError.operationActive }
        if stop.requested { dispose(); throw CommandReceiveHostError.stopped }
        running = true
        defer { running = false; close() }
        while true { _ = try receiveTurn(handleInput: handleInput) }
    }

    /// Current policy is read again before assembly. Target and environment still come from protected host resolution.
    public func assemble(received: sending ReceivedMachCommandInputSubmission, captureSchemaVersion: UInt64,
                         resolvedTarget: CommandTarget, minimalEnvironment: [CapturedEnvironmentEntry], streamBinding: Data,
                         submissionLimits: CBORLimits, captureLimits: CBORLimits, maximumAncestryEntries: Int = 16,
                         checkCancellation: @Sendable () throws -> Void = {}) throws -> sending RetainedCommandCapture {
        if busy, activeInput == ObjectIdentifier(received.input) { throw CommandReceiveHostError.operationActive }
        do { try begin() } catch { received.closeIfUnclaimed(); throw error }
        activeInput = ObjectIdentifier(received.input)
        defer { activeInput = nil; end() }
        let context: CommandSessionRegistry.Context
        do { context = try currentContext() }
        catch { received.closeIfUnclaimed(); throw error }
        return try registry.assemble(received: received, context: { context }, captureSchemaVersion: captureSchemaVersion,
            resolvedTarget: resolvedTarget, minimalEnvironment: minimalEnvironment, streamBinding: streamBinding,
            submissionLimits: submissionLimits, captureLimits: captureLimits, maximumAncestryEntries: maximumAncestryEntries,
            checkCancellation: { [stop] in try stop.check(); try checkCancellation(); try stop.check() })
    }

    /// Transfer the original input and private reply before capture. Every operation reads current protected policy again.
    public func prepareAdmission(received: sending ReceivedMachCommandInputSubmission,
                                 submissionLimits: CBORLimits) throws -> sending RetainedCommandAdmissionAttempt {
        if busy, activeInput == ObjectIdentifier(received.input) { throw CommandReceiveHostError.operationActive }
        do { try begin() } catch { received.closeIfUnclaimed(); throw error }
        activeInput = ObjectIdentifier(received.input)
        defer { activeInput = nil; end() }
        let context: CommandSessionRegistry.Context
        do { context = try currentContext() }
        catch { received.closeIfUnclaimed(); throw error }
        return try registry.prepareAdmission(received: received, context: { context }, submissionLimits: submissionLimits)
    }

    /// One typed admission turn. The host callback observes request-local failures without retiring a healthy receive queue.
    /// A failed protected policy read requests stop. No service, elevation policy, or execution dispatcher is activated here.
    public func pollAdmission(journal: AuthorityJournal, submissionLimits: CBORLimits,
                              resolve: (CommandSubmission) throws -> CommandAdmissionResolution,
                              draft: (CommandCapture) throws -> ApprovalRequestDraft,
                              now: () throws -> AuthorityMoment, receiptTimeMs: UInt64?,
                              checkCancellation: @escaping @Sendable () throws -> Void = {},
                              onResult: (Result<IssuedRequestPayload, Error>) throws -> Void) throws -> CommandReceiveEvent {
        try pollAdmission(journal: journal, submissionLimits: submissionLimits, resolve: resolve, draft: draft,
            now: now, receiptTime: { receiptTimeMs }, checkCancellation: checkCancellation, onResult: onResult)
    }
    /// Sample receipt time only after an authenticated input arrives, before its admission work.
    func pollAdmission(journal: AuthorityJournal, submissionLimits: CBORLimits,
                       resolve: (CommandSubmission) throws -> CommandAdmissionResolution,
                       draft: (CommandCapture) throws -> ApprovalRequestDraft,
                       now: () throws -> AuthorityMoment, receiptTime: () -> UInt64?,
                       checkCancellation: @escaping @Sendable () throws -> Void = {},
                       onResult: (Result<IssuedRequestPayload, Error>) throws -> Void) throws -> CommandReceiveEvent {
        try poll { received in
            let receiptTimeMs = receiptTime()
            let result: Result<IssuedRequestPayload, Error>
            do {
                let attempt = try prepareAdmission(received: received, submissionLimits: submissionLimits)
                result = .success(try journal.admitCommandAttempt(attempt, resolve: resolve, draft: draft, now: now,
                    receiptTimeMs: receiptTimeMs, checkCancellation: { [stop] in
                        try stop.check(); try checkCancellation(); try stop.check()
                    }))
            } catch { result = .failure(error) }
            try onResult(result)
        }
    }

    /// Signal first. A reentrant close defers disposal until the active receive or capture has returned.
    public func close() { stop.requestStop(); if !busy { dispose() } }

    private func begin() throws {
        if stop.requested { if !busy { dispose() }; throw CommandReceiveHostError.stopped }
        guard !busy, port != MACH_PORT_NULL else { throw CommandReceiveHostError.operationActive }
        busy = true
    }
    private func end() { busy = false; if stop.requested { dispose() } }
    private func dispose() {
        registry.close()
        if port != MACH_PORT_NULL {
            _ = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1)
            port = 0
        }
    }
    private func currentContext() throws -> CommandSessionRegistry.Context {
        do {
            try stop.check()
            let context = try loadContext()
            _ = try registry.prune(context: { context })
            try stop.check()
            return context
        } catch { stop.requestStop(); throw error }
    }
    private func accept(hello: sending MachCommandHello, context: CommandSessionRegistry.Context) throws -> CommandHandshakeProfile {
        try registry.accept(hello: hello, context: { context }, timeoutMilliseconds: replyTimeoutMilliseconds)
    }
    private func receiveTurn(handleInput: (sending ReceivedMachCommandInputSubmission) throws -> Void) throws -> CommandReceiveEvent {
        try begin(); defer { end() }
        let before = try currentContext()
        let receiver: MachCommandCallerReceiver
        do { receiver = try MachCommandCallerReceiver(receivePort: port, expression: before.expression, userID: userID,
            auditSessionID: auditSessionID, maxPayloadBytes: maximumPayloadBytes) }
        catch { stop.requestStop(); throw error }
        let message: ReceivedMachCommandMessage
        do { message = try receiver.receiveNext(timeoutMilliseconds: receiveWaitMilliseconds) }
        catch let error as MachCommandCallerError {
            // Even rejected traffic and empty queues must observe a changed or unreadable policy.
            _ = try currentContext()
            switch error {
            case .timeout: return .idle
            case .malformed, .version: return .rejected(.malformed)
            case .wrongPeer, .retired, .unavailable, .security: return .rejected(.wrongPeer)
            case .configuration, .mach: stop.requestStop(); throw error
            }
        } catch let error as RetainedCommandInputError {
            guard error == .system(EINVAL) else { stop.requestStop(); throw error }
            _ = try currentContext()
            return .rejected(.malformed)
        }
        let current: CommandSessionRegistry.Context
        do { current = try currentContext() }
        catch {
            switch message {
            case .hello(let hello): hello.close()
            case .input(let received): received.closeIfUnclaimed()
            }
            throw error
        }
        switch message {
        case .hello(let hello):
            do { return .hello(try accept(hello: hello, context: current)) }
            catch let error as CommandSessionRegistryError {
                if error == .capacity { return .rejected(.capacity) }
                stop.requestStop(); throw error
            } catch let error as MachCommandHandshakeError {
                return .rejected(error == .incompatible ? .incompatible : .malformed)
            } catch let error as MachCommandCallerError {
                return .rejected({ if case .mach = error { return .replyFailure }; return .wrongPeer }())
            } catch is CBORError { return .rejected(.malformed) }
            catch { stop.requestStop(); throw error }
        case .input(let received):
            do {
                try received.caller.recheck(expression: current.expression, userID: userID, auditSessionID: auditSessionID)
                try stop.check()
            } catch let error as CommandReceiveHostError { received.closeIfUnclaimed(); throw error }
            catch { received.closeIfUnclaimed(); return .rejected(.wrongPeer) }
            end()
            delivering = true
            defer { delivering = false }
            do { try handleInput(received) }
            catch { stop.requestStop(); throw error }
            return .inputHandled
        }
    }
}
