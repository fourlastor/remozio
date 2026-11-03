import Darwin
import Foundation
import RemozioMach
import RemozioProtocol

/// Owns one monitor and the original command resources. Only the serialized journal calls this owner.
final class CommandExecution {
    enum Progress { case preparing, prepared, running, terminal(CommandTerminalOutcome) }
    let resources: RetainedCommandExecutionResources
    let approval: CommandExecutionApproval
    let clock: () throws -> AuthorityMoment
    let receiptTime: () -> UInt64?
    private struct Validation {
        let callerExpression: String
        let callerUserID: uid_t
        let callerSessionID: au_asid_t?
        let launcher: () throws -> Void
        let elevation: (CommandCapture) throws -> Void
    }
    private let validation: Validation?
    private var monitor: OpaquePointer?
    private var pump: CommandPTYStreamPump?
    private var pipeControls: CommandPipeControlChannel?
    private var monitorOwned = false
    private var targetActive = false
    private var pendingSignals: [UInt32] = []
    var committedOutcome: CommandTerminalOutcome?
    private var released = false
    private var releaseSucceeded = false
    private var cancelledBeforeRelease = false
    private var observationUncertain = false
    private var disposed = false
    private var terminalDeliveryPending = false
    private var terminalDeliveryFinished = false
    var dispatchRevision: UInt64 = 0
    var terminalCommitFailed = false

    private init(resources: RetainedCommandExecutionResources, approval: CommandExecutionApproval,
                 clock: @escaping () throws -> AuthorityMoment, receiptTime: @escaping () -> UInt64?, validation: Validation?) {
        self.resources = resources; self.approval = approval; self.clock = clock; self.receiptTime = receiptTime
        self.validation = validation
    }
    convenience init(resources: RetainedCommandExecutionResources, approval: CommandExecutionApproval,
                     clock: @escaping () throws -> AuthorityMoment, receiptTime: @escaping () -> UInt64?,
                     callerExpression: String, callerUserID: uid_t, callerSessionID: au_asid_t?,
                     validateLauncher: @escaping () throws -> Void, validateElevation: @escaping (CommandCapture) throws -> Void) {
        self.init(resources: resources, approval: approval, clock: clock, receiptTime: receiptTime,
            validation: Validation(callerExpression: callerExpression, callerUserID: callerUserID,
                callerSessionID: callerSessionID, launcher: validateLauncher, elevation: validateElevation))
    }
    /// Retains only a failed pre-spawn outcome. This owner has no runtime validation and cannot spawn.
    convenience init(resources: RetainedCommandExecutionResources, approval: CommandExecutionApproval,
                     clock: @escaping () throws -> AuthorityMoment, receiptTime: @escaping () -> UInt64?) {
        self.init(resources: resources, approval: approval, clock: clock, receiptTime: receiptTime, validation: nil)
    }
    func validateLauncher() throws {
        guard let validation else { throw CommandExecutionError.unavailable }
        try validation.launcher()
    }
    func validateElevation(_ capture: CommandCapture) throws {
        guard let validation else { throw CommandExecutionError.unavailable }
        try validation.elevation(capture)
    }

    /// A failed spawn can return a live monitor. Retain it until actual reaping or ownership loss.
    func prepare(monitorPath: String, childPath: String, preparationMilliseconds: UInt32, fileCreationMask: UInt32,
                 releaseActivity: ReleaseActivityToken? = nil) throws {
        guard validation != nil, !disposed, !released, !cancelledBeforeRelease, monitor == nil,
              (resources.capture.ioMode == .pipes && !resources.requiresStreamPump ||
               resources.capture.ioMode == .pty && resources.requiresStreamPump) else { throw CommandExecutionError.unavailable }
        let frame = try CommandChildLaunchSpecification(capture: resources.capture,
            preparationMilliseconds: preparationMilliseconds, fileCreationMask: fileCreationMask).canonicalBytes
        try validateLauncher(); try validateElevation(resources.capture)
        try recheck()
        if resources.requiresPipeControls {
            pipeControls = try CommandPipeControlChannel(channel: resources.makeStreamAuthority())
        }
        let status = try resources.withBorrowedDescriptors { input, output, error, directory in
            let pty: RetainedCommandPTY?
            if resources.requiresStreamPump {
                let privatePTY = try resources.withBorrowedCallerTerminal { callerTerminal in
                    let source = resources.requiresMappedLayout ? callerTerminal : input
                    var attributes = termios(), size = winsize()
                    let hasTerminal = source.map { isatty($0) == 1 } ?? false
                    if hasTerminal, let source {
                        guard tcgetattr(source, &attributes) == 0, ioctl(source, TIOCGWINSZ, &size) == 0 else {
                            throw RetainedCommandPTYError.native(errno)
                        }
                    }
                    return try RetainedCommandPTY(attributes: hasTerminal ? attributes : nil, size: hasTerminal ? size : nil)
                }
                pty = privatePTY
                pump = try CommandPTYStreamPump(pty: privatePTY, channel: resources.makeStreamAuthority())
            } else { pty = nil }
            defer { pty?.sealSlave() }
            func spawn(_ input: Int32, _ output: Int32, _ error: Int32, terminal: Int32? = nil) throws -> Int32 {
                func perform(activity: Int32? = nil) -> Int32 { frame.withUnsafeBytes { bytes in
                    monitorPath.withCString { monitorPath in
                        childPath.withCString { childPath in
                            if let activity {
                                return remozio_command_monitor_spawn_with_activity(monitorPath, childPath, bytes.baseAddress, bytes.count,
                                    input, output, error, directory, terminal ?? -1, activity, &monitor)
                            }
                            if let terminal {
                                return remozio_command_monitor_spawn_with_terminal(monitorPath, childPath, bytes.baseAddress, bytes.count,
                                    input, output, error, directory, terminal, &monitor)
                            }
                            return remozio_command_monitor_spawn(monitorPath, childPath, bytes.baseAddress, bytes.count, input, output, error, directory, &monitor)
                        }
                    }
                } }
                if let releaseActivity { return try releaseActivity.withSharedDescriptorForSpawn { perform(activity: $0) } }
                return perform()
            }
            if let pty {
                if resources.requiresMappedLayout {
                    guard let layout = resources.capture.stdioLayout else { throw CommandExecutionError.unavailable }
                    return try pty.withBorrowedMappedStreams(layout: layout, direct: [input, output, error]) { streams, terminal in
                        try spawn(streams[0], streams[1], streams[2], terminal: terminal)
                    }
                }
                return try pty.withBorrowedSlave { try spawn($0, $0, $0) }
            }
            return try spawn(input, output, error)
        }
        monitorOwned = monitor != nil
        if status != 0 { cancelBeforeRelease(); throw CommandExecutionError.native(status) }
    }

    func recheck() throws {
        guard let validation else { throw CommandExecutionError.unavailable }
        try resources.recheck(expression: validation.callerExpression, userID: validation.callerUserID,
            auditSessionID: validation.callerSessionID)
    }

    /// Call only after the dispatch transition commits and all final checks pass.
    func release() throws {
        guard !disposed, !released, !cancelledBeforeRelease, let monitor else { throw CommandExecutionError.unavailable }
        released = true
        let status = remozio_command_monitor_release(monitor)
        if status != 0 { pendingSignals.removeAll(); observationUncertain = true; cancelOwned(); throw CommandExecutionError.native(status) }
        releaseSucceeded = true
    }
    func cancelBeforeRelease() {
        guard !released else { return }
        cancelledBeforeRelease = true; pendingSignals.removeAll()
        cancelOwned()
    }
    private func cancelOwned() {
        guard monitorOwned, let monitor else { return }
        if targetActive { try? pump?.signalForeground(SIGKILL) }
        _ = remozio_command_monitor_cancel(monitor)
    }
    private func applyControl(_ body: CommandStreamFrame.Body) throws {
        guard monitorOwned, let monitor else { return }
        switch body {
        case .cancel: if released { cancelOwned() } else { cancelBeforeRelease() }
        case .signal(let number):
            if !released {
                guard !cancelledBeforeRelease else { return }
                guard pendingSignals.count < CommandPTYStreamPump.maximumControlsPerTurn else { throw CommandStreamError.capacity }
                pendingSignals.append(number)
                return
            }
            guard releaseSucceeded, targetActive else { return }
            func signalOriginalGroup() throws {
                let status = remozio_command_monitor_signal(monitor, Int32(number))
                if status != 0 && status != ESRCH { throw CommandExecutionError.native(status) }
            }
            if let pump {
                do { try pump.signalForeground(Int32(number)) }
                catch RetainedCommandPTYError.native(let error) where error == EPIPE || error == EIO { try signalOriginalGroup() }
            } else { try signalOriginalGroup() }
        case .resize(let rows, let columns, let width, let height):
            do { try pump?.resize(winsize(ws_row: rows, ws_col: columns, ws_xpixel: width, ws_ypixel: height)) }
            catch RetainedCommandPTYError.native(let error) where error == EPIPE || error == EIO { }
        default: throw CommandStreamError.malformed
        }
    }
    /// Delivery waits for the original frontend to drain output. Durable native outcomes remain independent.
    func deliverTerminal(_ outcome: CommandTerminalOutcome) {
        guard !terminalDeliveryFinished, pump?.readyForTerminal ?? true else { return }
        terminalDeliveryPending = true
        do {
            guard try resources.queueTerminalOutcome(outcome, outputInterrupted: pump?.outputInterrupted ?? false) else { return }
        } catch { }
        terminalDeliveryPending = false; terminalDeliveryFinished = true
        pump?.finishDelivery(); pipeControls?.close()
    }
    func poll(checkStreamPolicy: () throws -> Void = { throw CommandExecutionError.unavailable }) -> Progress {
        guard !disposed else { return .terminal(.unknown) }
        guard let monitor else {
            return .terminal(resources.requesterExitObserved ? .requesterExitedBeforeStart : .failedBeforeStart)
        }
        var observation = remozio_command_monitor_observation_t()
        let status = remozio_command_monitor_poll(monitor, &observation)
        if status != 0 {
            observationUncertain = true
            if !released { cancelBeforeRelease() }
        }
        monitorOwned = !observation.monitor_reaped && !observation.monitor_ownership_lost
        targetActive = observation.prepared && !observation.target_exit_observed && !observation.status.reaped && !observation.monitor_ownership_lost
        if observation.status.failed { observationUncertain = true }
        if let pump, let validation {
            if observation.monitor_ownership_lost { pump.detach() }
            else {
                do {
                    try flushPendingSignals(validation: validation, checkPolicy: checkStreamPolicy)
                    try pump.observeJobState(currentJobState(observation))
                    if !released, !cancelledBeforeRelease, observation.prepared, !observation.monitor_reaped {
                        _ = try pump.open()
                    }
                    try pump.poll(expression: validation.callerExpression, userID: validation.callerUserID,
                        auditSessionID: validation.callerSessionID, allowInput: releaseSucceeded,
                        checkCaller: { try self.resources.recheckCaller(expression: validation.callerExpression,
                            userID: validation.callerUserID, auditSessionID: validation.callerSessionID) },
                        checkControlPolicy: checkStreamPolicy, applyControl: { try self.applyControl($0) },
                        currentJob: { try self.queryCurrentJob() })
                } catch {
                    pump.detach()
                    if !released || resources.capture.disconnectBehavior == .terminate { cancelOwned() }
                }
            }
        }
        if let pipeControls, let validation {
            if observation.monitor_ownership_lost { pipeControls.detach() }
            else {
                do {
                    try flushPendingSignals(validation: validation, checkPolicy: checkStreamPolicy)
                    try pipeControls.observeJobState(currentJobState(observation))
                    if !released, !cancelledBeforeRelease, observation.prepared, !observation.monitor_reaped {
                        _ = try pipeControls.open()
                    }
                    try pipeControls.poll(expression: validation.callerExpression, userID: validation.callerUserID,
                        auditSessionID: validation.callerSessionID,
                        checkCaller: { try self.resources.recheckCaller(expression: validation.callerExpression,
                            userID: validation.callerUserID, auditSessionID: validation.callerSessionID) },
                        checkControlPolicy: checkStreamPolicy, applyControl: { try self.applyControl($0) },
                        currentJob: { try self.queryCurrentJob() })
                } catch {
                    pipeControls.detach()
                    if !released || resources.capture.disconnectBehavior == .terminate { cancelOwned() }
                }
            }
        }
        if observation.monitor_ownership_lost { return .terminal(.unknown) }
        if observation.monitor_reaped {
            guard observation.status_closed || observation.protocol_failed else { return released ? .running : .preparing }
            if observationUncertain && released { return .terminal(.unknown) }
            if !released { return .terminal(.failedBeforeStart) }
            guard observation.status_closed, !observation.protocol_failed, observation.target_kernel_registered,
                  observation.target_exit_observed, observation.status.reaped else { return .terminal(.unknown) }
            guard observation.target_exec_observed else { return .terminal(.failedBeforeStart) }
            guard observation.monitor_wait_status == 0, observation.status.target_release_attempted else { return .terminal(.unknown) }
            let waitStatus = observation.status.latest.detail
            let signal = waitStatus & 0x7f
            if signal == 0 { return .terminal(.exited(UInt8((waitStatus >> 8) & 0xff))) }
            if signal > 0 && signal < UInt32(NSIG) { return .terminal(.signalled(UInt32(signal))) }
            return .terminal(.unknown)
        }
        if released {
            if resources.capture.disconnectBehavior == .terminate, let validation {
                do { try resources.recheckCaller(expression: validation.callerExpression, userID: validation.callerUserID,
                    auditSessionID: validation.callerSessionID) }
                catch { cancelOwned() }
            }
            return .running
        }
        if cancelledBeforeRelease || observation.status.failed { cancelBeforeRelease(); return .preparing }
        return observation.prepared && (pump == nil || pump?.opened == true && pump?.connected == true) &&
            (pipeControls == nil || pipeControls?.opened == true && pipeControls?.connected == true) ? .prepared : .preparing
    }
    private func currentJobState(_ observation: remozio_command_monitor_observation_t) throws -> CommandJobStatePayload? {
        guard resources.reportsJobState, releaseSucceeded, targetActive, !observationUncertain,
              observation.status.latest.tag == UInt32(REMOZIO_MONITOR_JOB_STATE.rawValue) else { return nil }
        return try CommandJobStatePayload(nativeRecord: observation.status.latest)
    }
    private func queryCurrentJob() throws -> CommandCurrentJobState {
        guard releaseSucceeded, targetActive, monitorOwned, !observationUncertain, !disposed, let monitor else { return .unknown }
        var observation = remozio_command_monitor_observation_t()
        guard remozio_command_monitor_poll(monitor, &observation) == 0 else { return .unknown }
        let before = try pump?.foregroundGroup()
        var job = remozio_command_current_job_t()
        guard remozio_command_monitor_current_job(monitor, &job) == 0, job.known, !job.traced, job.original_group else { return .unknown }
        let after = try pump?.foregroundGroup()
        if pump != nil {
            guard let before, before == after, UInt32(exactly: before) == observation.status.latest.target_pid else { return .unknown }
        }
        if job.stopped {
            guard observation.status.latest.stop_code == UInt32(CLD_STOPPED) else { return .unknown }
            return .stopped(signal: job.stop_signal, revision: job.job_revision)
        }
        return .running
    }
    private func flushPendingSignals(validation: Validation, checkPolicy: () throws -> Void) throws {
        guard releaseSucceeded, !pendingSignals.isEmpty else { return }
        let signals = pendingSignals; pendingSignals.removeAll()
        guard monitorOwned else { return }
        try resources.recheckCaller(expression: validation.callerExpression, userID: validation.callerUserID,
            auditSessionID: validation.callerSessionID)
        try checkPolicy()
        for number in signals { try applyControl(.signal(number)) }
    }
    /// Poll until this succeeds. Disposal does not wait for a live monitor.
    func dispose() -> Bool {
        guard !disposed else { return true }
        guard !terminalDeliveryPending, pump?.readyForTerminal ?? true else { return false }
        if let monitor, remozio_command_monitor_dispose(monitor) != 0 { return false }
        monitor = nil; monitorOwned = false; targetActive = false; disposed = true; pump?.close(); pipeControls?.close(); resources.close(); return true
    }
}

enum CommandExecutionError: Error, Equatable { case invalidConfiguration, unavailable, policyChanged, native(Int32) }

/// Original consumption bindings retained in memory. These values cannot recreate a command or grant a release.
struct CommandApprovalEnrollment: Sendable { let epoch: Data; let key: EnrolledApprovalKey }
struct CommandExecutionApproval: Sendable {
    let retained: RetainedApprovalRequest
    let receipt: ConsumptionReceipt
    let enrollment: CommandApprovalEnrollment
    func requireCurrent(_ current: RequestDeliveryTrust) throws {
        let payload = retained.payload, decision = receipt.decision
        guard current.approval.macID == payload.macID, current.approval.accountID == payload.accountID,
              current.approval.allowedContracts.contains(payload.contract),
              let localFeatures = current.approval.authorityCapabilities.contracts[payload.contract],
              payload.requiredFeatures.isSubset(of: localFeatures),
              current.approval.enrollments.contains(where: { $0.phoneID == decision.phoneID && $0.active }),
              let phone = current.enrollments.first(where: {
                  $0.approval.phoneID == decision.phoneID && $0.epoch == enrollment.epoch && $0.approval.active
              }),
              let peerFeatures = phone.approval.capabilities.contracts[payload.contract],
              payload.requiredFeatures.isSubset(of: peerFeatures),
              let key = phone.approval.keys.first(where: { $0.id == decision.keyID }),
              key.keyClass == .biometric, key.publicKey == enrollment.key.publicKey,
              enrollment.key.keyClass == .biometric else { throw CommandExecutionError.policyChanged }
    }
}
