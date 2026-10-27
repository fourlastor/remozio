import CComposedSupport
import Foundation
import Glibc
import LinuxApprovalFixtureCore
import LinuxOSObservation
import RemozioHostCore
import RemozioProtocol

/// The fixed command executable, retained and refused if it could transition credentials.
final class RetainedCommand {
    static let markerName = "command.marker"
    static let expectedOutput = Data("remozio-composed-output\n".utf8)
    let executable: RetainedExecutable

    init(path: Data) throws {
        do { executable = try RetainedExecutable(path: path) } catch is ObservationError { throw Refusal.command }
        try requireNoTransition()
    }

    var arguments: [Data] { [executable.capture.path, Data("-a".utf8), Data(Self.markerName.utf8)] }

    func recheck() throws {
        do { try executable.recheck() } catch is ObservationError { throw Refusal.command }
        try requireNoTransition()
    }

    /// No set-ID bits and an explicitly absent file capability attribute (ENODATA, not denied or unknown).
    private func requireNoTransition() throws {
        try refuse(executable.observation.mode & (S_ISUID | S_ISGID) == 0, .command)
        try refuse(ccs_file_capability_absent(executable.descriptor.value) == 1, .command)
    }
}

/// In-memory, one-use and owner-bound. Never serialized; a decoded receipt is not a permit.
final class LaunchPermit {
    let owner: ObjectIdentifier
    let captureDigest: Data
    private var token: FixtureDispatchToken?
    init(owner: ObjectIdentifier, captureDigest: Data, token: FixtureDispatchToken) {
        self.owner = owner; self.captureDigest = captureDigest; self.token = token
    }
    func take() throws -> FixtureDispatchToken {
        guard let token else { throw FixtureError.failed("permitReplay") }
        self.token = nil
        return token
    }
}

struct LaunchOutcome {
    var spawned = false
    var childExit: Int32?
    var requesterLostDuringDispatch = false
    var markerMatched = false
}

/// Serial fixture owner: one caller, one capture, one store, one optional command child.
final class ComposedOwner {
    let control: FrameChannel
    let store: FixtureStore
    let caller: RetainedCaller
    let command: RetainedCommand
    let capture: LinuxCommandCapture
    let policy: LinuxCurrentCommandElevationPolicy
    let admissionGrant: Data
    let grantPath: String
    let target: CommandTarget
    /// Signature, current trust and authority time of the retained decision; installed once it exists.
    var verifyDecision: () throws -> Void = {}

    init(control: FrameChannel, store: FixtureStore, caller: RetainedCaller, command: RetainedCommand,
         grantPath: String, submission: CapturedSubmission, execEpoch: UInt64) throws {
        self.control = control; self.store = store; self.caller = caller; self.command = command; self.grantPath = grantPath
        let uid = caller.admission.credentials.credentials.realUID
        let load: @Sendable () throws -> CommandElevationPolicy = {
            try CommandElevationPolicy.decode(Data(contentsOf: URL(fileURLWithPath: grantPath)))
        }
        do {
            admissionGrant = try load().canonicalBytes
            policy = try LinuxCurrentCommandElevationPolicy(macID: FixtureProtocol.macID, accountID: FixtureProtocol.accountID,
                callerUID: uid, load: load, readCallerCredentials: { [caller] in try caller.currentCredentials() })
            target = try policy.resolveTarget(macID: FixtureProtocol.macID, accountID: FixtureProtocol.accountID,
                callerUID: uid, requestedTargetUID: uid)
        } catch let refusal as Refusal { throw refusal } catch { throw Refusal.grant }
        let requester = CapturedLinuxRequester(pid: UInt32(caller.callerPID), processBinding: randomBytes(16),
            monitorIncarnation: randomBytes(16), execEpoch: execEpoch, executable: caller.executable.capture,
            credentials: caller.admission.credentials.credentials, sessionID: caller.admission.session,
            codePolicyDigest: digest(Data("synthetic composed fixture policy; trustedCode=false".utf8)))
        capture = try LinuxCommandCapture(executable: command.executable.capture, arguments: command.arguments,
            directory: caller.directory.capture, target: target,
            environment: [.init(name: Data("LANG".utf8), value: Data("C".utf8), source: .minimal)],
            input: caller.streams[0].capture.source, requester: requester,
            unverifiedRationale: "Composed fixture; monitored provenance and policy are synthetic; trustedCode=false",
            submission: submission,
            stdioLayout: .init(input: caller.streams[0].capture, output: caller.streams[1].capture,
                error: caller.streams[2].capture, terminal: nil, ptyMask: 0),
            limits: FixtureProtocol.limits)
        try requireExecutorMatchesTarget()
    }

    /// Exact canonical grant, current authorization, caller credentials and freshly resolved target.
    func requireCurrentPolicy() throws {
        do {
            let current = try CommandElevationPolicy.decode(Data(contentsOf: URL(fileURLWithPath: grantPath)))
            try refuse(current.canonicalBytes == admissionGrant, .grant)
            try policy.validate(capture: capture)
            // `validate` loads the grant again; a still-authorizing swap between the reads must not pass.
            let after = try CommandElevationPolicy.decode(Data(contentsOf: URL(fileURLWithPath: grantPath)))
            try refuse(after.canonicalBytes == admissionGrant, .grant)
        } catch let refusal as Refusal { throw refusal } catch { throw Refusal.grant }
    }

    /// This owner's own task is the one that spawns: its credentials must already be the target's.
    func requireExecutorMatchesTarget() throws {
        do {
            let own = try CredentialObservation.current()
            try own.requireOrdinaryAccount()
            let c = own.credentials
            try refuse(c.realUID == target.uid && c.realGID == target.gid &&
                c.supplementaryGroups == target.supplementaryGroups, .executor)
            let directory = try OwnedFD(open("/proc/thread-self", O_RDONLY | O_DIRECTORY | O_CLOEXEC))
            let task = try withExtendedLifetime(directory) { try TaskObservation.read(directory.value) }
            try refuse(task.holdsNoCapabilities, .executor)
        } catch let refusal as Refusal { throw refusal } catch { throw Refusal.executor }
    }

    /// Every check this owner can make before a dispatch decision, in one place.
    func recheckAll(_ decoded: LinuxCommandCapture? = nil) throws {
        if let decoded { try refuse(decoded == capture, .capture) }
        do { try verifyDecision() } catch { throw Refusal.decision }
        try caller.recheck()
        try command.recheck()
        try requireCurrentPolicy()
        try requireExecutorMatchesTarget()
    }

    func barrier(_ name: String) throws {
        try control.send(["phase": "barrier", "name": name])
        let (reply, _) = try control.receive(timeoutMilliseconds: 30_000)
        try require(reply["phase"] as? String == "continue", "barrier")
    }

    /// Consumes the permit, records the durable dispatch transition, rechecks and spawns at most once.
    func launchOnce(_ permit: LaunchPermit) throws -> LaunchOutcome {
        try require(permit.owner == ObjectIdentifier(self) && permit.captureDigest == digest(capture.canonicalBytes), "permitOwner")
        let token = try permit.take()
        try store.dispatched(token)
        var outcome = LaunchOutcome()
        try barrier("B4")
        do { try recheckAll() } catch {
            try store.lostOutcome()
            throw error
        }
        // Past the last check. Monitor/caller loss from here to spawn can only be recorded, not prevented.
        try barrier("B4L")
        let child = try spawn()
        outcome.spawned = true
        outcome.requesterLostDuringDispatch = !caller.stillHeld()
        outcome.childExit = try wait(child)
        let marker = try? readRelative(caller.directoryDescriptor.value, RetainedCommand.markerName)
        outcome.markerMatched = marker == RetainedCommand.expectedOutput
        if outcome.requesterLostDuringDispatch { try store.lostOutcome() }
        else if outcome.childExit == 0 && outcome.markerMatched { try store.succeeded() }
        else { try store.failed() }
        return outcome
    }

    private func spawn() throws -> pid_t {
        // Raw bytes, never re-encoded: paths need not be valid UTF-8.
        func cString(_ bytes: Data) -> UnsafeMutablePointer<CChar> {
            let pointer = UnsafeMutablePointer<CChar>.allocate(capacity: bytes.count + 1)
            for (index, byte) in bytes.enumerated() { pointer[index] = CChar(bitPattern: byte) }
            pointer[bytes.count] = 0
            return pointer
        }
        let path = cString(command.executable.capture.path)
        let arguments = command.arguments.map(cString), environment = [cString(Data("LANG=C".utf8))]
        defer { for pointer in [path] + arguments + environment { pointer.deallocate() } }
        var argv: [UnsafeMutablePointer<CChar>?] = arguments + [nil]
        var envp: [UnsafeMutablePointer<CChar>?] = environment + [nil]
        let streams = caller.streams.map(\.descriptor.value)
        var child: pid_t = 0
        let result = ccs_spawn(&child, path, &argv, &envp, streams, caller.directoryDescriptor.value)
        try require(result == 0 && child > 0, "spawn")
        return child
    }

    private func wait(_ child: pid_t) throws -> Int32 {
        var status: Int32 = 0
        for _ in 0..<500 {
            let observed = waitpid(child, &status, WNOHANG)
            if observed == child { return status & 0x7f == 0 ? (status >> 8) & 0xff : -1 }
            try require(observed == 0 || errno == EINTR, "wait")
            usleep(10_000)
        }
        kill(child, SIGKILL)
        while waitpid(child, &status, 0) < 0 && errno == EINTR {}
        throw FixtureError.failed("commandTimeout")
    }
}
