import Foundation
import Glibc
import LinuxApprovalFixtureCore
import LinuxOSObservation
import RemozioHostCore
import RemozioProtocol

#if !DEBUG
#error("This disposable composed fixture is debug-only")
#endif

/// Fixture grants: valid, changed but still authorizing, and revoked. Disposable test provenance only.
func writeGrants(_ workspace: String) throws {
    let uid = getuid()
    try require(uid > 0 && uid < UInt32.max - 1, "grantUID")
    let variants: [(String, Set<UInt32>)] = [("grant.cbor", [uid]), ("grant-changed.cbor", [uid, uid == 65534 ? uid + 1 : 65534]),
                                              ("grant-revoked.cbor", [])]
    for (name, targets) in variants {
        let grant = try CommandElevationPolicy(macID: FixtureProtocol.macID, accountID: FixtureProtocol.accountID,
            callerUID: uid, allowedTargetUIDs: targets, independentPolicyDisclosureAccepted: true)
        try grant.canonicalBytes.write(to: URL(fileURLWithPath: workspace + "/" + name), options: .atomic)
    }
}

func runOwner(scenario: String, workspace: String, handshake: FrameChannel, control: FrameChannel) throws -> [String: Any] {
    var report: [String: Any] = ["phase": "result"]
    let clock = try LinuxAuthorityClock()
    let store = try FixtureStore(directory: workspace + "/store", reopening: false)
    func finish(_ refusal: Refusal?, _ stage: String) throws -> [String: Any] {
        let snapshot = try store.snapshot()
        report.merge(["refusal": refusal?.rawValue ?? NSNull(), "stage": stage, "ledgerPhase": snapshot.phase,
            "rows": snapshot.rows, "records": snapshot.records, "reservations": snapshot.reservations,
            "checkpointMatches": try store.checkpointMatches()]) { $1 }
        return report
    }

    let (start, _) = try control.receive(timeoutMilliseconds: 30_000)
    if start["phase"] as? String == "abort" { return try finish(.carrier, "carrier") }
    try require(start["phase"] as? String == "start", "start")
    let nonce = randomBytes(32).hex
    try handshake.send(["phase": "challenge", "nonce": nonce])
    let (prepare, bundle) = try handshake.receive(descriptors: 8)
    guard prepare["phase"] as? String == "prepare", prepare["nonce"] as? String == nonce,
          let binding = prepare["binding"] as? String, let callerBinding = Data(hex: binding), callerBinding.count == 16,
          let generation = prepare["generation"] as? Int, let execEpoch = prepare["execEpoch"] as? Int, execEpoch == 1,
          prepare["stopConfirmed"] as? Bool == true else { return try finish(.monitor, "prepare") }

    let caller: RetainedCaller
    do {
        caller = try RetainedCaller(prepare: prepare, bundle: bundle, streamBindings: (0..<3).map { _ in randomBytes(16) })
    } catch let refusal as Refusal { return try finish(refusal, "admission") } catch { return try finish(.observation, "admission") }
    report["remoteObservation"] = try caller.isRemote()
    report["callerInheritableCapabilities"] = caller.admission.capabilities["CapInh"] != 0
    let owner: ComposedOwner
    do {
        owner = try ComposedOwner(control: control, store: store, caller: caller,
            command: RetainedCommand(path: Data((workspace + "/cmd/tee").utf8)), grantPath: workspace + "/grant.cbor",
            submission: CapturedSubmission(id: randomBytes(16), nonce: randomBytes(32), callerBinding: callerBinding),
            execEpoch: UInt64(execEpoch))
    } catch let refusal as Refusal { return try finish(refusal, "admission") }
    try owner.barrier("B0")

    try handshake.send(["phase": "ack", "nonce": nonce, "binding": binding, "generation": generation])
    try handshake.send(["phase": "ack-complete", "nonce": nonce, "binding": binding])
    let (acknowledged, _) = try handshake.receive()
    guard acknowledged["phase"] as? String == "ack-result", acknowledged["valid"] as? Bool == true else {
        return try finish(.monitor, "ack")
    }
    try control.send(["phase": "captured"])
    let material = try FixtureProtocol.make(capture: owner.capture.canonicalBytes, clock: clock,
                                            decline: scenario == "healthy-decline")
    owner.verifyDecision = { _ = try material.verify(now: clock.now()) }

    let (final, _) = try control.receive(timeoutMilliseconds: 30_000)
    try require(final["phase"] as? String == "final", "final")
    let (state, _) = try handshake.receive()
    guard state["phase"] as? String == "final-state", state["nonce"] as? String == nonce,
          state["binding"] as? String == binding, state["generation"] as? Int == generation,
          state["reason"] as? String == "held_stop", state["stopConfirmed"] as? Bool == true else {
        report["monitorReason"] = state["reason"] as? String ?? NSNull()
        return try finish(.monitor, "final")
    }
    do { try caller.requireMonitorFrozen(); try caller.requireHeld() }
    catch let refusal as Refusal { return try finish(refusal, "final") }
    try owner.barrier("B1")

    let token: FixtureDispatchToken?
    do { token = try store.consume(material, validate: { try owner.recheckAll($0) }, now: clock.now) }
    catch let refusal as Refusal { return try finish(refusal, "consume") }
    guard let token else { return try finish(nil, "declined") }
    try owner.barrier("B3")
    do { try owner.recheckAll() } catch let refusal as Refusal {
        try store.provedNoDispatch()
        return try finish(refusal, "dispatch-check")
    }
    let permit = LaunchPermit(owner: ObjectIdentifier(owner), captureDigest: digest(owner.capture.canonicalBytes), token: token)
    let outcome: LaunchOutcome
    do { outcome = try owner.launchOnce(permit) } catch let refusal as Refusal { return try finish(refusal, "last-check") }
    report["spawned"] = outcome.spawned
    report["childExit"] = outcome.childExit.map { Int($0) as Any } ?? NSNull()
    report["markerMatched"] = outcome.markerMatched
    report["requesterLostDuringDispatch"] = outcome.requesterLostDuringDispatch
    report["strictAdmission"] = outcome.spawned && !outcome.requesterLostDuringDispatch && outcome.childExit == 0 && outcome.markerMatched
    if scenario == "healthy-approve" {
        var consumedAgain = false, permitAgain = false
        do { _ = try store.consume(material, validate: { try owner.recheckAll($0) }, now: clock.now) }
        catch ConsumptionJournalError.alreadyConsumed { consumedAgain = true }
        do { _ = try owner.launchOnce(permit) } catch FixtureError.failed("permitReplay") { permitAgain = true }
        report["replayRejected"] = consumedAgain && permitAgain
    }
    return try finish(nil, "dispatched")
}

func main() -> Int32 {
    let arguments = CommandLine.arguments
    do {
        if arguments.count == 3 && arguments[1] == "grants" {
            try writeGrants(arguments[2])
            return 0
        }
        try require(arguments.count == 6 && arguments[1] == "run", "arguments")
        guard let handshake = Int32(arguments[4]), let control = Int32(arguments[5]) else { throw FixtureError.failed("descriptors") }
        // Inherited without close-on-exec; the command child must receive only its three streams.
        for descriptor in [handshake, control] {
            try require(fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0, "descriptorFlags")
        }
        _ = signal(SIGPIPE, SIG_IGN)
        let controlChannel = FrameChannel(control)
        do {
            let report = try runOwner(scenario: arguments[2], workspace: arguments[3], handshake: FrameChannel(handshake),
                                      control: controlChannel)
            try controlChannel.send(report)
            return 0
        } catch {
            // R must not wait on a silent failure; no raw paths or values in the reported detail.
            let detail: String
            if case FixtureError.failed(let reason) = error { detail = reason } else { detail = String(reflecting: type(of: error)) }
            try? controlChannel.send(["phase": "result", "error": detail])
            return 1
        }
    } catch {
        FileHandle.standardError.write(Data("composed owner failed\n".utf8))
        return 2
    }
}

exit(main())
