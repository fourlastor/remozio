import Foundation
import Glibc
import LinuxApprovalFixtureCore
import RemozioHostCore
import RemozioProtocol

#if !DEBUG
#error("This disposable component integration fixture is debug-only")
#endif

let ordinaryCases: Set<String> = ["approve", "malformed-decision", "malformed-capture", "bad-signature", "decline",
    "expired", "expire-before-consume", "expire-at-shared-consume", "replay", "submission-id-replay", "submission-nonce-replay",
    "audit-failure", "crash-before-launch", "crash-after-output"]
let reopenCases: Set<String> = ["reopen-completed", "recover-before-launch", "recover-after-output"]

func expectedRefusal(_ operation: () throws -> Void, matching: (Error) -> Bool) throws {
    do { try operation() }
    catch { try require(matching(error), "unexpectedRefusal"); return }
    throw FixtureError.failed("expectedRefusalMissing")
}

/// New capture, request and software keys; only the historical identifier is reused.
/// A valid new decision cannot authorize a second admission of the reserved ID or nonce.
func refuseSubmissionReplay(store: FixtureStore, directory: String, clock: LinuxAuthorityClock,
                            original: CapturedSubmission, sameID: Bool) throws {
    var changedID = original.id, changedNonce = original.nonce, changedCaller = original.callerBinding
    changedID[0] ^= 0xff; changedNonce[0] ^= 0xff; changedCaller[0] ^= 0xff
    let submission = CapturedSubmission(id: sameID ? original.id : changedID,
        nonce: sameID ? changedNonce : original.nonce, callerBinding: changedCaller)
    let command = try OwnedCommand(directory: directory, submission: submission)
    let material = try FixtureProtocol.make(capture: command.capture.canonicalBytes, clock: clock)
    try command.validate(command.capture)
    _ = try material.verify(now: clock.now())
    try expectedRefusal({ _ = try store.consume(material, validate: command.validate, now: clock.now) }) {
        ($0 as? CommandSubmissionReplayError) == .alreadyReserved
    }
}

func runFixture() throws {
    try require(CommandLine.arguments.count == 3, "arguments")
    let scenario = CommandLine.arguments[1], directory = CommandLine.arguments[2]
    try require(ordinaryCases.contains(scenario) || reopenCases.contains(scenario), "scenario")
    try require(directory.hasPrefix("/") && !directory.utf8.contains(0), "absoluteDirectory")
    var info = stat()
    try require(lstat(directory, &info) == 0 && info.st_mode & S_IFMT == S_IFDIR &&
        info.st_mode & 0o777 == 0o700 && info.st_uid == getuid(), "privateDirectory")
    if ordinaryCases.contains(scenario) {
        try require(try FileManager.default.contentsOfDirectory(atPath: directory).isEmpty, "emptyDirectory")
    }
    _ = signal(SIGPIPE, SIG_IGN)
    let clock = try LinuxAuthorityClock()
    let store = try FixtureStore(directory: directory, reopening: reopenCases.contains(scenario))
    var outputMatched = false, childExitStatus: Int32?
    var decisionResult = ""
    var expectedPhase = "none", expectedRows = 0, expectedRecords = 0, expectedExecutions = 0

    if reopenCases.contains(scenario) {
        // No request/key/token reconstruction. The fresh authority lifetime owns no old live request.
        let prior = try store.snapshot()
        if scenario == "reopen-completed" {
            try require(prior.phase == "succeeded" && prior.rows == 1 && prior.records == 3, "reopenState")
            let reservation = try store.reservation()
            for sameID in [true, false] {
                try refuseSubmissionReplay(store: store, directory: directory, clock: clock,
                    original: reservation.submission, sameID: sameID)
            }
            decisionResult = "reopened"; expectedPhase = "succeeded"; expectedExecutions = 1; expectedRecords = 3
        } else {
            try require(prior.phase == (scenario == "recover-before-launch" ? "authorized" : "executing"), "recoveryState")
            try store.retireUncertainOutcome()
            decisionResult = "recovered"; expectedPhase = "unknown"
            expectedExecutions = scenario == "recover-before-launch" ? 0 : 1
            expectedRecords = scenario == "recover-before-launch" ? 2 : 3
        }
        expectedRows = 1
    } else {
        let command = try OwnedCommand(directory: directory)
        let capture = scenario == "malformed-capture" ? Data([0xa0]) : command.capture.canonicalBytes
        var material = try FixtureProtocol.make(capture: capture, clock: clock, decline: scenario == "decline")
        if scenario == "malformed-decision" { material = material.withDecision(Data([0xa0])) }
        if scenario == "bad-signature" { material = material.withDecision(material.decisionBytes, signature: Data(repeating: 0, count: 64)) }
        let deadline = AuthorityMoment(epoch: material.retained.admittedAt.epoch, milliseconds: material.retained.deadlineMilliseconds)
        let initialNow = try scenario == "expired" ? deadline : clock.now()
        let admit: () throws -> Void = {
            let decoded = try LinuxCommandCapture(canonicalBytes: material.request.canonicalCapture,
                limits: FixtureProtocol.limits, expectedSchemaVersion: material.request.contract.schemaVersion)
            try command.validate(decoded)
            _ = try material.verify(now: initialNow)
        }
        switch scenario {
        case "malformed-capture":
            try expectedRefusal(admit) { $0 is CommandCaptureError }
            decisionResult = "malformedCapture"
        case "malformed-decision":
            try expectedRefusal(admit) { $0 is DecisionPayloadError }
            decisionResult = "malformedDecision"
        case "bad-signature":
            try expectedRefusal(admit) { ($0 as? DecisionVerificationError) == .invalidSignature }
            decisionResult = "invalidSignature"
        case "expired":
            try expectedRefusal(admit) { ($0 as? DecisionVerificationError) == .expired }
            decisionResult = "expired"
        case "expire-before-consume":
            try admit()
            try expectedRefusal({ _ = try store.consume(material, validate: command.validate, now: { deadline }) }) {
                ($0 as? DecisionVerificationError) == .expired
            }
            decisionResult = "expiredBeforeConsume"
        case "expire-at-shared-consume":
            try admit()
            var samples = 0
            try expectedRefusal({
                _ = try store.consume(material, validate: command.validate, now: {
                    samples += 1
                    return samples == 1 ? initialNow : deadline
                })
            }) { ($0 as? DecisionVerificationError) == .expired }
            try require(samples == 2, "sharedConsumptionClockSample")
            decisionResult = "expiredAtSharedConsume"
        case "audit-failure":
            try admit()
            try store.injectAuditFailure()
            try expectedRefusal({ _ = try store.consume(material, validate: command.validate, now: clock.now) }) {
                if case .storage = $0 as? AuditJournalError { return true }; return false
            }
            decisionResult = "auditFailure"
        default:
            try admit()
            let token = try store.consume(material, validate: command.validate, now: clock.now, leavePending: scenario == "crash-before-launch")
            if scenario == "crash-before-launch" { _exit(86) }
            expectedRows = 1
            if scenario == "decline" {
                try require(token == nil, "declineToken")
                decisionResult = "declined"; expectedPhase = "declined"; expectedRecords = 1
            } else {
                guard let token else { throw FixtureError.failed("missingFixtureToken") }
                try store.dispatched(token)
                let result = try command.run()
                outputMatched = result.output == OwnedCommand.line
                childExitStatus = result.exit
                try require(outputMatched && result.exit == 0, "commandResult")
                if scenario == "crash-after-output" { _exit(86) }
                try store.succeeded()
                decisionResult = "accepted"; expectedPhase = "succeeded"; expectedRecords = 3; expectedExecutions = 1
                if scenario == "replay" {
                    try expectedRefusal({ _ = try store.consume(material, validate: command.validate, now: clock.now) }) {
                        ($0 as? ConsumptionJournalError) == .alreadyConsumed
                    }
                    try expectedRefusal({ try store.dispatched(token) }) {
                        if case FixtureError.failed("fixtureTokenReplay") = $0 { return true }; return false
                    }
                    decisionResult = "replayRejected"
                }
                if scenario == "submission-id-replay" || scenario == "submission-nonce-replay" {
                    try refuseSubmissionReplay(store: store, directory: directory, clock: clock,
                        original: command.capture.submission, sameID: scenario == "submission-id-replay")
                    decisionResult = scenario == "submission-id-replay" ? "submissionIDReplayRejected" : "submissionNonceReplayRejected"
                }
            }
        }
    }

    let marker = directory + "/command.marker"
    let markerBytes = FileManager.default.fileExists(atPath: marker) ? try Data(contentsOf: URL(fileURLWithPath: marker)) : Data()
    try require(markerBytes.count <= OwnedCommand.line.count * 2, "markerBounds")
    let expectedMarker = expectedExecutions == 0 ? Data() : OwnedCommand.line
    let snapshot = try store.snapshot()
    let expectedCheckpoint = scenario == "recover-before-launch" ? "finalizePending" : "unchanged"
    let checks = ["expectedDecisionResult": !decisionResult.isEmpty,
        "expectedLedgerState": snapshot.phase == expectedPhase && snapshot.rows == expectedRows,
        "expectedAuditState": snapshot.records == expectedRecords,
        "expectedReplayState": snapshot.reservations == expectedRows,
        "expectedExecutionCount": markerBytes == expectedMarker,
        "expectedCheckpointState": try store.checkpointMatches() && store.checkpointAction == expectedCheckpoint]
    try require(checks.values.allSatisfy { $0 }, "reportChecks")
    let report: [String: Any] = ["passed": true, "checks": checks, "observations": [
        "fixtureOnlyOwner": true, "sharedConsumptionTables": true, "sharedReplayTables": true, "productionAuthority": false, "physicalPhone": false, "hardwareKeys": false,
        "syntheticRequesterClaims": true, "executions": expectedExecutions, "phase": snapshot.phase,
        "checkpointAction": store.checkpointAction, "consumptionRows": snapshot.rows, "submissionReservations": snapshot.reservations, "auditRecords": snapshot.records,
        "outputMatched": outputMatched, "childExitStatus": childExitStatus.map { $0 as Any } ?? NSNull(),
        "decisionResult": decisionResult,
    ]]
    let bytes = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
    FileHandle.standardOutput.write(bytes + Data([10]))
}

do { try runFixture() }
catch {
    let detail: String
    if case FixtureError.failed(let reason) = error { detail = reason }
    else { detail = String(reflecting: type(of: error)) }
    FileHandle.standardError.write(Data("fixture failed: \(detail)\n".utf8))
    exit(1)
}
