import Foundation
import RemozioProtocol

extension AuthorityJournal {
    /// Uses the original authenticated scope and UID. Draft construction remains trusted host code.
    public func admitCommandAttempt(_ attempt: sending RetainedCommandAdmissionAttempt,
                                    elevationPolicy: CurrentCommandElevationPolicy, captureSchemaVersion: UInt64,
                                    minimalEnvironment: [CapturedEnvironmentEntry], streamBinding: Data,
                                    captureLimits: CBORLimits, maximumAncestryEntries: Int = 16,
                                    draft: (CommandCapture) throws -> ApprovalRequestDraft,
                                    now: () throws -> AuthorityMoment, receiptTimeMs: UInt64?,
                                    checkCancellation: @escaping @Sendable () throws -> Void = {}) throws -> IssuedRequestPayload {
        try admitCommandAttempt(attempt, elevationPolicy: elevationPolicy,
            captureSchemaVersion: captureSchemaVersion, minimalEnvironment: minimalEnvironment,
            streamBinding: { streamBinding }, captureLimits: captureLimits, maximumAncestryEntries: maximumAncestryEntries,
            draft: draft, now: now, receiptTimeMs: receiptTimeMs, checkCancellation: checkCancellation)
    }

    /// Creates stream metadata after grants pass, under the journal lock. The factory must not reenter the journal.
    public func admitCommandAttempt(_ attempt: sending RetainedCommandAdmissionAttempt,
                                    elevationPolicy: CurrentCommandElevationPolicy, captureSchemaVersion: UInt64,
                                    minimalEnvironment: [CapturedEnvironmentEntry], streamBinding: @escaping @Sendable () throws -> Data,
                                    captureLimits: CBORLimits, maximumAncestryEntries: Int = 16,
                                    draft: (CommandCapture) throws -> ApprovalRequestDraft,
                                    now: () throws -> AuthorityMoment, receiptTimeMs: UInt64?,
                                    checkCancellation: @escaping @Sendable () throws -> Void = {}) throws -> IssuedRequestPayload {
        let check = CommandElevationAdmissionCheck(profile: attempt.profile, callerUID: attempt.userID, policy: elevationPolicy,
            schemaVersion: captureSchemaVersion, environment: minimalEnvironment, streamBinding: streamBinding,
            limits: captureLimits, maximumAncestryEntries: maximumAncestryEntries)
        return try admitCommandAttempt(attempt, resolve: check.resolve, draft: { try check.draft($0, build: draft) },
            now: now, receiptTimeMs: receiptTimeMs, checkCancellation: checkCancellation)
    }

    /// Fixture identity seam. Production always uses the Root role and current frontend code policy.
    func admitCommandAttempt(_ attempt: RetainedCommandAdmissionAttempt, expression: String,
                             elevationPolicy: CurrentCommandElevationPolicy, captureSchemaVersion: UInt64,
                             minimalEnvironment: [CapturedEnvironmentEntry], streamBinding: Data,
                             captureLimits: CBORLimits, maximumAncestryEntries: Int = 16,
                             draft: (CommandCapture) throws -> ApprovalRequestDraft,
                             now: () throws -> AuthorityMoment, receiptTimeMs: UInt64?,
                             checkCancellation: @escaping @Sendable () throws -> Void = {}) throws -> IssuedRequestPayload {
        try admitCommandAttempt(attempt, expression: expression, elevationPolicy: elevationPolicy,
            captureSchemaVersion: captureSchemaVersion, minimalEnvironment: minimalEnvironment,
            streamBinding: { streamBinding }, captureLimits: captureLimits, maximumAncestryEntries: maximumAncestryEntries,
            draft: draft, now: now, receiptTimeMs: receiptTimeMs, checkCancellation: checkCancellation)
    }

    func admitCommandAttempt(_ attempt: RetainedCommandAdmissionAttempt, expression: String,
                             elevationPolicy: CurrentCommandElevationPolicy, captureSchemaVersion: UInt64,
                             minimalEnvironment: [CapturedEnvironmentEntry], streamBinding: @escaping @Sendable () throws -> Data,
                             captureLimits: CBORLimits, maximumAncestryEntries: Int = 16,
                             draft: (CommandCapture) throws -> ApprovalRequestDraft,
                             now: () throws -> AuthorityMoment, receiptTimeMs: UInt64?,
                             checkCancellation: @escaping @Sendable () throws -> Void = {}) throws -> IssuedRequestPayload {
        let check = CommandElevationAdmissionCheck(profile: attempt.profile, callerUID: attempt.userID, policy: elevationPolicy,
            schemaVersion: captureSchemaVersion, environment: minimalEnvironment, streamBinding: streamBinding,
            limits: captureLimits, maximumAncestryEntries: maximumAncestryEntries)
        return try admitCommandAttempt(attempt, expression: expression, resolve: check.resolve,
            draft: { try check.draft($0, build: draft) }, now: now, receiptTimeMs: receiptTimeMs,
            checkCancellation: checkCancellation)
    }

    /// Connects fresh protected grants to the existing pre-spawn and pre-release checks.
    public func beginCommandExecution(requestID: Data, monitorPath: String, childPath: String,
                                      preparationMilliseconds: UInt32, fileCreationMask: UInt32,
                                      maximumActiveCommands: Int = 32, pollIntervalMilliseconds: Int = 20,
                                      elevationPolicy: CurrentCommandElevationPolicy,
                                      clock: @escaping @Sendable () throws -> AuthorityMoment,
                                      receiptTime: @escaping @Sendable () -> UInt64? = { nil },
                                      checkCancellation: @escaping @Sendable () throws -> Void = {}) throws {
        try checkCancellation()
        try read { transaction in
            let trust = try transaction.approvalTrustSnapshot()
            guard trust.macID == elevationPolicy.macID, trust.accountID == elevationPolicy.accountID else {
                throw CommandElevationPolicyError.policyRejected
            }
        }
        try beginCommandExecution(requestID: requestID, monitorPath: monitorPath, childPath: childPath,
            preparationMilliseconds: preparationMilliseconds, fileCreationMask: fileCreationMask,
            maximumActiveCommands: maximumActiveCommands, pollIntervalMilliseconds: pollIntervalMilliseconds,
            validateElevation: { capture in
                try checkCancellation(); try elevationPolicy.validate(capture: capture); try checkCancellation()
            }, clock: clock, receiptTime: receiptTime)
    }
}

private struct CommandElevationAdmissionCheck: Sendable {
    let profile: CommandHandshakeProfile
    let callerUID: UInt32
    let policy: CurrentCommandElevationPolicy
    let context: @Sendable (CommandTarget) throws -> CommandAdmissionCaptureContext

    init(profile: CommandHandshakeProfile, callerUID: UInt32, policy: CurrentCommandElevationPolicy, schemaVersion: UInt64,
         environment: [CapturedEnvironmentEntry], streamBinding: @escaping @Sendable () throws -> Data, limits: CBORLimits, maximumAncestryEntries: Int) {
        self.profile = profile; self.callerUID = callerUID; self.policy = policy
        context = { .init(schemaVersion: schemaVersion, target: $0, minimalEnvironment: environment,
            streamBinding: try streamBinding(), limits: limits, maximumAncestryEntries: maximumAncestryEntries) }
    }

    func resolve(_ submission: CommandSubmission) throws -> CommandAdmissionResolution {
        let target: CommandTarget
        do {
            target = try policy.resolveTarget(macID: profile.macID, accountID: profile.accountID,
                callerUID: callerUID, requestedTargetUID: submission.requestedTargetUID)
        } catch CommandElevationPolicyError.policyRejected { return .refuse(.policyRejected) }
        return .capture(try context(target))
    }

    func draft(_ capture: CommandCapture, build: (CommandCapture) throws -> ApprovalRequestDraft) throws -> ApprovalRequestDraft {
        try policy.validate(capture: capture)
        let result = try build(capture)
        try policy.validate(capture: capture)
        return result
    }
}
