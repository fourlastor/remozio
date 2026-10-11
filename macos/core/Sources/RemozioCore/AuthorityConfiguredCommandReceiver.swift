import Darwin
import Foundation
import RemozioProtocol
import Security

extension AuthorityCommandStartupConfiguration {
    /// The installer supplies a fresh receive right from a separately validated protected registration.
    /// Check-in success alone is insufficient. This factory never registers a service or dispatches a command.
    public func receiverFactory(takingRegisteredReceiveRight: @escaping @Sendable () throws -> mach_port_t,
        onAdmission: @escaping @Sendable (Result<IssuedRequestPayload, any Error>) -> Void = { _ in },
        report: @escaping @Sendable (AuthorityCommandReceiveWorker.Status) -> Void = { _ in }) throws -> AuthorityCommandReceiveFactory {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let policy = try currentElevationPolicy()
        let capabilities = try self.capabilities
        return { journal, clock in
            try AuthorityCommandReceiveWorker(journal: journal, submissionLimits: submissionLimits, makeHost: {
                try CommandReceiveHost(takingReceiveRight: takingRegisteredReceiveRight(), journal: journal,
                    macID: macID, accountID: accountID, userID: callerUID, maximumSessions: maximumSessions,
                    maximumPayloadBytes: submissionLimits.maxBytes, receiveWaitMilliseconds: receiveWaitMilliseconds,
                    replyTimeoutMilliseconds: replyTimeoutMilliseconds, capabilities: capabilities)
            }, elevationPolicy: policy, captureSchemaVersion: Self.captureSchemaVersion,
                minimalEnvironment: environment, captureLimits: captureLimits,
                maximumAncestryEntries: maximumAncestryEntries, streamBinding: Self.freshStreamBinding,
                draft: { try commandDraft($0, observed: clock.now(), unixMilliseconds: Self.unixMilliseconds()) },
                clock: { try clock.now() }, receiptTime: { try? Self.unixMilliseconds() },
                onAdmission: onAdmission, report: report)
        }
    }

    /// Trusted admission has already validated OS provenance and current grants. The coordinator supplies IDs and challenges.
    func commandDraft(_ capture: CommandCapture, observed: AuthorityMoment, unixMilliseconds: UInt64) throws -> ApprovalRequestDraft {
        guard capture.schemaVersion == Self.captureSchemaVersion, capture.stdioLayout != nil else {
            throw ApprovalCoordinatorError.invalidDraft
        }
        let deadline = observed.milliseconds.addingReportingOverflow(approvalLifetimeMilliseconds)
        let expires = unixMilliseconds.addingReportingOverflow(approvalLifetimeMilliseconds)
        guard !deadline.overflow, !expires.overflow else { throw ApprovalCoordinatorError.invalidClock }
        return try .init(contract: .init(requestKind: .command, wireVersion: 1, schemaVersion: Self.captureSchemaVersion),
            requiredFeatures: [], capture: capture.canonicalBytes,
            actions: Self.permittedCommandActions,
            firstObservedAt: observed, deadlineMilliseconds: deadline.partialValue,
            createdUnixMilliseconds: unixMilliseconds, expiresUnixMilliseconds: expires.partialValue)
    }

    private static func freshStreamBinding() throws -> Data {
        var bytes = Data(count: 16)
        let result = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        guard result == errSecSuccess else { throw ApprovalCoordinatorError.unavailable }
        return bytes
    }
    private static func unixMilliseconds() throws -> UInt64 {
        let value = Date().timeIntervalSince1970 * 1000
        guard value.isFinite, value >= 0, value < Double(UInt64.max) else { throw ApprovalCoordinatorError.invalidClock }
        return UInt64(value)
    }
}
