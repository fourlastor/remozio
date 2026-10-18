import Foundation
import RemozioProtocol

public enum GatewayJournalSetupInterface {
    public static let version: UInt64 = 1
    public static let supportedVersions: Set<UInt64> = [version]
}

@objc public protocol GatewayJournalSetupXPCProtocol {
    func hello(reply: @escaping @Sendable (UInt64) -> Void)
    func prepare(_ intentDigest: Data, challenge: Data, reply: @escaping @Sendable (Data?) -> Void)
}

/// Report framing only. The client must authenticate the live gateway connection before accepting these bytes.
enum GatewayJournalSetupResponse {
    static func encode(report: GatewayJournalSetupReport, challenge: Data) throws -> Data {
        guard challenge.count == 32 else { throw GatewayPreparationError.invalidRecord }
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(challenge), 2: .bytes(report.encoded)]), limits: limits)
    }
    static func decode(_ bytes: Data, challenge: Data, intentID: Data, scopeDigest: Data) throws -> GatewayJournalSetupReport {
        guard challenge.count == 32, case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...2), fields[0] == .unsigned(1), fields[1] == .bytes(challenge),
              case .bytes(let record) = fields[2] else { throw GatewayPreparationError.invalidRecord }
        let report = try GatewayJournalSetupReport.decode(record)
        guard report.intentID == intentID, report.scopeDigest == scopeDigest,
              try encode(report: report, challenge: challenge) == bytes else { throw GatewayPreparationError.changedScope }
        return report
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: 1024, maxDepth: 1, maxItems: 7) } }
}

/// One pending setup operation. The caller must load the intent and setup code from protected release metadata.
/// The listener owns activation, connection limits and process retirement. This endpoint starts no normal request listener.
final class GatewayJournalSetupXPCEndpoint: NSObject, GatewayJournalSetupXPCProtocol, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let intentID: Data
    private let scopeDigest: Data
    private let verify: () throws -> Void
    private let invalidate: () -> Void
    private let onHandshake: @Sendable () -> Void
    private let budget: AuthorityXPCWorkBudget
    private let execute: @Sendable () async throws -> Data
    private var ready = false
    private var closed = false
    private var consumed = false
    private var task: Task<Void, Never>?
    private var operationID: UUID?

    convenience init(connection: NSXPCConnection, setupCode: AuthorityCodeEntry, intent: GatewayJournalSetupIntent,
                     budget: AuthorityXPCWorkBudget, onHandshake: @escaping @Sendable () -> Void,
                     onClose: @escaping @Sendable () -> Void) throws {
        try intent.configuration.requireNativeProcess()
        guard setupCode.role == .setupController, setupCode.active else { throw GatewayPreparationError.invalidRecord }
        let policy = try XPCPeerPolicy(teamID: setupCode.teamID, componentIdentifier: setupCode.identifier,
            approvedCodeDirectoryHashes: [setupCode.codeDirectoryHash], expectedUserID: 0)
        _ = try policy.verifyCredentials(connection)
        let invocation = XPCInvocationGuard(connection: connection, policy: policy)
        let encodedIntent = try intent.encoded
        try self.init(intentID: intent.id, scopeDigest: intent.digest, verify: { _ = try invocation.verifyInvocation() },
            budget: budget, onHandshake: onHandshake, invalidate: { [weak connection] in connection?.invalidate(); onClose() },
            execute: {
                let retained = try GatewayJournalSetupIntent.decode(encodedIntent)
                return try GatewayJournalPreparationOperation.execute(intent: retained) { configuration, files in
                    try GatewayJournalInitialization.resume(configuration: configuration, expected: files, mayInitializeEmpty: true)
                }
            })
        policy.configure(connection)
        connection.exportedInterface = NSXPCInterface(with: GatewayJournalSetupXPCProtocol.self)
        connection.exportedObject = self
        connection.interruptionHandler = { [weak self] in self?.close() }
        connection.invalidationHandler = { [weak self] in self?.close() }
    }
    // Fixtures exercise invocation sequencing. They cannot substitute for native code and UID admission.
    init(intentID: Data, scopeDigest: Data, verify: @escaping () throws -> Void, budget: AuthorityXPCWorkBudget,
         onHandshake: @escaping @Sendable () -> Void = {}, invalidate: @escaping () -> Void,
         execute: @escaping @Sendable () async throws -> Data) throws {
        guard intentID.count == 16, scopeDigest.count == 32 else { throw GatewayPreparationError.invalidRecord }
        self.intentID = intentID; self.scopeDigest = scopeDigest; self.verify = verify; self.budget = budget
        self.onHandshake = onHandshake; self.invalidate = invalidate; self.execute = execute
    }
    func close() {
        let result = lock.withLock { () -> (Bool, Task<Void, Never>?) in
            guard !closed else { return (false, nil) }
            closed = true; ready = false; return (true, task)
        }
        if result.0 { invalidate(); result.1?.cancel() }
    }
    func hello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            try verify()
            try lock.withLock {
                guard !closed, !ready, !consumed else { throw GatewayPreparationError.incomplete }
                ready = true; onHandshake(); reply(GatewayJournalSetupInterface.version)
            }
        } catch { close(); reply(0) }
    }
    func prepare(_ intentDigest: Data, challenge: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            try verify()
            try lock.withLock {
                guard ready, !closed, !consumed, intentDigest == scopeDigest, challenge.count == 32,
                      budget.acquire() else { throw GatewayPreparationError.changedScope }
                consumed = true
                let id = UUID(); operationID = id
                task = Task { [self] in
                    defer { finish(id) }
                    do {
                        try Task.checkCancellation()
                        let record = try await execute()
                        try Task.checkCancellation()
                        let report = try GatewayJournalSetupReport.decode(record)
                        guard report.intentID == intentID, report.scopeDigest == scopeDigest else { throw GatewayPreparationError.changedScope }
                        let response = try GatewayJournalSetupResponse.encode(report: report, challenge: challenge)
                        lock.withLock { finish(id); if !closed { reply(response) } }
                    } catch { lock.withLock { finish(id); if !closed { reply(nil) } } }
                }
            }
        } catch { close(); reply(nil) }
    }
    private func finish(_ id: UUID) {
        lock.withLock {
            guard operationID == id else { return }
            operationID = nil; task = nil; budget.release()
        }
    }
}
