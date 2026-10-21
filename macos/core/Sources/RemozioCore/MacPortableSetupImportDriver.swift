import Foundation

protocol MacPortableSetupImportDriver: Sendable {
    func progress() async throws -> SetupPortableImportProgress?
    func perform(_ request: SetupPortableImportOperation) async throws -> SetupPortableImportOperationResult
    func importFile(_ reviewed: ReviewedSetupFile, expected: SetupPortableImportProgress,
                    custody: SetupPortableImportCustodyChoices,
                    step: @escaping @Sendable (SetupPortableImportOperation.Action, SetupPortableImportProgress) async -> Void) async throws -> SetupPortableImportOperationResult
}
extension MacPortableSetupImportDriver {
    func importFile(_ reviewed: ReviewedSetupFile, expected: SetupPortableImportProgress,
                    custody: SetupPortableImportCustodyChoices,
                    step: @escaping @Sendable (SetupPortableImportOperation.Action, SetupPortableImportProgress) async -> Void) async throws -> SetupPortableImportOperationResult {
        throw AdministrativeSetupChannelError.unsupportedVersion
    }
}
protocol MacPortableSetupImportRoot: Sendable {
    func start() async throws
    func progress() async throws -> SetupPortableImportProgress?
    func perform(_ request: SetupPortableImportOperation, authorization: Data) async throws -> SetupPortableImportOperationResult
    func close() async
}
protocol MacPortableSetupImportAdministrator: Sendable {
    func authorization() async throws -> Data
    func close() async
}
extension PortableSetupImportChannel: MacPortableSetupImportRoot {}

private actor NativePortableImportAdministrator: MacPortableSetupImportAdministrator {
    private var session: SetupAdministratorSession?
    func authorization() throws -> Data {
        try Task.checkCancellation()
        if let session { return try session.externalForm() }
        let session = try SetupAdministratorSession()
        self.session = session
        try session.authorize()
        try Task.checkCancellation()
        return try session.externalForm()
    }
    func close() { session?.close(); session = nil }
}

/// Each explicit operation verifies Root and current progress before requesting administrator rights.
/// A failed or lost reply never causes another write attempt.
actor NativeMacPortableSetupImportDriver: MacPortableSetupImportDriver {
    private let open: @Sendable () async throws -> any MacPortableSetupImportRoot
    private let administrator: @Sendable () -> any MacPortableSetupImportAdministrator
    private let now: @Sendable () -> ContinuousClock.Instant
    private var operationActive = false
    init(open: @escaping @Sendable () async throws -> any MacPortableSetupImportRoot = {
        try await MacAccountSetupConnection.openPortableImport()
    }, administrator: @escaping @Sendable () -> any MacPortableSetupImportAdministrator = {
        NativePortableImportAdministrator()
    }, now: @escaping @Sendable () -> ContinuousClock.Instant = { .now }) {
        self.open = open; self.administrator = administrator; self.now = now
    }
    func progress() async throws -> SetupPortableImportProgress? {
        guard !operationActive else { throw AdministrativeSetupChannelError.busy }
        operationActive = true
        defer { operationActive = false }
        try Task.checkCancellation()
        let root = try await open()
        do {
            try await root.start()
            let value = try await root.progress()
            try Task.checkCancellation()
            await root.close(); return value
        } catch { await root.close(); throw error }
    }
    func perform(_ request: SetupPortableImportOperation) async throws -> SetupPortableImportOperationResult {
        guard !operationActive else { throw AdministrativeSetupChannelError.busy }
        operationActive = true
        defer { operationActive = false }
        let rights = administrator()
        do {
            let result = try await perform(request, rights: rights)
            await rights.close(); return result
        } catch { await rights.close(); throw error }
    }

    /// One explicit import attempt owns its rights until completion, a paused result or failure.
    /// The five-minute bound prevents a later step from extending this authorization window.
    func importFile(_ reviewed: ReviewedSetupFile, expected: SetupPortableImportProgress,
                    custody: SetupPortableImportCustodyChoices,
                    step: @escaping @Sendable (SetupPortableImportOperation.Action, SetupPortableImportProgress) async -> Void) async throws -> SetupPortableImportOperationResult {
        guard !operationActive else { throw AdministrativeSetupChannelError.busy }
        let actions = try reviewed.actions(expected: expected, custody: custody)
        operationActive = true
        defer { operationActive = false }
        let clock = now
        let started = clock(), deadline = started.advanced(by: .seconds(300))
        let rights = administrator()
        @Sendable func checkWindow() throws {
            try Task.checkCancellation()
            let time = clock()
            guard time >= started, time < deadline else { throw SetupPortableImportFlowError.authorizationExpired }
        }
        do {
            var current = expected
            for action in actions {
                try checkWindow()
                await step(action, current)
                try checkWindow()
                let request = try reviewed.operation(action: action, expected: current, fileCustodyAccepted: custody.accepts(action))
                let result = try await perform(request, rights: rights, beforeDispatch: checkWindow)
                current = result.progress
                if result.status != .applied || action == .complete {
                    await rights.close(); return result
                }
            }
            throw AdministrativeSetupChannelError.invalidMessage
        } catch { await rights.close(); throw error }
    }

    private func perform(_ request: SetupPortableImportOperation, rights: any MacPortableSetupImportAdministrator,
                         beforeDispatch: @Sendable () throws -> Void = {}) async throws -> SetupPortableImportOperationResult {
        try Task.checkCancellation()
        let root = try await open()
        do {
            try await root.start()
            guard try await root.progress() == request.expected else { throw AdministrativeSetupError.staleProgress }
            try Task.checkCancellation()
            let form = try await rights.authorization()
            try beforeDispatch(); try Task.checkCancellation()
            let result = try await root.perform(request, authorization: form)
            try Task.checkCancellation(); try result.validate(request)
            await root.close(); return result
        } catch { await root.close(); throw error }
    }
}
