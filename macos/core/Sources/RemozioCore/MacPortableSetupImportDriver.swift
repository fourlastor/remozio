import Foundation

protocol MacPortableSetupImportDriver: Sendable {
    func progress() async throws -> SetupPortableImportProgress?
    func perform(_ request: SetupPortableImportOperation) async throws -> SetupPortableImportOperationResult
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
        guard session == nil else { throw AdministrativeSetupChannelError.busy }
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
    init(open: @escaping @Sendable () async throws -> any MacPortableSetupImportRoot = {
        try await MacAccountSetupConnection.openPortableImport()
    }, administrator: @escaping @Sendable () -> any MacPortableSetupImportAdministrator = {
        NativePortableImportAdministrator()
    }) {
        self.open = open; self.administrator = administrator
    }
    func progress() async throws -> SetupPortableImportProgress? {
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
        try Task.checkCancellation()
        let root = try await open()
        do {
            try await root.start()
            guard try await root.progress() == request.expected else { throw AdministrativeSetupError.staleProgress }
            try Task.checkCancellation()
            let rights = administrator()
            do {
                let form = try await rights.authorization()
                try Task.checkCancellation()
                let result = try await root.perform(request, authorization: form)
                try Task.checkCancellation()
                try result.validate(request)
                await rights.close(); await root.close(); return result
            } catch { await rights.close(); throw error }
        } catch { await root.close(); throw error }
    }
}
