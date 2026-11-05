import Darwin
import Foundation
import Synchronization

protocol MacAuditUpgradeDriver: Sendable {
    func progress() async throws -> SetupAuditUpgradeProgress?
    func perform(_ expected: SetupAuditUpgradeProgress) async throws -> SetupAuditUpgradeProgress
}
enum MacAuditUpgradeDriverError: Error, Equatable { case notSubmitted, progressUnavailable, progressChanged, outcomeUnknown }
protocol MacAuditUpgradeAppAuthorization: Sendable {
    func authorize() throws
    func externalForm() throws -> Data
    func close()
}
// The wrapped session serializes its reference operations and checks its creating process before locking.
private final class NativeAuditUpgradeAppAuthorization: MacAuditUpgradeAppAuthorization, @unchecked Sendable {
    private let session: SetupAdministratorSession
    init() throws { session = try SetupAdministratorSession() }
    func authorize() throws { try session.authorize() }
    func externalForm() throws -> Data { try session.externalForm() }
    func close() { session.close() }
}

/// Each explicit attempt uses a fresh connection. Reads never request rights or repeat an earlier mutation.
actor NativeMacAuditUpgradeDriver: MacAuditUpgradeDriver {
    private let open: @Sendable (SetupAuditUpgradeProgress?) async throws -> AuditUpgradeSetupChannel
    private let authorization: @Sendable () throws -> any MacAuditUpgradeAppAuthorization
    init(settings: @escaping @Sendable () throws -> MacAuditUpgradeSettings = {
        try .capture { UserDefaults.standard.object(forKey: $0) }
    }) {
        open = { expected in
            let selected = try settings()
            return try await MacAccountSetupConnection.openAuditUpgrade(expected: expected,
                timeoutMilliseconds: selected.readTimeoutMilliseconds, operationTimeoutMilliseconds: selected.operationTimeoutMilliseconds)
        }
        authorization = { try NativeAuditUpgradeAppAuthorization() }
    }
    init(operationTimeoutMilliseconds: UInt64) throws {
        let selected = try MacAuditUpgradeSettings(operationTimeoutMilliseconds: operationTimeoutMilliseconds)
        self.init(settings: { selected })
    }
    init(open: @escaping @Sendable (SetupAuditUpgradeProgress?) async throws -> AuditUpgradeSetupChannel,
         authorization: @escaping @Sendable () throws -> any MacAuditUpgradeAppAuthorization) {
        self.open = open; self.authorization = authorization
    }
    func progress() async throws -> SetupAuditUpgradeProgress? {
        let channel = try await open(nil)
        do {
            try await channel.start(); let result = try await channel.progress()
            try Task.checkCancellation(); await channel.close(); return result
        } catch { await channel.close(); throw error }
    }
    func perform(_ expected: SetupAuditUpgradeProgress) async throws -> SetupAuditUpgradeProgress {
        guard getuid() > 0, getuid() == geteuid(), expected.runtime.ownerUID == getuid() else {
            throw MacAuditUpgradeDriverError.notSubmitted
        }
        let channel: AuditUpgradeSetupChannel
        do { channel = try await open(expected) }
        catch let error as MacAuditUpgradeSettingsError { throw error }
        catch AuditUpgradeSetupChannelError.progressUnavailable { throw MacAuditUpgradeDriverError.progressUnavailable }
        catch { throw MacAuditUpgradeDriverError.notSubmitted }
        let exported = Mutex(false)
        do {
            try await channel.start()
            guard let current = try await channel.progress() else { throw MacAuditUpgradeDriverError.progressChanged }
            do { try current.validateScope(of: expected) }
            catch { throw MacAuditUpgradeDriverError.progressChanged }
            guard current.stage != .alreadyCurrent else { throw MacAuditUpgradeDriverError.progressChanged }
            try Task.checkCancellation()
            let grant = try authorization(); defer { grant.close() }
            try grant.authorize(); try Task.checkCancellation()
            let result = try await channel.perform(expected, readAuthorization: {
                let form = try grant.externalForm()
                exported.withLock { $0 = true }
                return form
            })
            await channel.close(); return result
        } catch {
            await channel.close()
            // Export marks a possible send. Cancellation cannot prove that the remote operation did not run.
            if exported.withLock({ $0 }) { throw MacAuditUpgradeDriverError.outcomeUnknown }
            if error as? AuditUpgradeSetupChannelError == .progressUnavailable {
                throw MacAuditUpgradeDriverError.progressUnavailable
            }
            if error as? MacAuditUpgradeDriverError == .progressChanged || error as? AdministrativeSetupError == .staleProgress {
                throw MacAuditUpgradeDriverError.progressChanged
            }
            if Task.isCancelled || error is CancellationError || error as? SetupAdministratorAuthorizationError == .cancelled {
                throw CancellationError()
            }
            throw MacAuditUpgradeDriverError.notSubmitted
        }
    }
}
