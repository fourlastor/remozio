import Foundation
import Observation

protocol MacAccountSetupDriver: Sendable {
    func progress() async throws -> SetupAccountEnrollmentProgress?
    func prepare(_ request: AccountEnrollmentRequest) async throws -> SetupAccountEnrollmentProgress
}
private actor NativeMacAccountSetupDriver: MacAccountSetupDriver {
    func progress() async throws -> SetupAccountEnrollmentProgress? {
        let channel = try await MacAccountSetupConnection.open()
        do {
            try await channel.start()
            let result = try await channel.enrollmentProgress()
            await channel.close()
            return result
        } catch { await channel.close(); throw error }
    }
    func prepare(_ request: AccountEnrollmentRequest) async throws -> SetupAccountEnrollmentProgress {
        let channel = try await MacAccountSetupConnection.open()
        do {
            try await channel.start()
            let previous = try await channel.enrollmentProgress()
            guard previous == nil || previous?.allowedTargetUIDs == request.allowedTargetUIDs else { throw AccountPreparationError.conflict }
            if let previous, previous.storagePrepared { await channel.close(); return previous }
            try Task.checkCancellation()
            // Native administrator UI stays off the UI executor. Export only after the Root handshake succeeds.
            let session = try SetupAdministratorSession()
            defer { session.close() }
            try session.authorize()
            try Task.checkCancellation()
            let retained: SetupAccountEnrollmentProgress
            if let previous { retained = previous }
            else { retained = try await channel.beginEnrollment(request, authorization: session.externalForm()) }
            try Task.checkCancellation()
            let result = try await channel.resumeEnrollment(retained, authorization: session.externalForm())
            await channel.close()
            return result
        } catch { await channel.close(); throw error }
    }
}

/// Explicit account setup only. Refresh never asks for administrator rights or retries a mutation.
@MainActor @Observable
public final class MacAccountSetupControls {
    public private(set) var progress: SetupAccountEnrollmentProgress?
    public private(set) var loaded = false
    public private(set) var working = false
    public private(set) var failed = false
    @ObservationIgnored private let driver: any MacAccountSetupDriver
    public convenience init() { self.init(driver: NativeMacAccountSetupDriver()) }
    init(driver: any MacAccountSetupDriver) { self.driver = driver }
    public func refresh() async {
        guard !working else { return }
        working = true; failed = false
        defer { working = false }
        do {
            let value = try await driver.progress()
            try Task.checkCancellation()
            progress = value; loaded = true
        } catch is CancellationError { }
        catch { loaded = false; failed = true }
    }
    public func prepare(_ request: AccountEnrollmentRequest) async {
        guard loaded, !working else { return }
        working = true; failed = false
        defer { working = false }
        do {
            let value = try await driver.prepare(request)
            try Task.checkCancellation()
            progress = value
        } catch is CancellationError { loaded = false }
        catch SetupAdministratorAuthorizationError.cancelled { loaded = false }
        catch {
            // A lost response can follow a successful commit. Read progress before offering another mutation.
            loaded = false; failed = true
        }
    }
}
