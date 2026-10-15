import Foundation
import Observation

protocol MacAccountSetupDriver: Sendable {
    func runtimeProgress() async throws -> SetupRuntimeProgress?
    func prepareRuntime(_ expected: SetupRuntimeProgress, fileCustodyAccepted: Bool) async throws -> SetupRuntimeProgress
    func progress() async throws -> SetupAccountEnrollmentProgress?
    func prepare(_ request: AccountEnrollmentRequest) async throws -> SetupAccountEnrollmentProgress
    func serviceAccountsProgress() async throws -> SetupServiceAccountProgress?
    func prepareServiceAccounts(_ expected: SetupServiceAccountProgress) async throws -> SetupServiceAccountProgress
}
private actor NativeMacAccountSetupDriver: MacAccountSetupDriver {
    func runtimeProgress() async throws -> SetupRuntimeProgress? {
        let channel = try await MacAccountSetupConnection.open(runtime: true)
        do {
            try await channel.start()
            let value = try await channel.runtimeProgress()
            await channel.close(); return value
        } catch { await channel.close(); throw error }
    }
    func prepareRuntime(_ expected: SetupRuntimeProgress, fileCustodyAccepted: Bool) async throws -> SetupRuntimeProgress {
        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
        let channel = try await MacAccountSetupConnection.open(runtime: true)
        do {
            try await channel.start()
            guard try await channel.runtimeProgress() == expected else { throw AdministrativeSetupError.staleProgress }
            try Task.checkCancellation()
            let session = try SetupAdministratorSession(); defer { session.close() }
            try session.authorize()
            try Task.checkCancellation()
            let value = try await channel.prepareRuntime(expected, fileCustodyAccepted: fileCustodyAccepted, authorization: session.externalForm())
            await channel.close(); return value
        } catch { await channel.close(); throw error }
    }
    func progress() async throws -> SetupAccountEnrollmentProgress? {
        let channel = try await MacAccountSetupConnection.open(serviceAccounts: true)
        do {
            try await channel.start()
            let result = try await channel.enrollmentProgress()
            await channel.close()
            return result
        } catch { await channel.close(); throw error }
    }
    func prepare(_ request: AccountEnrollmentRequest) async throws -> SetupAccountEnrollmentProgress {
        let channel = try await MacAccountSetupConnection.open(serviceAccounts: true)
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
    func serviceAccountsProgress() async throws -> SetupServiceAccountProgress? {
        let channel = try await MacAccountSetupConnection.open(serviceAccounts: true)
        do {
            try await channel.start()
            let value = try await channel.serviceAccountsProgress()
            await channel.close(); return value
        } catch { await channel.close(); throw error }
    }
    func prepareServiceAccounts(_ expected: SetupServiceAccountProgress) async throws -> SetupServiceAccountProgress {
        let channel = try await MacAccountSetupConnection.open(serviceAccounts: true)
        do {
            try await channel.start()
            guard try await channel.serviceAccountsProgress() == expected else { throw AdministrativeSetupError.staleProgress }
            try Task.checkCancellation()
            let session = try SetupAdministratorSession(); defer { session.close() }
            try session.authorize()
            try Task.checkCancellation()
            let result = try await channel.prepareServiceAccounts(expected, authorization: session.externalForm())
            await channel.close(); return result
        } catch { await channel.close(); throw error }
    }
}

/// Explicit account setup only. Refresh never asks for administrator rights or retries a mutation.
@MainActor @Observable
public final class MacAccountSetupControls {
    public private(set) var progress: SetupAccountEnrollmentProgress?
    public private(set) var services: SetupServiceAccountProgress?
    public private(set) var runtime: SetupRuntimeProgress?
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
            let serviceState = value?.storagePrepared == true ? try await driver.serviceAccountsProgress() : nil
            try checkScope(serviceState, account: value)
            try Task.checkCancellation()
            let runtimeState = serviceState?.complete == true ? try await driver.runtimeProgress() : nil
            try checkRuntime(runtimeState, services: serviceState)
            try Task.checkCancellation()
            progress = value; services = serviceState; runtime = runtimeState; loaded = true
        } catch is CancellationError { }
        catch { loaded = false; failed = true }
    }
    private func checkScope(_ services: SetupServiceAccountProgress?, account: SetupAccountEnrollmentProgress?) throws {
        guard let account, account.storagePrepared else {
            guard services == nil else { throw AdministrativeSetupChannelError.invalidMessage }; return
        }
        guard let services, services.macID == account.macID, services.accountID == account.accountID,
              services.setupID == account.setupID, services.accountRevision == account.revision, services.ownerUID == account.ownerUID else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
    }
    private func checkRuntime(_ runtime: SetupRuntimeProgress?, services: SetupServiceAccountProgress?) throws {
        guard let services, services.complete else {
            guard runtime == nil else { throw AdministrativeSetupChannelError.invalidMessage }; return
        }
        guard let runtime, runtime.macID == services.macID, runtime.accountID == services.accountID,
              runtime.setupID == services.setupID, runtime.accountRevision == services.accountRevision,
              runtime.ownerUID == services.ownerUID, runtime.servicePlanID == services.planID else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
    }
    public func prepareRuntime(fileCustodyAccepted: Bool) async {
        guard loaded, !working, services?.complete == true, let expected = runtime,
              !expected.configurationPublished, fileCustodyAccepted else { return }
        working = true; failed = false
        defer { working = false }
        do {
            let value = try await driver.prepareRuntime(expected, fileCustodyAccepted: fileCustodyAccepted)
            try Task.checkCancellation(); try value.validateCompletion(of: expected)
            runtime = value
        } catch is CancellationError { loaded = false }
        catch SetupAdministratorAuthorizationError.cancelled { loaded = false }
        catch { loaded = false; failed = true }
    }
    public func prepareServiceAccounts() async {
        guard loaded, !working, progress?.storagePrepared == true, let expected = services, !expected.complete else { return }
        working = true; failed = false
        defer { working = false }
        do {
            let value = try await driver.prepareServiceAccounts(expected)
            try Task.checkCancellation(); try value.validateCompletion(of: expected)
            let runtimeState = try await driver.runtimeProgress()
            try checkRuntime(runtimeState, services: value)
            try Task.checkCancellation()
            services = value; runtime = runtimeState
        } catch is CancellationError { loaded = false }
        catch SetupAdministratorAuthorizationError.cancelled { loaded = false }
        catch { loaded = false; failed = true }
    }
    public func prepare(_ request: AccountEnrollmentRequest) async {
        guard loaded, !working else { return }
        working = true; failed = false
        defer { working = false }
        do {
            let value = try await driver.prepare(request)
            try Task.checkCancellation()
            let serviceState = value.storagePrepared ? try await driver.serviceAccountsProgress() : nil
            try checkScope(serviceState, account: value)
            try Task.checkCancellation()
            let runtimeState = serviceState?.complete == true ? try await driver.runtimeProgress() : nil
            try checkRuntime(runtimeState, services: serviceState)
            try Task.checkCancellation()
            progress = value; services = serviceState; runtime = runtimeState
        } catch is CancellationError { loaded = false }
        catch SetupAdministratorAuthorizationError.cancelled { loaded = false }
        catch {
            // A lost response can follow a successful commit. Read progress before offering another mutation.
            loaded = false; failed = true
        }
    }
}
