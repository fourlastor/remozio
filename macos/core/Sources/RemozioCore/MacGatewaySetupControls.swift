import Foundation
import Observation

public enum MacGatewaySetupOperation: Equatable, Sendable { case refreshing, preparing, initializingJournal, activating, applyingSettings }
public enum MacGatewaySetupNotice: Equatable, Sendable { case refreshFailed, operationFailed, settingsTransitionRequired, settingsUnavailable }

/// Explicit optional setup only. Progress records history; it never proves current service or phone health.
@MainActor @Observable
public final class MacGatewaySetupControls {
    public private(set) var progress: SetupGatewayActivationProgress?
    public private(set) var initialSelection: GatewayRuntimeSettingsSelection?
    public private(set) var settingsProgress: SetupGatewaySettingsProgress?
    public private(set) var loaded = false
    public private(set) var operation: MacGatewaySetupOperation?
    public private(set) var notice: MacGatewaySetupNotice?
    /// The last explicit journal result only. Refresh clears this observation rather than assuming the job remains absent.
    public private(set) var lastJournalCleanupComplete: Bool?
    public var working: Bool { operation != nil }
    @ObservationIgnored private let driver: any MacGatewaySetupDriver
    public convenience init() { self.init(driver: try! NativeMacGatewaySetupDriver()) }
    public convenience init(operationTimeoutMilliseconds: UInt64) throws {
        self.init(driver: try NativeMacGatewaySetupDriver(operationTimeoutMilliseconds: operationTimeoutMilliseconds))
    }
    init(driver: any MacGatewaySetupDriver) { self.driver = driver }

    public func refresh() async {
        guard !working else { return }
        operation = .refreshing; loaded = false; notice = nil; lastJournalCleanupComplete = nil; initialSelection = nil
        defer { operation = nil }
        do {
            let value = try await driver.progress(); try Task.checkCancellation()
            let settings: SetupGatewaySettingsProgress?
            if value?.jobRegistered == true { settings = try await driver.settingsProgress() }
            else { settings = nil }
            try Task.checkCancellation()
            if let value, value.jobRegistered {
                guard settings?.activation == value else { throw AdministrativeSetupChannelError.invalidMessage }
            }
            let initial: GatewayRuntimeSettingsSelection?
            if let value, value.setup.gatewayMaterialID == nil { initial = try await driver.initialSelection(value.setup) }
            else { initial = nil }
            try Task.checkCancellation()
            progress = value; settingsProgress = settings; initialSelection = initial; loaded = true
        } catch { fail(error, reading: true) }
    }
    public func prepare(_ choices: GatewaySetupPreparationChoices) async {
        guard loaded, !working, let expected = progress, !expected.setup.journalInitialized,
              choices.fileWakeCustodyAccepted else { return }
        operation = .preparing; notice = nil; lastJournalCleanupComplete = nil
        defer { operation = nil }
        do {
            let result = try await driver.prepare(expected.setup, choices: choices)
            try Task.checkCancellation(); try result.validatePreparation(of: expected.setup)
            let current = try await driver.progress(); try Task.checkCancellation()
            guard let current, current.setup == result else { throw AdministrativeSetupChannelError.invalidMessage }
            progress = current
        } catch { fail(error) }
    }
    /// An initialized journal can still need cleanup. This explicit retry never implies permission to initialize it again.
    public func initializeJournal() async {
        guard loaded, !working, let expected = progress, expected.setup.journalIntentDigest != nil else { return }
        operation = .initializingJournal; notice = nil; lastJournalCleanupComplete = nil
        defer { operation = nil }
        do {
            let result = try await driver.initializeJournal(expected.setup)
            try Task.checkCancellation(); try result.progress.validateJournalCompletion(of: expected.setup)
            let current = try await driver.progress(); try Task.checkCancellation()
            guard let current, current.setup == result.progress else { throw AdministrativeSetupChannelError.invalidMessage }
            progress = current; lastJournalCleanupComplete = result.cleanupComplete
        } catch { fail(error) }
    }
    public func activate(settings: GatewayRuntimeActivationSettings) async {
        guard loaded, !working, let expected = progress, expected.setup.journalInitialized else { return }
        guard expected.settings == nil || expected.settings == settings else { notice = .settingsTransitionRequired; return }
        operation = .activating; notice = nil
        defer { operation = nil }
        do {
            let result = try await driver.activate(expected, settings: settings)
            try Task.checkCancellation(); try result.validateActivation(of: expected, selectedSettings: settings)
            let settings = try await driver.settingsProgress(); try Task.checkCancellation()
            guard settings?.activation == result else { throw AdministrativeSetupChannelError.invalidMessage }
            progress = result; settingsProgress = settings
        } catch { fail(error) }
    }
    public func applySettings(_ selection: GatewayRuntimeSettingsSelection) async {
        guard loaded, !working, let expected = settingsProgress else { return }
        guard expected.supportsSettingsChanges else { notice = .settingsUnavailable; return }
        operation = .applyingSettings; notice = nil
        defer { operation = nil }
        do {
            if let pending = try expected.pendingSelection {
                guard try pending.bytes == selection.bytes else { throw GatewayPreparationError.conflictingMaterial }
            }
            let result = try await driver.applySettings(expected, selection: selection)
            try Task.checkCancellation(); try result.validateApplication(of: expected, selection: selection)
            settingsProgress = result; progress = result.activation
        } catch { fail(error) }
    }
    private func fail(_ error: any Error, reading: Bool = false) {
        loaded = false; settingsProgress = nil; lastJournalCleanupComplete = nil; initialSelection = nil
        if Task.isCancelled || error is CancellationError || error as? SetupAdministratorAuthorizationError == .cancelled {
            notice = nil
        } else { notice = reading ? .refreshFailed : .operationFailed }
    }
}
