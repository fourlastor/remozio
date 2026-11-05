import Foundation
import Observation

public enum MacAuditUpgradeActivity: Equatable, Sendable { case refreshing, upgrading }
public enum MacAuditUpgradeNotice: Equatable, Sendable { case refreshFailed, progressUnavailable, invalidSettings, notSubmitted, progressChanged, outcomeUnknown }

/// Saved observations and explicit maintenance actions. No observation asserts current service health.
@MainActor @Observable
public final class MacAuditUpgradeControls {
    public private(set) var progress: SetupAuditUpgradeProgress?
    public private(set) var loaded = false
    public private(set) var activity: MacAuditUpgradeActivity?
    public private(set) var notice: MacAuditUpgradeNotice?
    public var working: Bool { activity != nil }
    public var canUpgrade: Bool {
        guard !closed, loaded, !working, let stage = progress?.stage else { return false }
        return [.ready, .waitingForActivity, .waitingForMachine, .graphPrepared, .waitingForQuiescence,
                .filesChanging, .filesVerified, .metadataCommitted].contains(stage)
    }
    @ObservationIgnored private let driver: any MacAuditUpgradeDriver
    @ObservationIgnored private var closed = false
    public convenience init() { self.init(driver: NativeMacAuditUpgradeDriver()) }
    public convenience init(operationTimeoutMilliseconds: UInt64) throws {
        self.init(driver: try NativeMacAuditUpgradeDriver(operationTimeoutMilliseconds: operationTimeoutMilliseconds))
    }
    init(driver: any MacAuditUpgradeDriver) { self.driver = driver }

    public func refresh() async {
        guard !closed, !working else { return }
        activity = .refreshing; loaded = false; progress = nil; notice = nil
        defer { activity = nil }
        do {
            let value = try await driver.progress(); try Task.checkCancellation()
            guard !closed else { return }
            if let value {
                guard [.ready, .graphPrepared, .filesChanging, .filesVerified, .metadataCommitted, .alreadyCurrent].contains(value.stage),
                      value.registrationObserved.isEmpty else { throw AdministrativeSetupChannelError.invalidMessage }
            }
            progress = value; loaded = true
        } catch {
            guard !closed else { return }
            if error as? AuditUpgradeSetupChannelError == .progressUnavailable { notice = .progressUnavailable }
            else if error is MacAuditUpgradeSettingsError { notice = .invalidSettings }
            else { notice = Task.isCancelled || error is CancellationError ? nil : .refreshFailed }
        }
    }
    public func upgrade() async {
        guard canUpgrade, let expected = progress else { return }
        activity = .upgrading; notice = nil
        defer { activity = nil }
        do {
            let result = try await driver.perform(expected)
            try result.validateScope(of: expected)
            guard [.waitingForActivity, .waitingForMachine, .waitingForQuiescence, .registrationObserved, .alreadyCurrent].contains(result.stage) else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            guard !closed else { return }
            if Task.isCancelled { throw MacAuditUpgradeDriverError.outcomeUnknown }
            progress = result
        } catch {
            guard !closed else { return }
            loaded = false; progress = nil
            switch error {
            case is MacAuditUpgradeSettingsError: notice = .invalidSettings
            case MacAuditUpgradeDriverError.progressUnavailable: notice = .progressUnavailable
            case MacAuditUpgradeDriverError.notSubmitted: notice = .notSubmitted
            case MacAuditUpgradeDriverError.progressChanged: notice = .progressChanged
            case is CancellationError: notice = nil
            default: notice = .outcomeUnknown
            }
        }
    }
    public func close() { closed = true; loaded = false; progress = nil; notice = nil }
}
