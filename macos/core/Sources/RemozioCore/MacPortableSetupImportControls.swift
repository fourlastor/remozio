import Foundation
import Observation

public enum MacPortableSetupImportActivity: Equatable, Sendable {
    case refreshing, applying(SetupPortableImportOperation.Action)
}
public enum MacPortableSetupImportNotice: Equatable, Sendable { case refreshFailed, operationOutcomeUnknown, custodyRequired, authorizationExpired, differentSetupFile }

/// Controls explicit import steps. Local completion does not assert provider access or live service health.
@MainActor @Observable
public final class MacPortableSetupImportControls {
    public private(set) var recovery: SetupPortableImportRecovery?
    public private(set) var progress: SetupPortableImportProgress?
    public private(set) var requiredCustody = Set<SetupPortableImportCustodyRequirement>()
    public private(set) var loaded = false
    public private(set) var activity: MacPortableSetupImportActivity?
    public private(set) var notice: MacPortableSetupImportNotice?
    public private(set) var lastResult: SetupPortableImportOperationResult?
    public var working: Bool { activity != nil }
    @ObservationIgnored private let reviewed: ReviewedSetupFile
    @ObservationIgnored private let driver: any MacPortableSetupImportDriver
    @ObservationIgnored private var closed = false

    public convenience init(reviewed: ReviewedSetupFile) {
        self.init(reviewed: reviewed, driver: NativeMacPortableSetupImportDriver())
    }
    init(reviewed: ReviewedSetupFile, driver: any MacPortableSetupImportDriver) {
        self.reviewed = reviewed; self.driver = driver
    }
    public func refresh() async {
        guard !closed, !working else { return }
        activity = .refreshing; loaded = false; progress = nil; recovery = nil; requiredCustody = []; notice = nil; lastResult = nil
        defer { activity = nil }
        do {
            let snapshot = try await driver.snapshot()
            let value = snapshot.progress
            guard snapshot.recovery == nil || snapshot.recovery?.progress == value else { throw AdministrativeSetupChannelError.invalidMessage }
            try Task.checkCancellation()
            guard !closed else { return }
            let requirements = try value.map { try reviewed.custodyRequirements(expected: $0) } ?? []
            progress = value; recovery = snapshot.recovery; requiredCustody = requirements; loaded = true
        } catch { fail(error, reading: true) }
    }
    public func perform(_ action: SetupPortableImportOperation.Action, fileCustodyAccepted: Bool = false) async {
        guard !closed, loaded, !working, let expected = progress else { return }
        activity = .applying(action); notice = nil; lastResult = nil; recovery = nil
        defer { activity = nil }
        do {
            let request = try reviewed.operation(action: action, expected: expected, fileCustodyAccepted: fileCustodyAccepted)
            let result = try await driver.perform(request)
            try Task.checkCancellation()
            try result.validate(request)
            guard !closed else { return }
            requiredCustody = try reviewed.custodyRequirements(expected: result.progress)
            progress = result.progress; lastResult = result
        } catch { fail(error) }
    }
    public func retryImport(resource: SetupPortableImportRecovery.Resource, custody: SetupPortableImportCustodyChoices) async {
        guard !closed, loaded, !working, let recovery, recovery.progress == progress, recovery.rejectedRecord(for: resource) != nil else { return }
        guard custody.satisfies(requiredCustody) else { notice = .custodyRequired; return }
        activity = .applying(.retain); notice = nil; lastResult = nil; self.recovery = nil
        defer { activity = nil }
        do {
            let result = try await driver.retryImportFile(reviewed, recovery: recovery, resource: resource, custody: custody) { [weak self] action, progress in
                await self?.observe(action, progress: progress)
            }
            try Task.checkCancellation(); guard !closed else { return }
            requiredCustody = try reviewed.custodyRequirements(expected: result.progress)
            progress = result.progress; lastResult = result
            await readPausedRecovery(result)
        } catch { fail(error) }
    }
    public func importFile(custody: SetupPortableImportCustodyChoices) async {
        guard !closed, loaded, !working, let expected = progress else { return }
        guard custody.satisfies(requiredCustody) else { notice = .custodyRequired; return }
        activity = .applying(.retain); notice = nil; lastResult = nil; recovery = nil
        defer { activity = nil }
        do {
            let result = try await driver.importFile(reviewed, expected: expected, custody: custody) { [weak self] action, progress in
                await self?.observe(action, progress: progress)
            }
            try Task.checkCancellation()
            guard !closed else { return }
            requiredCustody = try reviewed.custodyRequirements(expected: result.progress)
            progress = result.progress; lastResult = result
            await readPausedRecovery(result)
        } catch { fail(error) }
    }
    private func readPausedRecovery(_ result: SetupPortableImportOperationResult) async {
        recovery = nil
        guard result.status == .providerRejected || result.status == .requiresReconciliation else { return }
        do {
            let snapshot = try await driver.snapshot()
            try Task.checkCancellation(); guard !closed else { return }
            guard snapshot.progress == result.progress, snapshot.recovery == nil || snapshot.recovery?.progress == result.progress else {
                throw AdministrativeSetupError.staleProgress
            }
            recovery = snapshot.recovery
        } catch {
            guard !closed else { return }
            // The operation result is confirmed even when its later metadata read fails.
            loaded = false; recovery = nil
            notice = Task.isCancelled || error is CancellationError ? nil : .refreshFailed
        }
    }
    private func observe(_ action: SetupPortableImportOperation.Action, progress: SetupPortableImportProgress) {
        guard !closed else { return }
        activity = .applying(action); self.progress = progress
    }

    public func close() {
        closed = true; reviewed.close(); loaded = false; progress = nil; recovery = nil; requiredCustody = []; notice = nil; lastResult = nil
    }
    private func fail(_ error: any Error, reading: Bool = false) {
        loaded = false; progress = nil; recovery = nil; requiredCustody = []; lastResult = nil
        guard !closed else { return }
        if Task.isCancelled || error is CancellationError || error as? SetupAdministratorAuthorizationError == .cancelled {
            notice = nil
        } else if error as? SetupPortableImportFlowError == .authorizationExpired { notice = .authorizationExpired
        } else if error as? SetupPortableImportFlowError == .differentProposal { notice = .differentSetupFile
        } else { notice = reading ? .refreshFailed : .operationOutcomeUnknown }
    }
}
