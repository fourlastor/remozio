import Foundation
import Observation

public enum MacPortableSetupImportActivity: Equatable, Sendable {
    case refreshing, applying(SetupPortableImportOperation.Action)
}
public enum MacPortableSetupImportNotice: Equatable, Sendable { case refreshFailed, operationOutcomeUnknown }

/// Controls explicit import steps. Local completion does not assert provider access or live service health.
@MainActor @Observable
public final class MacPortableSetupImportControls {
    public private(set) var progress: SetupPortableImportProgress?
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
        activity = .refreshing; loaded = false; progress = nil; notice = nil; lastResult = nil
        defer { activity = nil }
        do {
            let value = try await driver.progress()
            try Task.checkCancellation()
            guard !closed else { return }
            progress = value; loaded = true
        } catch { fail(error, reading: true) }
    }
    public func perform(_ action: SetupPortableImportOperation.Action, fileCustodyAccepted: Bool = false) async {
        guard !closed, loaded, !working, let expected = progress else { return }
        activity = .applying(action); notice = nil; lastResult = nil
        defer { activity = nil }
        do {
            let request = try reviewed.operation(action: action, expected: expected, fileCustodyAccepted: fileCustodyAccepted)
            let result = try await driver.perform(request)
            try Task.checkCancellation()
            try result.validate(request)
            guard !closed else { return }
            progress = result.progress; lastResult = result
        } catch { fail(error) }
    }
    public func importFile(custody: SetupPortableImportCustodyChoices) async {
        guard !closed, loaded, !working, let expected = progress else { return }
        activity = .applying(.retain); notice = nil; lastResult = nil
        defer { activity = nil }
        do {
            let result = try await driver.importFile(reviewed, expected: expected, custody: custody) { [weak self] action, progress in
                await self?.observe(action, progress: progress)
            }
            try Task.checkCancellation()
            guard !closed else { return }
            progress = result.progress; lastResult = result
        } catch { fail(error) }
    }
    private func observe(_ action: SetupPortableImportOperation.Action, progress: SetupPortableImportProgress) {
        guard !closed else { return }
        activity = .applying(action); self.progress = progress
    }

    public func close() {
        closed = true; reviewed.close(); loaded = false; progress = nil; notice = nil; lastResult = nil
    }
    private func fail(_ error: any Error, reading: Bool = false) {
        loaded = false; progress = nil; lastResult = nil
        guard !closed else { return }
        if Task.isCancelled || error is CancellationError || error as? SetupAdministratorAuthorizationError == .cancelled {
            notice = nil
        } else { notice = reading ? .refreshFailed : .operationOutcomeUnknown }
    }
}
