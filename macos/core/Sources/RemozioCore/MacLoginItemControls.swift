import Observation
import ServiceManagement

public enum MacLoginItemState: Equatable, Sendable {
    case notRegistered, enabled, requiresApproval, notFound, unknown
    public var registered: Bool { self == .enabled || self == .requiresApproval }
}
public enum MacLoginItemNotice: Equatable, Sendable { case enableFailed, disableFailed }

@MainActor
protocol MacLoginItemDriver: AnyObject {
    func status() -> MacLoginItemState
    func register() throws
    func unregister() async throws
    func openSettings()
}
@MainActor
private final class NativeMacLoginItemDriver: MacLoginItemDriver {
    private let service = SMAppService.mainApp
    func status() -> MacLoginItemState {
        switch service.status {
        case .notRegistered: .notRegistered
        case .enabled: .enabled
        case .requiresApproval: .requiresApproval
        case .notFound: .notFound
        @unknown default: .unknown
        }
    }
    func register() throws { try service.register() }
    func unregister() async throws { try await service.unregister() }
    func openSettings() { SMAppService.openSystemSettingsLoginItems() }
}

/// The system owns login registration. This state grants no approval or service authority.
@MainActor @Observable
public final class MacLoginItemControls {
    public private(set) var state: MacLoginItemState = .unknown
    public private(set) var changing = false
    public private(set) var notice: MacLoginItemNotice?
    @ObservationIgnored private let driver: any MacLoginItemDriver
    public convenience init() { self.init(driver: NativeMacLoginItemDriver()) }
    init(driver: any MacLoginItemDriver) { self.driver = driver }
    public func refresh() {
        guard !changing else { return }
        state = driver.status()
        switch (notice, state) {
        case (.enableFailed?, .enabled), (.disableFailed?, .notRegistered): notice = nil
        default: break
        }
    }
    public func setEnabled(_ enabled: Bool) async {
        guard !changing else { return }
        refresh()
        guard state.registered != enabled else { return }
        changing = true; notice = nil
        defer { changing = false; refresh() }
        do {
            if enabled { try driver.register() }
            else { try await driver.unregister() }
        } catch { notice = enabled ? .enableFailed : .disableFailed }
    }
    public func openSettings() { driver.openSettings() }
}
