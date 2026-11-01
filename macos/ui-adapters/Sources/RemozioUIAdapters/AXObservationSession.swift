import ApplicationServices
import Foundation

/// Diagnostic hints only. None proves a dialog appeared, expired, disappeared or accepted an action.
public enum AXObservationEvent: String, Codable, CaseIterable, Sendable {
    case windowCreated, focusedWindowChanged, focusedElementChanged, elementDestroyed

    var nativeName: CFString {
        switch self {
        case .windowCreated: kAXWindowCreatedNotification as CFString
        case .focusedWindowChanged: kAXFocusedWindowChangedNotification as CFString
        case .focusedElementChanged: kAXFocusedUIElementChangedNotification as CFString
        case .elementDestroyed: kAXUIElementDestroyedNotification as CFString
        }
    }
    static func matching(_ name: CFString) -> Self? { allCases.first { CFEqual($0.nativeName, name) } }
}

public struct AXObservationState: Equatable, Sendable {
    public let isRunning: Bool
    public let registered: Set<AXObservationEvent>
    public let registrationFailures: [AXObservationEvent: AXStructureFailure]
    public let cleanupFailures: [AXObservationEvent: AXStructureFailure]
}

@MainActor
final class AXObservationMailbox {
    private var active = true
    private var events: Set<AXObservationEvent> = []
    func record(_ event: AXObservationEvent) { if active { events.insert(event) } }
    func drain() -> Set<AXObservationEvent> { let result = events; events.removeAll(keepingCapacity: true); return result }
    func close() { active = false; events.removeAll(keepingCapacity: false) }
}

@MainActor
protocol AXObservationDriver: AnyObject {
    func register(_ event: AXObservationEvent, context: UnsafeMutableRawPointer) throws
    func attach() throws
    func detach()
    func unregister(_ event: AXObservationEvent) throws
}

@MainActor
final class AXObservationOwner {
    private var driver: (any AXObservationDriver)?
    let mailbox = AXObservationMailbox()
    private var registered: Set<AXObservationEvent> = []
    private var failures: [AXObservationEvent: AXStructureFailure] = [:]
    private var cleanupFailures: [AXObservationEvent: AXStructureFailure] = [:]
    private var running = false

    init(driver: any AXObservationDriver) throws {
        self.driver = driver
        let context = Unmanaged.passUnretained(mailbox).toOpaque()
        for event in AXObservationEvent.allCases {
            do { try driver.register(event, context: context); registered.insert(event) }
            catch { failures[event] = error as? AXStructureFailure ?? .unavailable }
        }
        do {
            guard !registered.isEmpty else {
                let priority: [AXStructureFailure] = [.permissionDenied, .wrongProcess, .invalidElement, .cannotComplete,
                    .malformed, .limitExceeded, .unavailable, .noValue, .unsupported]
                throw priority.first { failures.values.contains($0) } ?? AXStructureFailure.unsupported
            }
            try driver.attach(); running = true
        } catch { close(); throw error }
    }
    var state: AXObservationState {
        .init(isRunning: running, registered: running ? registered : [], registrationFailures: failures, cleanupFailures: cleanupFailures)
    }
    func drain() -> Set<AXObservationEvent> { mailbox.drain() }
    func close() {
        // Disable the callback first. Keep its mailbox alive until local delivery and all registrations are removed.
        mailbox.close(); running = false
        guard let driver else { return }
        driver.detach()
        for event in AXObservationEvent.allCases where registered.contains(event) {
            do { try driver.unregister(event) }
            catch { cleanupFailures[event] = error as? AXStructureFailure ?? .unavailable }
        }
        self.driver = nil
    }
    isolated deinit { close() }
}

/// The main run loop owns notification callbacks. Drain hints on the main actor; perform later captures on a separate worker.
/// No process identity, app semantics, approval admission or autonomous recapture is supplied by this experiment.
@MainActor
public final class NativeAXObservationSession {
    public let processID: Int32
    private let owner: AXObservationOwner
    public var state: AXObservationState { owner.state }

    public init(processID: Int32, limits: AXStructureLimits = .standard) throws {
        guard processID > 0 else { throw AXStructureFailure.wrongProcess }
        guard AXIsProcessTrusted() else { throw AXStructureFailure.permissionDenied }
        let driver = try NativeAXObservationDriver(processID: processID, limits: limits)
        owner = try AXObservationOwner(driver: driver); self.processID = processID
    }
    public func drain() -> Set<AXObservationEvent> { owner.drain() }
    public func close() { owner.close() }
    isolated deinit { owner.close() }
}

@MainActor
final class AXObservationRunLoopSource {
    private let source: CFRunLoopSource
    init(_ source: CFRunLoopSource) { self.source = source }
    func attach() throws {
        guard CFRunLoopSourceIsValid(source) else { throw AXStructureFailure.unavailable }
        CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes)
        guard CFRunLoopContainsSource(CFRunLoopGetMain(), source, .defaultMode) else { throw AXStructureFailure.unavailable }
    }
    func detach() {
        CFRunLoopRemoveSource(CFRunLoopGetMain(), source, .commonModes)
        CFRunLoopSourceInvalidate(source)
    }
    isolated deinit { detach() }
}

@MainActor
private final class NativeAXObservationDriver: AXObservationDriver {
    private let observer: AXObserver
    private let application: AXUIElement
    private let source: AXObservationRunLoopSource

    init(processID: Int32, limits: AXStructureLimits) throws {
        application = AXUIElementCreateApplication(processID)
        try NativeAXStructureSource(processID: processID, limits: limits)
            .prepare(.init(value: application), timeoutSeconds: limits.messagingTimeoutSeconds)
        var created: AXObserver?
        let result = AXObserverCreate(processID, { _, _, name, context in
            guard Thread.isMainThread, let context, let event = AXObservationEvent.matching(name) else { return }
            // This callback has no external sink, target element, userInfo retention or capture work.
            MainActor.assumeIsolated {
                Unmanaged<AXObservationMailbox>.fromOpaque(context).takeUnretainedValue().record(event)
            }
        }, &created)
        try Self.require(result)
        guard let created else { throw AXStructureFailure.unavailable }
        observer = created; source = .init(AXObserverGetRunLoopSource(created))
    }
    func register(_ event: AXObservationEvent, context: UnsafeMutableRawPointer) throws {
        try Self.require(AXObserverAddNotification(observer, application, event.nativeName, context))
    }
    func attach() throws { try source.attach() }
    func detach() { source.detach() }
    func unregister(_ event: AXObservationEvent) throws {
        try Self.require(AXObserverRemoveNotification(observer, application, event.nativeName))
    }
    private static func require(_ result: AXError) throws {
        switch result {
        case .success: return
        case .apiDisabled: throw AXStructureFailure.permissionDenied
        case .invalidUIElement, .invalidUIElementObserver: throw AXStructureFailure.invalidElement
        case .notificationUnsupported, .notImplemented: throw AXStructureFailure.unsupported
        case .cannotComplete: throw AXStructureFailure.cannotComplete
        default: throw AXStructureFailure.unavailable
        }
    }
}
