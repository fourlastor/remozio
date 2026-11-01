import ApplicationServices
import Foundation

/// Explicit read-only experiment entry point. Run on an owned serial worker, not the UI thread.
/// This does not authenticate an application, grant permission, persist a fixture or admit an approval request.
public enum NativeAXStructureRecorder {
    public static func capture(processID: Int32, limits: AXStructureLimits = .standard) throws -> AXStructureSnapshot {
        guard processID > 0 else { throw AXStructureFailure.wrongProcess }
        guard AXIsProcessTrusted() else { throw AXStructureFailure.permissionDenied }
        let start = ContinuousClock.now
        let source = NativeAXStructureSource(processID: processID, limits: limits)
        return AXStructureCollector(source: source, limits: limits, now: {
            let elapsed = start.duration(to: .now).components
            return Double(elapsed.seconds) + Double(elapsed.attoseconds) / 1e18
        }).capture(root: .init(value: AXUIElementCreateApplication(processID)), processID: processID)
    }
}

struct NativeAXStructureElement: Hashable {
    let value: AXUIElement
    static func == (lhs: Self, rhs: Self) -> Bool { CFEqual(lhs.value, rhs.value) }
    func hash(into hasher: inout Hasher) { hasher.combine(CFHash(value)) }
}

struct NativeAXStructureSource: AXStructureSource {
    let processID: Int32
    let limits: AXStructureLimits

    func prepare(_ element: NativeAXStructureElement, timeoutSeconds: Float) throws {
        var actual: pid_t = 0
        try require(AXUIElementGetPid(element.value, &actual))
        guard actual == processID else { throw AXStructureFailure.wrongProcess }
        // This changes only this client's timeout for the exact element, never the global object or target UI.
        try require(AXUIElementSetMessagingTimeout(element.value, timeoutSeconds))
    }
    func string(_ field: AXStructureField, element: NativeAXStructureElement) throws -> String {
        let name: CFString
        switch field {
        case .role: name = kAXRoleAttribute as CFString
        case .subrole: name = kAXSubroleAttribute as CFString
        default: throw AXStructureFailure.malformed
        }
        var value: CFTypeRef?
        try require(AXUIElementCopyAttributeValue(element.value, name, &value))
        guard let value, CFGetTypeID(value) == CFStringGetTypeID() else { throw AXStructureFailure.malformed }
        return try boundedString(unsafeDowncast(value, to: CFString.self))
    }
    func names(_ field: AXStructureField, element: NativeAXStructureElement) throws -> [String] {
        var values: CFArray?
        switch field {
        case .attributeNames: try require(AXUIElementCopyAttributeNames(element.value, &values))
        case .actionNames: try require(AXUIElementCopyActionNames(element.value, &values))
        default: throw AXStructureFailure.malformed
        }
        guard let values else { throw AXStructureFailure.malformed }
        let count = CFArrayGetCount(values)
        guard count <= limits.maximumNames else { throw AXStructureFailure.limitExceeded }
        return try (0..<count).map { index in
            guard let pointer = CFArrayGetValueAtIndex(values, index) else { throw AXStructureFailure.malformed }
            let value = unsafeBitCast(pointer, to: CFTypeRef.self)
            guard CFGetTypeID(value) == CFStringGetTypeID() else { throw AXStructureFailure.malformed }
            return try boundedString(unsafeDowncast(value, to: CFString.self))
        }
    }
    func children(_ element: NativeAXStructureElement, maximumCount: Int) throws -> (elements: [NativeAXStructureElement], totalCount: Int) {
        var count = 0
        try require(AXUIElementGetAttributeValueCount(element.value, kAXChildrenAttribute as CFString, &count))
        guard count >= 0 else { throw AXStructureFailure.malformed }
        if count == 0 { return ([], 0) }
        var values: CFArray?
        try require(AXUIElementCopyAttributeValues(element.value, kAXChildrenAttribute as CFString, 0, min(count, maximumCount), &values))
        guard let values else { throw AXStructureFailure.malformed }
        let received = CFArrayGetCount(values)
        guard received <= maximumCount else { throw AXStructureFailure.limitExceeded }
        let elements = try (0..<received).map { index in
            guard let pointer = CFArrayGetValueAtIndex(values, index) else { throw AXStructureFailure.malformed }
            let value = unsafeBitCast(pointer, to: CFTypeRef.self)
            guard CFGetTypeID(value) == AXUIElementGetTypeID() else { throw AXStructureFailure.malformed }
            return NativeAXStructureElement(value: unsafeDowncast(value, to: AXUIElement.self))
        }
        return (elements, count)
    }
    private func boundedString(_ value: CFString) throws -> String {
        guard CFStringGetLength(value) <= limits.maximumNameBytes else { throw AXStructureFailure.limitExceeded }
        let result = value as String
        guard result.utf8.count <= limits.maximumNameBytes else { throw AXStructureFailure.limitExceeded }
        return result
    }
    private func require(_ result: AXError) throws {
        switch result {
        case .success: return
        case .apiDisabled: throw AXStructureFailure.permissionDenied
        case .invalidUIElement: throw AXStructureFailure.invalidElement
        case .attributeUnsupported, .actionUnsupported, .notImplemented: throw AXStructureFailure.unsupported
        case .noValue: throw AXStructureFailure.noValue
        case .cannotComplete: throw AXStructureFailure.cannotComplete
        default: throw AXStructureFailure.unavailable
        }
    }
}
