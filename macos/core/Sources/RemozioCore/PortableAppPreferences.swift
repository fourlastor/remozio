import CoreFoundation
import Foundation
import RemozioProtocol

/// Explicit shared app preferences only. Unset values do not replace defaults on another Mac.
public struct PortableAppPreferences: Sendable, Equatable {
    public static let menuBarKey = "showMenuBarExtra"
    public static let commandKeys = [CommandFrontendCallerSettings.modeKey, CommandFrontendCallerSettings.disconnectKey,
        CommandFrontendCallerSettings.timeoutKey, CommandFrontendCallerSettings.initialBackoffKey,
        CommandFrontendCallerSettings.maximumBackoffKey, CommandFrontendCallerSettings.controlTimeoutKey,
        CommandFrontendCallerSettings.controlRetryKey, CommandFrontendCallerSettings.foregroundRetryKey]
    public let menuBarVisible: Bool?
    public let commandOverrides: [String: String]
    private static let purpose = "remozio-shared-app-preferences"
    private static let limits = try! CBORLimits(maxBytes: 2048, maxDepth: 2, maxItems: 32)

    /// Ignore local identity, current routing, login registration and all keys outside this allowlist.
    public init(preferences: [String: Any]) throws {
        if let value = preferences[Self.menuBarKey] {
            guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { throw PortableSetupError.rejected }
            menuBarVisible = number.boolValue
        } else { menuBarVisible = nil }
        var commands: [String: String] = [:]
        for key in Self.commandKeys {
            if let raw = preferences[key] {
                guard let value = raw as? String else { throw PortableSetupError.rejected }
                commands[key] = value
            }
        }
        _ = try CommandFrontendCallerSettings(preferences: commands, defaultIOMode: .pty, defaultDisconnectBehavior: .terminate,
            defaultReadiness: .init(timeoutMilliseconds: 30_000))
        // Store numeric values canonically without rejecting valid leading zeros from the local settings UI.
        for key in Self.commandKeys.dropFirst(2) {
            if let text = commands[key], let number = UInt64(text) { commands[key] = String(number) }
        }
        commandOverrides = commands
    }
    /// Read only the keys that belong in a shared export.
    public static func capture(read: (String) -> Any?) throws -> Self {
        var selected: [String: Any] = [:]
        for key in [menuBarKey] + commandKeys { if let value = read(key) { selected[key] = value } }
        return try Self(preferences: selected)
    }
    /// Only these keys may be offered to the app's explicit import action.
    public var valuesToApply: [String: Any] {
        var result: [String: Any] = commandOverrides
        if let menuBarVisible { result[Self.menuBarKey] = menuBarVisible }
        return result
    }
    /// Validate sparse overrides with the destination values before the caller writes any preference.
    /// The caller must read and apply without suspension. This method returns only the imported keys.
    public func applicationValues(readExisting: (String) -> Any?) throws -> [String: Any] {
        guard !commandOverrides.isEmpty else { return valuesToApply }
        var merged: [String: Any] = [:]
        for key in Self.commandKeys {
            if let value = readExisting(key) { merged[key] = value }
        }
        for (key, value) in commandOverrides { merged[key] = value }
        _ = try CommandFrontendCallerSettings(preferences: merged, defaultIOMode: .pty,
            defaultDisconnectBehavior: .terminate, defaultReadiness: .init(timeoutMilliseconds: 30_000))
        return valuesToApply
    }
    public var bytes: Data { get throws {
        var values: [UInt64: CBORValue] = [:]
        if let menuBarVisible { values[0] = .boolean(menuBarVisible) }
        for (index, key) in Self.commandKeys.enumerated() {
            if let value = commandOverrides[key] { values[UInt64(index+1)] = .text(value) }
        }
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.purpose), 2: .map(values)]), limits: Self.limits)
    } }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let root) = try DeterministicCBOR.decode(bytes, limits: limits), Set(root.keys) == Set(UInt64(0)...2),
              root[0] == .unsigned(1), root[1] == .text(purpose), case .map(let values) = root[2],
              Set(values.keys).isSubset(of: Set(UInt64(0)...8)) else { throw PortableSetupError.rejected }
        var preferences: [String: Any] = [:]
        for (key, value) in values {
            if key == 0 {
                guard case .boolean(let visible) = value else { throw PortableSetupError.rejected }
                preferences[menuBarKey] = visible
            } else {
                guard case .text(let text) = value else { throw PortableSetupError.rejected }
                preferences[commandKeys[Int(key-1)]] = text
            }
        }
        let result = try Self(preferences: preferences)
        guard try result.bytes == bytes else { throw PortableSetupError.rejected }
        return result
    }
}
