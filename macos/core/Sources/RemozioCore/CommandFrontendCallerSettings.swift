import Darwin
import Foundation
import RemozioProtocol

public enum CommandFrontendCallerSettingsError: Error, Equatable {
    public enum Rule: Equatable, Sendable {
        case text, ioMode, disconnectBehavior, readinessWait, interval, maximumBackoff
    }

    case invalidPreferences
    case invalidValue(CommandFrontendCallerSettings.Field, Rule)

    public var field: CommandFrontendCallerSettings.Field? {
        guard case .invalidValue(let field, _) = self else { return nil }
        return field
    }

    public var message: String {
        guard case .invalidValue(let field, let rule) = self else { return "Invalid command settings." }
        let requirement: String
        switch rule {
        case .text: requirement = "must be stored as text."
        case .ioMode: requirement = "must be Terminal (PTY) or Pipes."
        case .disconnectBehavior: requirement = "must be Terminate the command or Let the command continue."
        case .readinessWait: requirement = "must be a valid positive whole number."
        case .interval: requirement = "must be a whole number from 1 to 60,000."
        case .maximumBackoff: requirement = "must be at least the initial connection backoff."
        }
        return "\(field.title) \(requirement)"
    }
}

/// User preferences control caller behavior. They contain no installation identity or authority pins.
public struct CommandFrontendCallerSettings: Sendable {
    public enum Field: String, CaseIterable, Sendable {
        case ioMode = "commandDefaultIOMode"
        case disconnectBehavior = "commandDefaultDisconnect"
        case readinessWait = "commandReadinessTimeoutMilliseconds"
        case initialBackoff = "commandInitialBackoffMilliseconds"
        case maximumBackoff = "commandMaximumBackoffMilliseconds"
        case controlTimeout = "commandControlTimeoutMilliseconds"
        case controlRetry = "commandControlRetryMilliseconds"
        case foregroundRetry = "commandForegroundRetryMilliseconds"

        public var title: String {
            switch self {
            case .ioMode: return "Default command I/O"
            case .disconnectBehavior: return "If the caller disconnects"
            case .readinessWait: return "Readiness wait (ms)"
            case .initialBackoff: return "Initial connection backoff (ms)"
            case .maximumBackoff: return "Maximum connection backoff (ms)"
            case .controlTimeout: return "Control validation timeout (ms)"
            case .controlRetry: return "Control retry interval (ms)"
            case .foregroundRetry: return "Foreground retry interval (ms)"
            }
        }
    }

    public static let modeKey = Field.ioMode.rawValue
    public static let disconnectKey = Field.disconnectBehavior.rawValue
    public static let timeoutKey = Field.readinessWait.rawValue
    public static let initialBackoffKey = Field.initialBackoff.rawValue
    public static let maximumBackoffKey = Field.maximumBackoff.rawValue
    public static let controlTimeoutKey = Field.controlTimeout.rawValue
    public static let controlRetryKey = Field.controlRetry.rawValue
    public static let foregroundRetryKey = Field.foregroundRetry.rawValue

    public let ioMode: CommandIOMode
    public let disconnectBehavior: StartedCommandDisconnect
    public let readiness: CommandCallerReadinessConfiguration
    public let controlRetryMilliseconds: UInt32
    public let foregroundRetryMilliseconds: UInt32

    public init(preferences: [String: Any], defaultIOMode: CommandIOMode,
                defaultDisconnectBehavior: StartedCommandDisconnect,
                defaultReadiness: CommandCallerReadinessConfiguration) throws {
        func text(_ field: Field) throws -> String? {
            guard let value = preferences[field.rawValue] else { return nil }
            guard let value = value as? String else { throw CommandFrontendCallerSettingsError.invalidValue(field, .text) }
            return value
        }
        func number(_ field: Field, fallback: UInt64, rule: CommandFrontendCallerSettingsError.Rule) throws -> UInt64 {
            guard let value = try text(field) else { return fallback }
            guard !value.isEmpty, value.utf8.allSatisfy({ (48...57).contains($0) }),
                  let result = UInt64(value), result > 0 else {
                throw CommandFrontendCallerSettingsError.invalidValue(field, rule)
            }
            return result
        }
        func duration(_ field: Field, fallback: UInt32) throws -> UInt32 {
            guard let value = UInt32(exactly: try number(field, fallback: UInt64(fallback), rule: .interval)),
                  (1...60_000).contains(value) else {
                throw CommandFrontendCallerSettingsError.invalidValue(field, .interval)
            }
            return value
        }
        switch try text(.ioMode) {
        case nil: ioMode = defaultIOMode
        case "pty": ioMode = .pty
        case "pipes": ioMode = .pipes
        default: throw CommandFrontendCallerSettingsError.invalidValue(.ioMode, .ioMode)
        }
        switch try text(.disconnectBehavior) {
        case nil: disconnectBehavior = defaultDisconnectBehavior
        case "terminate": disconnectBehavior = .terminate
        case "continue": disconnectBehavior = .continueRunning
        default: throw CommandFrontendCallerSettingsError.invalidValue(.disconnectBehavior, .disconnectBehavior)
        }
        let timeout = try number(.readinessWait, fallback: defaultReadiness.timeoutMilliseconds, rule: .readinessWait)
        let initial = try duration(.initialBackoff, fallback: defaultReadiness.initialBackoffMilliseconds)
        let maximum = try duration(.maximumBackoff, fallback: defaultReadiness.maximumBackoffMilliseconds)
        guard initial <= maximum else {
            throw CommandFrontendCallerSettingsError.invalidValue(.maximumBackoff, .maximumBackoff)
        }
        readiness = try .init(timeoutMilliseconds: timeout, initialBackoffMilliseconds: initial,
            maximumBackoffMilliseconds: maximum,
            controlTimeoutMilliseconds: duration(.controlTimeout, fallback: defaultReadiness.controlTimeoutMilliseconds))
        controlRetryMilliseconds = try duration(.controlRetry, fallback: 50)
        foregroundRetryMilliseconds = try duration(.foregroundRetry, fallback: 250)
    }

    public static func loadInstallationDefaults() throws -> Self {
        let configuration = try CommandFrontendConfigurationSelection.load(ownerUID: getuid()).configuration
        return try Self(preferences: [:], defaultIOMode: configuration.defaultIOMode,
            defaultDisconnectBehavior: configuration.defaultDisconnectBehavior, defaultReadiness: configuration.readiness)
    }

    public func text(for field: Field) -> String {
        switch field {
        case .ioMode: return ioMode == .pty ? "pty" : "pipes"
        case .disconnectBehavior: return disconnectBehavior == .terminate ? "terminate" : "continue"
        case .readinessWait: return String(readiness.timeoutMilliseconds)
        case .initialBackoff: return String(readiness.initialBackoffMilliseconds)
        case .maximumBackoff: return String(readiness.maximumBackoffMilliseconds)
        case .controlTimeout: return String(readiness.controlTimeoutMilliseconds)
        case .controlRetry: return String(controlRetryMilliseconds)
        case .foregroundRetry: return String(foregroundRetryMilliseconds)
        }
    }

    /// Use the installed defaults to validate the complete proposed persistent domain.
    public func applying(_ edits: [Field: String], to domain: [String: Any]) throws -> [String: Any] {
        var proposed = domain
        for (field, value) in edits { proposed[field.rawValue] = value }
        _ = try Self(preferences: proposed, defaultIOMode: ioMode,
            defaultDisconnectBehavior: disconnectBehavior, defaultReadiness: readiness)
        return proposed
    }

    public static func resettingOverrides(in domain: [String: Any]) -> [String: Any] {
        var proposed = domain
        for field in Field.allCases { proposed.removeValue(forKey: field.rawValue) }
        return proposed
    }
}
