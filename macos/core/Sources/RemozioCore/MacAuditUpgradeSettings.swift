import Foundation

public enum MacAuditUpgradeSettingsError: Error, Equatable { case invalidPreferences }

/// App connection waits only. These values do not limit command runtime or approval expiry.
public struct MacAuditUpgradeSettings: Sendable, Equatable {
    public static let readTimeoutKey = "auditUpgradeReadTimeoutMilliseconds"
    public static let operationTimeoutKey = "auditUpgradeOperationTimeoutMilliseconds"
    public static let keys = [readTimeoutKey, operationTimeoutKey]
    public let readTimeoutMilliseconds: UInt64
    public let operationTimeoutMilliseconds: UInt64

    public init(readTimeoutMilliseconds: UInt64 = 60_000, operationTimeoutMilliseconds: UInt64 = 60_000) throws {
        guard (1...60_000).contains(readTimeoutMilliseconds), (1...300_000).contains(operationTimeoutMilliseconds) else {
            throw MacAuditUpgradeSettingsError.invalidPreferences
        }
        self.readTimeoutMilliseconds = readTimeoutMilliseconds; self.operationTimeoutMilliseconds = operationTimeoutMilliseconds
    }
    public init(preferences: [String: Any]) throws {
        func number(_ key: String) throws -> UInt64 {
            guard let raw = preferences[key] else { return 60_000 }
            guard let text = raw as? String, !text.isEmpty, text.utf8.allSatisfy({ (48...57).contains($0) }),
                  let value = UInt64(text) else { throw MacAuditUpgradeSettingsError.invalidPreferences }
            return value
        }
        try self.init(readTimeoutMilliseconds: number(Self.readTimeoutKey), operationTimeoutMilliseconds: number(Self.operationTimeoutKey))
    }
    public static func capture(read: (String) -> Any?) throws -> Self {
        var values: [String: Any] = [:]
        for key in keys { if let value = read(key) { values[key] = value } }
        return try .init(preferences: values)
    }
}
