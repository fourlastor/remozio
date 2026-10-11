import Foundation
import RemozioProtocol

/// Reads the current protected grants for each operation. It retains no decoded policy or target credentials.
public struct CurrentCommandElevationPolicy: Sendable {
    public let macID: Data
    public let accountID: Data
    public let callerUID: UInt32
    private let load: @Sendable () throws -> CommandElevationPolicy

    public init(path: String, macID: Data, accountID: Data, callerUID: UInt32) throws {
        try self.init(macID: macID, accountID: accountID, callerUID: callerUID,
            load: { try CommandElevationPolicy.load(path: path) })
    }

    /// Fixture loader seam. Product construction always reloads protected metadata from its configured path.
    init(macID: Data, accountID: Data, callerUID: UInt32,
         load: @escaping @Sendable () throws -> CommandElevationPolicy) throws {
        guard macID.count == 16, accountID.count == 16, callerUID > 0, callerUID < UInt32.max else {
            throw CommandElevationPolicyError.invalidConfiguration
        }
        self.macID = macID; self.accountID = accountID; self.callerUID = callerUID; self.load = load
    }

    /// The host supplies authenticated scope and caller identity, never fields claimed by a command submission.
    public func resolveTarget(macID: Data, accountID: Data, callerUID: UInt32,
                              requestedTargetUID: UInt32) throws -> CommandTarget {
        try requireScope(macID: macID, accountID: accountID, callerUID: callerUID)
        return try load().resolveTarget(macID: macID, accountID: accountID,
            callerUID: callerUID, requestedTargetUID: requestedTargetUID)
    }

    /// Attach this check to the existing executor's final elevation callback. Failed reads have no cached fallback.
    public func validate(capture: CommandCapture) throws {
        try requireScope(macID: macID, accountID: accountID, callerUID: capture.requester.effectiveUID)
        try load().validate(capture: capture, macID: macID, accountID: accountID)
    }

    private func requireScope(macID: Data, accountID: Data, callerUID: UInt32) throws {
        guard self.macID == macID, self.accountID == accountID, self.callerUID == callerUID else {
            throw CommandElevationPolicyError.policyRejected
        }
    }
}
