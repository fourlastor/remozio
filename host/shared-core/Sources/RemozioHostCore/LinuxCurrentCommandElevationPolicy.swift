#if os(Linux)
import Foundation
import RemozioProtocol

/// Refreshes explicit grants, caller credentials and NSS target observations for each operation.
/// The caller supplies protected loading and a credential reader bound to its authenticated retained caller.
/// Neither closure is proof of provenance, protected ownership, process identity or continuous monitoring.
/// There is no path loader, capture-claim fallback, numeric-PID lookup or service-UID substitution here.
public struct LinuxCurrentCommandElevationPolicy: Sendable {
    public let macID: Data
    public let accountID: Data
    public let callerUID: UInt32
    private let load: @Sendable () throws -> CommandElevationPolicy
    private let readCallerCredentials: @Sendable () throws -> CapturedLinuxCredentials
    private let resolve: @Sendable (UInt32, UInt32) throws -> CommandTarget

    public init(macID: Data, accountID: Data, callerUID: UInt32,
                load: @escaping @Sendable () throws -> CommandElevationPolicy,
                readCallerCredentials: @escaping @Sendable () throws -> CapturedLinuxCredentials) throws {
        try self.init(macID: macID, accountID: accountID, callerUID: callerUID, load: load,
            readCallerCredentials: readCallerCredentials, resolve: LinuxOwnAccountTargetResolver.resolve)
    }

    // Fixture seam only. Product construction resolves the target through NSS on every call.
    init(macID: Data, accountID: Data, callerUID: UInt32,
         load: @escaping @Sendable () throws -> CommandElevationPolicy,
         readCallerCredentials: @escaping @Sendable () throws -> CapturedLinuxCredentials,
         resolve: @escaping @Sendable (UInt32, UInt32) throws -> CommandTarget) throws {
        guard macID.count == 16, accountID.count == 16, callerUID > 0, callerUID < UInt32.max else {
            throw CommandElevationPolicyError.invalidConfiguration
        }
        self.macID = macID; self.accountID = accountID; self.callerUID = callerUID
        self.load = load; self.readCallerCredentials = readCallerCredentials; self.resolve = resolve
    }

    /// Supply authenticated scope and caller identity, never untrusted command-submission fields.
    public func resolveTarget(macID: Data, accountID: Data, callerUID: UInt32,
                              requestedTargetUID: UInt32) throws -> CommandTarget {
        try requireScope(macID: macID, accountID: accountID, callerUID: callerUID, targetUID: requestedTargetUID)
        try load().authorize(macID: macID, accountID: accountID, callerUID: callerUID,
            requestedTargetUID: requestedTargetUID)
        _ = try currentCredentials()
        return try resolve(callerUID, requestedTargetUID)
    }

    /// Recheck before dispatch under the authority's own serialization/handoff boundary.
    /// Success is validation only; it neither consumes a decision nor grants a dispatch capability.
    public func validate(capture: LinuxCommandCapture) throws {
        try requireScope(macID: macID, accountID: accountID,
            callerUID: capture.requester.credentials.effectiveUID, targetUID: capture.target.uid)
        try load().authorize(macID: macID, accountID: accountID, callerUID: callerUID,
            requestedTargetUID: capture.target.uid)
        guard try currentCredentials() == capture.requester.credentials,
              try resolve(callerUID, capture.target.uid) == capture.target else {
            throw CommandElevationPolicyError.policyRejected
        }
    }

    private func requireScope(macID: Data, accountID: Data, callerUID: UInt32, targetUID: UInt32) throws {
        guard self.macID == macID, self.accountID == accountID, self.callerUID == callerUID,
              targetUID == callerUID else { throw CommandElevationPolicyError.policyRejected }
    }

    private func currentCredentials() throws -> CapturedLinuxCredentials {
        let value = try readCallerCredentials()
        guard [value.realUID, value.effectiveUID, value.savedUID, value.filesystemUID].allSatisfy({ $0 == callerUID }),
              value.realGID < UInt32.max,
              [value.effectiveGID, value.savedGID, value.filesystemGID].allSatisfy({ $0 == value.realGID }),
              value.supplementaryGroups.count <= 1024, !value.supplementaryGroups.contains(UInt32.max),
              zip(value.supplementaryGroups, value.supplementaryGroups.dropFirst()).allSatisfy({ $0.0 < $0.1 }) else {
            throw CommandElevationPolicyError.policyRejected
        }
        return value
    }
}
#endif
