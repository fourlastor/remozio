import Foundation
import RemozioProtocol
import RemozioHostCore

public typealias CommandElevationPolicyError = RemozioHostCore.CommandElevationPolicyError
public typealias CommandElevationPolicy = RemozioHostCore.CommandElevationPolicy

extension CommandElevationPolicy {
    /// Requires Root-owned private metadata. Setup must record the user's disclosure acceptance before installation.
    public static func load(path: String) throws -> Self { try decode(ProtectedServiceConfiguration.read(path: path)) }

    /// Resolve credentials only after the authenticated scope, caller and target pass the explicit grants.
    public func resolveTarget(macID: Data, accountID: Data, callerUID: UInt32, requestedTargetUID: UInt32) throws -> CommandTarget {
        try authorize(macID: macID, accountID: accountID, callerUID: callerUID, requestedTargetUID: requestedTargetUID)
        return try CommandTargetResolver.resolve(uid: requestedTargetUID)
    }

    /// Recheck current grants and OS credentials against the immutable capture before execution.
    public func validate(capture: CommandCapture, macID: Data, accountID: Data) throws {
        try validate(capture: capture, macID: macID, accountID: accountID, resolveTarget: CommandTargetResolver.resolve)
    }

    /// Fixture seam for OS identity changes. Product validation always resolves the actual OS target.
    func validate(capture: CommandCapture, macID: Data, accountID: Data,
                  resolveTarget: (UInt32) throws -> CommandTarget) throws {
        guard capture.requester.realUID == capture.requester.effectiveUID else {
            throw CommandElevationPolicyError.policyRejected
        }
        try authorize(macID: macID, accountID: accountID, callerUID: capture.requester.effectiveUID,
                      requestedTargetUID: capture.target.uid)
        guard try resolveTarget(capture.target.uid) == capture.target else { throw CommandElevationPolicyError.policyRejected }
    }

}
