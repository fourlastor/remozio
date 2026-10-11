import Foundation
import RemozioProtocol

public enum CommandElevationPolicyError: Error, Equatable {
    case invalidConfiguration, disclosureRequired, policyRejected
}

/// Explicit account grants. Parsing does not prove protected installation or authorize execution.
public struct CommandElevationPolicy: Sendable, CustomStringConvertible {
    public static let supportedVersions: Set<UInt64> = [1]
    public let macID: Data
    public let accountID: Data
    public let callerUID: UInt32
    public let allowedTargetUIDs: Set<UInt32>
    public let canonicalBytes: Data
    public var description: String { "CommandElevationPolicy(redacted)" }

    public init(macID: Data, accountID: Data, callerUID: UInt32, allowedTargetUIDs: Set<UInt32>,
                independentPolicyDisclosureAccepted: Bool) throws {
        guard independentPolicyDisclosureAccepted else { throw CommandElevationPolicyError.disclosureRequired }
        guard macID.count == 16, accountID.count == 16, callerUID > 0, callerUID < UInt32.max,
              allowedTargetUIDs.count <= 64, !allowedTargetUIDs.contains(UInt32.max) else {
            throw CommandElevationPolicyError.invalidConfiguration
        }
        self.macID = macID; self.accountID = accountID; self.callerUID = callerUID
        self.allowedTargetUIDs = allowedTargetUIDs
        canonicalBytes = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .text("independent-remozio"), 2: .bytes(macID), 3: .bytes(accountID),
            4: .unsigned(UInt64(callerUID)), 5: .array(allowedTargetUIDs.sorted().map { .unsigned(UInt64($0)) }),
            6: .boolean(true)
        ]), limits: Self.limits)
    }

    /// Requires Root-owned private metadata. Setup must record the user's disclosure acceptance before installation.
    public static func load(path: String) throws -> Self { try decode(ProtectedServiceConfiguration.read(path: path)) }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...6), fields[0] == .unsigned(1), fields[1] == .text("independent-remozio"),
              case .bytes(let mac) = fields[2], case .bytes(let account) = fields[3],
              case .unsigned(let uid) = fields[4], let caller = UInt32(exactly: uid),
              case .array(let targets) = fields[5], case .boolean(let accepted) = fields[6] else {
            throw CommandElevationPolicyError.invalidConfiguration
        }
        let values = try targets.map { value -> UInt32 in
            guard case .unsigned(let uid) = value, let target = UInt32(exactly: uid) else {
                throw CommandElevationPolicyError.invalidConfiguration
            }
            return target
        }
        let result = try Self(macID: mac, accountID: account, callerUID: caller, allowedTargetUIDs: Set(values),
                              independentPolicyDisclosureAccepted: accepted)
        guard result.canonicalBytes == bytes else { throw CommandElevationPolicyError.invalidConfiguration }
        return result
    }

    /// Call with the authenticated account and requested target. Administrator membership grants nothing here.
    public func authorize(macID: Data, accountID: Data, callerUID: UInt32, requestedTargetUID: UInt32) throws {
        guard self.macID == macID, self.accountID == accountID, self.callerUID == callerUID,
              allowedTargetUIDs.contains(requestedTargetUID) else { throw CommandElevationPolicyError.policyRejected }
    }

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

    private static var limits: CBORLimits { get throws { try .init(maxBytes: 4096, maxDepth: 2, maxItems: 96) } }
}
