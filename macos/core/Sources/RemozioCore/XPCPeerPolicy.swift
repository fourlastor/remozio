import Foundation
import Security

public enum XPCPeerPolicyError: Error { case invalidConfiguration, invalidRequirement, wrongPeer, wrongConnection }

/// Release peer policy from protected installation metadata, never from an XPC message.
/// Approved hashes must belong to bundles whose placement, runtime flags, entitlements and build floor passed activation checks.
public struct XPCPeerPolicy: Sendable {
    public let requirement: String
    public let expectedUserID: uid_t
    public let expectedAuditSessionID: au_asid_t?

    private static let compiledRequirements = AcceptedInputMemo<String>()

    static func hexadecimalCodeDirectoryHash(_ value: Data) -> String { LowercaseHexadecimal.encode(value) }

    public init(teamID: String, componentIdentifier: String, approvedCodeDirectoryHashes: Set<Data>,
                expectedUserID: uid_t, expectedAuditSessionID: au_asid_t? = nil) throws {
        let ascii = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".utf8)
        let identifierASCII = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-".utf8)
        guard teamID.utf8.count == 10, teamID.utf8.allSatisfy(ascii.contains),
              (1...255).contains(componentIdentifier.utf8.count), componentIdentifier.utf8.allSatisfy(identifierASCII.contains),
              (1...16).contains(approvedCodeDirectoryHashes.count), approvedCodeDirectoryHashes.allSatisfy({ $0.count == 20 }) else {
            throw XPCPeerPolicyError.invalidConfiguration
        }
        let hashes = approvedCodeDirectoryHashes.map { value in
            "cdhash H\"" + Self.hexadecimalCodeDirectoryHash(value) + "\""
        }.sorted().joined(separator: " or ")
        let forbidden = ["com.apple.security.get-task-allow", "com.apple.security.cs.disable-library-validation",
            "com.apple.security.cs.allow-dyld-environment-variables", "com.apple.security.cs.allow-jit", "com.apple.security.cs.allow-unsigned-executable-memory"]
            .map { "!(entitlement[\"\($0)\"] exists)" }.joined(separator: " and ")
        let requirement = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
            + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
            + "and certificate leaf[subject.OU] = \"\(teamID)\" and identifier \"\(componentIdentifier)\" "
            + "and (\(hashes)) and \(forbidden)"
        try Self.compiledRequirements.check(requirement) {
            var compiled: SecRequirement?
            guard SecRequirementCreateWithString(requirement as CFString, [], &compiled) == errSecSuccess,
                  compiled != nil else { throw XPCPeerPolicyError.invalidRequirement }
        }
        self.requirement = requirement
        self.expectedUserID = expectedUserID; self.expectedAuditSessionID = expectedAuditSessionID
    }

    /// Call exactly once before activating a connection. The platform checks subsequent incoming messages against this requirement.
    public func configure(_ connection: NSXPCConnection) {
        connection.setCodeSigningRequirement(requirement)
    }
    /// Apply before activating the listener. Configure each accepted connection as well for subsequent message checks.
    public func configure(_ listener: NSXPCListener) {
        listener.setConnectionCodeSigningRequirement(requirement)
    }
    /// Check on each exported invocation, before moving work onto an asynchronous executor.
    /// Client code must complete its harmless handshake before this check and before sending sensitive data.
    public func verifyCredentials(_ connection: NSXPCConnection) throws -> XPCPeerCredentials {
        try credentials(processID: connection.processIdentifier, userID: connection.effectiveUserIdentifier,
            auditSessionID: connection.auditSessionIdentifier)
    }
    func credentials(processID: pid_t, userID: uid_t, auditSessionID: au_asid_t) throws -> XPCPeerCredentials {
        guard processID > 0, userID == expectedUserID,
              expectedAuditSessionID == nil || auditSessionID == expectedAuditSessionID else { throw XPCPeerPolicyError.wrongPeer }
        return XPCPeerCredentials(processID: processID, userID: userID, auditSessionID: auditSessionID)
    }
}

/// Kernel-supplied connection attributes. These values identify the peer but never express user consent.
public struct XPCPeerCredentials: Sendable, Equatable {
    public let processID: pid_t
    public let userID: uid_t
    public let auditSessionID: au_asid_t
}

/// Bind an exported object to its accepted connection. This object does not own connection activation or lifetime.
public final class XPCInvocationGuard {
    private weak var connection: NSXPCConnection?
    private let policy: XPCPeerPolicy
    private let retainedProcess = getpid()
    private let retainedLock = NSLock()
    private var connectionRetired = false, retainedObserversInstalled = false
    public let incarnation = UUID()
    var acceptedPeerPolicy: XPCPeerPolicy { policy }
    public init(connection: NSXPCConnection, policy: XPCPeerPolicy) {
        self.connection = connection; self.policy = policy
    }
    func retireConnection() {
        guard getpid() == retainedProcess else { return }; retainedLock.withLock { connectionRetired = true }
    }
    /// Install once before activation. Retire the peer proof before running either existing handler.
    func observeConnectionLifetime(onClose: @escaping () -> Void = {}) throws {
        guard getpid() == retainedProcess, let connection else { throw XPCPeerPolicyError.wrongConnection }
        try retainedLock.withLock {
            guard !connectionRetired, !retainedObserversInstalled else { throw XPCPeerPolicyError.wrongConnection }
            retainedObserversInstalled = true
        }
        let interrupted = connection.interruptionHandler, invalidated = connection.invalidationHandler
        connection.interruptionHandler = { [self] in retireConnection(); interrupted?(); onClose() }
        connection.invalidationHandler = { [self] in retireConnection(); invalidated?(); onClose() }
    }
    func withRetainedConnection<Value>(_ body: (NSXPCConnection, XPCPeerPolicy, XPCPeerCredentials) throws -> Value) throws -> Value {
        guard getpid() == retainedProcess else { throw XPCPeerPolicyError.wrongConnection }
        let peer = try verifyInvocation()
        guard let connection else { throw XPCPeerPolicyError.wrongConnection }
        try requireRetainedConnection(connection, peer: peer, policy: policy)
        let result = try body(connection, policy, peer)
        try requireRetainedConnection(connection, peer: peer, policy: policy); return result
    }
    func requireRetainedConnection(_ actual: NSXPCConnection, peer: XPCPeerCredentials, policy expected: XPCPeerPolicy) throws {
        guard getpid() == retainedProcess else { throw XPCPeerPolicyError.wrongConnection }
        try retainedLock.withLock { guard !connectionRetired, retainedObserversInstalled else { throw XPCPeerPolicyError.wrongConnection } }
        guard let connection, actual === connection, expected.requirement == policy.requirement,
              expected.expectedUserID == policy.expectedUserID, expected.expectedAuditSessionID == policy.expectedAuditSessionID,
              try policy.verifyCredentials(connection) == peer else { throw XPCPeerPolicyError.wrongPeer }
        try retainedLock.withLock { guard !connectionRetired, retainedObserversInstalled else { throw XPCPeerPolicyError.wrongConnection } }
    }
    /// Invoke synchronously from every exported method, including hello. Never use a PID-based code lookup as a substitute.
    public func verifyInvocation() throws -> XPCPeerCredentials {
        guard let connection, NSXPCConnection.current() === connection else { throw XPCPeerPolicyError.wrongConnection }
        return try policy.verifyCredentials(connection)
    }
}
