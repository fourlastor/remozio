import Darwin
import Foundation
import Security

public enum SetupAdministratorAuthorizationError: Error, Equatable {
    case wrongProcess, closed, incompatiblePolicy, invalidExternalForm, cancelled
    case denied(OSStatus)
}

/// One local setup session. Use it off the UI executor and close it when the operation ends.
/// External forms are bearer credentials. Send them only after authenticating the Root setup endpoint.
public final class SetupAdministratorSession: CustomStringConvertible {
    private let processID = getpid()
    private let owner = getuid()
    private let lock = NSLock()
    private var reference: AuthorizationRef?
    public var description: String { "SetupAdministratorSession(redacted)" }

    public init() throws {
        guard getuid() > 0, getuid() == geteuid() else { throw SetupAdministratorAuthorizationError.wrongProcess }
        try SetupAdministratorNative.status(AuthorizationCreate(nil, nil, [], &reference))
        guard reference != nil else { throw SetupAdministratorAuthorizationError.closed }
    }
    deinit { close() }

    /// macOS handles administrator credentials. This does not enroll a phone or grant command access.
    public func authorize() throws {
        guard getpid() == processID else { throw SetupAdministratorAuthorizationError.wrongProcess }
        try lock.withLock {
            let reference = try current()
            try SetupAdministratorNative.validatePolicy()
            try SetupAdministratorNative.copyRights(reference, flags: [.interactionAllowed, .extendRights])
            try SetupAdministratorNative.validatePolicy()
        }
    }

    /// Export only current rights. A newly created or expired session cannot export an approval.
    public func externalForm() throws -> Data {
        guard getpid() == processID else { throw SetupAdministratorAuthorizationError.wrongProcess }
        return try lock.withLock {
            let reference = try current()
            try SetupAdministratorNative.validatePolicy()
            try SetupAdministratorNative.copyRights(reference, flags: [])
            var form = AuthorizationExternalForm()
            try SetupAdministratorNative.status(AuthorizationMakeExternalForm(reference, &form))
            return withUnsafeBytes(of: &form) { Data($0) }
        }
    }

    public func close() {
        // A fork can retain a lock held by a vanished thread. Do not enter it in the child.
        guard getpid() == processID else { return }
        lock.withLock {
            guard let reference else { return }
            self.reference = nil
            _ = AuthorizationFree(reference, .destroyRights)
        }
    }
    private func current() throws -> AuthorizationRef {
        guard getpid() == processID, getuid() == owner, geteuid() == owner else {
            throw SetupAdministratorAuthorizationError.wrongProcess
        }
        guard let reference else { throw SetupAdministratorAuthorizationError.closed }
        return reference
    }
}

/// Recheck immediately before each typed privileged setup operation.
/// The host separately validates protected code, operation scope, freshness and retained installation state.
public enum SetupAdministratorAuthorization {
    public static func validate(externalForm: Data, invocation: XPCInvocationGuard) throws {
        guard getuid() == 0, geteuid() == 0 else { throw SetupAdministratorAuthorizationError.wrongProcess }
        let peer = try invocation.verifyInvocation()
        guard peer.userID > 0, peer.userID < UInt32.max else { throw SetupAdministratorAuthorizationError.wrongProcess }
        try SetupAdministratorNative.validate(externalForm: externalForm)
    }
}

// Ordinary-owner controls use the actual platform importer without granting or prompting for rights.
enum SetupAdministratorNative {
    static let right = "system.privilege.admin"

    static func status(_ value: OSStatus) throws {
        guard value != errAuthorizationSuccess else { return }
        if value == errAuthorizationCanceled { throw SetupAdministratorAuthorizationError.cancelled }
        throw SetupAdministratorAuthorizationError.denied(value)
    }
    static func copyRights(_ reference: AuthorizationRef, flags: AuthorizationFlags) throws {
        try right.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            try withUnsafeMutablePointer(to: &item) { pointer in
                var rights = AuthorizationRights(count: 1, items: pointer)
                try status(AuthorizationCopyRights(reference, &rights, nil, flags, nil))
            }
        }
    }
    static func validate(externalForm: Data) throws {
        guard externalForm.count == MemoryLayout<AuthorizationExternalForm>.size else {
            throw SetupAdministratorAuthorizationError.invalidExternalForm
        }
        try validatePolicy()
        var form = AuthorizationExternalForm()
        _ = withUnsafeMutableBytes(of: &form) { externalForm.copyBytes(to: $0) }
        var reference: AuthorizationRef?
        try status(AuthorizationCreateFromExternalForm(&form, &reference))
        guard let reference else { throw SetupAdministratorAuthorizationError.invalidExternalForm }
        defer { _ = AuthorizationFree(reference, []) }
        // No interaction, extension, partial rights or preauthorization in the helper.
        try copyRights(reference, flags: [])
        try validatePolicy()
    }
    static func validatePolicy() throws {
        var definition: CFDictionary?
        try status(right.withCString { AuthorizationRightGet($0, &definition) })
        guard let definition else { throw SetupAdministratorAuthorizationError.incompatiblePolicy }
        try validatePolicy(definition as NSDictionary)
    }
    static func validatePolicy(_ definition: NSDictionary) throws {
        func boolean(_ key: String, equals expected: Bool) -> Bool {
            guard let number = definition[key] as? NSNumber,
                  CFGetTypeID(number) == CFBooleanGetTypeID() else { return false }
            return number.boolValue == expected
        }
        guard definition["class"] as? String == "user", definition["group"] as? String == "admin",
              boolean("authenticate-user", equals: true), boolean("session-owner", equals: false),
              boolean("shared", equals: false),
              let timeout = definition["timeout"] as? NSNumber, CFGetTypeID(timeout) != CFBooleanGetTypeID(),
              timeout.doubleValue.isFinite, timeout.doubleValue > 0, timeout.doubleValue <= 300 else {
            throw SetupAdministratorAuthorizationError.incompatiblePolicy
        }
    }
}
