import Foundation
import Security

/// Internal identity primitive. The calling host supplies a requirement from protected policy.
enum DynamicCodeValidation {
    enum Failure: Error, Equatable { case invalidRequirement, unavailable, security(OSStatus) }

    static func validateSelf(requirement expression: String) throws {
        var requirement: SecRequirement?
        try checked(SecRequirementCreateWithString(expression as CFString, [], &requirement))
        guard let requirement else { throw Failure.invalidRequirement }
        var code: SecCode?
        try checked(SecCodeCopySelf([], &code))
        guard let code else { throw Failure.unavailable }
        try checked(SecCodeCheckValidity(code, [], requirement))
    }

    static func selfPath() throws -> String {
        var code: SecCode?
        try checked(SecCodeCopySelf([], &code))
        guard let code else { throw Failure.unavailable }
        var staticCode: SecStaticCode?
        try checked(SecCodeCopyStaticCode(code, [], &staticCode))
        guard let staticCode else { throw Failure.unavailable }
        var path: CFURL?
        try checked(SecCodeCopyPath(staticCode, [], &path))
        guard let path else { throw Failure.unavailable }
        return (path as URL).path
    }

    private static func checked(_ status: OSStatus) throws {
        guard status == errSecSuccess else { throw Failure.security(status) }
    }
}
