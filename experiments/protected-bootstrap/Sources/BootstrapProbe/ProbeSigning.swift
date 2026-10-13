import Foundation
import Security

enum ProbeSigning {
    static let entitlement = "com.apple.developer.security.privileged-file-operations"
    static var hasPrivilegedSigning: Bool {
        var code: SecCode?, staticCode: SecStaticCode?, info: CFDictionary?, requirement: SecRequirement?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dictionary = info as? [String: Any],
              let entitlements = dictionary[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              let value = entitlements[entitlement] as? NSNumber,
              CFGetTypeID(value) == CFBooleanGetTypeID(), value.boolValue,
              SecRequirementCreateWithString("anchor apple generic and identifier \"dev.remozio.experiments.bootstrap\"" as CFString, [], &requirement) == errSecSuccess,
              let requirement, SecCodeCheckValidity(code, [], requirement) == errSecSuccess else { return false }
        return true
    }
}
