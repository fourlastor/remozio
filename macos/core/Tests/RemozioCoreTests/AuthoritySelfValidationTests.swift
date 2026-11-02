import Foundation
import Security
import XCTest
@testable import RemozioCore

final class AuthoritySelfValidationTests: XCTestCase {
    func testAuthorityRequirementBindsExactGenerationAndReleaseIdentity() throws {
        for generation in [UInt64(1), 4, .max] {
            let entry = try AuthorityCodeEntry(role: .authority, teamID: "ABCDEFGHIJ", identifier: "dev.sebastiano.remozio.macos.authority",
                installedGeneration: generation, minimumGeneration: generation, codeDirectoryHash: Data(repeating: 9, count: 20), active: true)
            let expression = try AuthoritySelfValidation.requirement(for: entry)
            var compiled: SecRequirement?
            XCTAssertEqual(SecRequirementCreateWithString(expression as CFString, [], &compiled), errSecSuccess)
            XCTAssertNotNil(compiled)
            XCTAssertTrue(expression.contains("anchor apple generic"))
            XCTAssertTrue(expression.contains("info[\"RemozioSecurityGeneration\"] = \"\(generation)\""))
            XCTAssertThrowsError(try DynamicCodeValidation.validateSelf(requirement: expression))
        }
    }
    func testInactiveOrWrongRoleCannotSupplyAuthorityPolicy() throws {
        for (role, active) in [(AuthorityCodeRole.authority, false), (.transport, true)] {
            let entry = try AuthorityCodeEntry(role: role, teamID: "ABCDEFGHIJ", identifier: "dev.sebastiano.remozio.macos.authority",
                installedGeneration: 4, minimumGeneration: 3, codeDirectoryHash: Data(repeating: 9, count: 20), active: active)
            XCTAssertThrowsError(try AuthoritySelfValidation.requirement(for: entry)) {
                XCTAssertEqual($0 as? AuthoritySelfValidationError, .invalidPolicy)
            }
        }
    }
    func testMalformedAndNonmatchingDynamicRequirementsFail() throws {
        XCTAssertThrowsError(try DynamicCodeValidation.validateSelf(requirement: "not a valid requirement ["))
        XCTAssertThrowsError(try DynamicCodeValidation.validateSelf(requirement: "identifier \"dev.remozio.not-this-process\""))
    }
}
