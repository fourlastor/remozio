import Foundation
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class ReleaseCompatibilityPreflightTests: XCTestCase {
    func testExactRetainedContractsAndBounds() throws {
        func require(_ condition: Bool, file: StaticString = #filePath, line: UInt = #line) { XCTAssertTrue(condition, file: file, line: line) }
        let hash = Data(repeating: 1, count: 20)
        let format = try ReleaseFormat(name: "authority.journal", readers: [2, 5], writers: [5], migrations: [1: 5])
        let request = try ReleaseRequestContract(kind: 0, wireVersion: 1, schemaVersion: 3, actions: [0, 2], purposes: [.issuedRequest, .biometricAuthorization], features: [2, 5])
        func component(_ role: AuthorityCodeRole, formats: [ReleaseFormat] = [], requests: [ReleaseRequestContract] = []) throws -> ReleaseComponent {
            try .init(role: role, identifier: "dev.remozio.role-\(role.rawValue)", generation: 4,
                      relativePath: "Contents/Helpers/role-\(role.rawValue)", codeDirectoryHash: role == .app ? nil : hash,
                      build: "4", teamID: "ABCDEFGHIJ", formats: formats, requests: requests)
        }
        let app = try component(.app)
        let authority = try component(.authority, formats: [format], requests: [request])
        let evidence = SignedReleaseEvidence(manifest: try .init(release: "0.1.0", build: "4", components: [app, authority]),
                                             codeDirectoryHashes: [.app: hash, .authority: hash])
        let policy = try AuthorityCodePolicy(entries: [AuthorityCodeEntry(role: .app, teamID: "ABCDEFGHIJ",
            identifier: app.identifier, installedGeneration: 4, minimumGeneration: 2, codeDirectoryHash: hash, active: true)])
        var passed = 0
        func check(_ formats: [RetainedReleaseFormat], _ requests: [RetainedReleaseRequest] = [], expected: ReleaseCompatibilityError? = nil) throws {
            let requirements = try RetainedReleaseRequirements(formats: formats, requests: requests)
            do {
                try ReleaseCompatibilityPreflight.validate(evidence, policy: policy, requirements: requirements)
                XCTAssertNil(expected)
            } catch let error as ReleaseCompatibilityError { XCTAssertEqual(error, expected) }
            passed += 1
        }
        try check([RetainedReleaseFormat(role: .authority, name: format.name, readVersions: [2, 5], writeVersions: [5])], [.init(role: .authority, contract: request)])
        try check([RetainedReleaseFormat(role: .authority, name: format.name, readVersions: [3])], expected: .missingReader(.authority, format.name, 3))
        try check([RetainedReleaseFormat(role: .authority, name: format.name, readVersions: [1])], expected: .missingReader(.authority, format.name, 1))
        try check([RetainedReleaseFormat(role: .authority, name: format.name, readVersions: [2], writeVersions: [2])], expected: .missingWriter(.authority, format.name, 2))
        try check([RetainedReleaseFormat(role: .authority, name: "authority.other", readVersions: [1])], expected: .missingFormat(.authority, "authority.other"))
        try check([RetainedReleaseFormat(role: .guiAgent, name: format.name, readVersions: [2])], expected: .missingRole(.guiAgent))
        let otherSchema = try ReleaseRequestContract(kind: 0, wireVersion: 1, schemaVersion: 2, actions: [0], purposes: [.issuedRequest])
        try check([], [.init(role: .authority, contract: otherSchema)], expected: .missingRequest(.authority, 0, 1, 2))
        let otherAction = try ReleaseRequestContract(kind: 0, wireVersion: 1, schemaVersion: 3, actions: [1], purposes: [.issuedRequest])
        try check([], [.init(role: .authority, contract: otherAction)], expected: .missingActions(.authority, 0, 1, 3))
        let otherPurpose = try ReleaseRequestContract(kind: 0, wireVersion: 1, schemaVersion: 3, actions: [0], purposes: [.status])
        try check([], [.init(role: .authority, contract: otherPurpose)], expected: .missingPurposes(.authority, 0, 1, 3))
        let retained = try RetainedReleaseFormat(role: .authority, name: format.name, readVersions: [2])
        do {
            _ = try RetainedReleaseRequirements(formats: [retained, retained], requests: [])
            XCTFail("duplicate accepted")
        } catch { require(error as? ReleaseCompatibilityError == .invalidRequirements); passed += 1 }
        do {
            _ = try RetainedReleaseFormat(role: .authority, name: format.name, readVersions: [0])
            XCTFail("zero accepted")
        } catch { require(error as? ReleaseCompatibilityError == .invalidRequirements); passed += 1 }
        do {
            _ = try RetainedReleaseRequirements(formats: [], requests: [.init(role: .authority, contract: request), .init(role: .authority, contract: request)])
            XCTFail("duplicate contract accepted")
        } catch { require(error as? ReleaseCompatibilityError == .invalidRequirements); passed += 1 }
        do {
            _ = try RetainedReleaseFormat(role: .authority, name: format.name, readVersions: Set(1...33))
            XCTFail("unbounded versions accepted")
        } catch { require(error as? ReleaseCompatibilityError == .invalidRequirements); passed += 1 }
        do {
            _ = try RetainedReleaseRequirements(formats: Array(repeating: retained, count: 385), requests: [])
            XCTFail("unbounded requirements accepted")
        } catch { require(error as? ReleaseCompatibilityError == .invalidRequirements); passed += 1 }
        let subset = try ReleaseRequestContract(kind: 0, wireVersion: 1, schemaVersion: 3, actions: [0], purposes: [.issuedRequest])
        try check([], [.init(role: .authority, contract: subset)])
        let otherWire = try ReleaseRequestContract(kind: 0, wireVersion: 2, schemaVersion: 3, actions: [0], purposes: [.issuedRequest])
        try check([], [.init(role: .authority, contract: otherWire)], expected: .missingRequest(.authority, 0, 2, 3))
        let supportedFeature = try ReleaseRequestContract(kind: 0, wireVersion: 1, schemaVersion: 3,
            actions: [0], purposes: [.issuedRequest], features: [2])
        try check([], [.init(role: .authority, contract: supportedFeature)])
        let missingFeature = try ReleaseRequestContract(kind: 0, wireVersion: 1, schemaVersion: 3,
            actions: [0], purposes: [.issuedRequest], features: [3])
        try check([], [.init(role: .authority, contract: missingFeature)], expected: .missingFeatures(.authority, 0, 1, 3))
        let oldContract = try ReleaseRequestContract(kind: 0, wireVersion: 1, schemaVersion: 3,
            actions: [0, 2], purposes: [.issuedRequest, .biometricAuthorization])
        let oldAuthority = try component(.authority, formats: [format], requests: [oldContract])
        let oldEvidence = SignedReleaseEvidence(manifest: try .init(release: "0.1.0", build: "4", components: [app, oldAuthority]),
                                               codeDirectoryHashes: [.app: hash, .authority: hash])
        XCTAssertEqual(oldEvidence.manifest.schemaVersion, 1)
        XCTAssertThrowsError(try ReleaseCompatibilityPreflight.validate(oldEvidence, policy: policy,
            requirements: .init(formats: [], requests: [.init(role: .authority, contract: supportedFeature)]))) {
            XCTAssertEqual($0 as? ReleaseCompatibilityError, .missingFeatures(.authority, 0, 1, 3))
        }
        XCTAssertNoThrow(try ReleaseCompatibilityPreflight.validate(oldEvidence, policy: policy,
            requirements: .init(formats: [], requests: [.init(role: .authority, contract: oldContract)])))
        XCTAssertEqual(passed, 18)
    }
}
