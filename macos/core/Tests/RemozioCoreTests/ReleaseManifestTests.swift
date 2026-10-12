import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class ReleaseManifestTests: XCTestCase {
    private func component(role: AuthorityCodeRole = .app, path: String = "Contents/MacOS/Remozio",
                           formats: [ReleaseFormat] = []) throws -> ReleaseComponent {
        try .init(role: role, identifier: "dev.remozio.test.\(role.rawValue)", generation: 1, relativePath: path,
            codeDirectoryHash: role == .app ? nil : Data(repeating: 7, count: 20), build: "1", teamID: nil, formats: formats)
    }
    private func manifest() throws -> ReleaseManifest {
        try .init(release: "0.1.0", build: "1", components: [component(),
            component(role: .authority, path: "Contents/Helpers/authority", formats: [
                .init(name: "authority.journal", readers: [12, 13], writers: [12, 13], migrations: [1: 12]),
                .init(name: "authority.config", readers: [1, 2], writers: [1, 2])])])
    }
    func testCanonicalRoundTripAndAbsentRoles() throws {
        let value = try manifest()
        XCTAssertEqual(try ReleaseManifest.decode(value.canonicalBytes), value)
        XCTAssertEqual(try ReleaseManifest(release: value.release, build: value.build, components: value.components.reversed()).canonicalBytes,
                       try value.canonicalBytes)
        XCTAssertTrue(value.absentRoles.contains(.guiAgent)); XCTAssertFalse(value.absentRoles.contains(.authority))
        XCTAssertEqual(value.components[1].formats.map(\.name), ["authority.config", "authority.journal"])
    }
    func testExactSetsAndMigrationBounds() throws {
        for values: Set<UInt64> in [[], [0], Set(1...33)] {
            XCTAssertThrowsError(try ReleaseFormat(name: "format", readers: values, writers: []))
        }
        XCTAssertThrowsError(try ReleaseFormat(name: "format", readers: [1], writers: [2]))
        for migrations: [UInt64: UInt64] in [[0: 2], [2: 2], [3: 2], [1: 3]] {
            XCTAssertThrowsError(try ReleaseFormat(name: "format", readers: [2], writers: [2], migrations: migrations))
        }
        XCTAssertEqual(try ReleaseFormat(name: "format", readers: [2, 5], writers: [5]).readers, [2, 5])
    }
    func testDuplicateRolesIdentifiersAndPathsCannotDescribeARelease() throws {
        let app = try component()
        XCTAssertThrowsError(try ReleaseManifest(release: "1", build: "1", components: [app, app]))
        XCTAssertThrowsError(try ReleaseManifest(release: "1", build: "1", components: [component(role: .authority)]))
        XCTAssertThrowsError(try ReleaseManifest(release: "1", build: "1", components: [app, component(role: .authority)]))
        XCTAssertThrowsError(try component(formats: [.init(name: "same", readers: [1], writers: [1]),
                                                     .init(name: "same", readers: [1], writers: [1])]))
    }
    func testPathAndIdentityBounds() throws {
        for path in ["/Contents/MacOS/Remozio", "Contents/../Remozio", "Contents//Remozio", "Contents/./Remozio", "Other/MacOS/Remozio", "Contents/MacOS/\u{0}"] {
            XCTAssertThrowsError(try component(path: path))
        }
        XCTAssertThrowsError(try ReleaseComponent(role: .app, identifier: "id;injection", generation: 1,
            relativePath: "Contents/MacOS/app", codeDirectoryHash: nil, build: "1", teamID: nil, formats: []))
        XCTAssertThrowsError(try ReleaseComponent(role: .authority, identifier: "id", generation: 1,
            relativePath: "Contents/Helpers/helper", codeDirectoryHash: nil, build: "1", teamID: nil, formats: []))
    }
    func testUnknownMissingReorderedAndDuplicateFieldsFailClosed() throws {
        let bytes = try manifest().canonicalBytes
        guard case .map(let original) = try DeterministicCBOR.decode(bytes, limits: ReleaseManifest.limits),
              case .array(let components) = original[5], case .map(let component) = components[1],
              case .array(let formats) = component[7], case .map(let format) = formats[0] else { return XCTFail("fixture") }
        var unknown = original; unknown[6] = .null
        var missing = original; missing.removeValue(forKey: 4)
        var reversed = original; reversed[5] = .array(components.reversed())
        var duplicate = original; duplicate[5] = .array(components + [components[1]])
        var candidates = [unknown, missing, reversed, duplicate]
        for (key, value) in [(UInt64(0), CBORValue.unsigned(99)), (4, .null), (9, .unsigned(1))] {
            var changed = component; changed[key] = value
            var root = original; root[5] = .array([components[0], .map(changed)]); candidates.append(root)
        }
        for values: [CBORValue] in [[.unsigned(1), .unsigned(1)], [.unsigned(2), .unsigned(1)], []] {
            var changed = format; changed[1] = .array(values)
            var c = component; c[7] = .array([.map(changed)])
            var root = original; root[5] = .array([components[0], .map(c)]); candidates.append(root)
        }
        for candidate in candidates {
            XCTAssertThrowsError(try ReleaseManifest.decode(DeterministicCBOR.encode(.map(candidate), limits: ReleaseManifest.limits)))
        }
        var next = original; next[0] = .unsigned(3)
        XCTAssertThrowsError(try ReleaseManifest.decode(DeterministicCBOR.encode(.map(next), limits: ReleaseManifest.limits))) {
            XCTAssertEqual($0 as? ReleaseManifestError, .unsupportedSchema)
        }
        XCTAssertThrowsError(try ReleaseManifest.decode(bytes + Data([0])))
        XCTAssertThrowsError(try ReleaseManifest.decode(Data(repeating: 0, count: ReleaseManifest.maximumBytes + 1)))
    }
    func testUnknownOrDuplicatedPurposeTagsCannotEnterADeclaration() throws {
        let request = try ReleaseRequestContract(kind: 0, wireVersion: 1, schemaVersion: 1,
            actions: [0, 2], purposes: [.cancellation, .biometricAuthorization])
        let app = try ReleaseComponent(role: .app, identifier: "id", generation: 1, relativePath: "Contents/MacOS/app",
            codeDirectoryHash: nil, build: "1", teamID: nil, formats: [], requests: [request])
        let manifest = try ReleaseManifest(release: "1", build: "1", components: [app])
        guard case .map(let root) = try DeterministicCBOR.decode(manifest.canonicalBytes, limits: ReleaseManifest.limits),
              case .array(let components) = root[5], case .map(let c) = components[0],
              case .array(let requests) = c[8], case .map(let contract) = requests[0] else { return XCTFail("fixture") }
        for tags: [UInt64] in [[0], [6], [2, 2], [4, 2], []] {
            var changed = contract; changed[4] = .array(tags.map(CBORValue.unsigned))
            var component = c; component[8] = .array([.map(changed)])
            var fields = root; fields[5] = .array([.map(component)])
            XCTAssertThrowsError(try ReleaseManifest.decode(DeterministicCBOR.encode(.map(fields), limits: ReleaseManifest.limits)))
        }
    }
    func testRequestContractsRejectUnknownActionsPurposesAndDuplicates() throws {
        let request = try ReleaseRequestContract(kind: 0, wireVersion: 1, schemaVersion: 3,
            actions: [0, 2], purposes: [.issuedRequest, .cancellation, .biometricAuthorization, .status])
        XCTAssertThrowsError(try ReleaseRequestContract(kind: 4, wireVersion: 1, schemaVersion: 1, actions: [0], purposes: [.status]))
        XCTAssertThrowsError(try ReleaseRequestContract(kind: 0, wireVersion: 0, schemaVersion: 1, actions: [0], purposes: [.status]))
        XCTAssertThrowsError(try ReleaseRequestContract(kind: 0, wireVersion: 1, schemaVersion: 1, actions: [10], purposes: [.status]))
        XCTAssertThrowsError(try ReleaseComponent(role: .app, identifier: "id", generation: 1, relativePath: "Contents/MacOS/app",
            codeDirectoryHash: nil, build: "1", teamID: nil, formats: [], requests: [request, request]))
    }
}
