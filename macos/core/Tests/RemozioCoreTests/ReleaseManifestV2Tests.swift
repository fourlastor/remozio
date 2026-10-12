import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class ReleaseManifestV2Tests: XCTestCase {
    private func app() throws -> ReleaseComponent {
        try .init(role: .app, identifier: "dev.remozio.app", generation: 1, relativePath: "Contents/MacOS/Remozio",
                  codeDirectoryHash: nil, build: "1", teamID: "ABCDEFGHIJ", formats: [])
    }
    private func dependency(owner: AuthorityCodeRole = .app, alias: String = "Contents/Frameworks/VendorAlias") throws -> ReleaseDependency {
        try .init(owner: owner, kind: .tool, signaturePath: "Contents/Frameworks/VendorTool",
                  executablePath: "Contents/Frameworks/VendorTool", identifier: "org.vendor.Tool",
                  codeDirectoryHash: Data(repeating: 1, count: 20), teamID: "ABCDEFGHIJ", build: nil,
                  executableAliases: [alias])
    }
    func testSchemaOneBytesMatchTheFrozenVersionOneCodec() throws {
        let frozenHex = "a600010165302e312e30026131036561726d3634046432362e300581aa0001016f6465762e72656d6f7a696f2e61707002010376436f6e74656e74732f4d61634f532f52656d6f7a696f04f6056131066a4142434445464748494a078008800900"
        let value = try ReleaseManifest(release: "0.1.0", build: "1", components: [app()])
        let encoded = try value.canonicalBytes
        XCTAssertEqual(encoded.map { String(format: "%02x", $0) }.joined(), frozenHex)
        let decoded = try ReleaseManifest.decode(encoded)
        XCTAssertEqual(decoded.schemaVersion, 1)
        XCTAssertTrue(decoded.dependencies.isEmpty)
        XCTAssertEqual(try decoded.canonicalBytes, encoded)
    }
    func testSchemaTwoRoundTripRetainsDependenciesWithoutChangingRoles() throws {
        let value = try ReleaseManifest(release: "0.1.0", build: "1", components: [app()], dependencies: [dependency()])
        let decoded = try ReleaseManifest.decode(value.canonicalBytes)
        XCTAssertEqual(decoded, value)
        XCTAssertEqual(decoded.schemaVersion, 2)
        XCTAssertEqual(decoded.components.map(\.role), [.app])
        XCTAssertEqual(decoded.absentRoles, Set(AuthorityCodeRole.allCases).subtracting([.app]))
    }
    func testMissingOwnerAndExecutableAliasCollisionAreRejected() throws {
        XCTAssertThrowsError(try ReleaseManifest(release: "0.1.0", build: "1", components: [app()],
            dependencies: [dependency(owner: .authority)]))
        XCTAssertThrowsError(try ReleaseManifest(release: "0.1.0", build: "1", components: [app()],
            dependencies: [dependency(alias: "Contents/MacOS/Remozio")]))
    }
    func testFutureSchemaAndDuplicateAliasAreRejected() throws {
        let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 8, maxItems: 8192)
        let value = try ReleaseManifest(release: "0.1.0", build: "1", components: [app()], dependencies: [dependency()])
        guard case .map(var fields) = try DeterministicCBOR.decode(value.canonicalBytes, limits: limits) else { return XCTFail() }
        fields[0] = .unsigned(4)
        XCTAssertThrowsError(try ReleaseManifest.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        fields[0] = .unsigned(2)
        guard case .array(var dependencies) = fields[6], case .map(var item) = dependencies[0], case .array(var aliases) = item[8] else { return XCTFail() }
        aliases.append(aliases[0]); item[8] = .array(aliases); dependencies[0] = .map(item); fields[6] = .array(dependencies)
        XCTAssertThrowsError(try ReleaseManifest.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
    }
    func testVersionTwoWithNoDependenciesRetainsItsWireVersion() throws {
        let value = try ReleaseManifest(release: "0.1.0", build: "1", components: [app()])
        let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 8, maxItems: 8192)
        guard case .map(var fields) = try DeterministicCBOR.decode(value.canonicalBytes, limits: limits) else { return XCTFail() }
        fields[0] = .unsigned(2); fields[6] = .array([])
        let encoded = try DeterministicCBOR.encode(.map(fields), limits: limits)
        let decoded = try ReleaseManifest.decode(encoded)
        XCTAssertEqual(decoded.schemaVersion, 2); XCTAssertTrue(decoded.dependencies.isEmpty)
        XCTAssertEqual(try decoded.canonicalBytes, encoded)
        fields.removeValue(forKey: 6)
        XCTAssertThrowsError(try ReleaseManifest.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
    }
    private func numberedDependency(_ number: Int, aliases: Int = 0) throws -> ReleaseDependency {
        let path = "Contents/Frameworks/Tool" + String(number)
        return try .init(owner: .app, kind: .tool, signaturePath: path, executablePath: path,
            identifier: "org.vendor.Tool" + String(number), codeDirectoryHash: Data(repeating: 1, count: 20),
            teamID: "ABCDEFGHIJ", build: nil,
            executableAliases: Set((0..<aliases).map { "Contents/Frameworks/Alias" + String(number) + "-" + String($0) }))
    }
    func testDependencyAndTotalInventoryBoundsIncludeAliases() throws {
        let maximumDependencies = try (0..<32).map { try numberedDependency($0) }
        XCTAssertEqual(try ReleaseManifest(release: "1", build: "1", components: [app()],
            dependencies: maximumDependencies).dependencies.count, 32)
        XCTAssertThrowsError(try ReleaseManifest(release: "1", build: "1", components: [app()],
            dependencies: maximumDependencies + [numberedDependency(32)]))
        let maximumPaths = try (0..<15).map { try numberedDependency($0, aliases: 16) }
        XCTAssertEqual(try ReleaseManifest(release: "1", build: "1", components: [app()],
            dependencies: maximumPaths).dependencies.count, 15)
        XCTAssertThrowsError(try ReleaseManifest(release: "1", build: "1", components: [app()],
            dependencies: maximumPaths + [numberedDependency(15)]))
    }
    func testDependencyOrderAndUnknownFieldsFailCanonicalDecoding() throws {
        let value = try ReleaseManifest(release: "1", build: "1", components: [app()],
            dependencies: [numberedDependency(0), numberedDependency(1)])
        let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 8, maxItems: 8192)
        guard case .map(var fields) = try DeterministicCBOR.decode(value.canonicalBytes, limits: limits),
              case .array(let dependencies) = fields[6] else { return XCTFail() }
        fields[6] = .array(dependencies.reversed())
        XCTAssertThrowsError(try ReleaseManifest.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        fields[6] = .array(dependencies); fields[7] = .null
        XCTAssertThrowsError(try ReleaseManifest.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
    }

}
