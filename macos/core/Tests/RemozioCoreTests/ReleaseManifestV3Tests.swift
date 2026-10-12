import Foundation
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class ReleaseManifestV3Tests: XCTestCase {
    func testFeatureEncodingAndOldCodecCompatibility() throws {
        func require(_ condition: Bool, file: StaticString = #filePath, line: UInt = #line) { XCTAssertTrue(condition, file: file, line: line) }
        var passed = 0
        let app = try ReleaseComponent(role: .app, identifier: "dev.remozio.app", generation: 1,
            relativePath: "Contents/MacOS/Remozio", codeDirectoryHash: nil, build: "1", teamID: "ABCDEFGHIJ", formats: [])
        let value = try ReleaseManifest(release: "0.1.0", build: "1", components: [app])
        let frozenHex = "a600010165302e312e30026131036561726d3634046432362e300581aa0001016f6465762e72656d6f7a696f2e61707002010376436f6e74656e74732f4d61634f532f52656d6f7a696f04f6056131066a4142434445464748494a078008800900"
        require(try value.canonicalBytes.map { String(format: "%02x", $0) }.joined() == frozenHex); passed += 1
        let dependency = try ReleaseDependency(owner: .app, kind: .tool, signaturePath: "Contents/Frameworks/Tool",
            executablePath: "Contents/Frameworks/Tool", identifier: "dev.remozio.tool", codeDirectoryHash: Data(repeating: 1, count: 20), teamID: "ABCDEFGHIJ", build: nil)
        let oldApp = try RemozioCore.ReleaseComponent(role: .app, identifier: app.identifier, generation: app.generation,
            relativePath: app.relativePath, codeDirectoryHash: nil, build: app.build, teamID: app.teamID, formats: [])
        let oldV2 = try RemozioCore.ReleaseManifest(release: "0.1.0", build: "1", components: [oldApp], dependencies: [dependency])
        let newV2 = try ReleaseManifest(release: "0.1.0", build: "1", components: [app], dependencies: [dependency])
        require(try newV2.canonicalBytes.map { String(format: "%02x", $0) }.joined() == "a700020165302e312e30026131036561726d3634046432362e300581aa0001016f6465762e72656d6f7a696f2e61707002010376436f6e74656e74732f4d61634f532f52656d6f7a696f04f6056131066a4142434445464748494a0780088009000681a900010104027818436f6e74656e74732f4672616d65776f726b732f546f6f6c037818436f6e74656e74732f4672616d65776f726b732f546f6f6c04706465762e72656d6f7a696f2e746f6f6c05540101010101010101010101010101010101010101066a4142434445464748494a07f60880"); passed += 1
        require(try ReleaseManifest.decode(oldV2.canonicalBytes).canonicalBytes == oldV2.canonicalBytes); passed += 1
        let contract = try ReleaseRequestContract(kind: 0, wireVersion: 1, schemaVersion: 3,
            actions: [0, 2], purposes: [.issuedRequest, .biometricAuthorization], features: [2, 5])
        do {
            _ = try ReleaseRequestContract(kind: 0, wireVersion: 1, schemaVersion: 3,
                actions: [0], purposes: [.issuedRequest], features: Set(1...33))
            XCTFail("unbounded feature declaration accepted")
        } catch { require(error as? ReleaseManifestError == .invalidDeclaration); passed += 1 }
        let emptyFeatures = try ReleaseRequestContract(kind: 0, wireVersion: 1, schemaVersion: 3,
            actions: [0, 2], purposes: [.issuedRequest, .biometricAuthorization])
        let newRequestedApp = try ReleaseComponent(role: .app, identifier: app.identifier, generation: app.generation,
            relativePath: app.relativePath, codeDirectoryHash: nil, build: app.build, teamID: app.teamID, formats: [], requests: [emptyFeatures])
        let newRequestedBytes = try ReleaseManifest(release: "1", build: "1", components: [newRequestedApp]).canonicalBytes
        require(newRequestedBytes.map { String(format: "%02x", $0) }.joined() == "a60001016131026131036561726d3634046432362e300581aa0001016f6465762e72656d6f7a696f2e61707002010376436f6e74656e74732f4d61634f532f52656d6f7a696f04f6056131066a4142434445464748494a07800881a500000101020303820002048201040900"); passed += 1
        let featuredApp = try ReleaseComponent(role: .app, identifier: app.identifier, generation: app.generation,
            relativePath: app.relativePath, codeDirectoryHash: nil, build: app.build, teamID: app.teamID, formats: [], requests: [contract])
        let featured = try ReleaseManifest(release: "0.1.0", build: "1", components: [featuredApp], dependencies: [dependency])
        let bytes = try featured.canonicalBytes
        require(featured.schemaVersion == 3); passed += 1
        require(try ReleaseManifest.decode(bytes) == featured); passed += 1
        guard case .map(let encodedHeader) = try DeterministicCBOR.decode(bytes, limits: ReleaseManifest.limits) else { return XCTFail() }
        XCTAssertEqual(encodedHeader[0], .unsigned(3)); passed += 1
        guard case .map(let root) = try DeterministicCBOR.decode(bytes, limits: ReleaseManifest.limits),
              case .array(let components) = root[5], case .map(let component) = components[0],
              case .array(let requests) = component[8], case .map(let request) = requests[0] else { return XCTFail("fixture") }
        func reject(_ fields: [UInt64: CBORValue]) throws {
            let malformed = try DeterministicCBOR.encode(.map(fields), limits: ReleaseManifest.limits)
            do { _ = try ReleaseManifest.decode(malformed); XCTFail("malformed declaration accepted") }
            catch { passed += 1 }
        }
        for features: [CBORValue] in [[.unsigned(2), .unsigned(2)], [.unsigned(5), .unsigned(2)], (1...33).map { .unsigned(UInt64($0)) }, [.text("2")]] {
            var r = request; r[5] = .array(features)
            var c = component; c[8] = .array([.map(r)])
            var fields = root; fields[5] = .array([.map(c)])
            try reject(fields)
        }
        for remove in [true, false] {
            var r = request
            if remove { r.removeValue(forKey: 5) } else { r[6] = .null }
            var c = component; c[8] = .array([.map(r)])
            var fields = root; fields[5] = .array([.map(c)])
            try reject(fields)
        }
        var downgrade = root; downgrade[0] = .unsigned(2); try reject(downgrade)
        var future = root; future[0] = .unsigned(4); try reject(future)
        var emptyRequest = request; emptyRequest[5] = .array([])
        var emptyComponent = component; emptyComponent[8] = .array([.map(emptyRequest)])
        var empty = root; empty[5] = .array([.map(emptyComponent)])
        let emptyBytes = try DeterministicCBOR.encode(.map(empty), limits: ReleaseManifest.limits)
        let decodedEmpty = try ReleaseManifest.decode(emptyBytes)
        require(decodedEmpty.schemaVersion == 3 && decodedEmpty.components[0].requests[0].features.isEmpty)
        require(try decodedEmpty.canonicalBytes == emptyBytes); passed += 1
        XCTAssertEqual(passed, 17)
    }
}
