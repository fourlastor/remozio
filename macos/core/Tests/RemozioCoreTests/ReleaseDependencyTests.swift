import Foundation
import XCTest
@testable import RemozioCore

final class ReleaseDependencyTests: XCTestCase {
    func testCanonicalFrameworkAndExplicitExecutableAliases() throws {
        let root = "Contents/Frameworks/Sparkle.framework"
        let value = try ReleaseDependency(owner: .app, kind: .framework, signaturePath: root,
            executablePath: root + "/Versions/B/Sparkle", identifier: "org.sparkle-project.Sparkle",
            codeDirectoryHash: Data(repeating: 1, count: 20), teamID: "ABCDEFGHIJ", build: "2033",
            executableAliases: [root + "/Sparkle", root + "/Versions/Current/Sparkle"])
        XCTAssertEqual(value.owner, .app)
        XCTAssertEqual(value.executableAliases.count, 2)
        XCTAssertEqual(value.kind, .framework)
    }
    func testPathEscapesAmbiguityAndExecutableSelfAliasAreRejected() {
        for path in ["/Contents/Frameworks/tool", "Contents/../tool", "Contents//tool",
                     "Contents/Frameworks/./tool", "Contents/Frameworks/tool\0", "Contents/Frameworks"] {
            XCTAssertThrowsError(try ReleaseDependency(owner: .app, kind: .tool, signaturePath: path,
                executablePath: path, identifier: "org.example.tool", codeDirectoryHash: Data(repeating: 1, count: 20),
                teamID: "ABCDEFGHIJ", build: nil))
        }
        let path = "Contents/Frameworks/tool"
        XCTAssertThrowsError(try ReleaseDependency(owner: .app, kind: .tool, signaturePath: path,
            executablePath: path, identifier: "org.example.tool", codeDirectoryHash: Data(repeating: 1, count: 20),
            teamID: "ABCDEFGHIJ", build: nil, executableAliases: [path]))
    }
    func testBundleKindCannotDescribeUnrelatedExecutableOrMissingBuild() {
        let root = "Contents/Frameworks/Vendor.app"
        for (path, build) in [("Contents/MacOS/other", "1" as String?), (root + "/Contents/MacOS/sub/tool", "1"),
                               (root + "/Contents/MacOS/tool", nil)] {
            XCTAssertThrowsError(try ReleaseDependency(owner: .app, kind: .application, signaturePath: root,
                executablePath: path, identifier: "org.example.tool", codeDirectoryHash: Data(repeating: 1, count: 20),
                teamID: "ABCDEFGHIJ", build: build))
        }
    }
    func testMalformedIdentityHashTeamAndAliasBoundAreRejected() {
        let path = "Contents/Frameworks/tool"
        for (identifier, hash, team) in [("bad identifier", Data(repeating: 1, count: 20), "ABCDEFGHIJ"),
                                        ("org.example.tool", Data(repeating: 1, count: 19), "ABCDEFGHIJ"),
                                        ("org.example.tool", Data(repeating: 1, count: 20), "bad-team")] {
            XCTAssertThrowsError(try ReleaseDependency(owner: .app, kind: .tool, signaturePath: path,
                executablePath: path, identifier: identifier, codeDirectoryHash: hash, teamID: team, build: nil))
        }
        XCTAssertThrowsError(try ReleaseDependency(owner: .app, kind: .tool, signaturePath: path,
            executablePath: path, identifier: "org.example.tool", codeDirectoryHash: Data(repeating: 1, count: 20),
            teamID: "ABCDEFGHIJ", build: nil, executableAliases: Set((0..<17).map { "Contents/Frameworks/tool\($0)" })))
    }
}
