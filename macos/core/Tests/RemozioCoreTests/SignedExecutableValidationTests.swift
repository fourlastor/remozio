import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class SignedExecutableValidationTests: XCTestCase {
    func testAcceptsInitialSameAndNewerGeneration() throws {
        XCTAssertEqual(try SignedExecutableValidation.validatedGeneration("1", committedFloor: 1, installedGeneration: 0), 1)
        XCTAssertEqual(try SignedExecutableValidation.validatedGeneration("4", committedFloor: 3, installedGeneration: 4), 4)
        XCTAssertEqual(try SignedExecutableValidation.validatedGeneration("5", committedFloor: 3, installedGeneration: 4), 5)
        XCTAssertEqual(try SignedExecutableValidation.validatedGeneration(String(UInt64.max), committedFloor: 1, installedGeneration: 0), UInt64.max)
    }
    func testRejectsRollbackAgainstEitherTrustedBound() throws {
        for (floor, installed) in [(UInt64(4), UInt64(2)), (2, 4)] {
            XCTAssertThrowsError(try SignedExecutableValidation.validatedGeneration("3", committedFloor: floor, installedGeneration: installed)) {
                XCTAssertEqual($0 as? SignedExecutableValidationError, .rollback)
            }
        }
    }
    func testRejectsMissingNoncanonicalOrOverflowingGeneration() throws {
        let invalid: [Any?] = [nil, 1, true, "", "0", "01", "+1", " 1", "1.0", "-1", "١", "18446744073709551616"]
        for value in invalid {
            XCTAssertThrowsError(try SignedExecutableValidation.validatedGeneration(value, committedFloor: 1, installedGeneration: 0)) {
                XCTAssertEqual($0 as? SignedExecutableValidationError, .invalidGeneration)
            }
        }
        XCTAssertThrowsError(try SignedExecutableValidation.validatedGeneration("1", committedFloor: 0, installedGeneration: 0)) {
            XCTAssertEqual($0 as? SignedExecutableValidationError, .invalidPolicy)
        }
    }
    private final class Fixture {
        let root: String
        let executable: String
        init(runtime: Bool = true) throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw JournalLeaseError.system(errno) }
            defer { free(canonical) }
            root = String(cString: canonical) + "/" + UUID().uuidString
            executable = root + "/probe"
            try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            do {
                try Data("int main(void) { return 0; }".utf8).write(to: URL(fileURLWithPath: root + "/probe.c"))
                let plist: [String: String] = ["CFBundleIdentifier": "dev.sebastiano.remozio.macos.tests.validation", "RemozioSecurityGeneration": "4"]
                try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: URL(fileURLWithPath: root + "/Info.plist"))
                try Self.run("/usr/bin/xcrun", ["clang", "-arch", "arm64", "-Wl,-sectcreate,__TEXT,__info_plist," + root + "/Info.plist", root + "/probe.c", "-o", executable])
                var arguments = ["--force", "--sign", "-", "--identifier", "dev.sebastiano.remozio.macos.tests.validation"]
                if runtime { arguments += ["--options", "runtime"] }
                try Self.run("/usr/bin/codesign", arguments + [executable])
            } catch { try? FileManager.default.removeItem(atPath: root); throw error }
        }
        deinit { try? FileManager.default.removeItem(atPath: root) }
        func path() throws -> ProtectedExecutablePath {
            try ProtectedExecutablePath(anchor: root, relativePath: "probe", owner: getuid())
        }
        private static func run(_ tool: String, _ arguments: [String]) throws {
            let process = Process(); process.executableURL = URL(fileURLWithPath: tool); process.arguments = arguments
            process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            try process.run(); process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw JournalLeaseError.system(process.terminationStatus) }
        }
    }
    func testSignedFixtureBindsGenerationAndRejectsWrongIdentity() throws {
        let fixture = try Fixture(), path = try fixture.path()
        let evidence = try SignedExecutableValidation.validate(path, requirement: "identifier \"dev.sebastiano.remozio.macos.tests.validation\"",
            committedFloor: 3, installedGeneration: 4)
        XCTAssertEqual(evidence.generation, 4); XCTAssertEqual(evidence.codeDirectoryHash.count, 20)
        XCTAssertEqual(evidence.identifier, "dev.sebastiano.remozio.macos.tests.validation")
        XCTAssertThrowsError(try SignedExecutableValidation.validate(path, requirement: "identifier \"dev.remozio.wrong\"", committedFloor: 1, installedGeneration: 0))
        XCTAssertThrowsError(try path.validate())
    }
    func testAdHocFixtureCannotPassProductionPolicy() throws {
        let fixture = try Fixture(), path = try fixture.path()
        let policy = try XPCPeerPolicy(teamID: "ABCDEFGHIJ", componentIdentifier: "dev.sebastiano.remozio.macos.tests.validation",
            approvedCodeDirectoryHashes: [Data(repeating: 1, count: 20)], expectedUserID: 0)
        XCTAssertThrowsError(try SignedExecutableValidation.validate(path, policy: policy, committedFloor: 1, installedGeneration: 0))
        XCTAssertThrowsError(try path.validate())
    }
    func testSignedFixtureWithoutRuntimeIsRejected() throws {
        let fixture = try Fixture(runtime: false), path = try fixture.path()
        XCTAssertThrowsError(try SignedExecutableValidation.validate(path, requirement: "identifier \"dev.sebastiano.remozio.macos.tests.validation\"", committedFloor: 1, installedGeneration: 0)) {
            XCTAssertEqual($0 as? SignedExecutableValidationError, .unsafeRuntime)
        }
    }

    func testTamperedGenerationFailsSignatureCheckBeforeMetadataIsTrusted() throws {
        let fixture = try Fixture()
        var bytes = try Data(contentsOf: URL(fileURLWithPath: fixture.executable))
        let original = Data("<string>4</string>".utf8)
        let range = try XCTUnwrap(bytes.range(of: original))
        bytes.replaceSubrange(range, with: Data("<string>5</string>".utf8))
        try bytes.write(to: URL(fileURLWithPath: fixture.executable))
        let path = try fixture.path()
        XCTAssertThrowsError(try SignedExecutableValidation.validate(path, requirement: "identifier \"dev.sebastiano.remozio.macos.tests.validation\"", committedFloor: 1, installedGeneration: 0)) {
            guard case SignedExecutableValidationError.security = $0 else { return XCTFail("Expected signature failure, got \($0)") }
        }
        XCTAssertThrowsError(try path.validate())
    }
    func testValidSignatureDoesNotPermitRollback() throws {
        let fixture = try Fixture(), path = try fixture.path()
        XCTAssertThrowsError(try SignedExecutableValidation.validate(path, requirement: "identifier \"dev.sebastiano.remozio.macos.tests.validation\"", committedFloor: 5, installedGeneration: 4)) {
            XCTAssertEqual($0 as? SignedExecutableValidationError, .rollback)
        }
        XCTAssertThrowsError(try path.validate())
    }

}
