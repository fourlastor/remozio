import Darwin
import Foundation
import XCTest
@testable import RemozioUIAdapters

final class AXStructureFixtureFileTests: XCTestCase {
    private func directory() throws -> URL {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary user fixture") }
        let result = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("remozio-ax-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: result, withIntermediateDirectories: false,
            attributes: [.posixPermissions: NSNumber(value: 0o700)])
        addTeardownBlock { try FileManager.default.removeItem(at: result) }
        return result
    }
    private func request(_ url: URL) throws -> AXStructureProbeRequest {
        try .init(arguments: ["--pid", "42", "--output", url.path])
    }
    private func snapshot(processID: Int32 = 42, role: String? = nil) -> AXStructureSnapshot {
        let nodes: [AXStructureNode] = role.map { [.init(id: 0, depth: 0, role: .value($0), subrole: .unavailable(.noValue),
            attributeNames: .value([]), actionNames: .value([]), children: [], childrenRead: .value(0), visited: true)] } ?? []
        return .init(formatVersion: 1, observationID: UUID(), processID: processID, nodes: nodes,
            stop: .finished, operations: 0, retainedTextBytes: role?.utf8.count ?? 0)
    }
    func testArgumentsRequireAnExplicitPositivePIDAndAnAbsoluteCanonicalOutputPath() throws {
        let accepted = try AXStructureProbeRequest(arguments: ["--output", "/a folder/capture.json", "--pid", "42"])
        XCTAssertEqual(accepted.processID, 42); XCTAssertEqual(accepted.outputPath, "/a folder/capture.json")
        let invalid: [[String]] = [[], ["--pid", "42"], ["--help"],
            ["--pid", "0", "--output", "/a/b"], ["--pid", "-1", "--output", "/a/b"],
            ["--pid", "2147483648", "--output", "/a/b"], ["--pid", "+42", "--output", "/a/b"],
            ["--pid", "４２", "--output", "/a/b"], ["--pid", "42", "--pid", "43"],
            ["--unknown", "42", "--output", "/a/b"], ["--pid", "42", "--output", "relative"],
            ["--pid", "42", "--output", "/a//b"], ["--pid", "42", "--output", "/a/../b"],
            ["--pid", "42", "--output", "/a/./b"], ["--pid", "42", "--output", "/a/"],
            ["--pid", "42", "--output", "/"], ["--pid", "42", "--output", "/a/\0b"],
            ["--pid", "42", "--output", "/a/" + String(repeating: "x", count: 256)]]
        for arguments in invalid { XCTAssertThrowsError(try AXStructureProbeRequest(arguments: arguments)) }
    }
    func testPublishesExactDecodableJSONWithPrivateModeAndNoTemporaryRemainder() throws {
        let root = try directory(), path = root.appendingPathComponent("capture with spaces.json"), value = snapshot()
        try AXStructureFixtureFile.save(value, request: request(path))
        XCTAssertEqual(try JSONDecoder().decode(AXStructureSnapshot.self, from: Data(contentsOf: path)), value)
        var info = stat(); XCTAssertEqual(lstat(path.path, &info), 0)
        XCTAssertEqual(info.st_mode & 0o777, 0o600); XCTAssertEqual(info.st_nlink, 1)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), [path.lastPathComponent])
    }
    func testExistingFileIsPreservedAndPrivateStagingIsRemoved() throws {
        let root = try directory(), path = root.appendingPathComponent("existing.json"), original = Data("original fixture".utf8)
        try original.write(to: path)
        XCTAssertThrowsError(try AXStructureFixtureFile.save(snapshot(), request: request(path))) {
            XCTAssertEqual($0 as? AXStructureProbeError, .outputExists)
        }
        XCTAssertEqual(try Data(contentsOf: path), original)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), [path.lastPathComponent])
    }
    func testDestinationSymlinkCannotReplaceOrModifyItsTarget() throws {
        let root = try directory(), target = root.appendingPathComponent("target"), link = root.appendingPathComponent("capture.json")
        let original = Data("preserve this".utf8); try original.write(to: target)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        XCTAssertThrowsError(try AXStructureFixtureFile.save(snapshot(), request: request(link))) {
            XCTAssertEqual($0 as? AXStructureProbeError, .outputExists)
        }
        XCTAssertEqual(try Data(contentsOf: target), original)
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: link.path), target.path)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path).sorted(), ["capture.json", "target"])
    }
    func testResolvedParentIsPinnedAndSharedWritableOutputDirectoriesAreRefused() throws {
        let root = try directory(), real = root.appendingPathComponent("real", isDirectory: true), alias = root.appendingPathComponent("alias")
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: false)
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: real)
        let value = snapshot()
        try AXStructureFixtureFile.save(value, request: request(alias.appendingPathComponent("capture.json")))
        XCTAssertEqual(try JSONDecoder().decode(AXStructureSnapshot.self,
            from: Data(contentsOf: real.appendingPathComponent("capture.json"))), value)
        XCTAssertEqual(chmod(real.path, 0o777), 0)
        defer { _ = chmod(real.path, 0o700) }
        XCTAssertThrowsError(try AXStructureFixtureFile.save(snapshot(), request: request(real.appendingPathComponent("refused.json")))) {
            XCTAssertEqual($0 as? AXStructureProbeError, .unsafeDirectory)
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: real.path), ["capture.json"])
    }
    func testWrongProcessAndOversizedArtifactsCreateNoFile() throws {
        let root = try directory(), path = root.appendingPathComponent("capture.json")
        XCTAssertThrowsError(try AXStructureFixtureFile.save(snapshot(processID: 43), request: request(path))) {
            XCTAssertEqual($0 as? AXStructureProbeError, .invalidArguments)
        }
        let large = snapshot(role: String(repeating: "x", count: AXStructureFixtureFile.maximumEncodedBytes))
        XCTAssertThrowsError(try AXStructureFixtureFile.save(large, request: request(path))) {
            XCTAssertEqual($0 as? AXStructureProbeError, .encodingFailed)
        }
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
    }
    func testMissingParentIsNotCreatedByTheProbe() throws {
        let root = try directory(), path = root.appendingPathComponent("missing/capture.json")
        XCTAssertThrowsError(try AXStructureFixtureFile.save(snapshot(), request: request(path))) {
            XCTAssertEqual($0 as? AXStructureProbeError, .unsafeDirectory)
        }
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
    }
    func testCommandHelpAndInvalidArgumentsNeverCaptureAndDoNotEchoInput() throws {
        let executable = Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("remozio-ax-structure")
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: executable.path))
        for args in [["--help"], ["--pid", "private-sentinel", "--output", "/not-created.json"]] {
            let process = Process(), output = Pipe(), error = Pipe()
            process.executableURL = executable; process.arguments = args
            process.standardInput = FileHandle.nullDevice; process.standardOutput = output; process.standardError = error
            try process.run(); process.waitUntilExit()
            let stdout = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            let stderr = String(decoding: error.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            XCTAssertEqual(process.terminationStatus, args == ["--help"] ? 0 : 1)
            XCTAssertFalse((stdout + stderr).contains("private-sentinel"))
            if args != ["--help"] { XCTAssertTrue(stdout.isEmpty); XCTAssertTrue(stderr.contains("invalidArguments")) }
        }
    }
}
