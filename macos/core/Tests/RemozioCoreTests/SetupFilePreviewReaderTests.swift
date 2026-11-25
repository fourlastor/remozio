import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class SetupFilePreviewReaderTests: XCTestCase, @unchecked Sendable {
    private func directory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return directory
    }
    func testReadsSelectedRegularFileAndRejectsOtherSources() throws {
        let directory = try directory(); defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("synthetic.remozio-setup")
        try Data([1, 2, 3]).write(to: file)
        XCTAssertEqual(try SetupFilePreviewReader.read(file), Data([1, 2, 3]))
        let link = directory.appendingPathComponent("link.remozio-setup")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        XCTAssertEqual(try SetupFilePreviewReader.read(link), Data([1, 2, 3]))
        XCTAssertThrowsError(try SetupFilePreviewReader.read(directory))
        XCTAssertThrowsError(try SetupFilePreviewReader.read(directory.appendingPathComponent("missing")))
        XCTAssertThrowsError(try SetupFilePreviewReader.read(URL(string: "https://example.invalid/setup")!))
        let fifo = directory.appendingPathComponent("pipe")
        XCTAssertEqual(mkfifo(fifo.path, 0o600), 0)
        XCTAssertThrowsError(try SetupFilePreviewReader.read(fifo))
        try Data().write(to: file)
        XCTAssertThrowsError(try SetupFilePreviewReader.read(file))
        try Data(repeating: 0, count: SetupFileEncryption.maximumFileBytes + 1).write(to: file)
        XCTAssertThrowsError(try SetupFilePreviewReader.read(file))
    }
    func testBackgroundReaderReturnsOnlyAuthenticatedMetadata() async throws {
        let directory = try directory(); defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("synthetic.remozio-setup")
        let defaults = try SharedSetupDefaults(
            presence: PresenceConfiguration(observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 1000),
            wake: GatewayWakePolicy(maximumEntries: 8, maximumAttempts: 2, minimumEnrollmentIntervalMillis: 1000, maximumLifetimeMillis: 60_000, maximumTTLSeconds: 60),
            delivery: GatewayDeliveryPolicy(maximumFlights: 2, minimumSendIntervalMillis: 100))
        let encrypted = try PortableSetup(defaults: defaults).encryptedFile(password: "synthetic password")
        try encrypted.write(to: file)
        let reader = SetupFilePreviewReader()
        let result = try await reader.preview(file: file, password: "synthetic password")
        XCTAssertEqual(result.categories, [.sharedDefaults])
        XCTAssertNil(result.firebaseProject)
        do { _ = try await reader.preview(file: file, password: "wrong"); XCTFail("Accepted wrong password") }
        catch { XCTAssertTrue(error is SetupPreviewReadError) }
        XCTAssertEqual(try Data(contentsOf: file), encrypted)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [file.lastPathComponent])
    }
    func testCancellationIsCheckedBeforeReading() async {
        let reader = SetupFilePreviewReader()
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await reader.preview(file: URL(string: "https://example.invalid/not-read")!, password: "synthetic")
        }
        do { _ = try await task.value; XCTFail("Accepted cancelled operation") }
        catch { XCTAssertTrue(error is CancellationError) }
    }
}
