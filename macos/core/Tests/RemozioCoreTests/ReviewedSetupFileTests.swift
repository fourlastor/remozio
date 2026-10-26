import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class ReviewedSetupFileTests: XCTestCase, @unchecked Sendable {
    func testEncryptedReviewBuildsTheExactProposalWithoutReadingTheFileAgain() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner()
        defer { try? owner.close() }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("synthetic.remozio-setup"), proposal = try fixture.f.proposal()
        try proposal.encryptedFile(password: "synthetic export password").write(to: file)
        let reviewed = try await SetupFilePreviewReader().review(file: file, password: "synthetic export password")
        defer { reviewed.close() }
        XCTAssertEqual(reviewed.preview.cloudflareAccount, proposal.preview.cloudflareAccount)
        try FileManager.default.removeItem(at: file)
        let expected = try fixture.progress(owner)
        let request = try reviewed.operation(action: .retain, expected: expected)
        XCTAssertEqual(try request.proposal.canonicalBytes(), try proposal.canonicalBytes())
        XCTAssertNotNil(try request.bytes.range(of: Data("synthetic-provider-token-only".utf8)))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
    }

    func testCloseRevokesAllAliasesWithoutRevokingAnAlreadyBuiltRequest() throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner()
        defer { try? owner.close() }
        let reviewed = ReviewedSetupFile(proposal: try fixture.f.proposal()), alias = reviewed
        let expected = try fixture.progress(owner), request = try reviewed.operation(action: .retain, expected: expected)
        alias.close(); reviewed.close()
        XCTAssertThrowsError(try reviewed.operation(action: .retain, expected: expected)) {
            XCTAssertEqual($0 as? AdministrativeSetupChannelError, .closed)
        }
        XCTAssertThrowsError(try alias.operation(action: .prepareRelayPlan, expected: expected))
        XCTAssertEqual(try SetupPortableImportOperation.decode(request.bytes).bytes, try request.bytes)
        XCTAssertNotNil(reviewed.preview.cloudflareAccount)
    }

    func testProgressBindingAndExplicitCustodySurviveTheReviewBoundary() throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner()
        defer { try? owner.close() }
        let proposal = try fixture.f.proposal(), expected = try fixture.progress(owner)
        let reviewed = ReviewedSetupFile(proposal: proposal)
        defer { reviewed.close() }
        XCTAssertFalse(try reviewed.operation(action: .prepareRunCredential, expected: expected).fileCustodyAccepted)
        XCTAssertTrue(try reviewed.operation(action: .prepareRunCredential, expected: expected, fileCustodyAccepted: true).fileCustodyAccepted)
        XCTAssertThrowsError(try reviewed.operation(action: .retain, expected: expected, fileCustodyAccepted: true))
        let different = ReviewedSetupFile(proposal: PortableSetup(defaults: proposal.defaults))
        defer { different.close() }
        XCTAssertThrowsError(try different.operation(action: .retain, expected: expected))
    }

    func testDebugInspectionDoesNotExposeTheRetainedProposal() throws {
        let fixture = try RelayProvisioningFixture(), reviewed = ReviewedSetupFile(proposal: try fixture.f.proposal())
        defer { reviewed.close() }
        XCTAssertEqual(String(describing: reviewed), "ReviewedSetupFile(redacted)")
        XCTAssertEqual(String(reflecting: reviewed), "ReviewedSetupFile(redacted)")
        var inspected = ""; dump(reviewed, to: &inspected)
        XCTAssertLessThan(inspected.count, 100)
        XCTAssertFalse(inspected.contains("synthetic-provider-token-only"))
        XCTAssertEqual(Mirror(reflecting: reviewed).children.count, 0)
    }

    func testCancelledReviewDoesNotReadAnUntrustedSource() async {
        let reader = SetupFilePreviewReader()
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await reader.review(file: URL(string: "https://example.invalid/not-read")!, password: "synthetic")
        }
        do { _ = try await task.value; XCTFail("Accepted cancelled review") }
        catch { XCTAssertTrue(error is CancellationError) }
    }
}
