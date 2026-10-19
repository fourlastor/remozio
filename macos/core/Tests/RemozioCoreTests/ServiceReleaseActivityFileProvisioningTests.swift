import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class ServiceReleaseActivityFileProvisioningTests: XCTestCase {
    private typealias P = ServiceReleaseActivityFileProvisioning
    private struct Interrupted: Error {}
    private func fixture(_ body: (URL, ProtectedSetupDirectory) throws -> Void) throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owned service activity fixture") }
        let root = URL(fileURLWithPath: "/private/tmp/remozio-service-activity-files-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { XCTAssertNoThrow(try FileManager.default.removeItem(at: root)) }
        guard chmod(root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
        let parent = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Service", owner: getuid(), visibility: .sharedMetadata)
        defer { parent.close() }; try body(root, parent)
    }
    private func prepare(_ parent: ProtectedSetupDirectory, mode: P.Mode = .createIfAbsent,
                         expected: [ServiceAccountRole: PreparationFileIdentity]? = nil,
                         verify: @escaping () throws -> Void = {}, stage: (P.Stage) throws -> Void = { _ in }) throws -> P.Result {
        try P.prepare(parent: parent, owner: getuid(), groups: [.transport: getgid(), .gateway: getgid()], mode: mode,
            expected: expected, verifyCurrent: verify, didStage: stage)
    }
    private func path(_ parent: ProtectedSetupDirectory, _ role: ServiceAccountRole) -> String {
        parent.path + "/" + ServiceReleaseActivityBarrier.fileName(role)
    }
    private func identity(_ path: String) throws -> PreparationFileIdentity {
        var value = stat(); guard lstat(path, &value) == 0 else { throw JournalLeaseError.system(errno) }
        return .init(device: UInt32(bitPattern: value.st_dev), inode: value.st_ino)
    }
    func testCreatesBothReadOnlyGroupFilesAndRetainsTheirExactIdentities() throws {
        try fixture { _, parent in
            let first = try prepare(parent)
            XCTAssertEqual(first.createdRoles, Set(ServiceAccountPlan.roles)); XCTAssertEqual(first.identities.count, 2)
            for role in ServiceAccountPlan.roles {
                let file = path(parent, role); var value = stat(); XCTAssertEqual(lstat(file, &value), 0)
                XCTAssertEqual(value.st_uid, getuid()); XCTAssertEqual(value.st_gid, getgid())
                XCTAssertEqual(value.st_mode & 0o7777, 0o440); XCTAssertEqual(value.st_size, 0); XCTAssertEqual(value.st_nlink, 1)
                XCTAssertEqual(first.identities[role], try identity(file))
            }
            let retained = try prepare(parent, mode: .requireExisting, expected: first.identities)
            XCTAssertTrue(retained.createdRoles.isEmpty); XCTAssertEqual(retained.identities, first.identities)
            XCTAssertEqual(try prepare(parent).identities, first.identities)
        }
    }
    func testCompletedRetentionCanValidateKnownFilesWhileARealReaderOwnsTheScope() throws {
        try fixture { root, parent in
            let first = try prepare(parent)
            let reader = try ServiceReleaseActivityBarrier(directory: ReleaseDestinationLease(anchor: root.path, relativeDirectory: "Service", owner: getuid()),
                role: .transport, owner: getuid(), group: getgid(), reader: getuid(), expected: XCTUnwrap(first.identities[.transport]), exclusiveAllowed: false)
            let token = try reader.acquireShared(); defer { token.close() }
            XCTAssertThrowsError(try prepare(parent)) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            let retained = try prepare(parent, mode: .requireExisting, expected: first.identities)
            XCTAssertEqual(retained.identities, first.identities); XCTAssertTrue(retained.createdRoles.isEmpty); try token.validate()
        }
    }
    func testEveryPublishedReplyLossRecoversTheSamePublishedFile() throws {
        for role in ServiceAccountPlan.roles {
            try fixture { _, parent in
                XCTAssertThrowsError(try prepare(parent, stage: {
                    if case .published(let current) = $0, current == role { throw Interrupted() }
                })) { XCTAssertTrue($0 is Interrupted) }
                let before = try identity(path(parent, role)), resumed = try prepare(parent)
                XCTAssertEqual(resumed.identities[role], before)
                XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: parent.path)),
                    Set(ServiceAccountPlan.roles.map(ServiceReleaseActivityBarrier.fileName)))
            }
        }
    }
    func testUnpublishedStagingFailureRemovesOnlyItsOwnTemporaryFile() throws {
        try fixture { _, parent in
            XCTAssertThrowsError(try prepare(parent, stage: { if case .staged = $0 { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: parent.path).isEmpty)
            XCTAssertEqual(try prepare(parent).createdRoles.count, 2)
        }
    }
    func testKnownMissingAndReplacedFilesCannotBeRecreatedOrAdopted() throws {
        for role in ServiceAccountPlan.roles {
            for replacement in [false, true] {
                try fixture { _, parent in
                    let first = try prepare(parent), file = path(parent, role)
                    XCTAssertEqual(rename(file, file + ".original"), 0)
                    if replacement {
                        let fd = open(file, O_RDONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o440)
                        XCTAssertGreaterThanOrEqual(fd, 0); XCTAssertEqual(fchown(fd, getuid(), getgid()), 0); XCTAssertEqual(fchmod(fd, 0o440), 0); _ = close(fd)
                    }
                    XCTAssertThrowsError(try prepare(parent, expected: first.identities))
                    XCTAssertThrowsError(try prepare(parent, mode: .requireExisting, expected: first.identities))
                    XCTAssertTrue(FileManager.default.fileExists(atPath: file + ".original"))
                    XCTAssertEqual(FileManager.default.fileExists(atPath: file), replacement)
                }
            }
        }
    }
    func testUnsafeExistingFilesAreRejectedWithoutChangingTheirContentsOrMode() throws {
        for mutation in 0..<4 {
            try fixture { _, parent in
                let initial = try prepare(parent), file = path(parent, .transport)
                if mutation == 0 { XCTAssertEqual(chmod(file, 0o444), 0) }
                if mutation == 1 { XCTAssertEqual(link(file, file + ".alias"), 0) }
                if mutation == 2 { XCTAssertEqual(unlink(file), 0); XCTAssertEqual(symlink("/dev/null", file), 0) }
                if mutation == 3 {
                    XCTAssertEqual(chmod(file, 0o640), 0); try Data([1]).write(to: URL(fileURLWithPath: file)); XCTAssertEqual(chmod(file, 0o440), 0)
                }
                XCTAssertThrowsError(try prepare(parent, expected: initial.identities))
                var value = stat(); XCTAssertEqual(lstat(file, &value), 0)
                if mutation == 0 { XCTAssertEqual(value.st_mode & 0o7777, 0o444) }
                if mutation == 1 { XCTAssertEqual(value.st_nlink, 2) }
                if mutation == 2 { XCTAssertEqual(value.st_mode & S_IFMT, S_IFLNK) }
                if mutation == 3 { XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file)), Data([1])) }
            }
        }
    }
    func testScopeLossAfterPublicationPreservesItsFileAndCanResumeWithoutReplacingIt() throws {
        try fixture { _, parent in
            var valid = true
            XCTAssertThrowsError(try prepare(parent, verify: { if !valid { throw Interrupted() } }, stage: {
                if case .published(.transport) = $0 { valid = false }
            })) { XCTAssertTrue($0 is Interrupted) }
            let before = try identity(path(parent, .transport)); valid = true
            let resumed = try prepare(parent); XCTAssertEqual(resumed.identities[.transport], before)
        }
        try fixture { _, parent in
            XCTAssertThrowsError(try prepare(parent, verify: { throw Interrupted() }))
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: parent.path).isEmpty)
        }
    }
    func testInvalidExpectedSelectionCannotWriteAndNativeEntryRefusesAnOrdinaryCaller() throws {
        try fixture { _, parent in
            XCTAssertThrowsError(try prepare(parent, expected: [:]))
            XCTAssertThrowsError(try prepare(parent, mode: .requireExisting))
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: parent.path).isEmpty)
        }
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary owner Root refusal") }
        let f = try GatewaySettingsConsumerControlFixture()
        XCTAssertThrowsError(try P.prepare(account: f.ready.fixture.runtime.account, services: f.plan.pair.authority.material.runtime.services,
            mode: .createIfAbsent, expected: nil, verifyCurrent: { XCTFail("Root guard must precede scope access") })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
    func testAnEarlierRoleCannotBeReplacedWhileTheSecondRoleIsPrepared() throws {
        try fixture { _, parent in
            let first = path(parent, .transport)
            XCTAssertThrowsError(try prepare(parent, stage: {
                if case .staged(.gateway) = $0 {
                    XCTAssertEqual(rename(first, first + ".original"), 0)
                    let replacement = open(first, O_RDONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o440)
                    XCTAssertGreaterThanOrEqual(replacement, 0); XCTAssertEqual(fchown(replacement, getuid(), getgid()), 0); XCTAssertEqual(fchmod(replacement, 0o440), 0)
                    var observed = stat(); XCTAssertEqual(fstat(replacement, &observed), 0)
                    XCTAssertEqual(observed.st_gid, getgid(), "The fixture must match the provisioned service group")
                    _ = close(replacement)
                }
            })) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
            XCTAssertTrue(FileManager.default.fileExists(atPath: first + ".original"))
            XCTAssertTrue(FileManager.default.fileExists(atPath: first))
        }
    }
    func testAReplacedStagingNameCannotCauseCleanupToDeleteTheReplacement() throws {
        try fixture { _, parent in
            var replaced: String?
            XCTAssertThrowsError(try prepare(parent, stage: {
                if case .staged(.transport) = $0 {
                    let name = try XCTUnwrap(FileManager.default.contentsOfDirectory(atPath: parent.path).first {
                        $0.hasPrefix(".remozio-service-activity-")
                    })
                    let file = parent.path + "/" + name; replaced = file
                    XCTAssertEqual(rename(file, file + ".original"), 0)
                    let replacement = open(file, O_RDONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o440)
                    XCTAssertGreaterThanOrEqual(replacement, 0); XCTAssertEqual(fchown(replacement, getuid(), getgid()), 0); XCTAssertEqual(fchmod(replacement, 0o440), 0); _ = close(replacement)
                }
            })) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
            let file = try XCTUnwrap(replaced)
            XCTAssertTrue(FileManager.default.fileExists(atPath: file))
            XCTAssertTrue(FileManager.default.fileExists(atPath: file + ".original"))
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(parent, .transport)))
        }
    }

}
