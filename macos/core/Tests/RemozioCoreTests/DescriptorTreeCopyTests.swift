import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class DescriptorTreeCopyTests: XCTestCase {
    private func fixture(_ body: (URL, URL, URL) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-copy-unit-" + UUID().uuidString)
        let source = root.appendingPathComponent("Source"), target = root.appendingPathComponent("Target")
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("content".utf8).write(to: source.appendingPathComponent("file"))
        try body(root, source, target)
    }
    func testCopyCreatesIndependentFilesAndPreservesRelativeLinks() throws {
        try fixture { _, source, target in
            try FileManager.default.createDirectory(at: source.appendingPathComponent("nested"), withIntermediateDirectories: true)
            try Data("nested".utf8).write(to: source.appendingPathComponent("nested/file"))
            try FileManager.default.createSymbolicLink(atPath: source.appendingPathComponent("link").path, withDestinationPath: "nested/file")
            let result = try DescriptorTreeCopy.copy(source: source, parent: target)
            let copy = target.appendingPathComponent("Fixture.app")
            XCTAssertEqual(result.files, 2); XCTAssertEqual(result.links, 1); XCTAssertEqual(result.bytes, 13)
            XCTAssertEqual(try Data(contentsOf: copy.appendingPathComponent("file")), Data("content".utf8))
            XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: copy.appendingPathComponent("link").path), "nested/file")
            try Data("changed".utf8).write(to: source.appendingPathComponent("file"))
            XCTAssertEqual(try Data(contentsOf: copy.appendingPathComponent("file")), Data("content".utf8))
        }
    }
    func testExistingDestinationIsNeverOverwritten() throws {
        try fixture { _, source, target in
            let existing = target.appendingPathComponent("Fixture.app")
            try FileManager.default.createDirectory(at: existing, withIntermediateDirectories: true)
            try Data("keep".utf8).write(to: existing.appendingPathComponent("sentinel"))
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target)) {
                XCTAssertEqual($0 as? ReleaseCopyError, .system(EEXIST))
            }
            XCTAssertEqual(try Data(contentsOf: existing.appendingPathComponent("sentinel")), Data("keep".utf8))
        }
    }
    func testByteEntryAndDepthLimitsRejectTheCopy() throws {
        try fixture { _, source, target in
            try Data([1]).write(to: source.appendingPathComponent("second"))
            try FileManager.default.createDirectory(at: source.appendingPathComponent("nested"), withIntermediateDirectories: true)
            for (name, limits) in [("bytes", try ReleaseCopyLimits(bytes: 1)), ("entries", try ReleaseCopyLimits(entries: 1)),
                                   ("depth", try ReleaseCopyLimits(depth: 0))] {
                XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: name, limits: limits)) {
                    XCTAssertEqual($0 as? ReleaseCopyError, .limit)
                }
                XCTAssertFalse(FileManager.default.fileExists(atPath: target.appendingPathComponent(name).path))
            }
        }
    }
    func testNamedSourceReplacementCannotBecomeACompletedCopy() throws {
        try fixture { _, source, target in
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                openedFile: { parent, name, _ in
                    XCTAssertEqual(unlinkat(parent, name, 0), 0)
                    let replacement = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
                    XCTAssertGreaterThanOrEqual(replacement, 0)
                    defer { close(replacement) }
                    _ = Data("content".utf8).withUnsafeBytes { write(replacement, $0.baseAddress!, $0.count) }
                })) { XCTAssertEqual($0 as? ReleaseCopyError, .changedSource) }
        }
    }
    func testHardlinksAndSpecialFilesAreRejected() throws {
        try fixture { _, source, target in
            XCTAssertEqual(link(source.appendingPathComponent("file").path, source.appendingPathComponent("hardlink").path), 0)
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "hardlink")) {
                XCTAssertEqual($0 as? ReleaseCopyError, .unsafeSource)
            }
            try FileManager.default.removeItem(at: source.appendingPathComponent("hardlink"))
            XCTAssertEqual(mkfifo(source.appendingPathComponent("fifo").path, 0o600), 0)
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "fifo")) {
                XCTAssertEqual($0 as? ReleaseCopyError, .unsafeSource)
            }
        }
    }
    func testAbsoluteLinksAndOverlappingDestinationAreRejected() throws {
        try fixture { _, source, target in
            try FileManager.default.createSymbolicLink(atPath: source.appendingPathComponent("absolute").path,
                withDestinationPath: source.appendingPathComponent("file").path)
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target)) {
                XCTAssertEqual($0 as? ReleaseCopyError, .unsafeSource)
            }
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: source)) {
                XCTAssertEqual($0 as? ReleaseCopyError, .invalidInput)
            }
        }
    }
    func testCancellationCannotReportACompletedCopy() throws {
        struct Cancelled: Error {}
        try fixture { _, source, target in
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, checkCancellation: { throw Cancelled() })) {
                XCTAssertTrue($0 is Cancelled)
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.appendingPathComponent("Fixture.app").path))
        }
    }
    func testUnsafeSourceModesAreNotCopied() throws {
        try fixture { _, source, target in
            XCTAssertEqual(chmod(source.appendingPathComponent("file").path, 0o4777), 0)
            _ = try DescriptorTreeCopy.copy(source: source, parent: target)
            var info = stat()
            XCTAssertEqual(lstat(target.appendingPathComponent("Fixture.app/file").path, &info), 0)
            XCTAssertEqual(info.st_mode & 0o7777, 0o755)
            XCTAssertEqual(info.st_nlink, 1)
        }
    }
    func testFailedReadRemovesOnlyCreatedTreeAndLeavesSibling() throws {
        struct Cancelled: Error {}
        try fixture { _, source, target in
            let sibling = target.appendingPathComponent("keep")
            try Data("keep".utf8).write(to: sibling)
            try FileManager.default.removeItem(at: source.appendingPathComponent("file"))
            try FileManager.default.createDirectory(at: source.appendingPathComponent("nested/nested"), withIntermediateDirectories: true)
            try Data("nested".utf8).write(to: source.appendingPathComponent("nested/nested/file"))
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                openedFile: { _, _, _ in throw Cancelled() })) { XCTAssertTrue($0 is Cancelled) }
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.appendingPathComponent("Fixture.app").path))
            XCTAssertEqual(try Data(contentsOf: sibling), Data("keep".utf8))
        }
    }
    func testCleanupRefusesAnUnrecordedFile() throws {
        struct Cancelled: Error {}
        try fixture { _, source, target in
            let copy = target.appendingPathComponent("Fixture.app")
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                openedFile: { _, _, _ in
                    try Data("keep".utf8).write(to: copy.appendingPathComponent("unrecorded"))
                    throw Cancelled()
                })) {
                    let failure = $0 as? ReleaseCopyCleanupFailure
                    XCTAssertTrue(failure?.original is Cancelled)
                    XCTAssertEqual(failure?.cleanup as? ReleaseCopyError, .system(ENOTEMPTY))
                }
            XCTAssertEqual(try Data(contentsOf: copy.appendingPathComponent("unrecorded")), Data("keep".utf8))
        }
    }
    func testCleanupRefusesAReplacementInode() throws {
        struct Cancelled: Error {}
        try fixture { _, source, target in
            let copy = target.appendingPathComponent("Fixture.app/file")
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                openedFile: { _, _, _ in
                    try FileManager.default.removeItem(at: copy)
                    try Data("replacement".utf8).write(to: copy)
                    throw Cancelled()
                })) {
                    let failure = $0 as? ReleaseCopyCleanupFailure
                    XCTAssertTrue(failure?.original is Cancelled)
                    XCTAssertEqual(failure?.cleanup as? ReleaseCopyError, .changedDestination)
                }
            XCTAssertEqual(try Data(contentsOf: copy), Data("replacement".utf8))
        }
    }
    func testCancellationAfterCreatingTheOutputRemovesPartialFiles() throws {
        struct Cancelled: Error {}
        try fixture { _, source, target in
            var checks = 0
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, checkCancellation: {
                checks += 1
                if checks == 4 { throw Cancelled() }
            })) { XCTAssertTrue($0 is Cancelled) }
            XCTAssertEqual(checks, 4)
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.appendingPathComponent("Fixture.app").path))
        }
    }
    func testCleanupDoesNotRemoveAReplacementOutputDirectory() throws {
        struct Cancelled: Error {}
        try fixture { _, source, target in
            let copy = target.appendingPathComponent("Fixture.app")
            let moved = target.appendingPathComponent("moved")
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                openedFile: { _, _, _ in
                    try FileManager.default.moveItem(at: copy, to: moved)
                    try FileManager.default.createDirectory(at: copy, withIntermediateDirectories: false)
                    try Data("replacement".utf8).write(to: copy.appendingPathComponent("keep"))
                    throw Cancelled()
                })) {
                    let failure = $0 as? ReleaseCopyCleanupFailure
                    XCTAssertTrue(failure?.original is Cancelled)
                    XCTAssertEqual(failure?.cleanup as? ReleaseCopyError, .changedDestination)
                }
            XCTAssertEqual(try Data(contentsOf: copy.appendingPathComponent("keep")), Data("replacement".utf8))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: moved.path), [])
        }
    }
    func testRelativeLinkEscapeThroughAnotherLinkIsRejected() throws {
        try fixture { root, source, target in
            try FileManager.default.createDirectory(at: source.appendingPathComponent("nested"), withIntermediateDirectories: false)
            try FileManager.default.createSymbolicLink(atPath: source.appendingPathComponent("nested/alias").path, withDestinationPath: "..")
            try FileManager.default.createSymbolicLink(atPath: source.appendingPathComponent("nested/escape").path, withDestinationPath: "alias/../outside")
            let outside = root.appendingPathComponent("outside")
            try Data("keep".utf8).write(to: outside)
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target)) {
                XCTAssertEqual($0 as? ReleaseCopyError, .unsafeSource)
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.appendingPathComponent("Fixture.app").path))
            XCTAssertEqual(try Data(contentsOf: outside), Data("keep".utf8))
        }
    }
    func testRelativeLinksCanReachAParentInsideTheCopy() throws {
        try fixture { _, source, target in
            try FileManager.default.createDirectory(at: source.appendingPathComponent("nested"), withIntermediateDirectories: false)
            try FileManager.default.createSymbolicLink(atPath: source.appendingPathComponent("nested/parent-file").path, withDestinationPath: "../file")
            let counts = try DescriptorTreeCopy.copy(source: source, parent: target)
            XCTAssertEqual(counts.links, 1)
            XCTAssertEqual(try Data(contentsOf: target.appendingPathComponent("Fixture.app/nested/parent-file")), Data("content".utf8))
        }
    }
    func testCyclicLinksCannotProduceACompletedCopy() throws {
        try fixture { _, source, target in
            try FileManager.default.createSymbolicLink(atPath: source.appendingPathComponent("a").path, withDestinationPath: "b")
            try FileManager.default.createSymbolicLink(atPath: source.appendingPathComponent("b").path, withDestinationPath: "a")
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target)) {
                XCTAssertEqual($0 as? ReleaseCopyError, .unsafeSource)
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.appendingPathComponent("Fixture.app").path))
        }
    }
    func testFailedFinalValidationRemovesOnlyTheCompletedCopy() throws {
        struct ValidationFailed: Error {}
        try fixture { _, source, target in
            let sibling = target.appendingPathComponent("keep")
            try Data("keep".utf8).write(to: sibling)
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                validateCopy: { counts in
                    XCTAssertEqual(counts.bytes, 7)
                    XCTAssertTrue(FileManager.default.fileExists(atPath: target.appendingPathComponent("Fixture.app/file").path))
                    throw ValidationFailed()
                }, openedFile: { _, _, _ in })) { XCTAssertTrue($0 is ValidationFailed) }
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.appendingPathComponent("Fixture.app").path))
            XCTAssertEqual(try Data(contentsOf: sibling), Data("keep".utf8))
        }
    }
    func testSuccessfulFinalValidationRunsBeforeReturningCounts() throws {
        try fixture { _, source, target in
            var validated = false
            let counts = try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                validateCopy: { _ in validated = true }, openedFile: { _, _, _ in })
            XCTAssertTrue(validated); XCTAssertEqual(counts.bytes, 7)
        }
    }
    func testOutputOpenFailureRemovesTheOwnedEmptyDirectory() throws {
        try fixture { _, source, target in
            let sibling = target.appendingPathComponent("keep")
            try Data("keep".utf8).write(to: sibling)
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                openOutput: { _, _, _ in errno = EMFILE; return -1 }, openedFile: { _, _, _ in })) {
                    XCTAssertEqual($0 as? ReleaseCopyError, .system(EMFILE))
                }
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.appendingPathComponent("Fixture.app").path))
            XCTAssertEqual(try Data(contentsOf: sibling), Data("keep".utf8))
        }
    }
    func testOutputInspectionFailureRemovesTheDirectoryAndClosesItsDescriptor() throws {
        try fixture { _, source, target in
            var descriptor: Int32 = -1
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                outputStatus: { fd in descriptor = fd; throw ReleaseCopyError.system(EIO) }, openedFile: { _, _, _ in })) {
                    XCTAssertEqual($0 as? ReleaseCopyError, .system(EIO))
                }
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.appendingPathComponent("Fixture.app").path))
            var info = stat(); XCTAssertEqual(fstat(descriptor, &info), -1); XCTAssertEqual(errno, EBADF)
        }
    }
    func testInitializationCleanupPreservesAReplacementDirectory() throws {
        try fixture { _, source, target in
            let copy = target.appendingPathComponent("Fixture.app"), moved = target.appendingPathComponent("moved")
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                openOutput: { _, _, _ in
                    do {
                        try FileManager.default.moveItem(at: copy, to: moved)
                        try FileManager.default.createDirectory(at: copy, withIntermediateDirectories: false)
                        try Data("keep".utf8).write(to: copy.appendingPathComponent("keep"))
                    } catch { XCTFail("Fixture replacement failed: \(error)") }
                    errno = EMFILE; return -1
                }, openedFile: { _, _, _ in })) {
                    let failure = $0 as? ReleaseCopyCleanupFailure
                    XCTAssertEqual(failure?.original as? ReleaseCopyError, .system(EMFILE))
                    XCTAssertEqual(failure?.cleanup as? ReleaseCopyError, .changedDestination)
                }
            XCTAssertEqual(try Data(contentsOf: copy.appendingPathComponent("keep")), Data("keep".utf8))
            XCTAssertTrue(FileManager.default.fileExists(atPath: moved.path))
        }
    }
    func testOpenedOutputMustMatchTheRecordedCreatedDirectory() throws {
        try fixture { _, source, target in
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                outputStatus: { fd in
                    var info = stat(); XCTAssertEqual(fstat(fd, &info), 0); info.st_ino += 1; return info
                }, openedFile: { _, _, _ in })) {
                    XCTAssertEqual($0 as? ReleaseCopyError, .changedDestination)
                }
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.appendingPathComponent("Fixture.app").path))
        }
    }
    func testNestedDirectoryOpenFailureCleansTheWholeOwnedCopy() throws {
        try fixture { _, source, target in
            try FileManager.default.createDirectory(at: source.appendingPathComponent("nested"), withIntermediateDirectories: false)
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                openOutput: { parent, name, flags in
                    if name == "nested" { errno = EMFILE; return -1 }
                    return openat(parent, name, flags)
                }, openedFile: { _, _, _ in })) {
                    XCTAssertEqual($0 as? ReleaseCopyError, .system(EMFILE))
                }
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.appendingPathComponent("Fixture.app").path))
        }
    }
    func testNestedDirectoryInspectionFailureCleansTheWholeOwnedCopy() throws {
        try fixture { _, source, target in
            try FileManager.default.createDirectory(at: source.appendingPathComponent("nested"), withIntermediateDirectories: false)
            var rootDescriptor: Int32?
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                outputStatus: { fd in
                    var info = stat(); XCTAssertEqual(fstat(fd, &info), 0)
                    if rootDescriptor == nil { rootDescriptor = fd }
                    else if info.st_mode & S_IFMT == S_IFDIR { throw ReleaseCopyError.system(EIO) }
                    return info
                }, openedFile: { _, _, _ in })) {
                    XCTAssertEqual($0 as? ReleaseCopyError, .system(EIO))
                }
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.appendingPathComponent("Fixture.app").path))
        }
    }
    func testNewFileInspectionFailureCleansTheWholeOwnedCopy() throws {
        try fixture { _, source, target in
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                outputStatus: { fd in
                    var info = stat(); XCTAssertEqual(fstat(fd, &info), 0)
                    if info.st_mode & S_IFMT == S_IFREG { throw ReleaseCopyError.system(EIO) }
                    return info
                }, openedFile: { _, _, _ in })) {
                    XCTAssertEqual($0 as? ReleaseCopyError, .system(EIO))
                }
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.appendingPathComponent("Fixture.app").path))
        }
    }
    func testNestedInitializationCleanupPreservesAReplacement() throws {
        try fixture { _, source, target in
            try FileManager.default.createDirectory(at: source.appendingPathComponent("nested"), withIntermediateDirectories: false)
            let nested = target.appendingPathComponent("Fixture.app/nested")
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                openOutput: { parent, name, flags in
                    if name != "nested" { return openat(parent, name, flags) }
                    do {
                        try FileManager.default.moveItem(at: nested, to: nested.deletingLastPathComponent().appendingPathComponent("moved"))
                        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: false)
                        try Data("keep".utf8).write(to: nested.appendingPathComponent("keep"))
                    } catch { XCTFail("Nested fixture replacement failed: \(error)") }
                    errno = EMFILE; return -1
                }, openedFile: { _, _, _ in })) {
                    let failure = $0 as? ReleaseCopyCleanupFailure
                    XCTAssertEqual(failure?.original as? ReleaseCopyError, .system(EMFILE))
                    XCTAssertEqual(failure?.cleanup as? ReleaseCopyError, .changedDestination)
                }
            XCTAssertEqual(try Data(contentsOf: nested.appendingPathComponent("keep")), Data("keep".utf8))
        }
    }
    func testNewFileNamedLookupFailureUsesTheRecordedDescriptorIdentityForCleanup() throws {
        try fixture { _, source, target in
            let sibling = target.appendingPathComponent("keep")
            try Data("keep".utf8).write(to: sibling)
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                outputNameStatus: { _, _ in throw ReleaseCopyError.system(EIO) }, openedFile: { _, _, _ in })) {
                    XCTAssertEqual($0 as? ReleaseCopyError, .system(EIO))
                }
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.appendingPathComponent("Fixture.app").path))
            XCTAssertEqual(try Data(contentsOf: sibling), Data("keep".utf8))
        }
    }
    func testNewFileNamedReplacementCannotBecomeTheRecordedCreation() throws {
        try fixture { _, source, target in
            let output = target.appendingPathComponent("Fixture.app/file")
            XCTAssertThrowsError(try DescriptorTreeCopy.copy(source: source, parent: target, name: "Fixture.app", limits: .init(),
                outputNameStatus: { parent, name in
                    try FileManager.default.removeItem(at: output)
                    try Data("keep".utf8).write(to: output)
                    var info = stat(); XCTAssertEqual(fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW), 0)
                    return info
                }, openedFile: { _, _, _ in })) {
                    let failure = $0 as? ReleaseCopyCleanupFailure
                    XCTAssertEqual(failure?.original as? ReleaseCopyError, .changedDestination)
                    XCTAssertEqual(failure?.cleanup as? ReleaseCopyError, .changedDestination)
                }
            XCTAssertEqual(try Data(contentsOf: output), Data("keep".utf8))
        }
    }
}
