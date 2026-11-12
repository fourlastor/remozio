import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Uses canonical values and ordinary owned files. This suite proves no native placement or completed-store authority.
final class MachineUpdateRetainedSetupPromotionFileTests: XCTestCase {
    private typealias Publication = RuntimeRetainedSetupCompletionPublication
    private typealias Files = MachineUpdateRetainedSetupPromotionFiles
    private typealias Verify = () throws -> Void
    private enum Fault: Error { case uncertainExchange, retention }

    private final class Fixture {
        let publication: Publication
        let root: URL
        private var runtime: ProtectedSetupDirectory
        private var services: ProtectedSetupDirectory
        private var clients: ProtectedSetupDirectory
        var exchanges: [UInt64: Int] = [:]
        var confirmations: [UInt64: Int] = [:]
        var readAttempts = 0

        init(_ publication: Publication) throws {
            self.publication = publication
            root = URL(fileURLWithPath: "/private/tmp/remozio-G7-files-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            runtime = try .init(anchor: root.path, relativePath: "Runtime", owner: getuid())
            services = try .init(anchor: root.path, relativePath: "Services", owner: getuid(), visibility: .sharedMetadata)
            clients = try .init(anchor: root.path, relativePath: "Clients", owner: getuid(), visibility: .sharedMetadata)
            for artifact in publication.artifacts {
                _ = try AdministrativeSetupPublication.publish(artifact.previous, file: artifact.file,
                    directory: directory(artifact), owner: getuid())
            }
        }
        deinit {
            runtime.close(); services.close(); clients.close()
            try? FileManager.default.removeItem(at: root)
        }
        func directory(_ artifact: Publication.Artifact) -> ProtectedSetupDirectory {
            switch artifact.location { case .runtime: runtime; case .services: services; case .clients: clients }
        }
        func path(_ artifact: Publication.Artifact) -> String { directory(artifact).path + "/" + artifact.file.name }
        func inode(_ artifact: Publication.Artifact) throws -> UInt64 {
            var info = stat()
            guard lstat(path(artifact), &info) == 0 else { throw JournalLeaseError.system(errno) }
            return info.st_ino
        }
        func reopen() throws {
            runtime.close(); services.close(); clients.close()
            runtime = try .init(anchor: root.path, relativePath: "Runtime", owner: getuid(), createIfMissing: false)
            services = try .init(anchor: root.path, relativePath: "Services", owner: getuid(), visibility: .sharedMetadata, createIfMissing: false)
            clients = try .init(anchor: root.path, relativePath: "Clients", owner: getuid(), visibility: .sharedMetadata, createIfMissing: false)
        }
        func operations(verify: @escaping Verify = {},
            didStage: @escaping (AdministrativeSetupPublication.Stage, Publication.Artifact) throws -> Void = { _, _ in }) -> Publication.Operations {
            .init(observation: .init(verify: verify, read: { artifact in
                self.readAttempts += 1
                return try Files.readInLease(self.publication, file: artifact.kind,
                    directory: self.directory(artifact), owner: getuid(), verify: verify)
            }), replace: { artifact in
                try Files.replaceInLease(self.publication, file: artifact.kind,
                    directory: self.directory(artifact), owner: getuid(), verify: verify, didStage: { stage in
                        if case .published = stage { self.exchanges[artifact.kind.rawValue, default: 0] += 1 }
                        try didStage(stage, artifact)
                    })
            }, retainSelected: { artifact in
                try Files.retainSelectedInLease(self.publication, file: artifact.kind,
                    directory: self.directory(artifact), owner: getuid(), verify: verify)
                self.confirmations[artifact.kind.rawValue, default: 0] += 1
            })
        }
    }

    private func fixture(_ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPromotionFilePublicationFixture { publication in
            try body(Fixture(publication))
        }
    }

    func testSourceResumeReadsBackAllSixArtifactsAndConfirmsDurability() throws {
        try fixture { f in
            let operations = f.operations()
            XCTAssertEqual(f.publication.artifacts.count, 6)
            XCTAssertGreaterThan(f.publication.artifacts.filter { $0.previous != $0.selected }.count, 0)
            XCTAssertEqual(try f.publication.progress(observation: operations.observation), .source)
            try f.publication.resume(operations: operations)
            XCTAssertEqual(try f.publication.progress(observation: operations.observation), .selected)
            for artifact in f.publication.artifacts {
                XCTAssertEqual(try operations.observation.read(artifact), artifact.selected)
                XCTAssertEqual(f.confirmations[artifact.kind.rawValue], 1)
                XCTAssertEqual(f.exchanges[artifact.kind.rawValue, default: 0], artifact.previous == artifact.selected ? 0 : 1)
            }
        }
    }

    func testAlreadySelectedFilesKeepTheirInodesWithoutAnotherExchange() throws {
        try fixture { f in
            try f.publication.resume(operations: f.operations())
            let before = try f.publication.artifacts.map { try f.inode($0) }
            f.exchanges = [:]; f.confirmations = [:]
            try f.publication.resume(operations: f.operations())
            XCTAssertTrue(f.exchanges.isEmpty)
            XCTAssertEqual(try f.publication.artifacts.map { try f.inode($0) }, before)
            XCTAssertEqual(Set(f.confirmations.keys), Set(Publication.File.allCases.map(\.rawValue)))
        }
    }

    func testMixedPublicationExchangesOnlyTheRemainingSourceFiles() throws {
        try fixture { f in
            let changed = f.publication.artifacts.filter { $0.previous != $0.selected }
            XCTAssertGreaterThan(changed.count, 1)
            let first = try XCTUnwrap(changed.first)
            try f.operations().replace(first)
            let inode = try f.inode(first)
            XCTAssertEqual(try f.publication.progress(observation: f.operations().observation), .mixed)
            f.exchanges = [:]
            try f.publication.resume(operations: f.operations())
            XCTAssertNil(f.exchanges[first.kind.rawValue])
            XCTAssertEqual(try f.inode(first), inode)
            XCTAssertEqual(try f.publication.progress(observation: f.operations().observation), .selected)
        }
    }

    func testLateUnknownBytesRefuseBeforeAnyExchange() throws {
        try fixture { f in
            let last = try XCTUnwrap(f.publication.artifacts.last)
            XCTAssertLessThan(last.previous.count, ProtectedServiceConfiguration.maximumBytes)
            try (last.previous + Data([0xA5])).write(to: URL(fileURLWithPath: f.path(last)))
            XCTAssertEqual(chmod(f.path(last), last.file.mode), 0)
            XCTAssertThrowsError(try f.publication.resume(operations: f.operations())) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            XCTAssertTrue(f.exchanges.isEmpty)
            XCTAssertTrue(f.confirmations.isEmpty)
        }
    }

    func testSymlinksAndHardlinksRefuseBeforeAnyExchange() throws {
        for symbolic in [true, false] {
            try fixture { f in
                let last = try XCTUnwrap(f.publication.artifacts.last)
                let alias = f.root.appendingPathComponent("Alias").path
                if symbolic {
                    try FileManager.default.moveItem(atPath: f.path(last), toPath: alias)
                    XCTAssertEqual(symlink(alias, f.path(last)), 0)
                } else { XCTAssertEqual(link(f.path(last), alias), 0) }
                XCTAssertThrowsError(try f.publication.resume(operations: f.operations()))
                XCTAssertTrue(f.exchanges.isEmpty)
            }
        }
    }

    func testModeAndDirectoryIdentitySubstitutionRefuseBeforeExchange() throws {
        for changeDirectory in [false, true] {
            try fixture { f in
                let last = try XCTUnwrap(f.publication.artifacts.last)
                if changeDirectory {
                    let path = f.directory(last).path
                    try FileManager.default.moveItem(atPath: path, toPath: path + ".old")
                    try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false, attributes: nil)
                    XCTAssertEqual(chmod(path, 0o755), 0)
                } else { XCTAssertEqual(chmod(f.path(last), 0o666), 0) }
                XCTAssertThrowsError(try f.publication.resume(operations: f.operations()))
                XCTAssertTrue(f.exchanges.isEmpty)
            }
        }
    }

    func testPostExchangeUncertaintyReopensAndConfirmsWithoutAnotherExchange() throws {
        try fixture { f in
            let first = try XCTUnwrap(f.publication.artifacts.first { $0.previous != $0.selected })
            XCTAssertThrowsError(try f.publication.resume(operations: f.operations(didStage: { stage, artifact in
                if case .published = stage, artifact.kind == first.kind { throw Fault.uncertainExchange }
            }))) { XCTAssertTrue($0 is Fault) }
            let inode = try f.inode(first)
            XCTAssertEqual(f.exchanges[first.kind.rawValue], 1)
            XCTAssertNil(f.confirmations[first.kind.rawValue])
            try f.reopen()
            try f.publication.resume(operations: f.operations())
            XCTAssertEqual(f.exchanges[first.kind.rawValue], 1)
            XCTAssertEqual(try f.inode(first), inode)
            XCTAssertEqual(f.confirmations[first.kind.rawValue], 1)
            XCTAssertEqual(try f.publication.progress(observation: f.operations().observation), .selected)
        }
    }

    func testReplacementWithoutExactReadBackCannotComplete() throws {
        try fixture { f in
            let actual = f.operations()
            let incomplete = Publication.Operations(observation: actual.observation, replace: { _ in }, retainSelected: actual.retainSelected)
            XCTAssertThrowsError(try f.publication.resume(operations: incomplete)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            XCTAssertTrue(f.exchanges.isEmpty)
            XCTAssertTrue(f.confirmations.isEmpty)
        }
    }

    func testRetentionFailureCannotReturnSuccessForSelectedBytes() throws {
        try fixture { f in
            try f.publication.resume(operations: f.operations())
            f.exchanges = [:]
            let actual = f.operations()
            let incomplete = Publication.Operations(observation: actual.observation, replace: actual.replace, retainSelected: { artifact in
                try actual.retainSelected(artifact)
                throw Fault.retention
            })
            XCTAssertThrowsError(try f.publication.resume(operations: incomplete)) { XCTAssertTrue($0 is Fault) }
            XCTAssertTrue(f.exchanges.isEmpty)
            XCTAssertEqual(try f.publication.progress(observation: actual.observation), .selected)
        }
    }

    func testEscapedFenceExpiresBeforeFileAccess() throws {
        try fixture { f in
            var escaped: Publication.Operations?
            try MachineUpdateRetainedSetupPromotionNativeSupport.withScopedVerification({}) { verify in
                escaped = f.operations(verify: verify)
            }
            XCTAssertThrowsError(try f.publication.resume(operations: XCTUnwrap(escaped))) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
            XCTAssertEqual(f.readAttempts, 0)
            XCTAssertTrue(f.exchanges.isEmpty)
        }
    }

    func testRealAdmissionIdentityLossStopsAfterTheFirstExchange() throws {
        try fixture { f in
            let admission = try UpdateAdmissionTestFixture()
            func directory() throws -> ReleaseDestinationLease {
                try .init(anchor: admission.activity.root.path, relativeDirectory: "Machine", owner: getuid())
            }
            let target = try directory()
            let owner = try UpdateOrdinaryAdmissionLease(activity: admission.activity.open(), admission: admission.open(),
                directory: directory(), expected: admission.identity)
            defer { owner.close(); target.close() }
            let first = try XCTUnwrap(f.publication.artifacts.first { $0.previous != $0.selected })
            XCTAssertThrowsError(try owner.withMachineAdmission { scope in
                try f.publication.resume(operations: f.operations(verify: {
                    try scope.validateMachineBoundary(directory: target, expected: admission.identity)
                }, didStage: { stage, artifact in
                    if case .published = stage, artifact.kind == first.kind {
                        XCTAssertEqual(rename(admission.path, admission.path + ".old"), 0)
                        let fd = Darwin.open(admission.path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
                        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                        Darwin.close(fd)
                    }
                }))
            }) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
            XCTAssertEqual(f.exchanges.values.reduce(0, +), 1)
            XCTAssertEqual(f.exchanges[first.kind.rawValue], 1)
        }
    }

    func testOwnedHelpersRejectRootBeforeCallingTheFence() throws {
        try fixture { f in
            let first = try XCTUnwrap(f.publication.artifacts.first)
            var verified = 0
            let verify = { verified += 1 }
            XCTAssertThrowsError(try Files.readInLease(f.publication, file: first.kind, directory: f.directory(first), owner: 0, verify: verify))
            XCTAssertThrowsError(try Files.replaceInLease(f.publication, file: first.kind, directory: f.directory(first), owner: 0, verify: verify))
            XCTAssertThrowsError(try Files.retainSelectedInLease(f.publication, file: first.kind, directory: f.directory(first), owner: 0, verify: verify))
            XCTAssertEqual(verified, 0)
            XCTAssertTrue(f.exchanges.isEmpty)
        }
    }
}
