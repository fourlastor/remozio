import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewayRuntimeActivationFilesTests: XCTestCase {
    private typealias Files = GatewayRuntimeActivationFiles
    private struct Interrupted: Error {}
    private final class Fixture {
        let f: GatewayJournalSetupExchangeTests.Fixture
        let plan: GatewayRuntimeActivationPlan
        let shared: ProtectedSetupDirectory
        let jobs: ProtectedSetupDirectory
        init() throws {
            f = try .init(); try f.retainCompletion(.decode(f.initialize()))
            plan = try .init(journal: f.state(), foreground: f.runtime.plan, inventory: XCTUnwrap(f.runtime.machine.inventory()))
            try f.runtime.machine.retainGatewayRuntimeActivation(plan)
            shared = try .init(anchor: f.root.path, relativePath: "Runtime", owner: getuid(), visibility: .sharedMetadata)
            jobs = try .init(anchor: f.root.path, relativePath: "Jobs", owner: getuid(), visibility: .sharedMetadata)
        }
        deinit { shared.close(); jobs.close() }
        func entries() -> [(Files.Artifact, AdministrativeSetupPublication.File, ProtectedSetupDirectory)] {
            [(.configuration, .gatewayConfiguration, shared),
             (.job, .accountJob(accountID: plan.accountID, role: .notificationGateway), jobs),
             (.authority, .authorityGatewayRuntime, shared), (.transport, .transportGatewayRuntime, shared), (.commit, .gatewayRuntimeCommit, shared)]
        }
        func path(_ artifact: Files.Artifact) -> String {
            let entry = entries().first { $0.0 == artifact }!; return entry.2.path + "/" + entry.1.name
        }
        func publish(_ mode: Files.Mode = .publishPending, verify: () throws -> Void = {},
                     stage: (Files.Artifact) throws -> Void = { _ in }) throws -> Files.Result {
            try Files.publish(plan, journal: f.state(), foreground: f.runtime.plan,
                inventory: XCTUnwrap(f.runtime.machine.inventory()), shared: shared, jobs: jobs, owner: getuid(),
                mode: mode, verifyCurrent: {
                    try verify()
                    let current = try self.f.runtime.machine.gatewayRuntimeActivation(accountID: self.plan.accountID)
                    guard try current.plan?.encoded == self.plan.encoded else { throw GatewayPreparationError.changedScope }
                }, didPublish: stage)
        }
    }
    func testPublicationWritesTheExactGatewayJobAndBothLoadableRolesWithoutEnrollingIt() throws {
        let f = try Fixture(), inventory = try f.f.runtime.machine.inventory(), foreground = try f.f.runtime.plan.encoded
        let result = try f.publish()
        XCTAssertEqual(result.files, Dictionary(uniqueKeysWithValues: Files.Artifact.allCases.map { ($0, .created) }))
        let configuration = try GatewayServiceConfiguration.decode(Data(contentsOf: URL(fileURLWithPath: f.path(.configuration))))
        XCTAssertEqual(configuration.canonicalBytes, f.f.intent.configuration.canonicalBytes)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.path(.job))), try f.plan.gatewayJob.bytes)
        for target: GatewayRuntimeExtension.Target in [.authority, .transport] {
            let loaded = try GatewayRuntimeLoader.load(target: target, read: { file in
                try ProtectedServiceConfiguration.read(anchor: f.shared.path, relativePath: file.name, owner: getuid(),
                    privateFile: file.name == AdministrativeSetupPublication.File.authorityGatewayRuntime.name)
            }, verifyCurrent: {}, validate: { value in
                if target == .authority { try value.validate(authority: f.f.runtime.plan.host) }
                else { try value.validate(transport: f.f.runtime.plan.transport) }
            })
            XCTAssertEqual(loaded?.commit.pairDigest, try f.plan.extensions.digest)
        }
        XCTAssertEqual(try f.f.runtime.machine.inventory(), inventory)
        XCTAssertEqual(try f.f.runtime.machine.runtimeActivation(accountID: f.plan.accountID).plan?.encoded, foreground)
        XCTAssertFalse(try f.f.runtime.machine.gatewayRuntimeActivation(accountID: f.plan.accountID).filesPublished)
        for (_, file, directory) in f.entries() {
            var info = stat(); XCTAssertEqual(lstat(directory.path + "/" + file.name, &info), 0)
            XCTAssertEqual(info.st_uid, getuid()); XCTAssertEqual(info.st_mode & 0o7777, file.mode)
        }
    }
    func testEachInterruptedPublicationResumesWithTheSameExistingInodes() throws {
        for interrupted in Files.Artifact.allCases {
            let f = try Fixture()
            XCTAssertThrowsError(try f.publish(stage: { if $0 == interrupted { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
            var inodes: [String: ino_t] = [:]
            for (_, file, directory) in f.entries() {
                let path = directory.path + "/" + file.name; var info = stat()
                if lstat(path, &info) == 0 { inodes[path] = info.st_ino }
            }
            _ = try f.publish(); _ = try f.publish(.validateRetained)
            for (path, inode) in inodes { var info = stat(); XCTAssertEqual(lstat(path, &info), 0); XCTAssertEqual(info.st_ino, inode) }
        }
    }
    func testAConflictInAnySiblingRefusesBeforeCreatingAnotherFile() throws {
        for artifact in Files.Artifact.allCases {
            for link in [false, true] {
                let f = try Fixture(), path = f.path(artifact)
                if link { try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: "/dev/null") }
                else {
                    try Data("conflict".utf8).write(to: URL(fileURLWithPath: path))
                    let file = f.entries().first { $0.0 == artifact }!.1; XCTAssertEqual(chmod(path, file.mode), 0)
                }
                XCTAssertThrowsError(try f.publish())
                let names = try FileManager.default.contentsOfDirectory(atPath: f.shared.path) + FileManager.default.contentsOfDirectory(atPath: f.jobs.path)
                XCTAssertEqual(names.count, 1)
            }
        }
    }
    func testCommittedPublicationCannotRecreateAnyMissingSibling() throws {
        for artifact in Files.Artifact.allCases where artifact != .commit {
            let f = try Fixture(); _ = try f.publish(); let path = f.path(artifact)
            try FileManager.default.removeItem(atPath: path)
            XCTAssertThrowsError(try f.publish()); XCTAssertThrowsError(try f.publish(.validateRetained))
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        }
    }
    func testReadOnlyValidationAndFailedScopeChecksCreateNothing() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.publish(.validateRetained))
        XCTAssertThrowsError(try f.publish(verify: { throw Interrupted() })) { XCTAssertTrue($0 is Interrupted) }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.shared.path), [])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.jobs.path), [])
    }
    func testJobMutationDuringRolePublicationPreventsTheCommitMarker() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.publish(stage: { artifact in
            if artifact == .transport {
                let file = try FileHandle(forWritingTo: URL(fileURLWithPath: f.path(.job))); defer { try? file.close() }
                try file.truncate(atOffset: 0); try file.write(contentsOf: Data("changed".utf8))
            }
        }))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.path(.commit)))
        XCTAssertThrowsError(try f.publish())
    }
}
