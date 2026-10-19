import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewayRuntimeSettingsFileTests: XCTestCase {
    private struct Interrupted: Error {}
    private func fixture(_ body: (GatewayJournalSetupExchangeTests.Fixture, GatewayRuntimeSettingsPublicationPlan, ProtectedSetupDirectory) throws -> Void) throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture(); try f.retainCompletion(.decode(f.initialize()))
        let inventory = try XCTUnwrap(f.runtime.machine.inventory())
        let activation = try GatewayRuntimeActivationPlan(journal: f.state(), foreground: f.runtime.plan, inventory: inventory)
        let selection = try GatewayRuntimeSettingsSelection(service: f.intent.configuration.settings,
            activation: .init(wakePollMilliseconds: 2000, wakeTimeoutMilliseconds: 6000))
        let revision = try GatewayRuntimeSettingsRevision(id: Data(repeating: 3, count: 16), selection: selection,
            activation: activation, journal: f.state(), foreground: f.runtime.plan, inventory: inventory)
        let plan = try GatewayRuntimeSettingsPublicationPlan(revision: revision, previous: nil, activation: activation,
            journal: f.state(), foreground: f.runtime.plan, inventory: inventory)
        let directory = try ProtectedSetupDirectory(anchor: f.root.path, relativePath: "Settings", owner: getuid(), visibility: .sharedMetadata)
        defer { directory.close() }
        for artifact in plan.artifacts {
            if let previous = artifact.previous {
                _ = try AdministrativeSetupPublication.publish(previous, file: artifact.file, directory: directory, owner: getuid())
            }
        }
        try body(f, plan, directory)
    }
    private func publish(_ plan: GatewayRuntimeSettingsPublicationPlan, _ directory: ProtectedSetupDirectory,
                         quiesced: () throws -> Void = {}, stage: (AdministrativeSetupPublication.File) throws -> Void = { _ in }) throws -> GatewayRuntimeSettingsPublication.Result {
        try GatewayRuntimeSettingsPublication.publish(plan, directory: directory, owner: getuid(), verifyCurrent: {}, requireQuiesced: quiesced, didPublish: stage)
    }
    private func path(_ directory: ProtectedSetupDirectory, _ file: AdministrativeSetupPublication.File) -> URL {
        URL(fileURLWithPath: directory.path).appendingPathComponent(file.name)
    }
    private func contents(_ directory: ProtectedSetupDirectory) throws -> [String: Data] {
        try Dictionary(uniqueKeysWithValues: FileManager.default.contentsOfDirectory(atPath: directory.path).map {
            ($0, try Data(contentsOf: URL(fileURLWithPath: directory.path).appendingPathComponent($0)))
        })
    }
    func testAtomicPublicationPreservesPermissionsAndRetainsAlreadySelectedFiles() throws {
        try fixture { f, plan, directory in
            let before = try f.state(), foreground = try f.runtime.plan.encoded
            let result = try publish(plan, directory)
            XCTAssertEqual(result.files.count, 5)
            XCTAssertEqual(result.files["authority-gateway-runtime.cbor"], .retained)
            XCTAssertEqual(result.files["gateway-settings-revision.cbor"], .created)
            XCTAssertEqual(result.files["gateway-runtime-commit.cbor"], .replaced)
            var inodes: [String: ino_t] = [:]
            for artifact in plan.artifacts {
                let url = path(directory, artifact.file); var info = stat(); XCTAssertEqual(lstat(url.path, &info), 0)
                XCTAssertEqual(info.st_uid, getuid()); XCTAssertEqual(info.st_mode & 0o7777, artifact.file.mode)
                XCTAssertEqual(try Data(contentsOf: url), artifact.selected); inodes[artifact.file.name] = info.st_ino
            }
            XCTAssertTrue(try publish(plan, directory).files.values.allSatisfy { $0 == .retained })
            for artifact in plan.artifacts {
                var info = stat(); XCTAssertEqual(lstat(path(directory, artifact.file).path, &info), 0)
                XCTAssertEqual(info.st_ino, inodes[artifact.file.name])
            }
            XCTAssertEqual(try contents(directory).count, 5)
            XCTAssertEqual(try f.state(), before); XCTAssertEqual(try f.runtime.plan.encoded, foreground)
        }
    }
    func testInterruptedPublicationResumesOnlyMatchingOldOrSelectedBytes() throws {
        for stopped in 0..<5 {
            try fixture { _, plan, directory in
                XCTAssertThrowsError(try publish(plan, directory, stage: {
                    if $0.name == plan.artifacts[stopped].file.name { throw Interrupted() }
                })) { XCTAssertTrue($0 is Interrupted) }
                let marker = try Data(contentsOf: path(directory, .gatewayRuntimeCommit))
                XCTAssertEqual(marker, stopped == 4 ? plan.artifacts[4].selected : plan.artifacts[4].previous)
                _ = try publish(plan, directory)
                XCTAssertEqual(try contents(directory).count, 5)
                for artifact in plan.artifacts { XCTAssertEqual(try Data(contentsOf: path(directory, artifact.file)), artifact.selected) }
            }
        }
    }
    func testAnyConflictingSiblingRefusesBeforeChangingAnotherFile() throws {
        for index in 0..<5 {
            try fixture { _, plan, directory in
                let artifact = plan.artifacts[index], url = path(directory, artifact.file)
                try Data("foreign".utf8).write(to: url); XCTAssertEqual(chmod(url.path, artifact.file.mode), 0)
                let original = try contents(directory)
                XCTAssertThrowsError(try publish(plan, directory))
                XCTAssertEqual(try contents(directory), original)
            }
        }
    }
    func testMissingEstablishedArtifactsAndLinkedFilesCannotBecomeCreation() throws {
        for linked in [false, true] {
            try fixture { _, plan, directory in
                let file = path(directory, .transportGatewayRuntime)
                try FileManager.default.removeItem(at: file)
                if linked { try FileManager.default.createSymbolicLink(atPath: file.path, withDestinationPath: "/dev/null") }
                XCTAssertThrowsError(try publish(plan, directory))
                XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory, .gatewaySettingsRevision).path))
            }
        }
    }
    func testASelectedCommitForbidsRepairByRecreatingAnyMissingSibling() throws {
        for index in 0..<5 {
            try fixture { _, plan, directory in
                _ = try publish(plan, directory)
                let missing = path(directory, plan.artifacts[index].file)
                try FileManager.default.removeItem(at: missing)
                XCTAssertThrowsError(try publish(plan, directory))
                XCTAssertFalse(FileManager.default.fileExists(atPath: missing.path))
            }
        }
    }
    func testQuiescenceLossPreventsTheFinalCommitAndRequiresAnExplicitResume() throws {
        try fixture { _, plan, directory in
            let before = try contents(directory)
            XCTAssertThrowsError(try publish(plan, directory, quiesced: { throw Interrupted() }))
            XCTAssertEqual(try contents(directory), before)
            var valid = true
            XCTAssertThrowsError(try publish(plan, directory, quiesced: { if !valid { throw Interrupted() } }, stage: {
                if case .transportGatewayRuntime = $0 { valid = false }
            }))
            XCTAssertEqual(try Data(contentsOf: path(directory, .gatewayRuntimeCommit)), plan.artifacts[4].previous)
            _ = try publish(plan, directory)
            XCTAssertEqual(try Data(contentsOf: path(directory, .gatewayRuntimeCommit)), plan.artifacts[4].selected)
        }
    }
    func testChangedPredecessorAfterStagingIsPreservedAndTheStagingFileIsRemoved() throws {
        try fixture { _, plan, directory in
            let artifact = plan.artifacts[2], url = path(directory, artifact.file), foreign = Data("other writer".utf8)
            XCTAssertThrowsError(try AdministrativeSetupPublication.replaceSettings(artifact.selected, expected: artifact.previous,
                file: artifact.file, directory: directory, owner: getuid(), verify: {}, didStage: {
                    if case .staged = $0 { try foreign.write(to: url) }
                }))
            XCTAssertEqual(try Data(contentsOf: url), foreign)
            XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: directory.path).contains { $0.hasPrefix(".remozio-settings-") })
        }
    }
    func testLostReplyAfterExchangeRetainsTheSelectedFileWithoutReplacingItAgain() throws {
        try fixture { _, plan, directory in
            let artifact = plan.artifacts[2], url = path(directory, artifact.file)
            XCTAssertThrowsError(try AdministrativeSetupPublication.replaceSettings(artifact.selected, expected: artifact.previous,
                file: artifact.file, directory: directory, owner: getuid(), verify: {}, didStage: {
                    if case .published = $0 { throw Interrupted() }
                })) { XCTAssertTrue($0 is Interrupted) }
            var info = stat(); XCTAssertEqual(lstat(url.path, &info), 0); let inode = info.st_ino
            XCTAssertEqual(try AdministrativeSetupPublication.replaceSettings(artifact.selected, expected: artifact.previous,
                file: artifact.file, directory: directory, owner: getuid(), verify: {}), .retained)
            XCTAssertEqual(lstat(url.path, &info), 0); XCTAssertEqual(info.st_ino, inode)
            XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: directory.path).contains { $0.hasPrefix(".remozio-settings-") })
        }
    }
    func testCredentialAndForegroundNamesAreOutsideTheReplacementAPI() throws {
        try fixture { _, _, directory in
            let before = try contents(directory)
            for file in [AdministrativeSetupPublication.File.startup, .commandHost, .transportConfiguration,
                         .gatewayProvider(ownerUID: getuid(), groupID: getgid()), .transportWakeKey(ownerUID: getuid(), groupID: getgid())] {
                XCTAssertThrowsError(try AdministrativeSetupPublication.replaceSettings(Data([1]), expected: Data([2]), file: file,
                    directory: directory, owner: getuid(), verify: {})) { XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .invalidArtifact) }
            }
            XCTAssertThrowsError(try AdministrativeSetupPublication.replaceSettings(Data([1]), expected: nil, file: .gatewayConfiguration,
                directory: directory, owner: getuid(), verify: {}))
            XCTAssertEqual(try contents(directory), before)
        }
    }
}
