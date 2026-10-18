import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewayJournalSetupJobArtifactsTests: XCTestCase {
    private struct Interrupted: Error {}
    private typealias Artifacts = GatewayJournalSetupJobArtifacts
    private func fixture(_ body: (RuntimeActivationFixture, GatewayJournalSetupServiceConfiguration, ProtectedSetupDirectory, ProtectedSetupDirectory) throws -> Void) throws {
        try GatewayJournalSetupNativeModelTests.fixture { f, _, configuration in
            let root = URL(fileURLWithPath: "/private/tmp/remozio-setup-artifacts-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            defer { XCTAssertNoThrow(try FileManager.default.removeItem(at: root)) }
            XCTAssertEqual(chmod(root.path, 0o755), 0)
            let service = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Service", owner: getuid(), visibility: .sharedMetadata)
            defer { service.close() }
            let jobs = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Jobs", owner: getuid(), visibility: .sharedMetadata)
            defer { jobs.close() }
            try body(f, configuration, service, jobs)
        }
    }
    private func publish(_ configuration: GatewayJournalSetupServiceConfiguration, _ service: ProtectedSetupDirectory, _ jobs: ProtectedSetupDirectory,
                         mode: Artifacts.Mode = .preparePending, stage: (Artifacts.Artifact) throws -> Void = { _ in }) throws -> Artifacts.Result {
        try Artifacts.publish(configuration: configuration, service: service, jobs: jobs, owner: getuid(), mode: mode, verifyCurrent: {}, didPublish: stage)
    }
    private func path(_ directory: ProtectedSetupDirectory, _ name: String) -> URL { URL(fileURLWithPath: directory.path).appendingPathComponent(name) }
    private func snapshot(_ directory: ProtectedSetupDirectory) throws -> [String: Data] {
        try Dictionary(uniqueKeysWithValues: FileManager.default.contentsOfDirectory(atPath: directory.path).map { ($0, try Data(contentsOf: path(directory, $0))) })
    }
    private func remove(_ job: GatewayJournalSetupJobManifest, _ jobs: ProtectedSetupDirectory, absent: () throws -> Bool = { true },
                        verify: () throws -> Void = {}, inspected: () throws -> Void = {}, removed: () throws -> Void = {}) throws -> Artifacts.Removal {
        try Artifacts.removeJobFile(job: job, jobs: jobs, owner: getuid(), jobIsAbsent: absent, verifyCurrent: verify, didValidate: inspected, didRemove: removed)
    }
    func testTypedPublicationRetainsBothRecordsWithoutReplacingInodes() throws {
        try fixture { _, configuration, service, jobs in
            let job = try GatewayJournalSetupJobManifest(configuration: configuration)
            let result = try publish(configuration, service, jobs)
            XCTAssertEqual(result.files, [.configuration: .created, .job: .created])
            let expected = [job.label + ".plist": job.bytes]
            XCTAssertEqual(try snapshot(jobs), expected)
            XCTAssertEqual(try snapshot(service), [GatewayJournalSetupServiceConfiguration.fileName: configuration.canonicalBytes])
            var first = stat(); XCTAssertEqual(lstat(path(jobs, job.label + ".plist").path, &first), 0)
            XCTAssertEqual(first.st_mode & 0o7777, 0o644)
            for mode in [Artifacts.Mode.preparePending, .validateRetained] {
                XCTAssertEqual(try publish(configuration, service, jobs, mode: mode).files, [.configuration: .retained, .job: .retained])
                var retained = stat(); XCTAssertEqual(lstat(path(jobs, job.label + ".plist").path, &retained), 0)
                XCTAssertEqual(retained.st_ino, first.st_ino); XCTAssertEqual(try snapshot(jobs), expected)
            }
            XCTAssertThrowsError(try AdministrativeSetupPublication.File.gatewayJournalJob(accountID: Data(), intentID: configuration.intent.id).validate())
        }
    }
    func testInterruptedPublicationResumesItsExactSubsetAndPreservesForegroundState() throws {
        for stop in [Artifacts.Artifact.configuration, .job] {
            try fixture { f, configuration, service, jobs in
                let inventory = try f.machine.inventory(), foreground = try f.machine.runtimeActivation(accountID: configuration.intent.accountID)
                XCTAssertThrowsError(try publish(configuration, service, jobs, stage: { if $0 == stop { throw Interrupted() } }))
                let beforeService = try snapshot(service), beforeJobs = try snapshot(jobs)
                _ = try publish(configuration, service, jobs)
                let afterService = try snapshot(service), afterJobs = try snapshot(jobs)
                for (name, bytes) in beforeService { XCTAssertEqual(afterService[name], bytes) }
                for (name, bytes) in beforeJobs { XCTAssertEqual(afterJobs[name], bytes) }
                XCTAssertEqual(try f.machine.inventory(), inventory)
                XCTAssertEqual(try f.machine.runtimeActivation(accountID: configuration.intent.accountID).plan?.encoded, try foreground.plan?.encoded)
            }
        }
    }
    func testRetentionCannotCreateMissingRecords() throws {
        try fixture { _, configuration, service, jobs in
            XCTAssertThrowsError(try publish(configuration, service, jobs, mode: .validateRetained))
            XCTAssertEqual(try snapshot(service), [:]); XCTAssertEqual(try snapshot(jobs), [:])
            _ = try publish(configuration, service, jobs)
            let job = try GatewayJournalSetupJobManifest(configuration: configuration)
            try FileManager.default.removeItem(at: path(jobs, job.label + ".plist"))
            XCTAssertThrowsError(try publish(configuration, service, jobs, mode: .validateRetained))
            XCTAssertEqual(try snapshot(jobs), [:]); XCTAssertEqual(try snapshot(service).count, 1)
        }
    }
    func testConflictingUnsafeAndLinkedSiblingsBlockAllNewPublication() throws {
        for mode in 0...2 {
            try fixture { _, configuration, service, jobs in
                let job = try GatewayJournalSetupJobManifest(configuration: configuration), destination = path(jobs, job.label + ".plist")
                if mode == 2 { try FileManager.default.createSymbolicLink(atPath: destination.path, withDestinationPath: "/dev/null") }
                else { try (mode == 0 ? Data("conflicting".utf8) : job.bytes).write(to: destination); XCTAssertEqual(chmod(destination.path, mode == 0 ? 0o644 : 0o600), 0) }
                XCTAssertThrowsError(try publish(configuration, service, jobs))
                XCTAssertEqual(try snapshot(service), [:]); XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: jobs.path), [job.label + ".plist"])
            }
        }
    }
    func testLoadedOrReappearingJobBlocksManifestRemoval() throws {
        try fixture { _, configuration, service, jobs in
            _ = try publish(configuration, service, jobs)
            let job = try GatewayJournalSetupJobManifest(configuration: configuration), before = try snapshot(jobs)
            XCTAssertThrowsError(try remove(job, jobs, absent: { false }))
            XCTAssertEqual(try snapshot(jobs), before)
            var reads = 0
            XCTAssertThrowsError(try remove(job, jobs, absent: { reads += 1; return reads == 1 }))
            XCTAssertEqual(try snapshot(jobs), before)
        }
    }
    func testReplacedManifestIsNeverUnlinkedEvenWhenItsBytesStillMatch() throws {
        try fixture { _, configuration, service, jobs in
            _ = try publish(configuration, service, jobs)
            let job = try GatewayJournalSetupJobManifest(configuration: configuration), destination = path(jobs, job.label + ".plist")
            XCTAssertThrowsError(try remove(job, jobs, inspected: {
                try FileManager.default.moveItem(at: destination, to: destination.appendingPathExtension("retained"))
                try job.bytes.write(to: destination); XCTAssertEqual(chmod(destination.path, 0o644), 0)
            })) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
            XCTAssertEqual(try Data(contentsOf: destination), job.bytes)
        }
    }
    func testCleanupRemovesOnlyTheJobAndRetainsTheServiceRecord() throws {
        try fixture { _, configuration, service, jobs in
            _ = try publish(configuration, service, jobs)
            let job = try GatewayJournalSetupJobManifest(configuration: configuration), before = try snapshot(service)
            XCTAssertEqual(try remove(job, jobs), .removed)
            XCTAssertEqual(try snapshot(jobs), [:]); XCTAssertEqual(try snapshot(service), before)
            XCTAssertEqual(try remove(job, jobs), .absent)
        }
    }
    func testLostRemovalReplyRecoversWithoutRecreatingTheManifest() throws {
        try fixture { _, configuration, service, jobs in
            _ = try publish(configuration, service, jobs)
            let job = try GatewayJournalSetupJobManifest(configuration: configuration)
            XCTAssertThrowsError(try remove(job, jobs, removed: { throw Interrupted() }))
            XCTAssertEqual(try snapshot(jobs), [:]); XCTAssertEqual(try remove(job, jobs), .absent)
            XCTAssertEqual(try snapshot(service).count, 1)
        }
    }
    func testLateJobAppearanceCannotReportCleanupCompleteAfterTheFileWasRemoved() throws {
        try fixture { _, configuration, service, jobs in
            _ = try publish(configuration, service, jobs)
            let job = try GatewayJournalSetupJobManifest(configuration: configuration)
            var reads = 0
            XCTAssertThrowsError(try remove(job, jobs, absent: { reads += 1; return reads < 3 })) {
                XCTAssertEqual($0 as? GatewayServiceError, .unavailable)
            }
            XCTAssertEqual(try snapshot(jobs), [:]); XCTAssertEqual(try snapshot(service).count, 1)
            XCTAssertEqual(try remove(job, jobs), .absent)
        }
    }
    func testChangedScopeAndOrdinaryNativeIdentityCannotReachRemoval() throws {
        try fixture { f, configuration, service, jobs in
            _ = try publish(configuration, service, jobs)
            let job = try GatewayJournalSetupJobManifest(configuration: configuration), before = try snapshot(jobs)
            XCTAssertThrowsError(try remove(job, jobs, absent: { XCTFail(); return true }, verify: { throw Interrupted() }))
            XCTAssertEqual(try snapshot(jobs), before)
            XCTAssertThrowsError(try Artifacts.removeAfterJobAbsent(configuration: configuration, machine: f.machine, verifyCurrent: { XCTFail() })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertThrowsError(try GatewayJournalSetupJobRegistration.isAbsent(job)) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        }
    }
}
