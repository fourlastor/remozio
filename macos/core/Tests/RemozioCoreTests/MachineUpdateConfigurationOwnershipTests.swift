import Darwin
import Dispatch
import Foundation
import XCTest
@testable import RemozioCore

/// Actual ordinary-owner controls. They grant no native authority or proof of the future promotion owner.
struct ConfigurationPublicationLockFixture {
    let archive: MachineUpdateConfigurationEpoch.Archive
    let accountID: Data
    let directory: ProtectedSetupDirectory
    let machine: PreparationIntentStore
    let lockPath: String
    let openSecond: () throws -> PreparationIntentStore
}

final class MachineUpdateConfigurationOwnershipTests: XCTestCase {
    private enum Fault: Error { case afterCommit }

    private func fixture(_ body: (ConfigurationPublicationLockFixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withOwnedConfigurationPublicationLockFixture(body)
    }

    private func childLockStatus(_ path: String) throws -> Int32 {
        let code = """
            import fcntl, sys
            with open(sys.argv[1], 'r+b') as lock:
                try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError: sys.exit(42)
            """
        let process = Process(), finished = DispatchSemaphore(value: 0)
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", "-c", code, path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.terminationHandler = { _ in finished.signal() }
        try process.run()
        if finished.wait(timeout: .now() + 10) == .timedOut {
            kill(process.processIdentifier, SIGKILL)
            _ = finished.wait(timeout: .now() + 5)
            XCTFail("Lock control timed out")
            throw JournalLeaseError.busy
        }
        return process.terminationStatus
    }

    private func requireBusy(_ f: ConfigurationPublicationLockFixture,
        file: StaticString = #filePath, line: UInt = #line) throws {
        try f.machine.validateStorageLease()
        do {
            let unexpected = try f.openSecond()
            try unexpected.close()
            XCTFail("A second machine store acquired the held writer lock", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? JournalLeaseError, .busy, file: file, line: line)
        }
        XCTAssertEqual(try childLockStatus(f.lockPath), 42, file: file, line: line)
    }

    func testHeldStoreExcludesIndependentAcquisitionThroughoutOwnedReplacementAndReleasesAfterClose() throws {
        try fixture { f in
            let configuration = try XCTUnwrap(f.archive.configuration(accountID: f.accountID))
            let source = try configuration.bytes(.host, target: false), selected = try configuration.bytes(.host, target: true)
            XCTAssertNotEqual(source, selected)
            let path = f.directory.path + "/" + AdministrativeSetupPublication.File.commandHost.name
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), source)
            try requireBusy(f)
            var staged = 0, published = 0, verified = 0
            try MachineUpdateConfigurationFiles.publishInLease(f.archive, accountID: f.accountID, file: .host,
                directory: f.directory, owner: getuid(), verify: {
                    try self.requireBusy(f); verified += 1
                }, didStage: { stage in
                    try self.requireBusy(f)
                    switch stage { case .staged: staged += 1; case .published: published += 1 }
                })
            XCTAssertGreaterThan(verified, 0)
            XCTAssertEqual(staged, 1)
            XCTAssertEqual(published, 1)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), selected)
            try requireBusy(f)
            try f.machine.close()
            XCTAssertEqual(try childLockStatus(f.lockPath), 0)
            let next = try f.openSecond()
            defer { try? next.close() }
            try next.validateStorageLease()
            XCTAssertEqual(try childLockStatus(f.lockPath), 42)
        }
    }

    func testOwnedHelperRefusesOwnerZeroBeforeVerificationAfterAValidReplacement() throws {
        try fixture { f in
            try MachineUpdateConfigurationFiles.publishInLease(f.archive, accountID: f.accountID, file: .host,
                directory: f.directory, owner: getuid(), verify: {})
            var verified = 0, published = 0
            // This ordinary-process refusal does not isolate every ownership guard or prove a native Root execution.
            XCTAssertThrowsError(try MachineUpdateConfigurationFiles.publishInLease(f.archive, accountID: f.accountID,
                file: .host, directory: f.directory, owner: 0, verify: { verified += 1 }, didStage: { _ in published += 1 })) {
                XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
            }
            XCTAssertEqual(verified, 0)
            XCTAssertEqual(published, 0)
        }
    }

    func testPostCommitErrorRetiresTheStoreAndReleasesItsWriterLockWithoutReplayingTheWrite() throws {
        let f = try AccountPreparationFixture()
        var failAfterCommit = false
        let machine = try f.open(initialize: true, hook: { if failAfterCommit { throw Fault.afterCommit } })
        defer { try? machine.close() }
        let first = try XCTUnwrap(machine.inventory())
        func revised(_ revision: Data) throws -> InstallationInventory {
            try .init(macID: first.macID, installationID: first.installationID, revision: revision,
                bundlePath: first.bundlePath, releaseDigest: first.releaseDigest,
                accounts: first.accounts, services: first.services, formatVersion: first.formatVersion)
        }
        let control = try revised(AccountPreparationIntent.randomID())
        XCTAssertNoThrow(try machine.writeInventory(control, expectedRevision: first.revision))
        XCTAssertEqual(try machine.inventory(), control)
        let lockPath = f.root.path + "/machine/writer.lock"
        XCTAssertEqual(try childLockStatus(lockPath), 42)
        let committed = try revised(AccountPreparationIntent.randomID())
        failAfterCommit = true
        XCTAssertThrowsError(try machine.writeInventory(committed, expectedRevision: control.revision)) {
            XCTAssertTrue($0 is Fault)
        }
        XCTAssertThrowsError(try machine.inventory()) {
            XCTAssertEqual($0 as? PreparationStoreError, .unavailable)
        }
        XCTAssertEqual(try childLockStatus(lockPath), 0)
        let next = try f.open()
        defer { try? next.close() }
        XCTAssertEqual(try next.inventory(), committed)
        XCTAssertEqual(try childLockStatus(lockPath), 42)
    }
}
