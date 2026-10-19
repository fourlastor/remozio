import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewayRuntimePublicationTests: XCTestCase {
    private typealias Publication = GatewayRuntimePublication
    private struct Interrupted: Error {}
    private func fixture(_ body: (GatewayJournalSetupExchangeTests.Fixture, GatewayRuntimeExtensions, ProtectedSetupDirectory) throws -> Void) throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture()
        try f.retainCompletion(.decode(f.initialize()))
        let pair = try GatewayRuntimeExtensions(journal: f.state(), foreground: f.runtime.plan, inventory: XCTUnwrap(f.runtime.machine.inventory()))
        let directory = try ProtectedSetupDirectory(anchor: f.root.path, relativePath: "Runtime", owner: getuid(), visibility: .sharedMetadata)
        defer { directory.close() }; try body(f, pair, directory)
    }
    private func publish(_ pair: GatewayRuntimeExtensions, _ directory: ProtectedSetupDirectory,
                         mode: Publication.Mode = .publishPending, verify: () throws -> Void = {},
                         stage: (Publication.Artifact) throws -> Void = { _ in }) throws -> Publication.Result {
        try Publication.publish(pair, directory: directory, owner: getuid(), mode: mode, verifyCurrent: verify, didPublish: stage)
    }
    private func path(_ directory: ProtectedSetupDirectory, _ file: AdministrativeSetupPublication.File) -> String {
        directory.path + "/" + file.name
    }
    private func read(_ directory: ProtectedSetupDirectory, _ file: AdministrativeSetupPublication.File) throws -> Data {
        let privateFile: Bool
        switch file { case .authorityGatewayRuntime: privateFile = true; default: privateFile = false }
        return try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name, owner: getuid(), privateFile: privateFile)
    }
    private func load(_ f: GatewayJournalSetupExchangeTests.Fixture, _ directory: ProtectedSetupDirectory,
                      role: GatewayRuntimeExtension.Target) throws -> GatewayRuntimeLoader.Loaded? {
        try GatewayRuntimeLoader.load(target: role, read: { try read(directory, $0) }, verifyCurrent: {}, validate: {
            if role == .authority { try $0.validate(authority: f.runtime.plan.host) }
            else { try $0.validate(transport: f.runtime.plan.transport) }
        })
    }
    func testPublishesRolePermissionsAndLoadsBothWithoutReplacingForegroundState() throws {
        try fixture { f, pair, directory in
            let inventory = try f.runtime.machine.inventory(), foreground = try f.runtime.plan.encoded
            let result = try publish(pair, directory)
            XCTAssertEqual(result.files, [.authority: .created, .transport: .created, .commit: .created])
            XCTAssertEqual(try load(f, directory, role: .authority)?.configuration.encoded, try pair.authority.encoded)
            XCTAssertEqual(try load(f, directory, role: .transport)?.configuration.encoded, try pair.transport.encoded)
            XCTAssertEqual(try load(f, directory, role: .transport)?.commit.pairDigest, try pair.digest)
            var inodes: [String: ino_t] = [:]
            for file in [AdministrativeSetupPublication.File.authorityGatewayRuntime, .transportGatewayRuntime, .gatewayRuntimeCommit] {
                var info = stat(); XCTAssertEqual(lstat(path(directory, file), &info), 0)
                XCTAssertEqual(info.st_mode & 0o7777, file.mode); XCTAssertEqual(info.st_uid, getuid()); inodes[file.name] = info.st_ino
            }
            for mode in [Publication.Mode.publishPending, .validateRetained] {
                XCTAssertEqual(try publish(pair, directory, mode: mode).files, [.authority: .retained, .transport: .retained, .commit: .retained])
                for file in [AdministrativeSetupPublication.File.authorityGatewayRuntime, .transportGatewayRuntime, .gatewayRuntimeCommit] {
                    var info = stat(); XCTAssertEqual(lstat(path(directory, file), &info), 0); XCTAssertEqual(info.st_ino, inodes[file.name])
                }
            }
            XCTAssertEqual(try f.runtime.machine.inventory(), inventory)
            XCTAssertEqual(try f.runtime.machine.runtimeActivation(accountID: f.intent.accountID).plan?.encoded, foreground)
        }
    }
    func testInterruptedSubsetsRemainUnavailableUntilFinalMarkerAndResume() throws {
        for stop in Publication.Artifact.allCases {
            try fixture { f, pair, directory in
                XCTAssertThrowsError(try publish(pair, directory, stage: { if $0 == stop { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
                if stop == .commit { XCTAssertNotNil(try load(f, directory, role: .authority)) }
                else { XCTAssertNil(try load(f, directory, role: .authority)); XCTAssertNil(try load(f, directory, role: .transport)) }
                _ = try publish(pair, directory)
                XCTAssertNotNil(try load(f, directory, role: .authority)); XCTAssertNotNil(try load(f, directory, role: .transport))
            }
        }
    }
    func testMissingCommittedRoleIsNeverRecreated() throws {
        try fixture { f, pair, directory in
            XCTAssertThrowsError(try publish(pair, directory, mode: .validateRetained))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
            _ = try publish(pair, directory)
            let missing = path(directory, .transportGatewayRuntime)
            try FileManager.default.removeItem(atPath: missing)
            XCTAssertThrowsError(try load(f, directory, role: .transport))
            XCTAssertThrowsError(try publish(pair, directory))
            XCTAssertFalse(FileManager.default.fileExists(atPath: missing))
        }
    }
    func testConflictingOrLinkedSiblingRefusesBeforeAnyOtherPublication() throws {
        for file in [AdministrativeSetupPublication.File.authorityGatewayRuntime, .transportGatewayRuntime, .gatewayRuntimeCommit] {
            for link in [false, true] {
                try fixture { _, pair, directory in
                    let destination = path(directory, file)
                    if link { try FileManager.default.createSymbolicLink(atPath: destination, withDestinationPath: "/dev/null") }
                    else { try Data("conflict".utf8).write(to: URL(fileURLWithPath: destination)); XCTAssertEqual(chmod(destination, file.mode), 0) }
                    XCTAssertThrowsError(try publish(pair, directory))
                    XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [file.name])
                }
            }
        }
    }
    func testMutationBeforeCommitDoesNotAdvertiseAPartialPair() throws {
        try fixture { f, pair, directory in
            XCTAssertThrowsError(try publish(pair, directory, stage: {
                if $0 == .transport { try Data("changed".utf8).write(to: URL(fileURLWithPath: path(directory, .authorityGatewayRuntime))) }
            }))
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory, .gatewayRuntimeCommit)))
            XCTAssertNil(try load(f, directory, role: .authority))
        }
    }
    func testMalformedUnsafeOrChangedMarkerDoesNotBecomeOptionalAbsence() throws {
        try fixture { f, pair, directory in
            _ = try publish(pair, directory)
            let marker = try read(directory, .gatewayRuntimeCommit)
            var count = 0
            XCTAssertThrowsError(try GatewayRuntimeLoader.load(target: .authority, read: {
                switch $0 {
                case .gatewayRuntimeCommit: count += 1; return count == 1 ? marker : Data("changed".utf8)
                default: return try read(directory, $0)
                }
            }, verifyCurrent: {}, validate: { try $0.validate(authority: f.runtime.plan.host) }))
            let markerPath = path(directory, .gatewayRuntimeCommit)
            XCTAssertEqual(chmod(markerPath, 0o666), 0)
            XCTAssertThrowsError(try load(f, directory, role: .authority))
            XCTAssertEqual(chmod(markerPath, 0o644), 0)
            try Data("malformed".utf8).write(to: URL(fileURLWithPath: markerPath))
            XCTAssertThrowsError(try load(f, directory, role: .authority))
            XCTAssertThrowsError(try GatewayRuntimeLoader.load(target: .authority, read: { _ in throw JournalLeaseError.system(EACCES) }, verifyCurrent: {}, validate: { _ in }))
        }
    }
    func testMarkerBindsTheRoleAndAllScopeDigests() throws {
        try fixture { _, pair, _ in
            let marker = try GatewayRuntimeCommit(pair), encoded = try marker.encoded
            XCTAssertEqual(try GatewayRuntimeCommit.decode(encoded).encoded, encoded)
            try marker.validate(pair.authority); try marker.validate(pair.transport)
            let limits = try CBORLimits(maxBytes: 65536, maxDepth: 2, maxItems: 64)
            guard case .map(let original) = try DeterministicCBOR.decode(encoded, limits: limits) else { return XCTFail() }
            for key in UInt64(2)...7 {
                var changed = original; changed[key] = .bytes(Data(repeating: 0, count: key == 2 ? 16 : 32))
                let bad = try GatewayRuntimeCommit.decode(DeterministicCBOR.encode(.map(changed), limits: limits))
                XCTAssertThrowsError(try bad.validate(pair))
                if [2, 3, 4, 6].contains(key) { XCTAssertThrowsError(try bad.validate(pair.authority)) }
                else { XCTAssertNoThrow(try bad.validate(pair.authority)) }
                if [2, 3, 4, 7].contains(key) { XCTAssertThrowsError(try bad.validate(pair.transport)) }
                else { XCTAssertNoThrow(try bad.validate(pair.transport)) }
                // Pair digest is checked by the setup owner and later live status. A single-role loader cannot reconstruct it.
            }
            for key in [UInt64(0), 1, 2, 8] {
                var changed = original; changed[key] = .null
                XCTAssertThrowsError(try GatewayRuntimeCommit.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
            }
            XCTAssertThrowsError(try GatewayRuntimeCommit.decode(Data(repeating: 0, count: 1025)))
        }
    }
    func testCurrentScopeChecksPrecedeFileAccessAndNativeEntriesRequireTheRightAccount() throws {
        try fixture { f, pair, directory in
            XCTAssertThrowsError(try publish(pair, directory, verify: { throw Interrupted() }))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
            XCTAssertThrowsError(try GatewayRuntimeLoader.load(target: .authority, read: { _ in XCTFail("No read"); return Data() },
                verifyCurrent: { throw Interrupted() }, validate: { _ in }))
            XCTAssertThrowsError(try Publication.publish(pair, journal: f.state(), foreground: f.runtime.plan,
                inventory: XCTUnwrap(f.runtime.machine.inventory()), mode: .publishPending, verifyCurrent: { XCTFail("No protected access") })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertThrowsError(try GatewayRuntimeLoader.load(authority: f.runtime.plan.host, verifyCurrent: { XCTFail("No protected access") })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertThrowsError(try GatewayRuntimeLoader.load(transport: f.runtime.plan.transport, verifyCurrent: { XCTFail("No protected access") })) {
                XCTAssertEqual($0 as? ApprovalTransportStartupError, .wrongAccount)
            }
        }
    }
}
