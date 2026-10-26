import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RelayConnectorSetupPublicationTests: XCTestCase {
    private struct Interrupted: Error {}
    private struct Fixture {
        let base: RelayRunCredentialPublicationTests.Fixture
        let context: RelayRunCredentialSetupContext
        let reference: RelayRunCredentialReference
        let bootstrap: TransportPairingStartupConfiguration
        let token: Data
        init() throws {
            base = try RelayRunCredentialPublicationTests().fixture()
            let old = base.runtime
            let runtime = try RuntimeMaterialReference(materialID: old.materialID, services: old.services,
                materialDigest: old.materialDigest, transportPublicKeyInfo: old.transportPublicKeyInfo, gateway: old.gateway,
                serviceActivity: .init(services: old.services, identities: [
                    .transport: .init(device: 1, inode: 100), .gateway: .init(device: 1, inode: 101)]))
            reference = try RelayRunCredentialMaterial(expected: base.expected, plan: base.plan, created: base.created,
                runtime: runtime, account: base.account, inventory: base.inventory, credential: base.credential).reference
            context = .init(account: base.account, inventory: base.inventory, expected: base.expected, plan: base.plan,
                created: base.created, runtime: runtime, reference: reference)
            let accountID = base.account.accountID
            let initialization = try base.host.machine { try XCTUnwrap($0.initialization(accountID: accountID)) }
            bootstrap = try RuntimeConfigurationBundle.initial(account: base.account, initialization: initialization,
                reference: runtime, inventory: base.inventory, importIntent: base.expected, relayPlan: base.plan).transport
            token = base.credential.withFileBytes { $0 }
        }
    }
    private func shared(_ body: (ProtectedSetupDirectory) throws -> Void) throws {
        let base = "/private/tmp/remozio-connector-setup-" + UUID().uuidString
        try FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(atPath: base) }
        XCTAssertEqual(chmod(base, 0o755), 0)
        let directory = try ProtectedSetupDirectory(anchor: base, relativePath: "Artifacts", owner: getuid(), visibility: .sharedMetadata)
        defer { directory.close() }; try body(directory)
    }
    private func path(_ directory: ProtectedSetupDirectory) -> String {
        directory.path + "/" + AdministrativeSetupPublication.File.transportRelayReference.name
    }
    private func publish(_ f: Fixture, _ directory: ProtectedSetupDirectory,
                         mode: RelayRunCredentialPublication.Mode = .prepareUnactivated,
                         bootstrap: (() throws -> Data)? = nil, token: (() throws -> Data)? = nil,
                         verify: () throws -> Void = {},
                         stage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        try RelayConnectorStartupPublication.publishPrepared(context: f.context, reference: f.reference,
            directory: directory, owner: getuid(), mode: mode,
            readBootstrap: bootstrap ?? { f.bootstrap.canonicalBytes }, readToken: token ?? { f.token },
            verifyCurrent: verify, didStage: stage)
    }
    func testPreparedPublicationUsesThePublishedBootstrapAndSelectedToken() throws {
        let f = try Fixture()
        try shared { directory in
            XCTAssertEqual(try publish(f, directory), .created)
            let before = try Data(contentsOf: URL(fileURLWithPath: path(directory)))
            XCTAssertEqual(before, try f.reference.encoded); XCTAssertNil(before.range(of: f.token))
            XCTAssertEqual(try publish(f, directory), .retained)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path(directory))), before)
        }
    }
    func testCrossedPortRuntimeAndTokenNeverPublish() throws {
        let f = try Fixture(), other = try Fixture()
        let base = f.bootstrap
        let wrongPort = try TransportPairingStartupConfiguration(transport: base.transport, control: base.control,
            wake: base.wake, relayPort: f.context.plan.port + 1, settingsHost: base.settingsHost)
        try shared { directory in
            for bytes in [wrongPort.canonicalBytes, other.bootstrap.canonicalBytes, Data("bad-bootstrap".utf8)] {
                XCTAssertThrowsError(try publish(f, directory, bootstrap: { bytes }))
                XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory)))
            }
            XCTAssertThrowsError(try publish(f, directory, token: { Data("wrong-selected-token".utf8) }))
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory)))
        }
    }
    func testChangedInputsDuringPublicationCannotCommitStartupMetadata() throws {
        let f = try Fixture()
        for changeToken in [false, true] {
            try shared { directory in
                var changed = false
                XCTAssertThrowsError(try publish(f, directory,
                    bootstrap: { !changeToken && changed ? Data() : f.bootstrap.canonicalBytes },
                    token: { changeToken && changed ? Data() : f.token },
                    stage: { if $0 == .staged { changed = true } }))
                XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory)))
            }
        }
    }
    func testVerificationFailureAndMissingAcceptanceNeverPublish() throws {
        let f = try Fixture(), c = f.context
        try shared { directory in
            XCTAssertThrowsError(try publish(f, directory, verify: { throw Interrupted() }))
            let unaccepted = RelayRunCredentialSetupContext(account: c.account, inventory: c.inventory, expected: c.expected,
                plan: c.plan, created: c.created, runtime: c.runtime, reference: nil)
            XCTAssertThrowsError(try RelayConnectorStartupPublication.publishPrepared(context: unaccepted, reference: f.reference,
                directory: directory, owner: getuid(), mode: .prepareUnactivated,
                readBootstrap: { XCTFail("Unaccepted state read published inputs"); return Data() },
                readToken: { XCTFail(); return Data() }, verifyCurrent: {}))
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory)))
        }
    }
    func testLostReplyRecoversButRetainedValidationNeverRepairsMissingMetadata() throws {
        let f = try Fixture()
        try shared { directory in
            XCTAssertThrowsError(try publish(f, directory, mode: .validateRetained))
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory)))
            XCTAssertThrowsError(try publish(f, directory, stage: { if $0 == .published { throw Interrupted() } }))
            let before = try Data(contentsOf: URL(fileURLWithPath: path(directory)))
            XCTAssertEqual(try publish(f, directory), .retained)
            XCTAssertEqual(try publish(f, directory, mode: .validateRetained), .retained)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path(directory))), before)
        }
    }
    func testNativeEntryRefusesAnOrdinaryCallerBeforeReadingMachineFiles() throws {
        guard getuid() != 0 else { throw XCTSkip("Ordinary caller required") }
        let f = try Fixture()
        XCTAssertThrowsError(try RelayConnectorStartupPublication.publishNative(context: f.context, reference: f.reference,
            mode: .prepareUnactivated, verifyCurrent: { XCTFail("Native Root gate did not precede access") })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
