import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityServiceTests: XCTestCase {
    private func configuration(_ fixture: Fixture, wrongScope: Bool = false) throws -> AuthorityServiceConfiguration {
        try AuthorityServiceConfiguration(macID: Data(repeating: wrongScope ? 9 : 1, count: 16),
            accountID: Data(repeating: 2, count: 16), journalDirectory: fixture.directory,
            serviceName: "dev.remozio.authority.test", teamID: "ABCDEFGHIJ",
            transportIdentifier: "dev.sebastiano.remozio.macos.transport", transportHashes: [Data(repeating: 3, count: 20)], transportUID: 501)
    }
    private func database(_ fixture: Fixture, initialize: Bool = true, configure: Bool = true, configureCode: Bool = true) throws -> sending JournalDatabase {
        let anchor = fixture.root.path
        let limits = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
        let database = try JournalDatabase(lease: ProtectedJournalLease(anchor: anchor, relativeDirectory: "store", owner: getuid()),
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
            maximumConsumptions: 10, busyMilliseconds: 100, initialize: initialize)
        if initialize && configure {
            let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
            _ = try database.write { try $0.configureApprovalAuthority(capabilities: ContractCapabilities(contracts: [contract: []]), allowedContracts: [contract]) }
        }
        if initialize && configureCode {
            _ = try database.write {
                try $0.installCodePolicy(AuthorityCodePolicy(entries: [AuthorityCodeEntry(role: .transport, teamID: "ABCDEFGHIJ",
                    identifier: "dev.sebastiano.remozio.macos.transport", installedGeneration: 1, minimumGeneration: 1,
                    codeDirectoryHash: Data(repeating: 3, count: 20), active: true)]), expectedRevision: nil)
            }
        }
        return database
    }
    private func assertReleased(_ fixture: Fixture) throws {
        let reopened = try database(fixture, initialize: false)
        try reopened.close()
    }
    func testServiceClosesSuppliedJournalOwner() throws {
        let fixture = try Fixture()
        let journal = AuthorityJournal(database: try database(fixture))
        let service = try AuthorityService(configuration: configuration(fixture), journal: journal, validateSelf: { _ in })
        XCTAssertFalse(try journal.read { try $0.approvalTrustSnapshot().allowedContracts.isEmpty })
        try service.close()
        XCTAssertThrowsError(try journal.read { try $0.approvalTrustSnapshot().revision }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .closed)
        }
        try assertReleased(fixture)
    }
    func testCloseBeforeStartReleasesLeaseAndPreventsStart() throws {
        let fixture = try Fixture()
        let service = try AuthorityService(configuration: configuration(fixture), journal: AuthorityJournal(database: database(fixture)), validateSelf: { _ in })
        XCTAssertThrowsError(try fixture.lease()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        try service.close(); try service.close()
        XCTAssertThrowsError(try service.start()) { XCTAssertEqual($0 as? AuthorityXPCEndpointError, .unavailable) }
        try assertReleased(fixture)
    }
    func testFailedStartRetiresInstanceAndReleasesLease() throws {
        guard geteuid() != 0 else { throw XCTSkip("Requires normal user") }
        let fixture = try Fixture()
        let service = try AuthorityService(configuration: configuration(fixture), journal: AuthorityJournal(database: database(fixture)), validateSelf: { _ in })
        XCTAssertThrowsError(try service.start()) { XCTAssertEqual($0 as? AuthorityXPCEndpointError, .unavailable) }
        try assertReleased(fixture)
        XCTAssertThrowsError(try service.start())
        try service.close()
    }
    func testWrongScopeConstructionReleasesLease() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try AuthorityService(configuration: configuration(fixture, wrongScope: true), journal: AuthorityJournal(database: database(fixture)), validateSelf: { _ in })) {
            XCTAssertEqual($0 as? AuthorityXPCEndpointError, .invalidConfiguration)
        }
        try assertReleased(fixture)
    }
    func testUnconfiguredStoreIsNotInitializedByService() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try AuthorityService(configuration: configuration(fixture), journal: AuthorityJournal(database: database(fixture, configure: false)), validateSelf: { _ in })) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unconfigured)
        }
        let reopened = try database(fixture, initialize: false)
        XCTAssertThrowsError(try reopened.read { try $0.approvalTrustSnapshot() }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unconfigured)
        }
        try reopened.close()
    }
    func testServiceRejectsAbsentCodePolicyAndReleasesStorageWithoutInitializingIt() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try AuthorityService(configuration: configuration(fixture), journal: AuthorityJournal(database: database(fixture, configureCode: false)), validateSelf: { _ in })) {
            XCTAssertEqual($0 as? AuthorityTransportAccessError, .unconfigured)
        }
        let reopened = try database(fixture, initialize: false)
        XCTAssertNil(try reopened.read { try $0.codePolicy() })
        try reopened.close()
    }

    func testPublicConstructionRequiresAuthoritySelfPolicyAndReleasesStorage() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try AuthorityService(configuration: configuration(fixture), database: database(fixture))) {
            XCTAssertEqual($0 as? AuthoritySelfValidationError, .unconfigured)
        }
        try assertReleased(fixture)
    }

    func testSelfValidationFailurePrecedesListenerConstructionAndClosesJournal() throws {
        enum Failure: Error { case injected }
        let fixture = try Fixture(), journal = AuthorityJournal(database: try database(fixture))
        // Wrong scope would fail listener construction if startup reached that stage.
        XCTAssertThrowsError(try AuthorityService(configuration: configuration(fixture, wrongScope: true), journal: journal,
            validateSelf: { owner in
                XCTAssertFalse(try owner.read { try $0.approvalTrustSnapshot().allowedContracts.isEmpty })
                throw Failure.injected
            })) { guard case Failure.injected = $0 else { return XCTFail("wrong failure") } }
        XCTAssertThrowsError(try journal.read { _ in true }) { XCTAssertEqual($0 as? JournalDatabaseError, .closed) }
        try assertReleased(fixture)
    }

    func testDeinitializationReleasesLease() throws {
        let fixture = try Fixture()
        var service: AuthorityService? = try AuthorityService(configuration: configuration(fixture), journal: AuthorityJournal(database: database(fixture)), validateSelf: { _ in })
        XCTAssertNotNil(service)
        service = nil
        try assertReleased(fixture)
    }

    func testProviderConfigurationMismatchReleasesJournalBeforeActivation() throws {
        let fixture = try Fixture(), config = try configuration(fixture), key = P256.Signing.PrivateKey()
        let bundle = try AuthorityRequestProviders(configuration: configuration(fixture, wrongScope: true), publicKey: key.publicKey.x963Representation,
            signing: { _ in XCTFail("Mismatched service signed"); return Data() }, routing: { throw AuthorityRequestSignerError.unavailable })
        let journal = AuthorityJournal(database: try database(fixture))
        XCTAssertThrowsError(try AuthorityService(configuration: config, journal: journal, validateSelf: { _ in },
            requestProviders: bundle, reconcileExpired: { _ in })) {
            XCTAssertEqual($0 as? AuthorityServiceConfigurationError, .invalidConfiguration)
        }
        try assertReleased(fixture)
    }
    func testProviderServiceRejectsMixedHandlersAndRetainsSelfValidation() throws {
        let fixture = try Fixture(), config = try configuration(fixture), key = P256.Signing.PrivateKey()
        let bundle = try AuthorityRequestProviders(configuration: config, publicKey: key.publicKey.x963Representation,
            signing: { _ in XCTFail("Unstarted service signed"); return Data() }, routing: { throw AuthorityRequestSignerError.unavailable })
        let journal = AuthorityJournal(database: try database(fixture))
        XCTAssertThrowsError(try AuthorityService(configuration: config, journal: journal, validateSelf: { _ in },
            requestFrame: { _, _, _, _ in XCTFail("Mixed handler"); return nil }, requestProviders: bundle, reconcileExpired: { _ in })) {
            XCTAssertEqual($0 as? AuthorityServiceConfigurationError, .invalidConfiguration)
        }
        try assertReleased(fixture)
        XCTAssertThrowsError(try AuthorityService(configuration: config,
            journal: AuthorityJournal(database: database(fixture, initialize: false)), requestProviders: bundle, reconcileExpired: { _ in })) {
            XCTAssertEqual($0 as? AuthoritySelfValidationError, .unconfigured)
        }
        try assertReleased(fixture)
    }
    func testPublicSignerLoadRequiresRootBeforeReadingTheRecord() throws {
        guard geteuid() != 0 else { throw XCTSkip("Normal-user admission guard") }
        let fixture = try Fixture(), journal = AuthorityJournal(database: try database(fixture))
        defer { try? journal.close() }
        XCTAssertThrowsError(try EnclaveAuthorityRequestSigner.load(path: "/not-read", configuration: configuration(fixture),
            expectedPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation, journal: journal)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
    func testMaintenanceRetirementReportsOnceAfterReleasingWriterLease() throws {
        let fixture = try Fixture(), anchor = fixture.root.path, owner = getuid()
        let retired = expectation(description: "service retired")
        retired.assertForOverFulfill = true
        let journal = AuthorityJournal(database: try database(fixture))
        let service = try AuthorityService(configuration: configuration(fixture), journal: journal,
            validateSelf: { _ in }, onMaintenanceFailure: {
                do {
                    let lease = try ProtectedJournalLease(anchor: anchor, relativeDirectory: "store", owner: owner)
                    lease.close()
                } catch { XCTFail("Retirement preceded writer release") }
                retired.fulfill()
            })
        service.maintenanceDidFail(); service.maintenanceDidFail()
        wait(for: [retired], timeout: 1)
        XCTAssertThrowsError(try journal.read { try $0.approvalTrustSnapshot() }) { XCTAssertEqual($0 as? JournalDatabaseError, .closed) }
        XCTAssertThrowsError(try service.start())
        try service.close()
    }

    private func startup(_ fixture: Fixture, publicKey: Data? = nil) throws -> AuthorityRequestStartupConfiguration {
        let base = try AuthorityServiceConfiguration(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            journalDirectory: fixture.directory, serviceName: "dev.remozio.authority.test", teamID: "ABCDEFGHIJ",
            transportIdentifier: "dev.sebastiano.remozio.macos.transport", transportHashes: [Data(repeating: 3, count: 20)], transportUID: 501,
            continuityDirectory: fixture.root.appendingPathComponent("continuity").path)
        return try AuthorityRequestStartupConfiguration(service: base, keyRecordPath: fixture.root.appendingPathComponent("authority.cbor").path,
            authorityPublicKey: publicKey ?? P256.Signing.PrivateKey().publicKey.x963Representation)
    }
    func testRequestStartupKeyFailureClosesOpenedStorageWithoutCallingRuntimeCallbacks() throws {
        let fixture = try Fixture(), inputs = try startup(fixture)
        let journal = AuthorityJournal(database: try database(fixture))
        var loaded = false
        XCTAssertThrowsError(try AuthorityService(requestStartup: inputs, openJournal: { journal }, loadSigner: { owner in
            XCTAssertTrue(owner === journal)
            XCTAssertThrowsError(try fixture.lease()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            loaded = true
            throw AuthorityRequestSignerError.unavailable
        }, routing: { XCTFail("Failed startup queried presence"); throw AuthorityRequestSignerError.unavailable },
            reconcileExpired: { _ in XCTFail("Failed startup performed cleanup") })) {
            XCTAssertEqual($0 as? AuthorityRequestSignerError, .unavailable)
        }
        XCTAssertTrue(loaded)
        XCTAssertThrowsError(try journal.read { try $0.approvalTrustSnapshot() }) { XCTAssertEqual($0 as? JournalDatabaseError, .closed) }
        try assertReleased(fixture)
    }
    func testRequestStartupPinMismatchClosesStorageWithoutRestoringAnotherKey() throws {
        let fixture = try Fixture(), inputs = try startup(fixture), other = P256.Signing.PrivateKey().publicKey.x963Representation
        let mismatched = try AuthoritySigningKeyRecord(macID: inputs.service.macID, accountID: inputs.service.accountID,
            publicKey: other, representation: Data([1])).encode()
        let journal = AuthorityJournal(database: try database(fixture))
        XCTAssertThrowsError(try AuthorityService(requestStartup: inputs, openJournal: { journal }, loadSigner: { _ in
            try EnclaveAuthorityRequestSigner.restore(mismatched, configuration: inputs.service, expectedPublicKey: inputs.authorityPublicKey)
        }, routing: { XCTFail("Mismatched key queried presence"); throw AuthorityRequestSignerError.wrongIdentity },
            reconcileExpired: { _ in XCTFail("Mismatched key performed cleanup") })) {
            XCTAssertEqual($0 as? AuthorityRequestSignerError, .wrongIdentity)
        }
        try assertReleased(fixture)
    }
    func testPublicRequestStartupRequiresRootWithoutInitializingStorage() throws {
        guard geteuid() != 0 else { throw XCTSkip("Requires normal user") }
        let fixture = try Fixture(), inputs = try startup(fixture)
        XCTAssertThrowsError(try AuthorityService(requestStartup: inputs,
            routing: { XCTFail("Non-root startup queried presence"); throw AuthorityRequestSignerError.unavailable },
            reconcileExpired: { _ in XCTFail("Non-root startup performed cleanup") })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: fixture.directory + "/journal.sqlite")).count, 0)
    }

    private final class Fixture {
        let root: URL
        var directory: String { root.appendingPathComponent("store").path }
        var path: String { directory + "/journal.sqlite" }
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw JournalLeaseError.system(errno) }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                Darwin.close(fd)
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func lease() throws -> ProtectedJournalLease { try ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()) }
    }
}
