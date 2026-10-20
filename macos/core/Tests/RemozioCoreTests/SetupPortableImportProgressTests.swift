import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned files and scoped factories prove readback mechanics. Native Root, XPC and administrator admission remain unproven.
final class SetupPortableImportProgressTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Fixture {
        let f: AccountPreparationFixture
        let account: AccountPreparationIntent
        let inventory: InstallationInventory
        let services: ServiceAccountPlan
        let owner: SetupAccountOwner
        init(servicesComplete: Bool = true) throws {
            f = try .init()
            let machine = try f.open(initialize: true)
            account = try f.resume(machine, f.begin(machine))
            services = try .init(account: account, planID: AccountPreparationIntent.randomID(), claims: [
                .init(accountID: account.accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
                .init(accountID: account.accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())])
            try machine.retainServiceAccountPlan(services)
            if servicesComplete { try machine.completeServiceAccountPlan(services) }
            inventory = try XCTUnwrap(machine.inventory()); try machine.close()
            let fixture = f, identity = f.identity
            owner = try .init(openMachine: { try fixture.open() }, expectedReleaseDigest: f.release,
                resume: { _, _ in throw Interrupted() }, accountCodePolicy: f.policy,
                lookupAccount: { uid in guard uid == identity.uid else { throw AdministrativeSetupError.wrongAccount }; return identity })
        }
        deinit { try? owner.close() }
        func proposal() throws -> PortableSetup {
            try .init(defaults: .init(presence: .init(idleMilliseconds: 420_000, observationLifetimeMilliseconds: 5000,
                unavailableGraceMilliseconds: 30_000), gateway: GatewaySetupForm().settingsSelection()),
                cloudflare: .init(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
                    dnsSuffix: "remozio.example.invalid", apiToken: "synthetic-import-readback-secret"))
        }
        func journal(initialize: Bool = false) throws -> SharedSetupImportJournal {
            if initialize { try f.prepare("machine/SharedSetupImport", .sharedSetupImport) }
            return try .init(lease: .init(anchor: f.root.path, relativeDirectory: "machine/SharedSetupImport", owner: getuid(),
                ancestorOwner: getuid(), databaseName: "setup-import.sqlite"), owner: getuid(), macID: inventory.macID,
                installationID: inventory.installationID, initialize: initialize)
        }
        func retain() throws -> SharedSetupImportIntent {
            let intent = try SharedSetupImportIntent(scope: .init(account: account, inventory: inventory), proposal: proposal())
            let journal = try journal(initialize: true); defer { try? journal.close() }; try journal.begin(intent); return intent
        }
        func read() throws -> SetupPortableImportProgress {
            guard let result = try owner.portableImportProgress(callerUID: getuid()) else { throw Interrupted() }
            return result
        }
        func publishRuntime() throws {
            let machine = try f.open(); defer { try? machine.close() }
            let now = Date(), material = try RuntimePreparationMaterial.create(services: services,
                notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
            try machine.retainRuntimeMaterial(material.reference); try machine.completeRuntimePublication(material.reference)
        }
    }
    private let limits = try! CBORLimits(maxBytes: 1024, maxDepth: 2, maxItems: 24)
    private func fields(_ progress: SetupPortableImportProgress) throws -> [UInt64: CBORValue] {
        guard case let .map(value) = try DeterministicCBOR.decode(progress.bytes, limits: limits) else { throw Interrupted() }
        return value
    }
    private func reject(_ fields: [UInt64: CBORValue], file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertThrowsError(try SetupPortableImportProgress.decode(DeterministicCBOR.encode(.map(fields), limits: limits)), file: file, line: line)
    }
    func testReadbackWithoutAJournalCreatesNoImportStateAndRoundTripsItsDestination() throws {
        let f = try Fixture(), before = try Data(contentsOf: URL(fileURLWithPath: f.f.root.path + "/machine/installation.sqlite"))
        let progress = try f.read(), decoded = try SetupPortableImportProgress.decode(progress.bytes)
        XCTAssertEqual(decoded, progress); XCTAssertNil(progress.operationID); XCTAssertNil(progress.phase)
        XCTAssertEqual(progress.runtime.accountID, f.account.accountID); XCTAssertEqual(progress.installationID, f.inventory.installationID)
        XCTAssertEqual(progress.releaseDigest, f.inventory.releaseDigest)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.f.root.path + "/machine/SharedSetupImport"))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.f.root.path + "/machine/installation.sqlite")), before)
    }
    func testRetainedReadbackReturnsOnlyDigestsAndLocalIdentity() throws {
        let f = try Fixture(), expected = try f.read(), intent = try f.retain(), progress = try f.read()
        XCTAssertEqual(progress.operationID, intent.operationID); XCTAssertEqual(progress.revision, intent.revision)
        XCTAssertEqual(progress.proposalDigest, intent.proposalDigest); XCTAssertEqual(progress.phase, .retained)
        XCTAssertEqual(progress.recordDigest, Data(SHA256.hash(data: try intent.bytes)))
        XCTAssertNil(try progress.bytes.range(of: Data("synthetic-import-readback-secret".utf8)))
        XCTAssertNil(try progress.bytes.range(of: Data("remozio.example.invalid".utf8)))
        XCTAssertEqual(progress.description, "SetupPortableImportProgress(redacted)")
        XCTAssertEqual(progress.debugDescription, progress.description)
        XCTAssertEqual(try SetupPortableImportProgress.decode(progress.bytes), progress)
        XCTAssertNoThrow(try progress.validateRetention(of: expected, proposalDigest: intent.proposalDigest))
        XCTAssertNoThrow(try progress.validateRetention(of: progress, proposalDigest: intent.proposalDigest))
    }
    func testIncompleteServiceSetupReturnsNoProgressAndCreatesNoJournal() throws {
        let f = try Fixture(servicesComplete: false)
        XCTAssertNil(try f.owner.portableImportProgress(callerUID: getuid()))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.f.root.path + "/machine/SharedSetupImport"))
    }
    func testHeldPartialAndForeignJournalsAreErrorsInsteadOfAnAbsentImport() throws {
        let f = try Fixture(); _ = try f.retain()
        let held = try f.journal()
        XCTAssertThrowsError(try f.read()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }; try held.close()
        let directory = f.f.root.path + "/machine/SharedSetupImport"
        XCTAssertEqual(unlink(directory + "/writer.lock"), 0)
        XCTAssertThrowsError(try f.read())
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory + "/writer.lock"))
        let g = try Fixture(); try g.f.prepare("machine/SharedSetupImport", .sharedSetupImport)
        let foreign = try SharedSetupImportJournal(lease: .init(anchor: g.f.root.path, relativeDirectory: "machine/SharedSetupImport",
            owner: getuid(), ancestorOwner: getuid(), databaseName: "setup-import.sqlite"), owner: getuid(),
            macID: g.inventory.macID, installationID: Data(repeating: 45, count: 16), initialize: true)
        try foreign.close(); XCTAssertThrowsError(try g.read())
    }
    func testAdvancedPhaseRequiresPublishedRuntimeAndChangesTheReadbackDigest() throws {
        let f = try Fixture(), retained = try f.retain(), before = try f.read()
        let journal = try f.journal(); let advanced = try journal.advance(retained, to: .runtimePublished); try journal.close()
        XCTAssertThrowsError(try f.read())
        try f.publishRuntime()
        let after = try f.read()
        XCTAssertEqual(after.phase, .runtimePublished); XCTAssertTrue(after.runtime.configurationPublished)
        XCTAssertEqual(after.operationID, before.operationID); XCTAssertEqual(after.revision, advanced.revision)
        XCTAssertNotEqual(after.recordDigest, before.recordDigest)
        XCTAssertThrowsError(try after.validateRetention(of: before, proposalDigest: retained.proposalDigest))
    }
    func testDecoderRejectsPartialOperationUnknownFieldsVersionsAndMalformedNestedRuntime() throws {
        let f = try Fixture(); _ = try f.retain(); let original = try fields(f.read())
        var changed = original; changed[0] = .unsigned(2); try reject(changed)
        changed = original; changed[9] = .boolean(true); try reject(changed)
        changed = original; changed[1] = .bytes(Data([1])); try reject(changed)
        for key in [UInt64(2), 3, 4, 5, 6, 8] {
            changed = original; changed[key] = .bytes(Data([1])); try reject(changed)
        }
        for key in UInt64(4)...8 { changed = original; changed[key] = .null; try reject(changed) }
        changed = original; changed[7] = .unsigned(5); try reject(changed)
        changed = original; changed[7] = .unsigned(1); try reject(changed)
    }
    func testRetentionReplyCannotSubstituteTheDestinationOrReviewedDigest() throws {
        let f = try Fixture(), expected = try f.read(), retained = try f.retain(), progress = try f.read()
        let other = try Fixture()
        XCTAssertThrowsError(try progress.validateRetention(of: other.read(), proposalDigest: retained.proposalDigest))
        XCTAssertThrowsError(try progress.validateRetention(of: expected, proposalDigest: Data(repeating: 1, count: 32)))
        XCTAssertThrowsError(try expected.validateRetention(of: progress, proposalDigest: retained.proposalDigest))
        var changed = try fields(progress); changed[2] = .bytes(Data(repeating: 1, count: 16))
        let foreign = try SetupPortableImportProgress.decode(DeterministicCBOR.encode(.map(changed), limits: limits))
        XCTAssertThrowsError(try foreign.validateRetention(of: expected, proposalDigest: retained.proposalDigest))
    }
    func testClosedOwnerCannotContinueToReadProgress() throws {
        let f = try Fixture(); _ = try f.read(); try f.owner.close()
        XCTAssertThrowsError(try f.read())
    }
}
