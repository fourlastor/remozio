import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class SharedSetupImportRecordTests: XCTestCase {
    private static let syntheticPEM = Result { () throws -> String in
        let process = Process(), output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run()
        let bytes = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw PortableSetupError.rejected }
        return String(decoding: bytes, as: UTF8.self)
    }
    private final class Fixture {
        let files: AccountPreparationFixture
        let account: AccountPreparationIntent
        let inventory: InstallationInventory
        let services: ServiceAccountPlanStorage.State
        let runtime: RuntimePreparationState
        let scope: SharedSetupImportIntent.Scope
        init() throws {
            files = try .init()
            let machine = try files.open(initialize: true)
            defer { try? machine.close() }
            account = try files.resume(machine, files.begin(machine))
            let plan = try ServiceAccountPlan(account: account, planID: AccountPreparationIntent.randomID(), claims: [
                .init(accountID: account.accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
                .init(accountID: account.accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())])
            try machine.retainServiceAccountPlan(plan)
            try machine.completeServiceAccountPlan(plan)
            inventory = try XCTUnwrap(machine.inventory())
            services = try machine.serviceAccountPlan(accountID: account.accountID)
            runtime = try machine.runtimePreparation(accountID: account.accountID)
            scope = try .init(account: account, inventory: inventory)
        }
        func proposal(token: String = "synthetic-provisioning-token", preferences: Bool = true) throws -> PortableSetup {
            try .init(defaults: .init(presence: .init(idleMilliseconds: 420_000, observationLifetimeMilliseconds: 5000,
                unavailableGraceMilliseconds: 30_000), gateway: GatewaySetupForm().settingsSelection()),
                cloudflare: .init(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
                    dnsSuffix: "remozio.example.invalid", apiToken: token),
                appPreferences: preferences ? .init(preferences: [PortableAppPreferences.menuBarKey: false]) : nil)
        }
        func intent() throws -> SharedSetupImportIntent { try .init(scope: scope, proposal: proposal()) }
        func progress(_ intent: SharedSetupImportIntent? = nil) throws -> SetupPortableImportProgress {
            try .init(account: account, inventory: inventory, services: services, runtime: runtime, retained: intent)
        }
    }
    private let limits = try! CBORLimits(maxBytes: 70_000, maxDepth: 2, maxItems: 40)
    private let progressLimits = try! CBORLimits(maxBytes: 1024, maxDepth: 2, maxItems: 24)
    private let recipeLimits = try! CBORLimits(maxBytes: 68_000, maxDepth: 3, maxItems: 32)
    private func fields(_ bytes: Data, _ limits: CBORLimits) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits) else {
            throw SharedSetupImportError.invalidRecord
        }
        return fields
    }
    private func rejectIntent(_ fields: [UInt64: CBORValue], file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertThrowsError(try SharedSetupImportIntent.decode(DeterministicCBOR.encode(.map(fields), limits: limits)), file: file, line: line)
    }
    private func rejectProgress(_ fields: [UInt64: CBORValue], file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertThrowsError(try SetupPortableImportProgress.decode(DeterministicCBOR.encode(.map(fields), limits: progressLimits)), file: file, line: line)
    }
    func testCanonicalIntentBindsThePreparedDestinationAndExcludesProviderSecrets() throws {
        let f = try Fixture(), intent = try f.intent(), decoded = try SharedSetupImportIntent.decode(intent.bytes)
        XCTAssertEqual(decoded, intent)
        XCTAssertEqual(decoded.scope.macID, f.account.macID)
        XCTAssertEqual(decoded.scope.installationID, f.account.installationID)
        XCTAssertEqual(decoded.scope.accountID, f.account.accountID)
        XCTAssertEqual(decoded.scope.ownerUID, f.account.ownerUID)
        XCTAssertEqual(decoded.scope.accountBinding, Data(SHA256.hash(data: try f.account.bytes)))
        XCTAssertEqual(decoded.description, "SharedSetupImportIntent(redacted)")
        XCTAssertEqual(decoded.debugDescription, decoded.description)
        for bytes in [try decoded.bytes, try decoded.recipe.bytes] {
            XCTAssertNil(bytes.range(of: Data("synthetic-provisioning-token".utf8)))
        }
        XCTAssertNil(try decoded.recipe.settings.cloudflare)
        XCTAssertEqual(decoded.recipe.cloudflare?.dnsSuffix, "remozio.example.invalid")
        XCTAssertEqual(try decoded.recipe.settings.appPreferences, try f.proposal().appPreferences)
    }
    func testRecoveryRequiresTheExactReopenedProposalIncludingCredentialsAndPreferences() throws {
        let f = try Fixture(), intent = try f.intent()
        XCTAssertTrue(try intent.matches(f.proposal()))
        XCTAssertFalse(try intent.matches(f.proposal(token: "another-synthetic-token")))
        XCTAssertFalse(try intent.matches(f.proposal(preferences: false)))
    }
    func testUnpreparedAccountsAndForeignInventoryCannotSupplyDestinationScope() throws {
        let f = try AccountPreparationFixture(), machine = try f.open(initialize: true)
        defer { try? machine.close() }
        let pending = try f.begin(machine), inventory = try XCTUnwrap(machine.inventory())
        XCTAssertThrowsError(try SharedSetupImportIntent.Scope(account: pending, inventory: inventory))
        let account = try f.resume(machine, pending), current = try XCTUnwrap(machine.inventory())
        let foreign = try InstallationInventory(macID: current.macID, installationID: Data(repeating: 0x72, count: 16),
            revision: current.revision, bundlePath: current.bundlePath, releaseDigest: current.releaseDigest,
            accounts: current.accounts, services: current.services, formatVersion: current.formatVersion)
        XCTAssertThrowsError(try SharedSetupImportIntent.Scope(account: account, inventory: foreign))
    }
    func testIntentRejectsMalformedScopeUnknownFieldsVersionsAndPhases() throws {
        let f = try Fixture(), original = try fields(f.intent().bytes, limits)
        for (key, value): (UInt64, CBORValue) in [
            (0, .unsigned(1)), (1, .text("another-purpose")), (6, .unsigned(0)),
            (6, .unsigned(UInt64(UInt32.max))), (10, .unsigned(5)), (13, .unsigned(3)), (14, .text("foreign-authority")),
        ] {
            var changed = original; changed[key] = value; try rejectIntent(changed)
        }
        for key in [UInt64(2), 3, 4, 5, 7, 8, 9, 12] {
            var changed = original; changed[key] = .bytes(Data([1])); try rejectIntent(changed)
        }
        for key in original.keys {
            var changed = original; changed.removeValue(forKey: key); try rejectIntent(changed)
        }
    }
    func testNestedRecipeCannotRetainCredentialsOrAddAuthorityFields() throws {
        let f = try Fixture(), intent = try f.intent(), original = try fields(intent.bytes, limits)
        let recipe = try fields(intent.recipe.bytes, recipeLimits)
        var changedRecipe = recipe
        changedRecipe[1] = .bytes(try f.proposal().canonicalBytes())
        var changed = original; changed[11] = .bytes(try DeterministicCBOR.encode(.map(changedRecipe), limits: recipeLimits))
        try rejectIntent(changed)
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (2, .text("..")), (5, .text("foreign-grant"))] {
            changedRecipe = recipe; changedRecipe[key] = value
            changed = original; changed[11] = .bytes(try DeterministicCBOR.encode(.map(changedRecipe), limits: recipeLimits))
            try rejectIntent(changed)
        }
    }
    func testMarkersAdvanceInOrderAndKeepTheReviewedOperation() throws {
        let f = try Fixture(), first = try f.intent(); var current = first
        XCTAssertThrowsError(try first.advanced(to: .rootComplete))
        for phase in [SharedSetupImportIntent.Phase.runtimePublished, .gatewayPrepared, .relayPrepared, .rootComplete] {
            let next = try current.advanced(to: phase)
            XCTAssertNotEqual(next.revision, current.revision)
            XCTAssertEqual(next.operationID, first.operationID)
            XCTAssertEqual(next.scope, first.scope)
            XCTAssertEqual(next.proposalDigest, first.proposalDigest)
            XCTAssertEqual(next.recipe, first.recipe)
            current = next
        }
        XCTAssertThrowsError(try current.advanced(to: .retained))
    }
    func testFirebaseRecoveryKeepsOriginalVersionAndExcludesThePrivateKey() throws {
        let f = try Fixture(), base = try f.proposal(), pem = try Self.syntheticPEM.get()
        func proposal(_ keyID: String) throws -> PortableSetup {
            try .init(defaults: base.defaults,
                fcm: .init(project: "synthetic-project", clientEmail: "fixture@fixture.iam.gserviceaccount.com",
                    privateKeyID: keyID, privateKeyPEM: pem),
                pushClient: .init(projectID: "synthetic-project", senderID: "123456789", packageName: "dev.remozio.android"))
        }
        let selected = try proposal("synthetic-private-key-id")
        let intent = try SharedSetupImportIntent(scope: f.scope, proposal: selected)
        let decoded = try SharedSetupImportIntent.decode(intent.bytes)
        XCTAssertEqual(decoded.originalPortableVersion, 3)
        XCTAssertEqual(try decoded.recipe.settingsVersion, 2)
        XCTAssertEqual(decoded.recipe.pushClient, selected.pushClient)
        XCTAssertEqual(decoded.recipe.firebaseProject, "synthetic-project")
        XCTAssertTrue(try decoded.matches(selected))
        XCTAssertFalse(try decoded.matches(proposal("another-key-id")))
        let keyBody = try XCTUnwrap(pem.split(separator: "\n").first { !$0.hasPrefix("-----") })
        for bytes in [try decoded.bytes, try decoded.recipe.bytes] {
            for secret in ["synthetic-private-key-id", "fixture@fixture.iam.gserviceaccount.com", "-----BEGIN PRIVATE KEY-----", String(keyBody)] {
                XCTAssertNil(bytes.range(of: Data(secret.utf8)))
            }
        }
    }
    func testProgressCarriesOnlyDestinationAndExactRecordDigests() throws {
        let f = try Fixture(), before = try f.progress(), intent = try f.intent(), retained = try f.progress(intent)
        XCTAssertNil(before.operationID); XCTAssertNil(before.phase)
        XCTAssertEqual(retained.recordDigest, Data(SHA256.hash(data: try intent.bytes)))
        XCTAssertEqual(retained.operationID, intent.operationID)
        XCTAssertEqual(retained.revision, intent.revision)
        XCTAssertEqual(retained.proposalDigest, intent.proposalDigest)
        XCTAssertEqual(retained.phase, .retained)
        XCTAssertEqual(try SetupPortableImportProgress.decode(retained.bytes), retained)
        XCTAssertNil(try retained.bytes.range(of: Data("synthetic-provisioning-token".utf8)))
        XCTAssertNil(try retained.bytes.range(of: Data("remozio.example.invalid".utf8)))
        XCTAssertNoThrow(try retained.validateRetention(of: before, proposalDigest: intent.proposalDigest))
        XCTAssertNoThrow(try retained.validateRetention(of: retained, proposalDigest: intent.proposalDigest))
    }
    func testRetentionReplyCannotSubstituteDestinationDigestOrOperation() throws {
        let f = try Fixture(), g = try Fixture(), before = try f.progress(), intent = try f.intent()
        let retained = try f.progress(intent)
        XCTAssertThrowsError(try retained.validateRetention(of: g.progress(), proposalDigest: intent.proposalDigest))
        XCTAssertThrowsError(try retained.validateRetention(of: before, proposalDigest: Data(repeating: 1, count: 32)))
        XCTAssertThrowsError(try before.validateRetention(of: retained, proposalDigest: intent.proposalDigest))
        XCTAssertThrowsError(try f.progress(g.intent()))
        let other = try f.progress(f.intent())
        XCTAssertThrowsError(try other.validateRetention(of: retained, proposalDigest: intent.proposalDigest))
    }
    func testProgressRejectsPartialOperationsAndMalformedNestedRecords() throws {
        let f = try Fixture(), original = try fields(f.progress(f.intent()).bytes, progressLimits)
        for key in UInt64(4)...8 {
            var changed = original; changed[key] = .null; try rejectProgress(changed)
        }
        for (key, value): (UInt64, CBORValue) in [
            (0, .unsigned(2)), (1, .bytes(Data([1]))), (7, .unsigned(5)), (9, .boolean(true)),
        ] {
            var changed = original; changed[key] = value; try rejectProgress(changed)
        }
        for key in [UInt64(2), 3, 4, 5, 6, 8] {
            var changed = original; changed[key] = .bytes(Data([1])); try rejectProgress(changed)
        }
    }
    func testUnpublishedRuntimeCannotClaimAdvancedImportPhases() throws {
        let f = try Fixture(), intent = try f.intent(), advanced = try intent.advanced(to: .runtimePublished)
        XCTAssertFalse(f.runtime.configurationPublished)
        XCTAssertThrowsError(try f.progress(advanced))
        var encoded = try fields(f.progress(intent).bytes, progressLimits)
        encoded[7] = .unsigned(SetupPortableImportProgress.Phase.runtimePublished.rawValue)
        try rejectProgress(encoded)
    }
    func testRecordAndProgressRejectTrailingOrOversizedInput() throws {
        let f = try Fixture(), intent = try f.intent(), progress = try f.progress(intent)
        XCTAssertThrowsError(try SharedSetupImportIntent.decode(intent.bytes + Data([0])))
        XCTAssertThrowsError(try SharedSetupImportIntent.decode(Data(repeating: 0, count: SharedSetupImportIntent.maximumBytes + 1)))
        XCTAssertThrowsError(try SetupPortableImportProgress.decode(progress.bytes + Data([0])))
        XCTAssertThrowsError(try SetupPortableImportProgress.decode(Data(repeating: 0, count: SetupPortableImportProgress.maximumByteCount + 1)))
    }
}
