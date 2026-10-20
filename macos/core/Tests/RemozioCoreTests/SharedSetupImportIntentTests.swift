import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class SharedSetupImportIntentTests: XCTestCase {
    private static let pem = Result { () throws -> String in
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        try process.run()
        let bytes = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw PortableSetupError.rejected }
        return String(decoding: bytes, as: UTF8.self)
    }
    private func providerProposal(_ fixture: SharedSetupImportFixture, token: String = "synthetic-provider-token-only",
                                  keyID: String = "synthetic-private-key-id", preferences: Bool = true) throws -> PortableSetup {
        let base = try fixture.proposal()
        return try .init(defaults: base.defaults,
            fcm: .init(project: "synthetic-project", clientEmail: "fixture@fixture.iam.gserviceaccount.com",
                privateKeyID: keyID, privateKeyPEM: Self.pem.get()),
            cloudflare: .init(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
                dnsSuffix: "remozio.example.invalid", apiToken: token),
            pushClient: .init(projectID: "synthetic-project", senderID: "123456789", packageName: "dev.remozio.android"),
            appPreferences: preferences ? base.appPreferences : nil)
    }
    private let limits = try! CBORLimits(maxBytes: 70_000, maxDepth: 2, maxItems: 40)
    private func fields(_ intent: SharedSetupImportIntent) throws -> [UInt64: CBORValue] {
        guard case let .map(fields) = try DeterministicCBOR.decode(intent.bytes, limits: limits) else { throw SharedSetupImportError.invalidRecord }
        return fields
    }
    private func reject(_ fields: [UInt64: CBORValue], file: StaticString = #filePath, line: UInt = #line) throws {
        let bytes = try DeterministicCBOR.encode(.map(fields), limits: limits)
        XCTAssertThrowsError(try SharedSetupImportIntent.decode(bytes), file: file, line: line)
    }
    func testCanonicalRecordPreservesPublicChoicesAndLocalBinding() throws {
        let f = try SharedSetupImportFixture(), intent = try f.intent(), decoded = try SharedSetupImportIntent.decode(intent.bytes)
        XCTAssertEqual(decoded, intent); XCTAssertEqual(try decoded.matches(f.proposal()), true)
        XCTAssertEqual(decoded.scope.macID, f.account.macID); XCTAssertEqual(decoded.scope.installationID, f.account.installationID)
        XCTAssertEqual(decoded.scope.accountID, f.account.accountID); XCTAssertEqual(decoded.scope.ownerUID, f.account.ownerUID)
        XCTAssertEqual(decoded.phase, .retained); XCTAssertEqual(decoded.proposalDigest.count, 32)
        XCTAssertEqual(decoded.description, "SharedSetupImportIntent(redacted)"); XCTAssertEqual(decoded.debugDescription, decoded.description)
    }
    func testOnlyPreparedLocalAccountAndMatchingInventoryCanConstructScope() throws {
        let f = try AccountPreparationFixture(), machine = try f.open(initialize: true)
        defer { try? machine.close() }
        let pending = try f.begin(machine), inventory = try XCTUnwrap(machine.inventory())
        XCTAssertThrowsError(try SharedSetupImportIntent.Scope(account: pending, inventory: inventory)) { XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope) }
        let account = try f.resume(machine, pending), current = try XCTUnwrap(machine.inventory())
        _ = try SharedSetupImportIntent.Scope(account: account, inventory: current)
        let other = try InstallationInventory(macID: current.macID, installationID: Data(repeating: 21, count: 16),
            revision: current.revision, bundlePath: current.bundlePath, releaseDigest: current.releaseDigest,
            accounts: current.accounts, services: current.services, formatVersion: current.formatVersion)
        XCTAssertThrowsError(try SharedSetupImportIntent.Scope(account: account, inventory: other)) { XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope) }
    }
    func testDecoderRejectsUnknownVersionPurposeFieldPhaseAndMalformedLocalScope() throws {
        let f = try SharedSetupImportFixture(), original = try fields(f.intent())
        var changed = original; changed[0] = .unsigned(1); try reject(changed)
        changed = original; changed[1] = .text("other-purpose"); try reject(changed)
        changed = original; changed[14] = .unsigned(1); try reject(changed)
        changed = original; changed[10] = .unsigned(5); try reject(changed)
        for key in [UInt64(2), 3, 4, 5, 7, 8, 9, 12] { changed = original; changed[key] = .bytes(Data([1])); try reject(changed) }
        changed = original; changed[6] = .unsigned(0); try reject(changed)
        changed = original; changed[6] = .unsigned(UInt64(UInt32.max)); try reject(changed)
        changed = original; changed.removeValue(forKey: 11); try reject(changed)
    }
    func testDecoderRevalidatesNestedSetupAndNeverAcceptsUnscopedAuthorityFields() throws {
        let f = try SharedSetupImportFixture(), intent = try f.intent()
        let recipeLimits = try CBORLimits(maxBytes: 68_000, maxDepth: 3, maxItems: 32)
        let setupLimits = try CBORLimits(maxBytes: 65_536, maxDepth: 4, maxItems: 128)
        guard case let .map(recipe) = try DeterministicCBOR.decode(intent.recipe.bytes, limits: recipeLimits),
              case var .map(setup) = try DeterministicCBOR.decode(intent.recipe.settings.canonicalBytes(), limits: setupLimits) else {
            return XCTFail("Missing recipe")
        }
        setup[30] = .text("foreign-account-or-identity")
        var changedRecipe = recipe; changedRecipe[1] = .bytes(try DeterministicCBOR.encode(.map(setup), limits: setupLimits))
        var changed = try fields(intent); changed[11] = .bytes(try DeterministicCBOR.encode(.map(changedRecipe), limits: recipeLimits))
        try reject(changed)
        // A valid portable proposal with credentials is still forbidden inside a recovery recipe.
        changedRecipe = recipe; changedRecipe[1] = .bytes(try providerProposal(f).canonicalBytes())
        changed[11] = .bytes(try DeterministicCBOR.encode(.map(changedRecipe), limits: recipeLimits)); try reject(changed)
        for key in [UInt64(0), 2, 3, 4, 5] {
            changedRecipe = recipe; changedRecipe[key] = .bytes(Data([1]))
            changed[11] = .bytes(try DeterministicCBOR.encode(.map(changedRecipe), limits: recipeLimits)); try reject(changed)
        }
        changed = try fields(intent); changed[13] = .unsigned(3); try reject(changed)
    }
    func testRecoveryBytesExcludeCredentialsAndRequireExactReopenedProposal() throws {
        let f = try SharedSetupImportFixture(), proposal = try providerProposal(f)
        let intent = try SharedSetupImportIntent(scope: f.scope, proposal: proposal)
        let journal = try f.open(initialize: true)
        try journal.begin(intent)
        let retained = try journal.advance(intent, to: .runtimePublished)
        try journal.close()
        let reopened = try f.open(); defer { try? reopened.close() }
        let current = try XCTUnwrap(reopened.current(scope: f.scope))
        XCTAssertEqual(current, retained); XCTAssertTrue(try current.matches(proposal))
        XCTAssertFalse(try current.matches(providerProposal(f, token: "different-synthetic-token")))
        XCTAssertFalse(try current.matches(providerProposal(f, keyID: "different-key-id")))
        XCTAssertFalse(try current.matches(providerProposal(f, preferences: false)))
        XCTAssertEqual(current.recipe.firebaseProject, proposal.fcm?.project)
        XCTAssertEqual(current.recipe.pushClient, proposal.pushClient)
        XCTAssertEqual(current.recipe.cloudflare?.zoneID, proposal.cloudflare?.zoneID)
        XCTAssertEqual(try current.recipe.settings.appPreferences, proposal.appPreferences)
        let keyBody = try XCTUnwrap(Self.pem.get().split(separator: "\n").first { !$0.hasPrefix("-----") })
        let secrets = ["synthetic-provider-token-only", "synthetic-private-key-id", "fixture@fixture.iam.gserviceaccount.com",
                       "-----BEGIN PRIVATE KEY-----", String(keyBody)]
        var blobs = [try current.bytes, try current.recipe.bytes]
        for name in try FileManager.default.contentsOfDirectory(atPath: f.accountFixture.root.path + "/imports") {
            blobs.append(try Data(contentsOf: URL(fileURLWithPath: f.accountFixture.root.path + "/imports/" + name)))
        }
        for bytes in blobs { for secret in secrets { XCTAssertNil(bytes.range(of: Data(secret.utf8))) } }
    }
    func testRecipeAndOriginalPortableVersionsRemainDistinct() throws {
        let f = try SharedSetupImportFixture(), proposal = try providerProposal(f, preferences: false)
        let intent = try SharedSetupImportIntent(scope: f.scope, proposal: proposal)
        XCTAssertEqual(intent.originalPortableVersion, 3); XCTAssertEqual(try intent.recipe.settingsVersion, 2)
        let decoded = try SharedSetupImportIntent.decode(intent.bytes)
        XCTAssertEqual(decoded.originalPortableVersion, 3); XCTAssertEqual(try decoded.recipe.settingsVersion, 2)
        XCTAssertTrue(try decoded.matches(proposal))
        let g = try SharedSetupImportFixture(relativeDirectory: "machine/SharedSetupImport")
        let retained = try SharedSetupImportIntent(scope: g.scope, proposal: proposal)
        let journal = try g.open(initialize: true); try journal.begin(retained); try journal.close()
        let machine = try g.accountFixture.open(); defer { try? machine.close() }
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: machine)
        let portable = try XCTUnwrap(snapshot.requirements.formats.first { $0.name == PortableSetup.formatName })
        XCTAssertEqual(portable.readVersions, [2, 3]); XCTAssertEqual(portable.writeVersions, [2, 3])
    }
    func testOrderedMarkersRetainProposalAndOperationWhileChangingRevision() throws {
        let f = try SharedSetupImportFixture(), first = try f.intent(); var current = first
        XCTAssertThrowsError(try first.advanced(to: .rootComplete)) { XCTAssertEqual($0 as? SharedSetupImportError, .invalidTransition) }
        for phase in [SharedSetupImportIntent.Phase.runtimePublished, .gatewayPrepared, .relayPrepared, .rootComplete] {
            let next = try current.advanced(to: phase)
            XCTAssertNotEqual(next.revision, current.revision); XCTAssertEqual(next.operationID, first.operationID)
            XCTAssertEqual(next.scope, first.scope); XCTAssertEqual(next.proposalDigest, first.proposalDigest)
            XCTAssertEqual(next.recipe, first.recipe); current = next
        }
        XCTAssertThrowsError(try current.advanced(to: .retained)) { XCTAssertEqual($0 as? SharedSetupImportError, .invalidTransition) }
    }
}
