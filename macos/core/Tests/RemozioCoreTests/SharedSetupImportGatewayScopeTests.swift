import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Synthetic retained records exercise admission. They do not prove administrator rights or native provider custody.
final class SharedSetupImportGatewayScopeTests: XCTestCase, @unchecked Sendable {
    private struct Interrupted: Error {}
    private static let pem = Result { () throws -> String in
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        try process.run(); let bytes = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw Interrupted() }; return String(decoding: bytes, as: UTF8.self)
    }
    private final class Fixture {
        let runtime: RuntimeActivationFixture
        let proposal: PortableSetup
        let expected: SharedSetupImportIntent
        init(phase: SharedSetupImportIntent.Phase = .runtimePublished, provider: Bool = true) throws {
            runtime = try .init()
            try runtime.machine.retainRuntimeActivation(runtime.plan)
            _ = try runtime.machine.enrollRuntimeActivation(runtime.plan)
            try runtime.machine.markRuntimeJobsRegistered(runtime.plan)
            let defaults = try SharedSetupDefaults(presence: runtime.plan.host.command.presence.presence.policy,
                gateway: GatewaySetupForm().settingsSelection())
            let fcm = provider ? try SetupFCMConfiguration(project: "fixture-project", clientEmail: "fixture@fixture.iam.gserviceaccount.com",
                privateKeyID: "fixture", privateKeyPEM: pem.get()) : nil
            let push = provider ? try SetupPushClientConfiguration(projectID: "fixture-project", senderID: "123", packageName: "dev.remozio.android") : nil
            proposal = try .init(defaults: defaults, fcm: fcm,
                cloudflare: .init(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
                    dnsSuffix: "remozio.example.invalid", apiToken: "synthetic-original-scope-token"), pushClient: push)
            var retained = try SharedSetupImportIntent(scope: .init(account: runtime.account, inventory: XCTUnwrap(runtime.machine.inventory())), proposal: proposal)
            try runtime.f.prepare("machine/SharedSetupImport", .sharedSetupImport)
            let journal = try SharedSetupImportJournal(lease: .init(anchor: runtime.f.root.path, relativeDirectory: "machine/SharedSetupImport",
                owner: getuid(), ancestorOwner: getuid(), databaseName: "setup-import.sqlite"), owner: getuid(),
                macID: runtime.account.macID, installationID: runtime.account.installationID, initialize: true)
            try journal.begin(retained)
            while retained.phase != phase {
                let next = SharedSetupImportIntent.Phase(rawValue: retained.phase.rawValue + 1)!
                retained = try journal.advance(retained, to: next)
            }
            try journal.close(); expected = retained
        }
        func run<Value>(proposal: PortableSetup? = nil, custody: Bool = true, expected: SharedSetupImportIntent? = nil,
                        verify: () throws -> Void = {},
                        operation: (GatewaySetupPreparationChoices?, () throws -> Void, SharedSetupImportJournal) throws -> Value) throws -> Value {
            try runtime.machine.withSharedImportJournal { journal in
                guard let journal else { throw Interrupted() }
                return try SharedSetupImportGatewayScope.withReviewedPreparation(machine: runtime.machine, account: runtime.account,
                    journal: journal, expected: expected ?? self.expected, proposal: proposal ?? self.proposal,
                    fileWakeCustodyAccepted: custody, verifyCurrent: verify) { choices, verify in
                    try withoutActuallyEscaping(verify) { current in try operation(choices, current, journal) }
                }
            }
        }
    }
    func testLegacyPreparationWithoutAnImportCreatesNoJournalAndPreservesForegroundState() throws {
        let f = try RuntimeActivationFixture(), before = try f.machine.runtimePreparation(accountID: f.account.accountID)
        XCTAssertNoThrow(try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: f.machine, account: f.account))
        XCTAssertEqual(try f.machine.runtimePreparation(accountID: f.account.accountID), before)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.f.root.path + "/machine/SharedSetupImport"))
    }
    func testEveryPendingPhaseRefusesLegacyMutationAndCompletionDoesNotDisableFutureSettings() throws {
        for phase in [SharedSetupImportIntent.Phase.retained, .runtimePublished, .gatewayPrepared, .relayPrepared, .rootComplete] {
            let f = try Fixture(phase: phase)
            if phase == .rootComplete {
                XCTAssertNoThrow(try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: f.runtime.machine, account: f.runtime.account))
            } else {
                XCTAssertThrowsError(try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: f.runtime.machine, account: f.runtime.account)) {
                    XCTAssertEqual($0 as? SharedSetupImportError, .conflict)
                }
            }
        }
    }
    func testReviewedProviderChoicesReachOnlyTheExplicitOperationWithoutAdvancingTheMarker() throws {
        let f = try Fixture(); var entered = 0
        let result = try f.run { choices, verify, journal in
            let selected = try XCTUnwrap(choices); try verify(); entered += 1
            XCTAssertEqual(try selected.provider.gatewayCredentialJSON(), try f.proposal.fcm?.gatewayCredentialJSON())
            XCTAssertEqual(selected.senderID, "123"); XCTAssertTrue(selected.fileWakeCustodyAccepted)
            XCTAssertEqual(try selected.settings.setupBytes, try f.proposal.defaults.gateway?.service.setupBytes)
            XCTAssertEqual(try journal.current(scope: f.expected.scope), f.expected); return 23
        }
        XCTAssertEqual(result, 23); XCTAssertEqual(entered, 1)
        try f.runtime.machine.withSharedImportJournal { journal in XCTAssertEqual(try journal?.current(scope: f.expected.scope), f.expected) }
    }
    func testChangedCredentialWithTheSamePublicRecipeCannotReachTheOperation() throws {
        let f = try Fixture(); var entered = 0
        let altered = try PortableSetup(defaults: f.proposal.defaults, fcm: f.proposal.fcm,
            cloudflare: .init(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
                dnsSuffix: "remozio.example.invalid", apiToken: "different-synthetic-scope-token"), pushClient: f.proposal.pushClient)
        XCTAssertEqual(try SharedSetupImportIntent.Recipe(proposal: altered), f.expected.recipe)
        XCTAssertThrowsError(try f.run(proposal: altered) { _, _, _ in entered += 1 }) { XCTAssertEqual($0 as? SharedSetupImportError, .conflict) }
        XCTAssertEqual(entered, 0)
    }
    func testPartialAndMismatchedProviderInputsAreRejected() throws {
        let f = try Fixture(), selected = f.proposal
        let mismatched = try SetupPushClientConfiguration(projectID: "another-project", senderID: "123", packageName: "dev.remozio.android")
        let noGateway = SharedSetupDefaults(presence: selected.defaults.presence, wake: selected.defaults.wake, delivery: selected.defaults.delivery)
        for proposal in [PortableSetup(defaults: selected.defaults, fcm: selected.fcm),
                         PortableSetup(defaults: selected.defaults, pushClient: selected.pushClient),
                         PortableSetup(defaults: selected.defaults, fcm: selected.fcm, pushClient: mismatched),
                         PortableSetup(defaults: noGateway, fcm: selected.fcm, pushClient: selected.pushClient)] {
            XCTAssertThrowsError(try proposal.gatewayPreparationChoices(fileWakeCustodyAccepted: true)) {
                guard case PortableSetupError.rejected = $0 else { return XCTFail("Expected rejected portable setup") }
            }
        }
    }
    func testProviderCustodyAndTheRuntimePhaseAreRequiredBeforeTheOperation() throws {
        let f = try Fixture(); var entered = 0
        XCTAssertThrowsError(try f.run(custody: false) { _, _, _ in entered += 1 }) { XCTAssertEqual($0 as? GatewayPreparationError, .custodyNotAccepted) }
        for phase in [SharedSetupImportIntent.Phase.retained, .gatewayPrepared, .relayPrepared, .rootComplete] {
            let other = try Fixture(phase: phase)
            XCTAssertThrowsError(try other.run { _, _, _ in entered += 1 }) { XCTAssertEqual($0 as? SharedSetupImportError, .invalidTransition) }
        }
        XCTAssertEqual(entered, 0)
    }
    func testNoSelectedProviderDoesNotInventOneOrRequireProviderFileCustody() throws {
        let f = try Fixture(provider: false); var entered = 0
        try f.run(custody: false) { choices, verify, _ in try verify(); XCTAssertNil(choices); entered += 1 }
        XCTAssertEqual(entered, 1)
    }
    func testScopeChangesAndLostRepliesNeverRepeatTheOperationOrAdvanceItsMarker() throws {
        let f = try Fixture(); var entered = 0
        XCTAssertThrowsError(try f.run(verify: { throw Interrupted() }) { _, _, _ in entered += 1 })
        XCTAssertEqual(entered, 0)
        XCTAssertThrowsError(try f.run { _, verify, _ in try verify(); entered += 1; throw Interrupted() })
        XCTAssertEqual(entered, 1)
        try f.runtime.machine.withSharedImportJournal { journal in XCTAssertEqual(try journal?.current(scope: f.expected.scope), f.expected) }
        XCTAssertThrowsError(try f.run { _, verify, journal in
            entered += 1; _ = try journal.advance(f.expected, to: .gatewayPrepared); try verify()
        }) { XCTAssertEqual($0 as? SharedSetupImportError, .staleRevision) }
        XCTAssertEqual(entered, 2)
    }
    private func insertPendingImport(_ h: GatewaySettingsSetupOwnerTests.Harness) throws {
        let f = h.ready.fixture.runtime.f, account = h.ready.fixture.runtime.account
        let machine = try f.open(); defer { try? machine.close() }
        let proposal = PortableSetup(defaults: .init(presence: h.ready.fixture.runtime.plan.host.command.presence.presence.policy,
            gateway: try GatewaySetupForm().settingsSelection()))
        let intent = try SharedSetupImportIntent(scope: .init(account: account, inventory: XCTUnwrap(machine.inventory())), proposal: proposal)
        try f.prepare("machine/SharedSetupImport", .sharedSetupImport)
        let journal = try SharedSetupImportJournal(lease: .init(anchor: f.root.path, relativeDirectory: "machine/SharedSetupImport",
            owner: getuid(), ancestorOwner: getuid(), databaseName: "setup-import.sqlite"), owner: getuid(),
            macID: account.macID, installationID: account.installationID, initialize: true)
        defer { try? journal.close() }; try journal.begin(intent); _ = try journal.advance(intent, to: .runtimePublished)
    }
    func testLegacyOwnerSettingsRetentionDoesNotOverwriteAPendingImport() throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), before = try h.read(); try insertPendingImport(h)
        XCTAssertThrowsError(try h.owner.retainGatewaySettings(callerUID: getuid(), expected: before, selection: h.selection)) {
            XCTAssertEqual($0 as? SharedSetupImportError, .conflict)
        }
        XCTAssertEqual(try h.read(), before); XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
    }
    func testLegacyOwnerSettingsResumeCannotEnterItsBackendWhileAnImportIsPending() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), pending = try h.retain(); try insertPendingImport(h)
        do { _ = try await h.owner.resumeGatewaySettings(callerUID: getuid(), expected: pending); XCTFail() }
        catch { XCTAssertEqual(error as? SharedSetupImportError, .conflict) }
        XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0); XCTAssertEqual(try h.read(), pending)
    }
}
