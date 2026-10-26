import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Synthetic registration state and owned publication test completion contracts. This is not native launchd evidence.
final class SharedSetupRelayCompletionTests: XCTestCase {
    private final class Fixture {
        let f: SharedSetupRelayConnectorOwnerTests.Fixture
        let plan: RuntimeActivationPlan
        let intent: SharedSetupImportIntent
        let base: String
        let directory: ProtectedSetupDirectory
        var foregroundReads = 0, relayReads = 0
        var duringForeground: (() throws -> Void)?
        init() throws {
            let fixture = try SharedSetupRelayConnectorOwnerTests.Fixture(); f = fixture
            let h = fixture.dns.base.h, account = h.f.account
            plan = try h.machine { machine in
                let plan = try RuntimeActivationPlan(account: account, initialization: XCTUnwrap(machine.initialization(accountID: account.accountID)),
                    runtime: machine.runtimePreparation(accountID: account.accountID), inventory: XCTUnwrap(machine.inventory()),
                    importIntent: fixture.intent, relayPlan: fixture.dns.base.plan)
                try machine.retainRuntimeActivation(plan); _ = try machine.enrollRuntimeActivation(plan); try machine.markRuntimeJobsRegistered(plan)
                return plan
            }
            let journal = try h.f.open(); let gateway = try journal.advance(fixture.intent, to: .gatewayPrepared)
            let relay = try journal.advance(gateway, to: .relayPrepared); intent = try journal.advance(relay, to: .rootComplete); try journal.close()
            base = "/private/tmp/remozio-relay-completion-" + UUID().uuidString
            try FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: false)
            guard chmod(base, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            directory = try .init(anchor: base, relativePath: "Artifacts", owner: getuid(), visibility: .sharedMetadata)
            _ = try AdministrativeSetupPublication.publish(fixture.reference.encoded, file: .transportRelayReference,
                directory: directory, owner: getuid())
        }
        deinit { directory.close(); try? FileManager.default.removeItem(atPath: base) }
        var path: String { directory.path + "/" + AdministrativeSetupPublication.File.transportRelayReference.name }
        func validate() throws {
            try f.dns.base.h.machine { machine in
                let operations = SharedSetupImportCompletionValidation.Operations(foreground: { _, verify in
                    self.foregroundReads += 1; try verify(); try self.duringForeground?(); try verify()
                }, gateway: { _, _, _ in XCTFail("No push provider is selected") }, relay: { machine, account, retained, verify in
                    self.relayReads += 1
                    try SharedSetupImportRelayPreparedValidation.validate(machine: machine, account: account, retained: retained,
                        verifyCurrent: verify) { context, current in
                        guard let reference = context.reference else { throw RuntimePreparationError.missingMaterial }
                        try AdministrativeSetupPublication.validateRetained(reference.encoded, file: .transportRelayReference,
                            directory: self.directory, owner: getuid(), verify: current)
                    }
                })
                try SharedSetupImportCompletionValidation.validate(machine: machine, account: f.dns.base.h.f.account,
                    retained: intent, proposal: f.dns.base.h.f.proposal(), operations: operations, verifyCurrent: {})
            }
        }
    }
    func testRelayCompletionRequiresTheRetainedPublicationAndUsesThePlannedPort() throws {
        let h = try Fixture(), bytes = try Data(contentsOf: URL(fileURLWithPath: h.path))
        XCTAssertEqual(h.plan.transport.relayPort, h.f.dns.base.plan.port)
        try h.validate(); try h.validate(); XCTAssertEqual(h.foregroundReads, 2); XCTAssertEqual(h.relayReads, 2)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: h.path)), bytes)
    }
    func testRootCompleteMarkerCannotRepairMissingRelayMetadata() throws {
        let h = try Fixture(); XCTAssertEqual(unlink(h.path), 0); XCTAssertThrowsError(try h.validate())
        XCTAssertEqual(h.relayReads, 1); XCTAssertFalse(FileManager.default.fileExists(atPath: h.path))
    }
    func testDependencyReplacementDuringForegroundValidationStopsBeforeRelayReadback() throws {
        let h = try Fixture()
        h.duringForeground = {
            let path = h.f.runPath, bytes = try Data(contentsOf: URL(fileURLWithPath: path)), next = path + ".replacement"
            try bytes.write(to: URL(fileURLWithPath: next)); XCTAssertEqual(chmod(next, 0o600), 0); XCTAssertEqual(rename(next, path), 0)
        }
        defer { h.duringForeground = nil }
        XCTAssertThrowsError(try h.validate()); XCTAssertEqual(h.foregroundReads, 1); XCTAssertEqual(h.relayReads, 0)
    }
}
