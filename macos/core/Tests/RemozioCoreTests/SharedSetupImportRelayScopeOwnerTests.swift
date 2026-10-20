import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Injected reads test owner scope and lease lifetime. No Cloudflare, Root or installed service is used.
final class SharedSetupImportRelayScopeOwnerTests: XCTestCase, @unchecked Sendable {
    private struct Interrupted: Error {}
    private actor Counter { private(set) var calls = 0; func record() { calls += 1 } }
    private final class Harness: @unchecked Sendable {
        let fixture: SharedSetupImportGatewayApplicationTests.Fixture
        let proposal: PortableSetup
        let owner: SetupAccountOwner
        init(selected: Bool = true) throws {
            fixture = try .init(prepared: false)
            proposal = .init(defaults: fixture.proposal().defaults,
                cloudflare: selected ? try .init(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
                    dnsSuffix: "relay.fixture.example", apiToken: "synthetic-not-a-secret") : nil)
            owner = try fixture.owner(proposal: proposal)
        }
        deinit { try? owner.close() }
        func progress() throws -> SetupPortableImportProgress { try XCTUnwrap(owner.portableImportProgress(callerUID: getuid())) }
        func result() throws -> CloudflareProvisioningScope {
            let config = try XCTUnwrap(proposal.cloudflare)
            return .init(accountID: config.accountID, zoneID: config.zoneID, zoneName: "fixture.example", dnsSuffix: config.dnsSuffix)
        }
        func machine<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            let machine = try fixture.core.runtime.f.open(); defer { try? machine.close() }; return try body(machine)
        }
    }
    func testProviderReadReleasesBothDatabaseLeasesAndAdvancesNoMarker() async throws {
        let h = try Harness(), expected = try h.progress(), count = Counter()
        let result = try await h.owner.inspectImportedRelayScope(callerUID: getuid(), expected: expected, proposal: h.proposal, inspect: { _ in
            await count.record()
            try h.machine { machine in
                try machine.withSharedImportJournal { journal in XCTAssertEqual(try journal?.records().count, 1) }
            }
            return try h.result()
        })
        XCTAssertEqual(result, try h.result()); XCTAssertEqual(try h.progress(), expected)
        let calls = await count.calls; XCTAssertEqual(calls, 1)
    }
    func testCrossedProviderScopeCannotBeReturnedByTheOwner() async throws {
        let h = try Harness(), expected = try h.progress(), result = try h.result()
        let crossed = [
            CloudflareProvisioningScope(accountID: String(repeating: "c", count: 32), zoneID: result.zoneID, zoneName: result.zoneName, dnsSuffix: result.dnsSuffix),
            .init(accountID: result.accountID, zoneID: String(repeating: "c", count: 32), zoneName: result.zoneName, dnsSuffix: result.dnsSuffix),
            .init(accountID: result.accountID, zoneID: result.zoneID, zoneName: "other.example", dnsSuffix: result.dnsSuffix),
            .init(accountID: result.accountID, zoneID: result.zoneID, zoneName: result.zoneName, dnsSuffix: "other.fixture.example")]
        for value in crossed {
            do { _ = try await h.owner.inspectImportedRelayScope(callerUID: getuid(), expected: expected, proposal: h.proposal, inspect: { _ in value }); XCTFail() }
            catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        }
        XCTAssertEqual(try h.progress(), expected)
    }
    func testWrongCallerAndChangedProposalStopBeforeProviderAccess() async throws {
        let h = try Harness(), expected = try h.progress(), count = Counter()
        let changed = PortableSetup(defaults: h.proposal.defaults)
        for (uid, proposal) in [(getuid() + 1, h.proposal), (getuid(), changed)] {
            do { _ = try await h.owner.inspectImportedRelayScope(callerUID: uid, expected: expected, proposal: proposal,
                inspect: { _ in await count.record(); return try h.result() }); XCTFail() } catch {}
        }
        let calls = await count.calls; XCTAssertEqual(calls, 0)
    }
    func testAnImportRevisionChangedDuringTheReadCannotBeAccepted() async throws {
        let h = try Harness(), expected = try h.progress()
        do { _ = try await h.owner.inspectImportedRelayScope(callerUID: getuid(), expected: expected, proposal: h.proposal, inspect: { _ in
            try h.machine { machine in
                try machine.withSharedImportJournal { journal in
                    let journal = try XCTUnwrap(journal), retained = try XCTUnwrap(journal.records().first)
                    _ = try journal.advance(retained, to: .gatewayPrepared)
                }
            }
            return try h.result()
        }); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        XCTAssertEqual(try h.progress().phase, .gatewayPrepared)
    }
    func testAnInventoryRevisionChangedDuringTheReadCannotBeAccepted() async throws {
        let h = try Harness(), expected = try h.progress()
        do { _ = try await h.owner.inspectImportedRelayScope(callerUID: getuid(), expected: expected, proposal: h.proposal, inspect: { _ in
            try h.machine { machine in
                let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision)
            }
            return try h.result()
        }); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        // This progress codec omits the inventory revision. The owner compares the complete inventory separately.
        XCTAssertEqual(try h.progress(), expected)
    }
    func testMissingRelaySelectionStopsBeforeProviderAccess() async throws {
        let h = try Harness(selected: false), expected = try h.progress(), count = Counter()
        do { _ = try await h.owner.inspectImportedRelayScope(callerUID: getuid(), expected: expected, proposal: h.proposal,
            inspect: { _ in await count.record(); throw Interrupted() }); XCTFail() }
        catch { XCTAssertEqual(error as? SharedSetupImportCompletionValidation.Failure, .incomplete) }
        let calls = await count.calls; XCTAssertEqual(calls, 0)
    }
    func testProviderFailureIsNotRetriedAndReleasesTheAdmission() async throws {
        let h = try Harness(), expected = try h.progress(), count = Counter()
        do { _ = try await h.owner.inspectImportedRelayScope(callerUID: getuid(), expected: expected, proposal: h.proposal,
            inspect: { _ in await count.record(); throw CloudflareProvisioningError.unauthorized }); XCTFail() }
        catch { XCTAssertEqual(error as? CloudflareProvisioningError, .unauthorized) }
        let calls = await count.calls; XCTAssertEqual(calls, 1); XCTAssertEqual(try h.progress(), expected)
        XCTAssertNoThrow(try h.owner.close())
    }
    func testCancellationDuringTheReadCannotReturnProviderEvidence() async throws {
        let h = try Harness(), expected = try h.progress()
        let task = Task { @Sendable in
            try await h.owner.inspectImportedRelayScope(callerUID: getuid(), expected: expected, proposal: h.proposal, inspect: { _ in
                withUnsafeCurrentTask { $0?.cancel() }; return try h.result()
            })
        }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(try h.progress(), expected); XCTAssertNoThrow(try h.owner.close())
    }
    func testOwnerShutdownRejectsLateProviderEvidenceAndReleasesTheAdmission() async throws {
        let h = try Harness(), expected = try h.progress()
        do {
            _ = try await h.owner.inspectImportedRelayScope(callerUID: getuid(), expected: expected, proposal: h.proposal, inspect: { _ in
                XCTAssertThrowsError(try h.owner.close()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
                return try h.result()
            })
            XCTFail("Shutdown must reject late provider evidence")
        } catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
        XCTAssertNoThrow(try h.owner.close())
    }
}
