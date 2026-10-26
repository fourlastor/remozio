import CryptoKit
import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Owned storage and injected inventory reads only. Native administrator/XPC admission remains a separate gate.
final class SharedSetupRelayRefusalRetryOwnerTests: XCTestCase, @unchecked Sendable {
    private struct Refused: Error {}
    private struct Fixture: Sendable {
        let h: RelayProvisioningFixture
        let plan: SharedSetupImportRelayPlan
        let record: SharedSetupRelayProvisioningRecord
        init(phase: SharedSetupRelayProvisioningRecord.Phase = .rejected) throws {
            let host = try RelayProvisioningFixture(), localPlan = try host.prepare()
            h = host; plan = localPlan
            record = try host.directory { directory in
                let first = try SharedSetupRelayProvisioningStorage.begin(expected: host.intent, plan: localPlan, directory: directory, owner: getuid(), verifyCurrent: {})
                if phase == .prepared { return first }
                let sent = try first.transition(to: .dispatched)
                try SharedSetupRelayProvisioningStorage.replace(sent, previous: first, expected: host.intent, plan: localPlan, directory: directory, owner: getuid(), verifyCurrent: {})
                if phase == .dispatched { return sent }
                let selected: SharedSetupRelayProvisioningRecord
                switch phase {
                case .rejected: selected = try sent.transition(to: .rejected, refusal: .unauthorized)
                case .unknown: selected = try sent.transition(to: .unknown)
                case .created: selected = try sent.transition(to: .created, tunnelID: "11111111-1111-4111-8111-111111111111")
                default: throw Refused()
                }
                try SharedSetupRelayProvisioningStorage.replace(selected, previous: sent, expected: host.intent, plan: localPlan, directory: directory, owner: getuid(), verifyCurrent: {})
                return selected
            }
        }
        var digest: Data { Data(SHA256.hash(data: record.bytes)) }
        func read() throws -> SharedSetupRelayProvisioningRecord? {
            try h.directory { try SharedSetupRelayProvisioningStorage.read(expected: h.intent, plan: plan, directory: $0, owner: getuid()) }
        }
        func absent() throws -> CloudflareImportedRelayInspection {
            let config = try XCTUnwrap(h.f.proposal().cloudflare)
            return .init(scope: .init(accountID: config.accountID, zoneID: config.zoneID, zoneName: "example.invalid", dnsSuffix: config.dnsSuffix), tunnel: nil)
        }
        var path: String {
            URL(fileURLWithPath: h.path).deletingLastPathComponent().appendingPathComponent(AdministrativeSetupPublication.File.importRelayProvisioning(accountID: h.intent.scope.accountID).name).path
        }
    }
    func testExactRejectedAttemptNeedsFreshAbsenceAndNeverSendsCreation() async throws {
        let f = try Fixture(), owner = try f.h.owner(); defer { try? owner.close() }
        let expected = try f.h.progress(owner), calls = Mutex(0)
        let next = try await owner.prepareRefusedImportedRelayTunnelRetry(callerUID: getuid(), expected: expected,
            proposal: f.h.f.proposal(), expectedRecordDigest: f.digest, inspect: { _, _, _ in
                calls.withLock { $0 += 1 }
                try f.h.machine { machine in try machine.withSharedImportJournal { journal in XCTAssertEqual(try journal?.records(), [f.h.intent]) } }
                XCTAssertEqual(try f.read(), f.record)
                return try f.absent()
            })
        XCTAssertEqual(calls.withLock { $0 }, 1); XCTAssertEqual(try f.read(), next)
        XCTAssertEqual(next.phase, .prepared); XCTAssertEqual(next.recordID, f.record.recordID)
        XCTAssertEqual(next.requestDigest, f.record.requestDigest); XCTAssertEqual(next.attemptNumber, 2)
        XCTAssertNotEqual(next.attemptID, f.record.attemptID); XCTAssertNotEqual(next.revision, f.record.revision)
        XCTAssertNil(next.tunnelID); XCTAssertNil(next.refusal); XCTAssertEqual(try f.h.progress(owner), expected)
        do {
            _ = try await owner.prepareRefusedImportedRelayTunnelRetry(callerUID: getuid(), expected: expected,
                proposal: f.h.f.proposal(), expectedRecordDigest: f.digest, inspect: { _, _, _ in XCTFail("Stale intent read the provider"); throw Refused() })
            XCTFail("Replayed retry was accepted")
        } catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
        XCTAssertEqual(try f.read(), next)
    }
    func testPreparedRetryNeedsAnotherAbsenceCheckBeforeOneNewDispatch() async throws {
        for present in [false, true] {
            let f = try Fixture(), owner = try f.h.owner(); defer { try? owner.close() }
            let expected = try f.h.progress(owner), proposal = try f.h.f.proposal(), posts = Mutex(0), reads = Mutex(0)
            let prepared = try await owner.prepareRefusedImportedRelayTunnelRetry(callerUID: getuid(), expected: expected,
                proposal: proposal, expectedRecordDigest: f.digest, inspect: { _, _, _ in try f.absent() })
            do {
                let created = try await owner.createImportedRelayTunnel(callerUID: getuid(), expected: expected, proposal: proposal,
                    inspect: { _, _, _ in
                        reads.withLock { $0 += 1 }
                        if !present { return try f.absent() }
                        let config = try XCTUnwrap(proposal.cloudflare)
                        return .init(scope: try f.absent().scope,
                            tunnel: .init(accountID: config.accountID, tunnelID: "11111111-1111-4111-8111-111111111111", name: f.plan.tunnelName),
                            configuration: .init(accountID: config.accountID, tunnelID: "11111111-1111-4111-8111-111111111111", providerVersion: 1, planDigest: Data(SHA256.hash(data: f.plan.bytes))))
                    }, create: { config, _, _, dispatched in
                        posts.withLock { $0 += 1 }
                        XCTAssertEqual(dispatched.attemptID, prepared.attemptID); XCTAssertEqual(dispatched.attemptNumber, 2)
                        XCTAssertEqual(try f.read(), dispatched)
                        return .created(.init(accountID: config.accountID, tunnelID: "11111111-1111-4111-8111-111111111111", name: f.plan.tunnelName))
                    })
                XCTAssertFalse(present); XCTAssertEqual(created.phase, .created); XCTAssertEqual(try f.read(), created)
            } catch { XCTAssertTrue(present); XCTAssertEqual(try f.read(), prepared) }
            XCTAssertEqual(reads.withLock { $0 }, 1); XCTAssertEqual(posts.withLock { $0 }, present ? 0 : 1)
        }
    }
    func testOtherStatesCannotBeRearmedOrReadTheProvider() async throws {
        for phase: SharedSetupRelayProvisioningRecord.Phase in [.prepared, .dispatched, .unknown, .created] {
            let f = try Fixture(phase: phase), owner = try f.h.owner(); defer { try? owner.close() }
            do {
                _ = try await owner.prepareRefusedImportedRelayTunnelRetry(callerUID: getuid(), expected: f.h.progress(owner),
                    proposal: f.h.f.proposal(), expectedRecordDigest: f.digest, inspect: { _, _, _ in XCTFail("Nonrefused state read the provider"); throw Refused() })
                XCTFail("Nonrefused state was rearmed")
            } catch { XCTAssertEqual(error as? RelayProvisioningError, .invalidTransition) }
            XCTAssertEqual(try f.read(), f.record)
        }
    }
    func testWrongDigestCallerAndProposalCannotReadOrChangeAnything() async throws {
        let f = try Fixture(), owner = try f.h.owner(); defer { try? owner.close() }
        for variant in 0..<4 {
            do {
                _ = try await owner.prepareRefusedImportedRelayTunnelRetry(callerUID: variant == 2 ? getuid() + 1 : getuid(), expected: f.h.progress(owner),
                    proposal: variant == 3 ? PortableSetup(defaults: f.h.f.proposal().defaults) : f.h.f.proposal(),
                    expectedRecordDigest: variant == 0 ? Data() : variant == 1 ? Data(repeating: 0, count: 32) : f.digest,
                    inspect: { _, _, _ in XCTFail("Wrong scope read the provider"); throw Refused() })
                XCTFail("Wrong scope was accepted")
            } catch {}
            XCTAssertEqual(try f.read(), f.record)
        }
    }
    func testUncertainOrPresentInventoryLeavesTheRejectedAttemptIntact() async throws {
        for present in [false, true] {
            let f = try Fixture(), owner = try f.h.owner(); defer { try? owner.close() }
            do {
                _ = try await owner.prepareRefusedImportedRelayTunnelRetry(callerUID: getuid(), expected: f.h.progress(owner),
                    proposal: f.h.f.proposal(), expectedRecordDigest: f.digest, inspect: { _, _, _ in
                        if !present { throw Refused() }
                        let config = try XCTUnwrap(f.h.f.proposal().cloudflare)
                        return .init(scope: try f.absent().scope,
                            tunnel: .init(accountID: config.accountID, tunnelID: "11111111-1111-4111-8111-111111111111", name: f.plan.tunnelName),
                            configuration: .init(accountID: config.accountID, tunnelID: "11111111-1111-4111-8111-111111111111", providerVersion: 1, planDigest: Data(SHA256.hash(data: f.plan.bytes))))
                    })
                XCTFail("Unknown absence rearmed a record")
            } catch {}
            XCTAssertEqual(try f.read(), f.record)
        }
    }
    func testChangesDuringTheInventoryReadCannotRearmTheRecord() async throws {
        for variant in 0..<3 {
            let f = try Fixture(), owner = try f.h.owner(); defer { try? owner.close() }
            let expected = try f.h.progress(owner)
            let attempt = Task { @Sendable in
                try await owner.prepareRefusedImportedRelayTunnelRetry(callerUID: getuid(), expected: expected,
                    proposal: f.h.f.proposal(), expectedRecordDigest: f.digest, inspect: { _, _, _ in
                        if variant == 0 {
                            let replacement = f.path + ".replacement"; try f.record.bytes.write(to: URL(fileURLWithPath: replacement))
                            guard chmod(replacement, 0o600) == 0, rename(replacement, f.path) == 0 else { throw Refused() }
                        } else if variant == 1 {
                            try f.h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
                        } else { withUnsafeCurrentTask { $0?.cancel() } }
                        return try f.absent()
                    })
            }
            do {
                _ = try await attempt.value
                XCTFail("Changed or cancelled scope rearmed a record")
            } catch {}
            XCTAssertEqual(try f.read(), f.record)
        }
    }
}
