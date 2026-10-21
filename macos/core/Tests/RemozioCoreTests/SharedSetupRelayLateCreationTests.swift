import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class SharedSetupRelayLateCreationTests: XCTestCase, @unchecked Sendable {
    private func later(_ intent: SharedSetupImportIntent, phase: SharedSetupImportIntent.Phase) throws -> SharedSetupImportIntent {
        var result = intent
        while result.phase != phase {
            result = try result.advanced(to: XCTUnwrap(.init(rawValue: result.phase.rawValue + 1)))
        }
        return result
    }
    private actor Probe { var calls = 0; func record() { calls += 1 } }
    func testAnAdvancedImportCannotBeginANewCreationRecord() throws {
        for phase in [SharedSetupImportIntent.Phase.relayPrepared, .rootComplete] {
            let h = try RelayProvisioningFixture(), plan = try h.prepare(), expected = try later(h.intent, phase: phase)
            try h.directory { directory in
                XCTAssertThrowsError(try SharedSetupRelayProvisioningStorage.begin(expected: expected, plan: plan,
                    directory: directory, owner: getuid(), verifyCurrent: {})) {
                    XCTAssertEqual($0 as? RelayProvisioningError, .invalidTransition)
                }
                XCTAssertNil(try SharedSetupRelayProvisioningStorage.read(expected: expected, plan: plan, directory: directory, owner: getuid()))
            }
        }
    }
    func testAnAdvancedImportCannotDispatchAPreviouslyPreparedRecord() throws {
        for phase in [SharedSetupImportIntent.Phase.relayPrepared, .rootComplete] {
            let h = try RelayProvisioningFixture(), plan = try h.prepare(), expected = try later(h.intent, phase: phase)
            try h.directory { directory in
                let prepared = try SharedSetupRelayProvisioningStorage.begin(expected: h.intent, plan: plan, directory: directory,
                    owner: getuid(), verifyCurrent: {})
                XCTAssertThrowsError(try SharedSetupRelayProvisioningStorage.replace(prepared.transition(to: .dispatched), previous: prepared,
                    expected: expected, plan: plan, directory: directory, owner: getuid(), verifyCurrent: {})) {
                    XCTAssertEqual($0 as? RelayProvisioningError, .invalidTransition)
                }
                XCTAssertEqual(try SharedSetupRelayProvisioningStorage.read(expected: expected, plan: plan, directory: directory, owner: getuid()), prepared)
            }
        }
    }
    func testCompletedImportsKeepTheirPreviouslyCreatedResultReadable() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare()
        try h.directory { directory in
            let prepared = try SharedSetupRelayProvisioningStorage.begin(expected: h.intent, plan: plan, directory: directory,
                owner: getuid(), verifyCurrent: {})
            let sent = try prepared.transition(to: .dispatched)
            let created = try sent.transition(to: .created, tunnelID: "11111111-1111-4111-8111-111111111111")
            for (next, previous) in [(sent, prepared), (created, sent)] {
                try SharedSetupRelayProvisioningStorage.replace(next, previous: previous, expected: h.intent, plan: plan,
                    directory: directory, owner: getuid(), verifyCurrent: {})
            }
            XCTAssertEqual(try SharedSetupRelayProvisioningStorage.begin(expected: later(h.intent, phase: .rootComplete), plan: plan,
                directory: directory, owner: getuid(), verifyCurrent: {}), created)
        }
    }
    func testTheClientCannotTransmitALateCreationRequest() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare()
        let prepared = try SharedSetupRelayProvisioningRecord(expected: h.intent, plan: plan), sent = try prepared.transition(to: .dispatched)
        let configuration = try XCTUnwrap(h.f.proposal().cloudflare), probe = Probe()
        let client = CloudflareTunnelCreationClient(send: { _ in await probe.record(); return .init(status: 200, retryAfter: nil, body: Data()) })
        for phase in [SharedSetupImportIntent.Phase.relayPrepared, .rootComplete] {
            do { _ = try await client.create(configuration, expected: later(h.intent, phase: phase), plan: plan, dispatched: sent); XCTFail() }
            catch { XCTAssertEqual(error as? RelayProvisioningError, .wrongScope) }
        }
        let calls = await probe.calls; XCTAssertEqual(calls, 0)
    }
}
