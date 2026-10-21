import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class SharedSetupAccessLateCreationTests: XCTestCase, @unchecked Sendable {
    private func later(_ intent: SharedSetupImportIntent, phase: SharedSetupImportIntent.Phase) throws -> SharedSetupImportIntent {
        var result = intent
        while result.phase != phase {
            result = try result.advanced(to: XCTUnwrap(.init(rawValue: result.phase.rawValue + 1)))
        }
        return result
    }
    private actor Probe { var calls = 0; func record() { calls += 1 } }
    func testAnAdvancedImportCannotBeginAnAccessApplicationRecord() throws {
        for phase in [SharedSetupImportIntent.Phase.relayPrepared, .rootComplete] {
            let f = try AccessApplicationFixture(), expected = try later(f.h.intent, phase: phase)
            try f.h.directory { directory in
                XCTAssertThrowsError(try SharedSetupAccessApplicationStorage.begin(expected: expected, plan: f.plan,
                    createdTunnel: f.tunnel, directory: directory, owner: getuid(), verifyCurrent: {})) {
                    XCTAssertEqual($0 as? RelayProvisioningError, .invalidTransition)
                }
                XCTAssertNil(try SharedSetupAccessApplicationStorage.read(expected: expected, plan: f.plan,
                    createdTunnel: f.tunnel, directory: directory, owner: getuid()))
            }
        }
    }
    func testAnAdvancedImportCannotDispatchAPreparedAccessApplication() throws {
        for phase in [SharedSetupImportIntent.Phase.relayPrepared, .rootComplete] {
            let f = try AccessApplicationFixture(), prepared = try f.begin(), expected = try later(f.h.intent, phase: phase)
            try f.h.directory { directory in
                XCTAssertThrowsError(try SharedSetupAccessApplicationStorage.replace(prepared.transition(to: .dispatched), previous: prepared,
                    expected: expected, plan: f.plan, createdTunnel: f.tunnel, directory: directory, owner: getuid(), verifyCurrent: {})) {
                    XCTAssertEqual($0 as? RelayProvisioningError, .invalidTransition)
                }
                XCTAssertEqual(try SharedSetupAccessApplicationStorage.read(expected: expected, plan: f.plan,
                    createdTunnel: f.tunnel, directory: directory, owner: getuid()), prepared)
            }
        }
    }
    func testCompletedImportsKeepTheirCreatedAccessApplicationReadable() throws {
        let f = try AccessApplicationFixture(), created = try f.retainCreated(), expected = try later(f.h.intent, phase: .rootComplete)
        try f.h.directory { directory in
            XCTAssertEqual(try SharedSetupAccessApplicationStorage.begin(expected: expected, plan: f.plan,
                createdTunnel: f.tunnel, directory: directory, owner: getuid(), verifyCurrent: {}), created)
        }
    }
    func testTheClientCannotTransmitALateAccessCreationRequest() async throws {
        let f = try AccessApplicationFixture(), dispatched = try f.begin().transition(to: .dispatched)
        let configuration = try XCTUnwrap(f.h.f.proposal().cloudflare), probe = Probe()
        let client = CloudflareAccessApplicationClient(send: { _ in await probe.record(); return .init(status: 200, retryAfter: nil, body: Data()) })
        for phase in [SharedSetupImportIntent.Phase.relayPrepared, .rootComplete] {
            do {
                _ = try await client.create(configuration, expected: later(f.h.intent, phase: phase), plan: f.plan,
                    createdTunnel: f.tunnel, dispatched: dispatched)
                XCTFail()
            } catch { XCTAssertEqual(error as? RelayProvisioningError, .wrongScope) }
        }
        let calls = await probe.calls; XCTAssertEqual(calls, 0)
    }
}
