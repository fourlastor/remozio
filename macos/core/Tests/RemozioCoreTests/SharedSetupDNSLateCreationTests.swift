import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class SharedSetupDNSLateCreationTests: XCTestCase, @unchecked Sendable {
    private func later(_ intent: SharedSetupImportIntent, phase: SharedSetupImportIntent.Phase) throws -> SharedSetupImportIntent {
        var result = intent
        while result.phase != phase {
            result = try result.advanced(to: XCTUnwrap(.init(rawValue: result.phase.rawValue + 1)))
        }
        return result
    }
    private actor Probe { var calls = 0; func record() { calls += 1 } }
    func testAnAdvancedImportCannotBeginADNSRecord() throws {
        for phase in [SharedSetupImportIntent.Phase.relayPrepared, .rootComplete] {
            let f = try DNSRecordFixture(), expected = try later(f.base.h.intent, phase: phase)
            try f.base.h.directory { directory in
                XCTAssertThrowsError(try SharedSetupDNSStorage.begin(expected: expected, plan: f.base.plan,
                    createdTunnel: f.base.tunnel, application: f.access, directory: directory, owner: getuid(), verifyCurrent: {})) {
                    XCTAssertEqual($0 as? RelayProvisioningError, .invalidTransition)
                }
                XCTAssertNil(try SharedSetupDNSStorage.read(expected: expected, plan: f.base.plan,
                    createdTunnel: f.base.tunnel, application: f.access, directory: directory, owner: getuid()))
            }
        }
    }
    func testAnAdvancedImportCannotDispatchAPreparedDNSRecord() throws {
        for phase in [SharedSetupImportIntent.Phase.relayPrepared, .rootComplete] {
            let f = try DNSRecordFixture(), prepared = try f.begin(), expected = try later(f.base.h.intent, phase: phase)
            try f.base.h.directory { directory in
                XCTAssertThrowsError(try SharedSetupDNSStorage.replace(prepared.transition(to: .dispatched), previous: prepared,
                    expected: expected, plan: f.base.plan, createdTunnel: f.base.tunnel, application: f.access,
                    directory: directory, owner: getuid(), verifyCurrent: {})) {
                    XCTAssertEqual($0 as? RelayProvisioningError, .invalidTransition)
                }
                XCTAssertEqual(try SharedSetupDNSStorage.read(expected: expected, plan: f.base.plan,
                    createdTunnel: f.base.tunnel, application: f.access, directory: directory, owner: getuid()), prepared)
            }
        }
    }
    func testCompletedImportsKeepTheirCreatedDNSRecordReadable() throws {
        let f = try DNSRecordFixture(), created = try f.retainCreated(), expected = try later(f.base.h.intent, phase: .rootComplete)
        try f.base.h.directory { directory in
            XCTAssertEqual(try SharedSetupDNSStorage.begin(expected: expected, plan: f.base.plan,
                createdTunnel: f.base.tunnel, application: f.access, directory: directory, owner: getuid(), verifyCurrent: {}), created)
        }
    }
    func testTheClientCannotTransmitALateDNSCreationRequest() async throws {
        let f = try DNSRecordFixture(), dispatched = try f.begin().transition(to: .dispatched)
        let configuration = try XCTUnwrap(f.base.h.f.proposal().cloudflare), probe = Probe()
        let client = CloudflareDNSRecordClient(send: { _ in await probe.record(); return .init(status: 200, retryAfter: nil, body: Data()) })
        for phase in [SharedSetupImportIntent.Phase.relayPrepared, .rootComplete] {
            do {
                _ = try await client.create(configuration, expected: later(f.base.h.intent, phase: phase), plan: f.base.plan,
                    createdTunnel: f.base.tunnel, application: f.access, dispatched: dispatched)
                XCTFail()
            } catch { XCTAssertEqual(error as? RelayProvisioningError, .wrongScope) }
        }
        let calls = await probe.calls; XCTAssertEqual(calls, 0)
    }
}
