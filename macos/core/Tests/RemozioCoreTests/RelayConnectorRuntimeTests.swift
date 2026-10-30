import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Synthetic metadata and owned children test lifecycle mechanics, not native service admission.
final class RelayConnectorRuntimeTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private actor ProbeGate {
        private(set) var entered = false
        private var continuation: CheckedContinuation<Void, Never>?
        func wait() async { entered = true; await withCheckedContinuation { continuation = $0 } }
        func release() { let previous = continuation; continuation = nil; previous?.resume() }
    }
    private func reference() throws -> RelayConnectorStartupReference {
        let f = try RelayRunCredentialPublicationTests().fixture(), value = try f.material().reference
        return try XCTUnwrap(RelayConnectorStartupReference.load(runtime: f.runtime, relayPort: f.plan.port,
            read: { try value.encoded }, verifyCurrent: {}))
    }
    private func until(_ predicate: () async throws -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while try await !predicate() {
            guard ContinuousClock.now < deadline else { throw Failed() }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    func testMissingOptionalReferenceCanBePublishedLaterWithoutReplacingTheOwner() async throws {
        let f = try RelayConnectorProcessTests.Fixture(), selected = try reference(), present = Mutex(false), made = Mutex(0)
        let runtime = try RelayConnectorRuntime(retryMilliseconds: 100, load: { present.withLock { $0 } ? selected : nil }, make: { value in
            XCTAssertEqual(value, selected); made.withLock { $0 += 1 }
            return RelayConnectorSupervisor(operations: .init(start: { try f.start("normal", event: $0) }, probe: { _ in .connected }))
        })
        try await runtime.poll(); let absent = await runtime.status; XCTAssertEqual(absent, .absent)
        XCTAssertEqual(made.withLock { $0 }, 0); present.withLock { $0 = true }
        try await Task.sleep(for: .milliseconds(110))
        try await until { try await runtime.poll(); return await runtime.status == .active(.connected) }
        XCTAssertEqual(made.withLock { $0 }, 1); XCTAssertThrowsError(try f.updater.acquireExclusive())
        try await runtime.close(); try f.assertUpdateAvailable()
    }
    func testTemporaryMetadataReadErrorRetriesWithoutCreatingAnUnvalidatedChild() async throws {
        let f = try RelayConnectorProcessTests.Fixture(), selected = try reference(), reads = Mutex(0), made = Mutex(0)
        let runtime = try RelayConnectorRuntime(retryMilliseconds: 100, load: {
            let index = reads.withLock { let old = $0; $0 += 1; return old }
            if index == 0 { throw JournalLeaseError.system(EIO) }; return selected
        }, make: { _ in
            made.withLock { $0 += 1 }
            return RelayConnectorSupervisor(operations: .init(start: { try f.start("normal", event: $0) }, probe: { _ in .disconnected }))
        })
        try await runtime.poll(); let waiting = await runtime.status; XCTAssertEqual(waiting, .waiting)
        XCTAssertEqual(made.withLock { $0 }, 0)
        try await Task.sleep(for: .milliseconds(110))
        try await until { try await runtime.poll(); return await runtime.status == .active(.disconnected) }
        XCTAssertEqual(reads.withLock { $0 }, 2); XCTAssertEqual(made.withLock { $0 }, 1)
        try await runtime.close(); try f.assertUpdateAvailable()
    }
    func testMalformedOrChangedMetadataRefusesWithoutFactoryOrAutomaticRetry() async throws {
        let reads = Mutex(0)
        let runtime = try RelayConnectorRuntime(retryMilliseconds: 100, load: {
            reads.withLock { $0 += 1 }; throw RuntimePreparationError.changedScope
        }, make: { _ in XCTFail("Unvalidated metadata reached the factory"); throw Failed() })
        try await runtime.poll(); let refused = await runtime.status; XCTAssertEqual(refused, .refused)
        try await Task.sleep(for: .milliseconds(110)); try await runtime.poll()
        XCTAssertEqual(reads.withLock { $0 }, 1); try await runtime.close()
    }
    func testConcurrentCancelledClosesJoinTheSupervisorAndItsLateProbe() async throws {
        let f = try RelayConnectorProcessTests.Fixture(), selected = try reference(), gate = ProbeGate(), done = Mutex(0)
        let runtime = try RelayConnectorRuntime(load: { selected }, make: { _ in
            RelayConnectorSupervisor(operations: .init(start: { try f.start("normal", event: $0) }, probe: { _ in await gate.wait(); return .connected }))
        })
        try await runtime.poll(); try await until { await gate.entered }
        let first = Task { @Sendable in try await runtime.close(); done.withLock { $0 += 1 } }
        try await until { await runtime.status == .closing }
        let second = Task { @Sendable in try await runtime.close(); done.withLock { $0 += 1 } }; first.cancel()
        XCTAssertEqual(done.withLock { $0 }, 0); await gate.release()
        try await first.value; try await second.value
        let status = await runtime.status; XCTAssertEqual(status, .closed)
        XCTAssertEqual(done.withLock { $0 }, 2); try f.assertUpdateAvailable()
    }
    func testCloseBeforePollingAndInvalidBoundsDoNotReadOrSpawn() async throws {
        let runtime = try RelayConnectorRuntime(load: { XCTFail(); return nil }, make: { _ in XCTFail(); throw Failed() })
        try await runtime.close()
        do { try await runtime.poll(); XCTFail() } catch { XCTAssertEqual(error as? GatewayServiceError, .unavailable) }
        for delay in [0, 99, 60_001] {
            XCTAssertThrowsError(try RelayConnectorRuntime(retryMilliseconds: delay, load: { nil }, make: { _ in throw Failed() }))
        }
    }
    func testDroppingRuntimeStopsItsOwnedChild() async throws {
        let f = try RelayConnectorProcessTests.Fixture(), selected = try reference(), exited = Mutex(false)
        var runtime: RelayConnectorRuntime? = try .init(load: { selected }, make: { _ in
            RelayConnectorSupervisor(operations: .init(start: { event in
                try f.start("normal") { value in if case .completed = value { exited.withLock { $0 = true } }; event(value) }
            }, probe: { _ in .connected }))
        })
        try await runtime?.poll()
        try await until { try await runtime?.poll(); return await runtime?.status == .active(.connected) }
        runtime = nil
        try await until { exited.withLock { $0 } }; try f.assertUpdateAvailable()
    }
    func testReleaseRequiresTheTransportReaderAndSetupWriterForTheExistingReferenceVersion() throws {
        let name = RelayRunCredentialReference.formatName
        func component(_ role: AuthorityCodeRole, readers: Set<UInt64>, writers: Set<UInt64>) throws -> ReleaseComponent {
            try .init(role: role, identifier: role == .transport ? "dev.remozio.transport" : "dev.remozio.setup",
                generation: 1, relativePath: role == .app ? "Contents/MacOS/Fixture" : "Contents/Library/LaunchServices/Fixture",
                codeDirectoryHash: role == .app ? nil : Data(repeating: 1, count: 20),
                build: "1", teamID: nil, formats: [.init(name: name, readers: readers, writers: writers)])
        }
        let reader = try component(.transport, readers: [1], writers: []), writer = try component(.setupController, readers: [1], writers: [1])
        XCTAssertNoThrow(try RelayConnectorStartupReference.validateReleaseFormats([reader, writer]))
        for invalid in [[writer], [reader],
            [try component(.transport, readers: [2], writers: []), writer],
            [reader, try component(.setupController, readers: [1], writers: [])],
            [try component(.app, readers: [1], writers: []), writer]] {
            XCTAssertThrowsError(try RelayConnectorStartupReference.validateReleaseFormats(invalid))
        }
    }
}
