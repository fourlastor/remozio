import Darwin
import Foundation
import RemozioProtocol
import Security
import XCTest
@testable import RemozioCore

/// Logical exported-invocation calls with owned cutover files and fake rights. No native XPC or Root identity is qualified.
final class AuditUpgradeSetupEndpointTests: XCTestCase {
    private struct Refused: Error {}
    private final class Probe: @unchecked Sendable {
        private let lock = NSLock()
        var releaseAllowed = true
        var callerUID = getuid()
        var authorizedUID = getuid()
        private(set) var imports = 0, opens = 0, invalidations = 0
        private(set) var importedOnMain = false, workerStack = 0
        let workerGate = DispatchSemaphore(value: 0)
        var workerStarted: XCTestExpectation?
        var pauseWorker = false
        func imported() { lock.withLock { imports += 1; importedOnMain = pthread_main_np() != 0 } }
        func opened() { lock.withLock { opens += 1; workerStack = pthread_get_stacksize_np(pthread_self()) } }
        func invalidated() { lock.withLock { invalidations += 1 } }
    }
    private final class EndpointReference: @unchecked Sendable {
        private let lock = NSLock()
        private weak var endpoint: AdministrativeSetupXPCEndpoint?
        private var fired = false
        func set(_ value: AdministrativeSetupXPCEndpoint) { lock.withLock { endpoint = value } }
        /// Closes the endpoint once, as an XPC invalidation would, from inside the running cutover.
        func invalidateOnce() {
            let target = lock.withLock { () -> AdministrativeSetupXPCEndpoint? in
                if fired { return nil }; fired = true; return endpoint
            }
            target?.close()
        }
        var invalidated: Bool { lock.withLock { fired } }
    }
    private struct Fixture {
        let h: RuntimeAuditUpgradeOperationTests.Harness
        let owner: SetupAccountOwner
        let endpoint: AdministrativeSetupXPCEndpoint
        let probe: Probe
        init(gateway: Bool = false) throws {
            let h = try RuntimeAuditUpgradeOperationTests.Harness(gateway: gateway), owner = try h.owner(), probe = Probe()
            let operations = try SetupAuditUpgradeEndpointOperations.owned(requireRelease: {
                if !probe.releaseAllowed { throw Refused() }
            }, importAuthorization: { form in
                XCTAssertEqual(form.count, MemoryLayout<AuthorizationExternalForm>.size); probe.imported()
                return try .openOwned(callerUID: probe.authorizedUID, verifyRights: {})
            }, openInvocation: { expected, grant in
                probe.opened()
                if probe.pauseWorker {
                    probe.workerStarted?.fulfill()
                    guard probe.workerGate.wait(timeout: .now() + 15) == .success else { throw Refused() }
                }
                return try .openOwned(owner: owner, expected: expected, authorization: grant, openOperation: h.operation(scope:))
            })
            endpoint = .init(owner: owner, verify: { probe.callerUID }, authorize: { _ in XCTFail("Legacy authorization") },
                invalidate: probe.invalidated, auditUpgradeOperations: operations)
            self.h = h; self.owner = owner; self.probe = probe
        }
        var form: Data { Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size) }
        func progress() throws -> SetupAuditUpgradeProgress { try XCTUnwrap(owner.auditUpgradeProgress(callerUID: getuid())) }
    }
    private func hello(_ endpoint: AdministrativeSetupXPCEndpoint) {
        endpoint.auditUpgradeHello { XCTAssertEqual($0, SetupAuditUpgradeLocalContract.version) }
    }
    private func settle(_ endpoint: AdministrativeSetupXPCEndpoint) {
        let done = expectation(description: "Maintenance task settled")
        Task.detached { await endpoint.waitForAuditUpgradeWork(); done.fulfill() }
        wait(for: [done], timeout: 30)
    }
    func testCompleteExportedFlowImportsRightsBeforeDispatchAndKeepsAdmissionThroughReply() throws {
        let f = try Fixture(gateway: true); defer { f.endpoint.close(); try? f.owner.close() }
        let expected = try f.progress(); hello(f.endpoint)
        let replied = expectation(description: "Scoped completion")
        f.endpoint.performAuditUpgrade(try expected.bytes, authorization: f.form) { [owner = f.owner] bytes in
            do {
                let result = try SetupAuditUpgradeProgress.decode(XCTUnwrap(bytes))
                try result.validateScope(of: expected)
                XCTAssertEqual(result.stage, .registrationObserved)
                XCTAssertEqual(result.registrationObserved, [.authority, .transport, .notificationGateway])
                XCTAssertThrowsError(try owner.verifyCurrent())
            } catch { XCTFail("Reply: \(error)") }
            replied.fulfill()
        }
        XCTAssertEqual(f.probe.imports, 1); XCTAssertTrue(f.probe.importedOnMain)
        wait(for: [replied], timeout: 25); settle(f.endpoint)
        XCTAssertEqual(f.probe.opens, 1); XCTAssertGreaterThanOrEqual(f.probe.workerStack, SetupAuditUpgradeWorkExecutor.stackBytes)
        try f.owner.verifyCurrent()
        f.endpoint.auditUpgradeProgress { bytes in
            do {
                let retained = try SetupAuditUpgradeProgress.decode(XCTUnwrap(bytes))
                XCTAssertEqual(retained.stage, .metadataCommitted); XCTAssertTrue(retained.registrationObserved.isEmpty)
            } catch { XCTFail("Recovery: \(error)") }
        }
        XCTAssertTrue(f.h.bootstraps.values.allSatisfy { $0 == 1 })
    }
    func testNoHandshakeAndMalformedOrOversizedRequestsNeverImportRights() throws {
        for variant in 0..<4 {
            let f = try Fixture(); defer { f.endpoint.close(); try? f.owner.close() }
            if variant != 0 { hello(f.endpoint) }
            let expected = try f.progress().bytes
            let input = variant == 1 ? Data() : variant == 2 ? Data(repeating: 0, count: SetupAuditUpgradeProgress.maximumBytes + 1) : expected
            f.endpoint.performAuditUpgrade(input, authorization: variant == 3 ? Data() : f.form) { XCTAssertNil($0) }
            XCTAssertEqual(f.probe.imports, 0); XCTAssertEqual(f.probe.opens, 0); XCTAssertEqual(f.probe.invalidations, 1)
            try f.owner.verifyCurrent()
        }
    }
    func testWrongCallerAndMismatchedAuthorizationUIDCannotDispatch() throws {
        for mismatchedGrant in [false, true] {
            let f = try Fixture(); defer { f.endpoint.close(); try? f.owner.close() }
            hello(f.endpoint)
            if mismatchedGrant { f.probe.authorizedUID = getuid() + 1 } else { f.probe.callerUID = getuid() + 1 }
            f.endpoint.performAuditUpgrade(try f.progress().bytes, authorization: f.form) { XCTAssertNil($0) }
            XCTAssertEqual(f.probe.imports, mismatchedGrant ? 1 : 0); XCTAssertEqual(f.probe.opens, 0)
            try f.owner.verifyCurrent()
        }
    }
    func testAnotherMacScopeWithTheSameCallerUIDCannotChangeThisMac() throws {
        let f = try Fixture(), other = try Fixture()
        defer { f.endpoint.close(); other.endpoint.close(); try? f.owner.close(); try? other.owner.close() }
        let expected = try other.progress(); hello(f.endpoint)
        let replied = expectation(description: "Foreign Mac refused")
        f.endpoint.performAuditUpgrade(try expected.bytes, authorization: f.form) { bytes in XCTAssertNil(bytes); replied.fulfill() }
        wait(for: [replied], timeout: 10); settle(f.endpoint)
        XCTAssertEqual(f.probe.imports, 1); XCTAssertEqual(f.probe.opens, 1)
        XCTAssertEqual(f.h.preparations, 0); XCTAssertFalse(try f.h.fencePresent())
        try f.owner.verifyCurrent(); try other.owner.verifyCurrent()
    }
    func testFailedInvocationCleanupStaysOwnedAfterTheEndpointTaskSettles() throws {
        let f = try Fixture(); defer { f.endpoint.close(); try? f.owner.close() }
        f.h.quiescenceValidationFails = true; f.h.quiescenceCloseFails = true
        hello(f.endpoint)
        let replied = expectation(description: "Failed invocation")
        f.endpoint.performAuditUpgrade(try f.progress().bytes, authorization: f.form) { bytes in XCTAssertNil(bytes); replied.fulfill() }
        wait(for: [replied], timeout: 10); settle(f.endpoint)
        XCTAssertThrowsError(try f.owner.verifyCurrent()); XCTAssertThrowsError(try f.h.installer.acquireShared())
        XCTAssertThrowsError(try f.h.machine { _ in () }); XCTAssertFalse(f.owner.retryAuditUpgradeCleanup())
        try XCTUnwrap(f.h.q).closeFails = false
        XCTAssertTrue(f.owner.retryAuditUpgradeCleanup()); try f.owner.verifyCurrent()
        XCTAssertTrue(try f.h.fencePresent()); XCTAssertEqual(f.probe.invalidations, 1)
    }
    func testFailureReplyIsSentWhileTheInvocationStillHoldsTheSetupReservation() throws {
        let f = try Fixture(); defer { f.endpoint.close(); try? f.owner.close() }
        f.h.quiescenceValidationFails = true
        hello(f.endpoint)
        let replied = expectation(description: "Failure reply")
        f.endpoint.performAuditUpgrade(try f.progress().bytes, authorization: f.form) { [owner = f.owner] bytes in
            XCTAssertNil(bytes)
            // Cleanup has not started. Another setup operation cannot enter before this reply returns.
            do {
                try owner.verifyCurrent()
                XCTFail("The setup reservation must remain held during the failure reply.")
            } catch {}
            replied.fulfill()
        }
        wait(for: [replied], timeout: 10); settle(f.endpoint)
        try f.owner.verifyCurrent(); XCTAssertTrue(f.owner.retryAuditUpgradeCleanup())
        XCTAssertEqual(f.probe.invalidations, 1)
    }
    func testInvalidationDuringCutoverRetainsFailedCleanupUntilRetry() throws {
        let h = try RuntimeAuditUpgradeOperationTests.Harness(), owner = try h.owner(), probe = Probe(), reference = EndpointReference()
        defer { try? owner.close() }
        h.quiescenceCloseFails = true
        let operations = try SetupAuditUpgradeEndpointOperations.owned(importAuthorization: { _ in
            try .openOwned(verifyRights: { if h.q != nil { reference.invalidateOnce() } })
        }, openInvocation: { expected, grant in
            try .openOwned(owner: owner, expected: expected, authorization: grant, openOperation: h.operation(scope:))
        })
        let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in XCTFail("Legacy authorization") },
            invalidate: probe.invalidated, auditUpgradeOperations: operations)
        reference.set(endpoint); defer { endpoint.close() }
        let expected = try XCTUnwrap(owner.auditUpgradeProgress(callerUID: getuid()))
        hello(endpoint)
        endpoint.performAuditUpgrade(try expected.bytes, authorization: Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)) { _ in
            XCTFail("Invalidated reply")
        }
        settle(endpoint)
        XCTAssertTrue(reference.invalidated); XCTAssertEqual(probe.invalidations, 1)
        XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try h.installer.acquireShared())
        XCTAssertFalse(owner.retryAuditUpgradeCleanup())
        try XCTUnwrap(h.q).closeFails = false
        XCTAssertTrue(owner.retryAuditUpgradeCleanup()); try owner.verifyCurrent(); try h.machine { _ in () }
    }
    func testUnavailableReleaseClosesHandshakeWithoutGrantOrWorker() throws {
        let f = try Fixture(); defer { f.endpoint.close(); try? f.owner.close() }
        f.probe.releaseAllowed = false
        f.endpoint.auditUpgradeHello { XCTAssertEqual($0, 0) }
        XCTAssertEqual(f.probe.imports, 0); XCTAssertEqual(f.probe.opens, 0); XCTAssertEqual(f.probe.invalidations, 1)
        XCTAssertEqual(AdministrativeSetupInterface.supportedVersions, Set(UInt64(1)...11))
    }
    func testCloseCancelsDispatchedWorkBeforeItCanAcquireScopeOrChangeFiles() throws {
        let f = try Fixture(); defer { f.endpoint.close(); try? f.owner.close() }
        f.probe.pauseWorker = true; f.probe.workerStarted = expectation(description: "Worker entered")
        hello(f.endpoint)
        f.endpoint.performAuditUpgrade(try f.progress().bytes, authorization: f.form) { _ in XCTFail("Closed reply") }
        wait(for: [try XCTUnwrap(f.probe.workerStarted)], timeout: 5)
        f.endpoint.close(); f.probe.workerGate.signal(); settle(f.endpoint)
        XCTAssertEqual(f.h.preparations, 0); XCTAssertFalse(try f.h.fencePresent())
        XCTAssertEqual(f.probe.invalidations, 1); try f.owner.verifyCurrent()
    }
    func testNormalLegacyInterfaceRemainsUsableWithoutMaintenanceAdapters() throws {
        let h = try RuntimeAuditUpgradeOperationTests.Harness(), owner = try h.owner(); defer { try? owner.close() }
        let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in }, invalidate: {})
        defer { endpoint.close() }
        endpoint.hello { XCTAssertEqual($0, AdministrativeSetupInterface.storageVersion) }
        XCTAssertTrue(endpoint.responds(to: #selector(AuditUpgradeSetupXPCProtocol.auditUpgradeHello(reply:))))
        _ = NSXPCInterface(with: AdministrativeSetupMaintenanceXPCProtocol.self)
        _ = NSXPCInterface(with: AdministrativeSetupXPCProtocol.self)
        XCTAssertThrowsError(try owner.requireAuditUpgradeSupport()) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
    }
    func testLocalReleaseContractRequiresBothPeersAndTheProgressCodec() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneAudit: true, auditDelivery: true)
        let policy = f.plan.host.codePolicy
        try SetupAuditUpgradeLocalContract.validate(XCTUnwrap(f.nativeRelease), policy: policy)
        func release(omit: AuthorityCodeRole? = nil, omitProgress: Bool = false) throws -> SignedReleaseEvidence {
            try NativeHostReleaseFixture.make(policy: policy, phoneAudit: true, auditDelivery: true) { c in
                guard [.app, .setupController].contains(c.role) else { return c }
                var formats = c.formats.filter { $0.name != AdministrativeSetupInterface.formatName && $0.name != SetupAuditUpgradeProgress.formatName }
                let versions = c.role == omit ? AdministrativeSetupInterface.supportedVersions.subtracting([11]) : AdministrativeSetupInterface.supportedVersions
                formats.append(try .init(name: AdministrativeSetupInterface.formatName, readers: versions, writers: versions))
                if !omitProgress { formats.append(try .init(name: SetupAuditUpgradeProgress.formatName, readers: [1], writers: [1])) }
                return try .init(role: c.role, identifier: c.identifier, generation: c.generation, relativePath: c.relativePath,
                    codeDirectoryHash: c.codeDirectoryHash, build: c.build, teamID: c.teamID, formats: formats, requests: c.requests)
            }
        }
        try SetupAuditUpgradeLocalContract.validate(release(), policy: policy)
        XCTAssertThrowsError(try SetupAuditUpgradeLocalContract.validate(release(omit: .app), policy: policy))
        XCTAssertThrowsError(try SetupAuditUpgradeLocalContract.validate(release(omit: .setupController), policy: policy))
        XCTAssertThrowsError(try SetupAuditUpgradeLocalContract.validate(release(omitProgress: true), policy: policy))
    }
}
