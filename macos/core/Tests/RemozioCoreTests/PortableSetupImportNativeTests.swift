import CoreGraphics
import Darwin
import Foundation
import Security
import Synchronization
import XCTest
@testable import RemozioCore

/// Owns an anonymous connection and disposable storage. It never imports administrator rights or registers a service.
final class PortableSetupImportNativeTests: XCTestCase, @unchecked Sendable {
    private struct Refused: Error {}
    private enum Mode: Sendable { case normal, legacyHello, malformedOperation, loseOperationReply }

    /// Pins this test binary. The production driver still requires a Developer ID Root service.
    private final class Driver: PortableSetupImportDriver, @unchecked Sendable {
        let connection: NSXPCConnection
        let policy: XPCPeerPolicy
        let mode: Mode
        let checks = Mutex(0)
        let lostResult = Mutex<Data?>(nil)
        init(server: Server, requirement: String, mode: Mode) {
            connection = NSXPCConnection(listenerEndpoint: server.listener.endpoint)
            policy = server.policy; self.mode = mode
            connection.remoteObjectInterface = NSXPCInterface(with: AdministrativeSetupXPCProtocol.self)
            connection.setCodeSigningRequirement(requirement)
        }
        func start(closed: @escaping @Sendable () -> Void) {
            connection.invalidationHandler = closed; connection.interruptionHandler = closed; connection.activate()
        }
        func verify() throws {
            guard try policy.verifyCredentials(connection).processID == getpid() else { throw Refused() }
            checks.withLock { $0 += 1 }
        }
        func invoke(_ call: PortableSetupImportCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            let once = Mutex<(@Sendable (SetupClientReply) -> Void)?>(reply)
            let finish: @Sendable (SetupClientReply) -> Void = { value in
                let callback = once.withLock { saved in let callback = saved; saved = nil; return callback }
                callback?(value)
            }
            do { switch call { case .hello, .recoveryHello: break; default: try verify() } }
            catch { finish(.failed); return }
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in finish(.failed) }) as? any AdministrativeSetupXPCProtocol else {
                finish(.failed); return
            }
            switch call {
            case .recoveryHello: proxy.portableImportRecoveryHello { [self] in checked(.version($0), reply: finish) }
            case .recovery: proxy.portableImportRecovery { [self] in checked(.progress($0), reply: finish) }
            case .hello:
                if mode == .legacyHello { proxy.hello { [self] in checked(.version($0), reply: finish) } }
                else { proxy.portableImportHello { [self] in checked(.version($0), reply: finish) } }
            case .progress: proxy.portableImportProgress { [self] in checked(.progress($0), reply: finish) }
            case .perform(let request, let authorization):
                do {
                    let bytes = mode == .malformedOperation ? Data() : try request.bytes
                    proxy.performPortableImport(bytes, authorization: authorization) { [self] result in
                        if mode == .loseOperationReply, let result {
                            do { try verify(); lostResult.withLock { $0 = result }; connection.invalidate() }
                            catch { finish(.failed) }
                        } else { checked(.progress(result), reply: finish) }
                    }
                } catch { finish(.failed) }
            }
        }
        private func checked(_ value: SetupClientReply, reply: @Sendable (SetupClientReply) -> Void) {
            do { try verify(); reply(value) } catch { reply(.failed) }
        }
        func close() { connection.invalidate() }
        deinit { connection.invalidate() }
    }

    private final class WorkGate: @unchecked Sendable {
        private let state = Mutex((armed: false, entered: false))
        private let releaseSignal = DispatchSemaphore(value: 0)
        var entered: Bool { state.withLock { $0.entered } }
        func arm() { state.withLock { $0.armed = true } }
        func beforeOpen() throws {
            let hold = state.withLock { value in
                guard value.armed else { return false }
                value.armed = false; value.entered = true; return true
            }
            if hold, releaseSignal.wait(timeout: .now() + 20) != .success { throw Refused() }
        }
        func release() { releaseSignal.signal() }
    }

    private final class Server: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
        let listener = NSXPCListener.anonymous()
        let owner: SetupAccountOwner
        let policy: XPCPeerPolicy
        let requirement: String
        let rightsAllowed = Mutex(false)
        let rights = Mutex(0)
        let invocations = Mutex(0)
        let closedConnections = Mutex(0)
        private let afterAuthorization: @Sendable () throws -> Void
        private let lock = NSLock()
        private var closed = false
        private var connections: [(NSXPCConnection, AdministrativeSetupXPCEndpoint)] = []
        init(owner: SetupAccountOwner, requirement: String, afterAuthorization: @escaping @Sendable () throws -> Void = {}) throws {
            self.owner = owner; self.requirement = requirement; self.afterAuthorization = afterAuthorization
            policy = try .init(teamID: "ABCDEFGHIJ", componentIdentifier: "dev.remozio.native-import-fixture",
                approvedCodeDirectoryHashes: [Data(repeating: 1, count: 20)], expectedUserID: getuid())
            super.init()
            listener.setConnectionCodeSigningRequirement(requirement); listener.delegate = self; listener.activate()
        }
        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            lock.withLock {
                guard !closed, listener === self.listener, connections.count < 8 else { return false }
                do {
                    let peer = try policy.verifyCredentials(connection)
                    guard peer.processID == getpid() else { throw Refused() }
                    let invocation = XPCInvocationGuard(connection: connection, policy: policy)
                    let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { [weak self] in
                        guard let self, try invocation.verifyInvocation() == peer else { throw Refused() }
                        invocations.withLock { $0 += 1 }; return peer.userID
                    }, authorize: { [weak self] _ in
                        guard let self, try invocation.verifyInvocation() == peer else { throw Refused() }
                        rights.withLock { $0 += 1 }
                        guard rightsAllowed.withLock({ $0 }) else { throw Refused() }
                        try afterAuthorization()
                    }, invalidate: { [weak connection] in connection?.invalidate() })
                    connection.setCodeSigningRequirement(requirement)
                    connection.exportedInterface = NSXPCInterface(with: AdministrativeSetupXPCProtocol.self)
                    connection.exportedObject = endpoint
                    connection.invalidationHandler = { [weak self, weak endpoint] in
                        endpoint?.close(); self?.closedConnections.withLock { $0 += 1 }
                    }
                    connection.interruptionHandler = { [weak endpoint] in endpoint?.close() }
                    connections.append((connection, endpoint)); connection.activate(); return true
                } catch { connection.invalidate(); return false }
            }
        }
        func close() {
            let saved = lock.withLock {
                closed = true; listener.invalidate(); listener.delegate = nil
                let saved = connections; connections.removeAll(); return saved
            }
            for (connection, endpoint) in saved { endpoint.close(); connection.invalidate() }
        }
        deinit { close() }
    }

    private func testRequirement() throws -> String {
        var code: SecCode?, staticCode: SecStaticCode?, info: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess, let fields = info as? [String: Any],
              let hash = fields[kSecCodeInfoUnique as String] as? Data, hash.count == 20 else { throw Refused() }
        return "cdhash H\"" + hash.map { String(format: "%02x", $0) }.joined() + "\""
    }

    func testLiveAnonymousImportWireRetainsAndRecoversWithoutRetry() async throws {
        guard getuid() > 0, getuid() == geteuid(), CGSessionCopyCurrentDictionary() != nil else {
            throw XCTSkip("Requires an ordinary Mac GUI session. Installed Root authorization remains a separate gate.")
        }
        let host = try RelayProvisioningFixture(), f = host.f.accountFixture
        let bridge = GatewaySetupImportedRuntimeOperations(initialize: { _, _, _, _ in throw Refused() },
            activate: { _, _, _, _, _ in throw Refused() })
        let owner = try SetupAccountOwner(openMachine: { try f.open() }, expectedReleaseDigest: f.release,
            resume: { _, _ in throw Refused() }, accountCodePolicy: f.policy,
            lookupAccount: { uid in guard uid == f.identity.uid else { throw Refused() }; return f.identity },
            importedGatewayOperation: bridge)
        defer { try? owner.close() }
        let requirement = try testRequirement(), server = try Server(owner: owner, requirement: requirement)
        defer { server.close() }
        let expected = try host.progress(owner)
        let request = try SetupPortableImportOperation(action: .prepareRelayPlan, expected: expected, proposal: host.f.proposal())
        let form = Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)
        func client(_ mode: Mode = .normal, pin: String? = nil) -> (Driver, PortableSetupImportChannel) {
            let driver = Driver(server: server, requirement: pin ?? requirement, mode: mode)
            return (driver, PortableSetupImportChannel(driver: driver, timeoutMilliseconds: 5000, operationTimeoutMilliseconds: 5000))
        }
        XCTAssertNil(try host.readPlan())
        let (_, legacy) = client(.legacyHello)
        do { try await legacy.start(); XCTFail("Legacy hello admitted an import") }
        catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .unsupportedVersion) }
        do { _ = try await legacy.perform(request, authorization: form); XCTFail("Closed legacy channel sent an operation") } catch {}
        await legacy.close(); XCTAssertEqual(server.rights.withLock { $0 }, 0)

        let (_, wrongPin) = client(pin: "cdhash H\"0000000000000000000000000000000000000000\"")
        do { try await wrongPin.start(); XCTFail("A different code hash was admitted") } catch {}
        await wrongPin.close(); XCTAssertEqual(server.rights.withLock { $0 }, 0)

        for malformed in [true, false] {
            let (_, denied) = client(malformed ? .malformedOperation : .normal)
            try await denied.start()
            let progress = try await denied.progress(); XCTAssertEqual(progress, expected)
            do { _ = try await denied.perform(request, authorization: form); XCTFail("Refused request was applied") } catch {}
            await denied.close()
            XCTAssertEqual(server.rights.withLock { $0 }, malformed ? 0 : 1)
            XCTAssertNil(try host.readPlan()); XCTAssertEqual(try host.progress(owner), expected)
        }

        server.rightsAllowed.withLock { $0 = true }
        let (lostDriver, lost) = client(.loseOperationReply)
        try await lost.start()
        do { _ = try await lost.perform(request, authorization: form); XCTFail("A lost reply confirmed an operation") } catch {}
        await lost.close()
        let retained = try XCTUnwrap(host.readPlan())
        let lostBytes = try XCTUnwrap(lostDriver.lostResult.withLock { $0 })
        let committed = try SetupPortableImportOperationResult.decode(lostBytes, request: request)
        XCTAssertEqual(committed.status, .applied); XCTAssertEqual(committed.progress, expected)
        XCTAssertEqual(server.rights.withLock { $0 }, 2)

        let (freshDriver, fresh) = client()
        try await fresh.start()
        let recovered = try await fresh.progress(); XCTAssertEqual(recovered, committed.progress)
        XCTAssertEqual(try host.readPlan(), retained)
        XCTAssertEqual(server.rights.withLock { $0 }, 2, "Readback must not retry a write")
        let result = try await fresh.perform(request, authorization: form)
        XCTAssertEqual(result, committed); XCTAssertEqual(try host.readPlan(), retained)
        let crossed = try SetupPortableImportOperation(action: .retain, expected: expected, proposal: host.f.proposal())
        XCTAssertThrowsError(try SetupPortableImportOperationResult.decode(result.bytes, request: crossed))
        await fresh.close()
        XCTAssertEqual(server.rights.withLock { $0 }, 3)
        XCTAssertGreaterThan(freshDriver.checks.withLock { $0 }, 0)
        XCTAssertGreaterThan(server.invocations.withLock { $0 }, 0)
        server.close(); try await owner.closeWhenIdle()
        if let output = ProcessInfo.processInfo.environment["REMOZIO_PORTABLE_IMPORT_XPC_EVIDENCE"] {
            let evidence: [String: Any] = ["schemaVersion": 1, "experiment": "portable-import-native-xpc", "status": "passed",
                "osVersion": ProcessInfo.processInfo.operatingSystemVersionString, "hostArchitecture": "arm64",
                "guiSessionAvailable": true, "sameProcessNativeConnection": true, "testCodeHashRequirementApplied": true,
                "kernelPeerCredentialsChecked": true, "invocationConnectionChecked": true, "oldHandshakeRejected": true,
                "wrongCodeHashRejected": true, "malformedRequestRejectedBeforeRights": true, "refusedRightsLeaveStorageUnchanged": true,
                "lostReplyCommittedPlanRecovered": true, "readbackDidNotRetryWrite": true, "explicitRepeatPreservesPlan": true,
                "crossedResultRejected": true, "fixtureRightsChecks": server.rights.withLock { $0 },
                "verifiedInvocations": server.invocations.withLock { $0 }, "installedRootAccountsTested": false,
                "developerIDPolicyTested": false, "realAdministratorAuthorizationTested": false, "providerAPICalled": false,
                "serviceInstalled": false, "realApprovalIssued": false]
            try JSONSerialization.data(withJSONObject: evidence, options: [.sortedKeys, .prettyPrinted]).write(to: URL(fileURLWithPath: output))
        }
    }
    func testLiveAnonymousRecoveryReadsRejectedResourceWithoutRightsOrMutation() async throws {
        guard getuid() > 0, getuid() == geteuid(), CGSessionCopyCurrentDictionary() != nil else {
            throw XCTSkip("Requires an ordinary Mac GUI session. Installed Root authorization remains a separate gate.")
        }
        let fixture = try DNSRecordFixture(), f = fixture.base.h.f.accountFixture
        let prepared = try fixture.begin(), dispatched = try prepared.transition(to: .dispatched)
        let rejected = try dispatched.transition(to: .rejected, refusal: .unauthorized)
        try fixture.replace(dispatched, previous: prepared); try fixture.replace(rejected, previous: dispatched)
        let bridge = GatewaySetupImportedRuntimeOperations(initialize: { _, _, _, _ in throw Refused() },
            activate: { _, _, _, _, _ in throw Refused() })
        let owner = try SetupAccountOwner(openMachine: { try f.open() }, expectedReleaseDigest: f.release,
            resume: { _, _ in throw Refused() }, accountCodePolicy: f.policy,
            lookupAccount: { uid in guard uid == f.identity.uid else { throw Refused() }; return f.identity }, importedGatewayOperation: bridge)
        defer { try? owner.close() }
        let requirement = try testRequirement(), server = try Server(owner: owner, requirement: requirement)
        defer { server.close() }
        let expected = try XCTUnwrap(owner.portableImportRecovery(callerUID: getuid()))
        let path = URL(fileURLWithPath: fixture.base.h.path).deletingLastPathComponent()
        func files() throws -> [String: Data] {
            try Dictionary(uniqueKeysWithValues: FileManager.default.contentsOfDirectory(atPath: path.path).map {
                ($0, try Data(contentsOf: path.appendingPathComponent($0)))
            })
        }
        let before = try files()
        for _ in 0..<2 {
            let driver = Driver(server: server, requirement: requirement, mode: .normal)
            let channel = PortableSetupImportChannel(driver: driver, recoveryEnabled: true)
            try await channel.start()
            let actual = try await channel.recovery(); XCTAssertEqual(actual, expected)
            XCTAssertEqual(actual?.rejectedRecord(for: .dnsRecord)?.refusal, .unauthorized)
            XCTAssertEqual(try files(), before); XCTAssertEqual(server.rights.withLock { $0 }, 0)
            XCTAssertGreaterThan(driver.checks.withLock { $0 }, 0); await channel.close()
        }
        XCTAssertGreaterThan(server.invocations.withLock { $0 }, 0)
        server.close(); try await owner.closeWhenIdle()
    }
    func testLiveAnonymousRefusalRequestsRequireVersionTenRightsAndCurrentRecordDigest() async throws {
        guard getuid() > 0, getuid() == geteuid(), CGSessionCopyCurrentDictionary() != nil else {
            throw XCTSkip("Requires an ordinary Mac GUI session. Installed Root authorization remains a separate gate.")
        }
        let fixture = try DNSRecordFixture(), f = fixture.base.h.f.accountFixture
        let prepared = try fixture.begin(), sent = try prepared.transition(to: .dispatched), rejected = try sent.transition(to: .rejected, refusal: .unauthorized)
        try fixture.replace(sent, previous: prepared); try fixture.replace(rejected, previous: sent)
        let bridge = GatewaySetupImportedRuntimeOperations(initialize: { _, _, _, _ in throw Refused() }, activate: { _, _, _, _, _ in throw Refused() })
        let owner = try SetupAccountOwner(openMachine: { try f.open() }, expectedReleaseDigest: f.release,
            resume: { _, _ in throw Refused() }, accountCodePolicy: f.policy,
            lookupAccount: { uid in guard uid == f.identity.uid else { throw Refused() }; return f.identity }, importedGatewayOperation: bridge)
        defer { try? owner.close() }
        let requirement = try testRequirement(), server = try Server(owner: owner, requirement: requirement)
        defer { server.close() }
        let before = try XCTUnwrap(owner.portableImportRecovery(callerUID: getuid()))
        let form = Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)
        var expectedRights = 0
        for action: SetupPortableImportOperation.Action in [.prepareRefusedTunnelRetry, .prepareRefusedAccessRetry, .prepareRefusedDNSRetry] {
            for recovery in [false, true] {
                let driver = Driver(server: server, requirement: requirement, mode: .normal)
                let channel = PortableSetupImportChannel(driver: driver, recoveryEnabled: recovery)
                try await channel.start()
                server.rightsAllowed.withLock { $0 = true }
                let request = try SetupPortableImportOperation(action: action, expected: before.progress, proposal: fixture.base.h.f.proposal(), expectedRejectedRecordDigest: Data(repeating: 0, count: 32))
                // Bypass the client guard to test the native endpoint's independent version check.
                let reply: SetupClientReply = await withCheckedContinuation { continuation in
                    driver.invoke(.perform(request, form)) { continuation.resume(returning: $0) }
                }
                switch reply { case .failed, .progress(nil): break; default: XCTFail("An unbound refusal request was admitted") }
                if recovery { expectedRights += 1 }
                XCTAssertEqual(server.rights.withLock { $0 }, expectedRights)
                XCTAssertEqual(try owner.portableImportRecovery(callerUID: getuid()), before)
                await channel.close()
            }
        }
        let driver = Driver(server: server, requirement: requirement, mode: .normal)
        let channel = PortableSetupImportChannel(driver: driver, recoveryEnabled: true); try await channel.start()
        server.rightsAllowed.withLock { $0 = false }
        let request = try ReviewedSetupFile(proposal: fixture.base.h.f.proposal()).refusalRetryOperation(resource: .dnsRecord, recovery: before)
        do { _ = try await channel.perform(request, authorization: form); XCTFail("Refused rights authorized recovery") } catch {}
        XCTAssertEqual(server.rights.withLock { $0 }, expectedRights + 1)
        XCTAssertEqual(try owner.portableImportRecovery(callerUID: getuid()), before)
        await channel.close(); server.close(); try await owner.closeWhenIdle()
    }
    func testNativeCancellationKeepsUpdateExcludedUntilOwnedWorkSettles() async throws {
        guard getuid() > 0, getuid() == geteuid(), CGSessionCopyCurrentDictionary() != nil else {
            throw XCTSkip("Requires an ordinary Mac GUI session. Installed Root authorization remains a separate gate.")
        }
        let host = try RelayProvisioningFixture(), f = host.f.accountFixture
        let activity = try ReleaseActivityFixture(), installer = try activity.open(), gate = WorkGate()
        let bridge = GatewaySetupImportedRuntimeOperations(initialize: { _, _, _, _ in throw Refused() },
            activate: { _, _, _, _, _ in throw Refused() })
        let owner = try SetupAccountOwner(openMachine: { try gate.beforeOpen(); return try f.open() }, expectedReleaseDigest: f.release,
            resume: { _, _ in throw Refused() }, accountCodePolicy: f.policy,
            lookupAccount: { uid in guard uid == f.identity.uid else { throw Refused() }; return f.identity },
            releaseActivity: activity.open(), importedGatewayOperation: bridge)
        defer { gate.release(); try? owner.close() }
        let requirement = try testRequirement()
        let server = try Server(owner: owner, requirement: requirement, afterAuthorization: { gate.arm() })
        defer { server.close() }
        server.rightsAllowed.withLock { $0 = true }
        let request = try SetupPortableImportOperation(action: .prepareRelayPlan, expected: host.progress(owner), proposal: host.f.proposal())
        let driver = Driver(server: server, requirement: requirement, mode: .normal)
        let channel = PortableSetupImportChannel(driver: driver, timeoutMilliseconds: 5000, operationTimeoutMilliseconds: 15_000)
        try await channel.start()
        // The native reply can arrive before its server-side activity reference closes.
        let idleDeadline = ContinuousClock.now.advanced(by: .seconds(5))
        while true {
            do { try installer.acquireExclusive().close(); break }
            catch ReleaseActivityError.busy {
                guard ContinuousClock.now < idleDeadline else { throw Refused() }
                try await Task.sleep(for: .milliseconds(2))
            }
        }
        let pending = Task { try await channel.perform(request, authorization: Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)) }
        func waitUntil(_ predicate: () -> Bool) async throws {
            let deadline = ContinuousClock.now.advanced(by: .seconds(10))
            while !predicate() {
                guard ContinuousClock.now < deadline else { throw Refused() }
                try await Task.sleep(for: .milliseconds(2))
            }
        }
        func requireBusy() throws {
            do { let admitted = try installer.acquireExclusive(); admitted.close(); throw Refused() }
            catch ReleaseActivityError.busy { return }
        }
        do {
            try await waitUntil { gate.entered }
            try requireBusy()
            pending.cancel()
            do { _ = try await pending.value; XCTFail("Cancelled client confirmed an outcome") } catch {}
            try await waitUntil { server.closedConnections.withLock { $0 > 0 } }
            try requireBusy()
        } catch {
            pending.cancel(); gate.release(); _ = try? await pending.value
            await channel.close(); try await owner.closeWhenIdle(); throw error
        }
        gate.release(); await channel.close(); try await owner.closeWhenIdle()
        try installer.acquireExclusive().close()
        // A cancelled admitted write can settle either way. Do not infer its outcome from client cancellation.
        _ = try host.readPlan()
        XCTAssertEqual(server.rights.withLock { $0 }, 1)
        if let output = ProcessInfo.processInfo.environment["REMOZIO_PORTABLE_IMPORT_ACTIVITY_XPC_EVIDENCE"] {
            let evidence: [String: Any] = ["schemaVersion": 1, "experiment": "portable-import-native-xpc-activity", "status": "passed",
                "osVersion": ProcessInfo.processInfo.operatingSystemVersionString, "hostArchitecture": "arm64",
                "guiSessionAvailable": true, "sameProcessNativeConnection": true, "testCodeHashRequirementApplied": true,
                "kernelPeerCredentialsChecked": true, "invocationConnectionChecked": true,
                "idleConnectionAllowsUpdate": true, "admittedWorkExcludesUpdate": true,
                "peerInvalidationObservedBeforeSettlement": true, "cancelledClientDoesNotReleaseOwnedActivity": true,
                "settledOwnerAllowsUpdate": true, "cancellationOutcomeNotAssumed": true,
                "installedRootAccountsTested": false, "developerIDPolicyTested": false,
                "realAdministratorAuthorizationTested": false, "providerAPICalled": false, "serviceInstalled": false,
                "realApprovalIssued": false, "replyCallbackBoundaryTested": false]
            try JSONSerialization.data(withJSONObject: evidence, options: [.sortedKeys, .prettyPrinted]).write(to: URL(fileURLWithPath: output))
        }
    }

}
