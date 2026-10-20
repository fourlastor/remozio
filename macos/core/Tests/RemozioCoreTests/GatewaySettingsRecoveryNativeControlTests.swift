import Darwin
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsRecoveryNativeControlTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private struct Fixture {
        let old = try! GatewaySettingsConsumerControlFixture()
        var services: ServiceAccountPlan { old.plan.pair.authority.material.runtime.services }
        var policy: AuthorityCodePolicy { old.ready.fixture.runtime.plan.host.codePolicy }
        func recovery() throws -> GatewayRuntimeSettingsRecoveryPlan {
            try .init(state: .init(active: old.plan.revision, pending: nil, phase: nil), activation: old.ready.activation,
                journal: old.ready.fixture.state(), foreground: old.ready.fixture.runtime.plan,
                inventory: XCTUnwrap(old.ready.fixture.runtime.machine.inventory()), attemptID: Data(repeating: 3, count: 16))
        }
        func release() throws -> SignedReleaseEvidence {
            let entries = policy.entries.filter(\.active)
            let components = try entries.map { code in
                var formats: [ReleaseFormat] = []
                if [.authority, .transport, .notificationGateway, .setupController].contains(code.role) {
                    formats.append(try .init(name: GatewayRuntimeSettingsFenceReleaseValidation.formatName, readers: [1, 2],
                        writers: code.role == .authority ? [2] : code.role == .setupController ? [1] : []))
                }
                for consumer in GatewaySettingsConsumerRole.allCases where code.role == .authority || code.role == consumer.codeRole {
                    formats.append(try .init(name: consumer.formatName, readers: [1, 2], writers: [1, 2]))
                }
                return try ReleaseComponent(role: code.role, identifier: code.identifier, generation: code.installedGeneration,
                    relativePath: code.role == .authority ? InstalledAuthorityCommandConfiguration.executablePath : "Contents/Helpers/role-\(code.role.rawValue)",
                    codeDirectoryHash: code.role == .app ? nil : code.codeDirectoryHash, build: "1", teamID: code.teamID, formats: formats)
            }
            return try .init(manifest: .init(release: "0.1.0", build: "1", components: components),
                codeDirectoryHashes: Dictionary(uniqueKeysWithValues: entries.map { ($0.role, $0.codeDirectoryHash) }))
        }
        func services(release: SignedReleaseEvidence) throws -> ServiceAccountPlan {
            let limits = try CBORLimits(maxBytes: 16384, maxDepth: 4, maxItems: 256)
            guard case .map(var fields) = try DeterministicCBOR.decode(services.encoded, limits: limits) else { throw Failed() }
            fields[5] = .bytes(try InstallationInventory.digest(release))
            return try .decode(DeterministicCBOR.encode(.map(fields), limits: limits))
        }
    }
    private final class Driver: GatewaySettingsControlDriver {
        let binding: GatewaySettingsConsumerBinding
        let calls = Mutex((hello: 0, controls: 0, closes: 0))
        init(_ binding: GatewaySettingsConsumerBinding) { self.binding = binding }
        func start(closed: @escaping @Sendable () -> Void) {}
        func invoke(_ call: GatewaySettingsControlCall, reply: @escaping @Sendable (GatewaySettingsControlReply) -> Void) {
            do {
                switch call {
                case .hello: calls.withLock { $0.hello += 1 }; reply(.greeting(1, try binding.encoded))
                case .control(let bytes):
                    calls.withLock { $0.controls += 1 }
                    let request = try GatewaySettingsConsumerRequest.decode(bytes)
                    reply(.response(try GatewaySettingsConsumerResponse(request: request, observation: .paused).encoded))
                }
            } catch { reply(.failed) }
        }
        func close() { calls.withLock { $0.closes += 1 } }
    }
    func testNativePolicyBindsExactReleaseAuthorityRoleAndDedicatedConsumerClaim() throws {
        let f = Fixture(), release = try f.release(), services = try f.services(release: release)
        for role in GatewaySettingsConsumerRole.allCases {
            let policy = try GatewaySettingsRecoveryNativePolicy(role: role, services: services, codePolicy: f.policy, release: release)
            XCTAssertEqual(policy.authority.role, .authority); XCTAssertEqual(policy.consumer.role, role.codeRole)
            XCTAssertEqual(policy.serviceUID, services.claims.first { $0.role == (role == .gateway ? .gateway : .transport) }?.number)
            XCTAssertThrowsError(try GatewaySettingsRecoveryNativePolicy(role: role, services: f.services, codePolicy: f.policy, release: release))
            var hashes = release.codeDirectoryHashes; hashes[.authority] = Data(repeating: 19, count: 20)
            XCTAssertThrowsError(try GatewaySettingsRecoveryNativePolicy(role: role, services: services, codePolicy: f.policy,
                release: .init(manifest: release.manifest, codeDirectoryHashes: hashes)))
        }
    }
    func testRecoveryServiceNamesStaySeparateForBothRolesAndEveryAccount() throws {
        let account = Data(repeating: 1, count: 16), other = Data(repeating: 2, count: 16)
        let names = try GatewaySettingsConsumerRole.allCases.flatMap { role in
            [try role.serviceName(accountID: account), try role.recoveryServiceName(accountID: account), try role.recoveryServiceName(accountID: other)]
        }
        XCTAssertEqual(Set(names).count, 6)
        XCTAssertThrowsError(try GatewaySettingsConsumerRole.gateway.recoveryServiceName(accountID: Data()))
    }
    func testDefaultSetupChannelRejectsRecoveryBeforeHelloAndExplicitRecoveryRejectsSuccessors() async throws {
        let f = Fixture(), recovery = try f.recovery(), binding = try f.old.binding()
        for version: UInt64 in [1, 2] {
            let driver = Driver(binding)
            let channel = try GatewaySettingsConsumerChannel(driver: driver, role: binding.role, macID: binding.macID,
                accountID: binding.accountID, expectedGeneration: nil, requestVersion: version, challenge: { Data(repeating: 5, count: 32) })
            do { _ = try await channel.execute(version == 1 ? recovery.fence : f.old.fence, action: .quiesce); XCTFail() }
            catch { XCTAssertEqual(error as? GatewaySettingsControlChannelError, .changedScope) }
            XCTAssertEqual(driver.calls.withLock { $0.hello }, 0); XCTAssertEqual(driver.calls.withLock { $0.controls }, 0)
        }
        let driver = Driver(binding), channel = try GatewaySettingsConsumerChannel(driver: driver, role: binding.role,
            macID: binding.macID, accountID: binding.accountID, expectedGeneration: nil, requestVersion: 2,
            challenge: { Data(repeating: 5, count: 32) })
        let reply = try await channel.execute(recovery.fence, action: .quiesce)
        XCTAssertEqual(reply.request.change.version, 2); XCTAssertEqual(reply.observation, .paused)
        XCTAssertEqual(driver.calls.withLock { $0.controls }, 1)
        for version: UInt64 in [0, 3, .max] {
            XCTAssertThrowsError(try GatewaySettingsConsumerChannel(driver: driver, role: binding.role, macID: binding.macID,
                accountID: binding.accountID, expectedGeneration: nil, requestVersion: version, challenge: { Data(repeating: 1, count: 32) }))
        }
    }
    func testEndpointModesRejectCrossedRequestsBeforeBudgetOrExecution() async throws {
        let f = Fixture(), recovery = try f.recovery(), binding = try f.old.binding(), count = Mutex(0)
        for version: UInt64 in [1, 2] {
            let budget = try AuthorityXPCWorkBudget(maximum: 1)
            let endpoint = GatewaySettingsConsumerXPCEndpoint(binding: binding, requestVersion: version, verify: {}, verifyCurrent: {},
                budget: budget, invalidate: {}, execute: { _ in count.withLock { $0 += 1 }; return .paused })
            endpoint.hello { value, _ in XCTAssertEqual(value, 1) }
            let request = try GatewaySettingsConsumerRequest(binding: binding, fence: version == 1 ? recovery.fence : f.old.fence,
                action: .quiesce, challenge: Data(repeating: 1, count: 32))
            endpoint.control(try request.encoded) { XCTAssertNil($0) }
            await endpoint.closeAndWait()
            XCTAssertEqual(count.withLock { $0 }, 0)
            XCTAssertTrue(budget.acquire()); budget.release()
        }
    }
    private final class Calls: Sendable { let value = Mutex(0) }
    private struct Builder: GatewaySettingsConsumerEndpointBuilding {
        let binding: GatewaySettingsConsumerBinding
        let version: UInt64
        let calls: Calls
        func make(connection: NSXPCConnection, budget: AuthorityXPCWorkBudget,
                  onHandshake: @escaping @Sendable () -> Void,
                  onClose: @escaping @Sendable () -> Void) throws -> GatewaySettingsConsumerXPCEndpoint {
            let endpoint = GatewaySettingsConsumerXPCEndpoint(binding: binding, requestVersion: version, verify: {
                guard NSXPCConnection.current() === connection else { throw Failed() }
            }, verifyCurrent: {}, budget: budget, onHandshake: onHandshake, invalidate: {
                connection.invalidate(); onClose()
            }, execute: { _ in calls.value.withLock { $0 += 1 }; return .paused })
            connection.exportedInterface = NSXPCInterface(with: GatewaySettingsConsumerXPCProtocol.self)
            connection.exportedObject = endpoint
            connection.interruptionHandler = { [weak endpoint] in endpoint?.close() }
            connection.invalidationHandler = { [weak endpoint] in endpoint?.close() }
            return endpoint
        }
    }
    func testRecoveryRequestTraversesAnActualAnonymousConnectionAndOldEndpointRefusesIt() async throws {
        let f = Fixture(), recovery = try f.recovery()
        for endpointVersion: UInt64 in [1, 2] {
            let binding = try f.old.binding(), calls = Calls(), native = NSXPCListener.anonymous()
            let listener = try GatewaySettingsConsumerXPCListener(listener: native, builder: Builder(binding: binding, version: endpointVersion, calls: calls), verifyCurrent: {})
            try listener.start()
            let connection = NSXPCConnection(listenerEndpoint: native.endpoint)
            let channel = try GatewaySettingsConsumerChannel(driver: NativeGatewaySettingsConsumerDriver(connection: connection, verifyPeer: {}),
                role: binding.role, macID: binding.macID, accountID: binding.accountID, expectedGeneration: nil,
                timeoutMilliseconds: 1000, requestVersion: 2, challenge: { Data(repeating: 5, count: 32) })
            do {
                let result = try await channel.execute(recovery.fence, action: .quiesce)
                XCTAssertEqual(endpointVersion, 2); XCTAssertEqual(result.request.change.version, 2)
                XCTAssertEqual(result.observation, .paused)
            } catch { XCTAssertEqual(endpointVersion, 1) }
            await listener.closeAndWait()
            XCTAssertEqual(calls.value.withLock { $0 }, endpointVersion == 2 ? 1 : 0)
        }
    }
    func testNativeRecoveryFactoriesRefuseTheOrdinaryAccountBeforeScopeOrCodeWork() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("This control requires an ordinary account") }
        let f = Fixture(), release = try f.release(), invoked = Mutex(false), owner = try f.old.owner()
        XCTAssertThrowsError(try GatewaySettingsConsumerChannel.recovery(role: .gateway, services: f.services,
            codePolicy: f.policy, release: release, expectedGeneration: nil, verifyCurrent: { invoked.withLock { $0 = true } })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        let access = try GatewaySettingsConsumerAccess(owner: owner, services: f.services, verifyCurrent: { invoked.withLock { $0 = true } })
        XCTAssertThrowsError(try GatewaySettingsConsumerXPCListener.recovery(services: f.services, codePolicy: f.policy,
            release: release, access: access, acquireActivity: { invoked.withLock { $0 = true }; throw Failed() }))
        XCTAssertFalse(invoked.withLock { $0 })
    }
}
