import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Uses owned files and SQLite. These tests do not register services or qualify installed Root behavior.
final class RuntimeAuditUpgradeOwnedSourceTests: XCTestCase {
    private struct LostOwner: Error {}
    private func changing(_ bytes: Data, _ edits: [UInt64: CBORValue]) throws -> Data {
        let limits = try CBORLimits(maxBytes: 262144, maxDepth: 3, maxItems: 512)
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw LostOwner() }
        for (key, value) in edits { fields[key] = value }
        return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    private final class Fixture {
        let f: RuntimeActivationFixture
        let machine: PreparationIntentStore
        let runtime: ProtectedSetupDirectory
        let services: ProtectedSetupDirectory
        let clients: ProtectedSetupDirectory
        let initialization: AuthorityInitializationIntent
        let inventory: InstallationInventory
        let originalClients: RuntimeActivationClients
        init(includeHost: Bool = false) throws {
            f = try .init(nativeConsumerHosts: true, phoneRouting: true, phoneAudit: true,
                auditDelivery: true, materialAuditDelivery: false)
            try f.machine.close()
            guard chmod(f.f.root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            machine = try f.f.open()
            runtime = try .init(anchor: f.f.root.path, relativePath: "source-runtime", owner: getuid())
            services = try .init(anchor: f.f.root.path, relativePath: "source-services", owner: getuid(), visibility: .sharedMetadata)
            clients = try .init(anchor: f.f.root.path, relativePath: "source-clients", owner: getuid(), visibility: .sharedMetadata)
            initialization = try XCTUnwrap(machine.initialization(accountID: f.account.accountID))
            inventory = try XCTUnwrap(machine.inventory())
            let bundle = try f.plan.configurationBundle(account: f.account, initialization: initialization, inventory: inventory)
            originalClients = .init(presence: bundle.presenceClient, pairing: bundle.pairingClient, frontend: bundle.frontendClient)
            try write(bundle.command.canonicalBytes, .commandConfiguration, runtime)
            try write(bundle.transport.canonicalBytes, .transportConfiguration, services)
            try write(XCTUnwrap(f.plan.gatewaySettingsHost).encoded, .gatewaySettingsHost, services)
            try writeClients(originalClients)
            if includeHost { try write(f.plan.host.canonicalBytes, .commandHost, runtime) }
        }
        deinit { runtime.close(); services.close(); clients.close(); try? machine.close() }
        func path(_ file: AdministrativeSetupPublication.File, _ directory: ProtectedSetupDirectory) -> String {
            directory.path + "/" + file.name
        }
        func write(_ bytes: Data, _ file: AdministrativeSetupPublication.File,
                   _ directory: ProtectedSetupDirectory) throws {
            let path = path(file, directory)
            try bytes.write(to: URL(fileURLWithPath: path), options: .atomic)
            guard chmod(path, file.mode) == 0 else { throw JournalLeaseError.system(errno) }
        }
        func writeClients(_ value: RuntimeActivationClients) throws {
            try write(value.presence.canonicalBytes, .presenceClient(ownerUID: f.account.ownerUID), clients)
            try write(value.pairing.canonicalBytes, .pairingClient(ownerUID: f.account.ownerUID), clients)
            try write(value.frontend.canonicalBytes, .frontendClient(ownerUID: f.account.ownerUID), clients)
        }
        func retain(release: SignedReleaseEvidence? = nil,
                    verify: () throws -> Void = {}) throws -> RuntimeActivationPlan {
            try RuntimeAuditUpgradeSourcePlan.retainOwned(machine: machine, account: f.account,
                installedRelease: release ?? XCTUnwrap(f.nativeRelease), owner: getuid(),
                runtime: runtime, services: services, clientsDirectory: clients, verifyOwner: verify)
        }
        func assertUnretained() throws {
            let state = try machine.runtimeActivation(accountID: f.account.accountID)
            XCTAssertNil(state.plan); XCTAssertFalse(state.jobsRegistered)
            XCTAssertEqual(try machine.inventory(), inventory)
        }
    }
    func testRetainsThePublishedSourceWithoutCreatingAnOptionalHostOrRegisteringJobs() throws {
        let f = try Fixture()
        try f.assertUnretained()
        let plan = try f.retain()
        XCTAssertEqual(try plan.encoded, try f.f.plan.encoded)
        XCTAssertEqual(try f.machine.runtimeActivation(accountID: f.f.account.accountID).plan?.encoded, try plan.encoded)
        XCTAssertFalse(try f.machine.runtimeActivation(accountID: f.f.account.accountID).jobsRegistered)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.path(.commandHost, f.runtime)))
        XCTAssertEqual(try f.machine.inventory(), f.inventory)
    }
    func testOwnedCapturePreservesActualCommandRelayAndFrontendTunables() throws {
        let f = try Fixture(), source = f.f.plan
        let command = try AuthorityCommandStartupConfiguration.decode(changing(source.host.command.canonicalBytes,
            [7: .unsigned(17), 8: .unsigned(333), 9: .unsigned(7777), 10: .unsigned(23), 11: .unsigned(95000)]))
        let transport = try TransportPairingStartupConfiguration(transport: source.transport.transport,
            control: source.transport.control, wake: source.transport.wake, relayPort: 45678,
            settingsHost: source.transport.settingsHost)
        let authority = try XCTUnwrap(source.host.codePolicy.entries.first { $0.role == .authority && $0.active })
        let frontend = try CommandFrontendConfiguration(macID: f.f.account.macID, accountID: f.f.account.accountID,
            serviceName: command.serviceName, teamID: authority.teamID, authorityIdentifier: authority.identifier,
            authorityHashes: [authority.codeDirectoryHash], submissionLimits: .init(maxBytes: 70000, maxDepth: 17, maxItems: 9000),
            defaultIOMode: .pty, defaultDisconnectBehavior: .terminate, readiness: .init(timeoutMilliseconds: 9000))
        let clients = RuntimeActivationClients(presence: f.originalClients.presence,
            pairing: f.originalClients.pairing, frontend: frontend)
        try f.write(command.canonicalBytes, .commandConfiguration, f.runtime)
        try f.write(transport.canonicalBytes, .transportConfiguration, f.services); try f.writeClients(clients)
        let plan = try f.retain()
        let actualClients = try RuntimeActivationClients.load(directory: f.clients, owner: getuid(),
            ownerUID: f.f.account.ownerUID, verifyCurrent: {})
        let bundle = try plan.configurationBundle(account: f.f.account, initialization: f.initialization,
            inventory: f.inventory, clients: actualClients)
        XCTAssertEqual(bundle.command.canonicalBytes, command.canonicalBytes)
        XCTAssertEqual(bundle.transport.canonicalBytes, transport.canonicalBytes)
        XCTAssertEqual(bundle.frontendClient.canonicalBytes, frontend.canonicalBytes)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.path(.commandConfiguration, f.runtime))), command.canonicalBytes)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.path(.transportConfiguration, f.services))), transport.canonicalBytes)
        XCTAssertEqual(try f.machine.inventory(), f.inventory)
        XCTAssertFalse(try f.machine.runtimeActivation(accountID: f.f.account.accountID).jobsRegistered)
    }
    func testRegisteredPlansStillRequireTheCurrentReleaseAndRemainUnchanged() throws {
        let f = try Fixture(includeHost: true), plan = try f.retain()
        _ = try f.machine.enrollRuntimeActivation(plan); try f.machine.markRuntimeJobsRegistered(plan)
        let inventory = try f.machine.inventory()
        XCTAssertEqual(try f.retain().encoded, try plan.encoded)
        let changed = try NativeHostReleaseFixture.make(policy: plan.host.codePolicy,
            phoneRouting: true, phoneAudit: true, auditDelivery: true) { component in
            try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                build: "changed", teamID: component.teamID, formats: component.formats, requests: component.requests)
        }
        XCTAssertThrowsError(try f.retain(release: changed))
        XCTAssertEqual(try f.machine.runtimeActivation(accountID: f.f.account.accountID).plan?.encoded, try plan.encoded)
        XCTAssertTrue(try f.machine.runtimeActivation(accountID: f.f.account.accountID).jobsRegistered)
        XCTAssertEqual(try f.machine.inventory(), inventory)
    }
    func testMissingCommandOrConflictingHostCannotRetainAPlan() throws {
        for conflict in [false, true] {
            let f = try Fixture(includeHost: true)
            if conflict {
                try f.write(changing(f.f.plan.host.command.canonicalBytes, [7: .unsigned(17)]), .commandConfiguration, f.runtime)
            } else { XCTAssertEqual(unlink(f.path(.commandConfiguration, f.runtime)), 0) }
            XCTAssertThrowsError(try f.retain()); try f.assertUnretained()
        }
    }
    func testAnOptionalHostSymlinkCannotBecomeAnAbsentFile() throws {
        let f = try Fixture()
        XCTAssertEqual(symlink(AdministrativeSetupPublication.File.commandConfiguration.name, f.path(.commandHost, f.runtime)), 0)
        XCTAssertThrowsError(try f.retain()); try f.assertUnretained()
    }
    func testLostOwnershipRefusesBeforeRetainingTheSource() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.retain(verify: { throw LostOwner() })) { XCTAssertTrue($0 is LostOwner) }
        try f.assertUnretained()
    }
    func testEachForeignPublishedClientRefusesBeforeRetention() throws {
        let other = try Fixture()
        for role in 0..<3 {
            let f = try Fixture(), original = f.originalClients, foreign = other.originalClients
            let clients = RuntimeActivationClients(presence: role == 0 ? foreign.presence : original.presence,
                pairing: role == 1 ? foreign.pairing : original.pairing,
                frontend: role == 2 ? foreign.frontend : original.frontend)
            try f.writeClients(clients)
            XCTAssertThrowsError(try f.retain()); try f.assertUnretained()
        }
    }
    func testStorageInspectionIsReadOnlyAndCannotClaimANativeRootLocation() throws {
        let f = try Fixture(), before = try f.machine.inventory()
        try f.machine.validateStorageLease()
        XCTAssertThrowsError(try f.machine.validateStorageLease(nativeDirectory: MachineBootstrap.machineDirectory)) {
            XCTAssertEqual($0 as? JournalLeaseError, .invalidPath)
        }
        let activity = try ReleaseActivityFixture(), barrier = try activity.open()
        let token = try barrier.acquireExclusive(); defer { token.close() }
        XCTAssertThrowsError(try RuntimeAuditUpgradeSourcePlan.retain(machine: f.machine, account: f.f.account,
            installedRelease: XCTUnwrap(f.f.nativeRelease), rootActivity: token, verifyOwner: {})) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(try f.machine.inventory(), before); try f.assertUnretained()
    }
    func testClosedStorageCannotRetainSourceValues() throws {
        let f = try Fixture(); try f.machine.close()
        XCTAssertThrowsError(try f.retain()) { XCTAssertEqual($0 as? PreparationStoreError, .closed) }
        let reopened = try f.f.f.open(); defer { try? reopened.close() }
        XCTAssertNil(try reopened.runtimeActivation(accountID: f.f.account.accountID).plan)
    }
    func testMissingClientsStayMissingInsteadOfBeingRecreated() throws {
        let f = try Fixture(), file = AdministrativeSetupPublication.File.presenceClient(ownerUID: f.f.account.ownerUID)
        let path = f.path(file, f.clients); XCTAssertEqual(unlink(path), 0)
        XCTAssertThrowsError(try f.retain()); try f.assertUnretained()
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }
    func testAReplacedClientDirectoryCannotRetainAPlan() throws {
        let f = try Fixture(), path = f.clients.path
        XCTAssertEqual(rename(path, path + ".old"), 0)
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o755])
        XCTAssertThrowsError(try f.retain()); try f.assertUnretained()
    }
}
