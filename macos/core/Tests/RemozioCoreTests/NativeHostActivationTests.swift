import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Synthetic signed evidence checks declarations only. It does not prove native signature or service admission.
enum NativeHostReleaseFixture {
    static func make(policy: AuthorityCodePolicy, edit: (ReleaseComponent) throws -> ReleaseComponent = { $0 }) throws -> SignedReleaseEvidence {
        let entries = policy.entries.filter(\.active)
        let components = try entries.map { code in
            var formats: [ReleaseFormat] = []
            if [.authority, .setupController].contains(code.role) {
                formats.append(try .init(name: RuntimeActivationPlan.formatName, readers: [1, 2], writers: code.role == .setupController ? [1, 2] : []))
                formats.append(try .init(name: "authority.installation-preparation", readers: Set(UInt64(1)...11), writers: Set(UInt64(1)...11)))
                formats.append(try .init(name: "authority.command-host-config", readers: [1, 2, 3], writers: [1, 2, 3]))
                formats.append(try .init(name: GatewaySettingsControlReleaseValidation.formatName, readers: [1], writers: [1]))
            }
            if [.authority, .transport, .notificationGateway, .setupController].contains(code.role) {
                formats.append(try .init(name: GatewaySettingsConsumerHostConfiguration.formatName, readers: [1],
                    writers: code.role == .setupController ? [1] : []))
                formats.append(try .init(name: GatewayRuntimeSettingsFenceReleaseValidation.formatName, readers: [1, 2],
                    writers: code.role == .authority ? [2] : code.role == .setupController ? [1] : []))
            }
            if [.authority, .transport, .notificationGateway, .setupController].contains(code.role) {
                for name in ["transport.pairing-config", "gateway.service-config"] {
                    formats.append(try .init(name: name, readers: [1, 2], writers: code.role == .setupController ? [1, 2] : []))
                }
            }
            for consumer in GatewaySettingsConsumerRole.allCases where code.role == .authority || code.role == consumer.codeRole || code.role == .setupController {
                formats.append(try .init(name: consumer.formatName, readers: [1, 2], writers: code.role == .setupController ? [1] : [1, 2]))
            }
            for record in try GatewayRuntimeRecordFormats.requirements(commitVersions: GatewayRuntimeCommit.supportedVersions,
                                                                       settingsRetained: true) where record.role == code.role {
                formats.append(try .init(name: record.name, readers: record.readVersions, writers: record.writeVersions))
            }
            let path: String
            switch code.role {
            case .app: path = "Contents/MacOS/Remozio"
            case .authority: path = InstalledAuthorityCommandConfiguration.executablePath
            case .transport: path = "Contents/Library/LaunchServices/RemozioTransport"
            case .notificationGateway: path = GatewayJournalSetupServiceConfiguration.executableRelativePath
            case .setupController: path = AdministrativeSetupConfiguration.executablePath
            case .commandFrontend: path = "Contents/Helpers/remozio"
            case .commandMonitor: path = "Contents/Helpers/RemozioCommandMonitor"
            case .commandChild: path = "Contents/Helpers/RemozioCommandChild"
            default: throw GatewayPreparationError.invalidRecord
            }
            return try edit(.init(role: code.role, identifier: code.identifier, generation: code.installedGeneration,
                relativePath: path, codeDirectoryHash: code.role == .app ? nil : code.codeDirectoryHash, build: "1", teamID: code.teamID, formats: formats))
        }
        return try .init(manifest: .init(release: "0.1.0", build: "1", components: components),
            codeDirectoryHashes: Dictionary(uniqueKeysWithValues: entries.map { ($0.role, $0.codeDirectoryHash) }))
    }
}

final class NativeHostActivationTests: XCTestCase, @unchecked Sendable {
    private let limits = try! CBORLimits(maxBytes: 262144, maxDepth: 3, maxItems: 64)
    private func fields(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw RuntimeActivationError.invalidPlan }
        return fields
    }
    private func plan(_ f: RuntimeActivationFixture, release: SignedReleaseEvidence?) throws -> RuntimeActivationPlan {
        try .init(account: f.account, initialization: XCTUnwrap(f.machine.initialization(accountID: f.account.accountID)),
            runtime: f.machine.runtimePreparation(accountID: f.account.accountID), inventory: XCTUnwrap(f.machine.inventory()),
            gatewaySettingsRelease: release)
    }
    private func selection(_ f: RuntimeActivationFixture, release: SignedReleaseEvidence) throws -> GatewaySettingsNativeHostPlan {
        var services = try fields(f.services.encoded); services[5] = .bytes(try InstallationInventory.digest(release))
        let current = try ServiceAccountPlan.decode(DeterministicCBOR.encode(.map(services), limits: limits))
        let old = try f.material.reference
        let activity = try ServiceReleaseActivityReference(services: current,
            identities: [.transport: .init(device: 1, inode: 100), .gateway: .init(device: 1, inode: 101)])
        let reference = try RuntimeMaterialReference(materialID: old.materialID, services: current, materialDigest: old.materialDigest,
            transportPublicKeyInfo: old.transportPublicKeyInfo, gateway: old.gateway, serviceActivity: activity)
        return try .init(reference: reference, bundlePath: f.plan.bundlePath, policy: f.plan.host.codePolicy)
    }
    func testVersionTwoRoundTripAndReopenedStoreRetainBothExactHostAndJobSelectionsWithoutSecrets() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true), p = f.plan, bytes = try p.encoded
        XCTAssertEqual(try fields(bytes)[0], .unsigned(2)); XCTAssertEqual(try fields(bytes).count, 6)
        let decoded = try RuntimeActivationPlan.decode(bytes), hosts = try XCTUnwrap(decoded.consumerHosts)
        XCTAssertEqual(try decoded.encoded, bytes); XCTAssertEqual(decoded.transport.settingsHost, hosts.transport)
        XCTAssertEqual(decoded.gatewaySettingsHost, hosts.gateway); XCTAssertTrue(decoded.host.gatewaySettingsControlEnabled)
        XCTAssertEqual(decoded.transportJob.arguments[1], "--settings-host")
        let gateway = try hosts.job(.gateway); XCTAssertEqual(gateway.arguments[1], "--settings-host")
        XCTAssertEqual(gateway.configurationPath, try hosts.gateway.gatewayConfigurationPath)
        XCTAssertEqual(decoded.transportJob.configurationPath, try RuntimePreparationPaths(accountID: p.accountID).transportConfiguration)
        XCTAssertNil(bytes.range(of: f.material.transportIdentity))
        try f.machine.retainRuntimeActivation(p); try f.machine.close()
        let reopened = try f.f.open(); defer { try? reopened.close() }
        let retained = try XCTUnwrap(reopened.runtimeActivation(accountID: p.accountID).plan)
        XCTAssertEqual(try retained.encoded, bytes); XCTAssertEqual(retained.transportJob.bytes, decoded.transportJob.bytes)
        XCTAssertEqual(try retained.consumerHosts?.job(.gateway).bytes, gateway.bytes)
    }
    func testLegacyRecordBytesAndLaunchCommandsRemainVersionOne() throws {
        let f = try RuntimeActivationFixture(), before = try f.plan.encoded, decoded = try RuntimeActivationPlan.decode(before)
        XCTAssertEqual(try fields(before)[0], .unsigned(1)); XCTAssertEqual(try fields(before).count, 5)
        XCTAssertEqual(try decoded.encoded, before); XCTAssertNil(decoded.consumerHosts); XCTAssertNil(decoded.gatewaySettingsHost)
        XCTAssertNil(decoded.transport.settingsHost); XCTAssertEqual(decoded.transportJob.arguments[1], "--pairing-configuration")
        XCTAssertEqual(decoded.transportJob.machServices, [try RuntimePreparationPaths(accountID: decoded.accountID).pairingService])
        XCTAssertEqual(decoded.authorityJob.bytes, f.plan.authorityJob.bytes); XCTAssertEqual(decoded.transportJob.bytes, f.plan.transportJob.bytes)
    }
    func testEachRoleDeclaresBothDistinctControlServicesAlongsideItsExistingEndpoints() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true), hosts = try XCTUnwrap(f.plan.consumerHosts)
        let paths = try RuntimePreparationPaths(accountID: f.account.accountID)
        for role in GatewaySettingsConsumerRole.allCases {
            let job = try hosts.job(role), old = try InstalledAccountJobManifest(accountID: f.account.accountID, role: role.codeRole,
                executionUID: job.declaration.executionUID, userName: job.userName, bundlePath: f.plan.bundlePath)
            let controls = try Set([role.serviceName(accountID: f.account.accountID), role.recoveryServiceName(accountID: f.account.accountID)])
            XCTAssertEqual(job.machServices, old.machServices.union(controls)); XCTAssertEqual(controls.count, 2)
            XCTAssertEqual(job.declaration, old.declaration); XCTAssertNotEqual(job.bytes, old.bytes)
        }
        XCTAssertTrue(f.plan.authorityJob.machServices.contains(paths.gatewaySettingsControlService))
        XCTAssertThrowsError(try InstalledAccountJobManifest(accountID: f.account.accountID, role: .authority,
            executionUID: 0, userName: "root", bundlePath: f.plan.bundlePath, settingsConsumerHostEnabled: true))
    }
    func testActivityMetadataAloneCannotConstructAnActivationPlanOrSelectUnsignedParticipants() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true), legacy = try RuntimeActivationFixture()
        XCTAssertThrowsError(try plan(f, release: nil))
        XCTAssertThrowsError(try GatewaySettingsNativeHostPlan(reference: legacy.material.reference,
            bundlePath: legacy.plan.bundlePath, policy: legacy.plan.host.codePolicy))
        let release = try XCTUnwrap(f.nativeRelease)
        XCTAssertNoThrow(try plan(f, release: release))
        var inspected = release.codeDirectoryHashes; inspected[.transport] = Data(repeating: 99, count: 20)
        XCTAssertThrowsError(try f.plan.consumerHosts?.validateRelease(.init(manifest: release.manifest, codeDirectoryHashes: inspected)))
        // A changed service scope must not be smuggled through an existing codec2 transport record.
        let other = try RuntimeActivationFixture(nativeConsumerHosts: true)
        XCTAssertThrowsError(try f.plan.consumerHosts?.selecting(other.plan.transport))
    }
    func testMissingVersionReadersWritersAndExactExecutablePathsBlockNewSelection() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true), policy = f.plan.host.codePolicy
        let mutations: [(AuthorityCodeRole, String, Bool)] = [
            (.authority, RuntimeActivationPlan.formatName, false), (.setupController, RuntimeActivationPlan.formatName, true),
            (.authority, GatewaySettingsConsumerHostConfiguration.formatName, false),
            (.setupController, GatewaySettingsConsumerHostConfiguration.formatName, true),
            (.authority, "transport.pairing-config", false), (.notificationGateway, "transport.pairing-config", false),
            (.authority, "gateway.service-config", false), (.transport, "gateway.service-config", false),
            (.notificationGateway, "gateway.service-config", false), (.setupController, "gateway.service-config", true),
            (.transport, "transport.pairing-config", false), (.setupController, "transport.pairing-config", true),
            (.authority, GatewayRuntimeSettingsFenceReleaseValidation.formatName, true),
            (.transport, GatewayRuntimeSettingsFenceReleaseValidation.formatName, false),
            (.notificationGateway, GatewaySettingsConsumerRole.gateway.formatName, false),
            (.authority, GatewaySettingsConsumerRole.transport.formatName, true)]
        for (role, name, writer) in mutations {
            let release = try NativeHostReleaseFixture.make(policy: policy) { component in
                guard component.role == role else { return component }
                let formats = try component.formats.compactMap { f -> ReleaseFormat? in
                    guard f.name == name else { return f }
                    guard writer else { return nil }
                    return try ReleaseFormat(name: f.name, readers: f.readers, writers: [])
                }
                return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                    relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                    teamID: component.teamID, formats: formats)
            }
            XCTAssertThrowsError(try selection(f, release: release).validateRelease(release), "Missing \(name) for \(role)")
        }
        for role in [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController] {
            let release = try NativeHostReleaseFixture.make(policy: policy) { component in
                guard component.role == role else { return component }
                return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                    relativePath: "Contents/Helpers/wrong", codeDirectoryHash: component.codeDirectoryHash,
                    build: component.build, teamID: component.teamID, formats: component.formats)
            }
            XCTAssertThrowsError(try selection(f, release: release).validateRelease(release))
        }
    }
    func testClosedRecordRejectsMissingForeignOrDowngradedNestedHostRecords() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true), other = try RuntimeActivationFixture(nativeConsumerHosts: true)
        let original = try fields(f.plan.encoded)
        var mutations: [[UInt64: CBORValue]] = []
        var v = original; v[0] = .unsigned(1); mutations.append(v)
        v = original; v[0] = .unsigned(3); mutations.append(v)
        v = original; v[5] = nil; mutations.append(v)
        v = original; v[6] = .null; mutations.append(v)
        v = original; v[5] = .bytes(try XCTUnwrap(other.plan.gatewaySettingsHost).encoded); mutations.append(v)
        v = original; v[4] = .bytes(try RuntimeActivationFixture().plan.transport.canonicalBytes); mutations.append(v)
        let h = f.plan.host
        let withoutControl = try InstalledAuthorityCommandConfiguration(machineDirectory: h.machineDirectory,
            installationID: h.installationID, releaseDigest: h.releaseDigest, codePolicy: h.codePolicy, command: h.command,
            label: h.label, plistName: h.plistName, jobPlacement: .systemAccount)
        v = original; v[3] = .bytes(withoutControl.canonicalBytes); mutations.append(v)
        for fields in mutations {
            XCTAssertThrowsError(try RuntimeActivationPlan.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        }
    }
    func testGatewayProposalAndRetainedActivationDeriveTheSameNativeJobAndPreserveTransportHostMetadata() throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture(nativeConsumerHosts: true)
        try f.retainCompletion(.decode(f.initialize()))
        let runtime = f.runtime, inventory = try XCTUnwrap(runtime.machine.inventory())
        let activation = try GatewayRuntimeActivationPlan(journal: f.state(), foreground: runtime.plan, inventory: inventory)
        let proposal = try activation.proposal(journal: f.state(), foreground: runtime.plan, inventory: inventory)
        XCTAssertEqual(try activation.gatewayJob.bytes, proposal.gatewayJob.bytes)
        XCTAssertEqual(proposal.gatewayJob.arguments[1], "--settings-host")
        XCTAssertEqual(proposal.transport.settingsHost, runtime.plan.transport.settingsHost)
        XCTAssertEqual(proposal.transport.transport.canonicalBytes, runtime.plan.transport.transport.canonicalBytes)
        XCTAssertEqual(proposal.commandHost.command.execution, runtime.plan.host.command.execution)
        let bundle = try RuntimeConfigurationBundle.initial(account: runtime.account,
            initialization: XCTUnwrap(runtime.machine.initialization(accountID: runtime.account.accountID)),
            reference: runtime.plan.reference, inventory: inventory)
        XCTAssertEqual(try bundle.gatewaySettingsHost?.encoded, try runtime.plan.gatewaySettingsHost?.encoded)
        XCTAssertEqual(AdministrativeSetupPublication.File.gatewaySettingsHost.mode, 0o644)
        XCTAssertEqual(AdministrativeSetupPublication.File.gatewaySettingsHost.name, GatewaySettingsConsumerHostConfiguration.gatewayFileName)
    }
    func testCompletedNativeSettingsRecoverThroughTheActualRootOwnerWithBothSelectedHosts() async throws {
        let f = try AuthorityGatewayRecoveryAccessTests.Fixture(nativeConsumerHosts: true)
        let original = try f.root.state(), coordinator = try f.access().makeCoordinator()
        XCTAssertNotNil(f.ready.fixture.runtime.plan.consumerHosts)
        try await f.service.start()
        let recovered = try await coordinator.refresh(); XCTAssertTrue(recovered)
        let snapshot = try XCTUnwrap(f.state.withLock { $0.snapshot })
        XCTAssertEqual(snapshot.foreground.transport.settingsHost, snapshot.foreground.consumerHosts?.transport)
        XCTAssertNotNil(snapshot.plan.pair.transport.material.runtime.serviceActivity)
        XCTAssertEqual(try snapshot.activation.gatewayJob.arguments[1], "--settings-host")
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.fencePath)); XCTAssertNil(f.root.capability.publication)
        try await f.service.installPhonePush(f.root.options, commitDigest: snapshot.plan.commit.observationDigest, verifyCurrent: {})
        XCTAssertNotNil(f.root.capability.publication); XCTAssertEqual(try f.root.state(), original)
        XCTAssertEqual(f.root.starts.withLock { $0 }, 1)
        await coordinator.close(); XCTAssertNil(f.root.capability.publication)
        try await f.closeOwners()
    }

}
