import Darwin
import Foundation
import Synchronization
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Synthetic release and binding inputs test codec gates only. They grant no native startup authority.
final class MachineUpdateConsumerHealthStartupTests: XCTestCase {
    private struct Fixture {
        let runtime: RuntimeActivationFixture
        let release: SignedReleaseEvidence
        let original: GatewaySettingsConsumerHostConfiguration
        let startup: GatewaySettingsConsumerHostConfiguration
        let completion: GatewaySettingsConsumerHostConfiguration
        init(authorityReadsReleaseBoundHost: Bool = true) throws {
            let runtime = try RuntimeActivationFixture(nativeConsumerHosts: true)
            let original = try XCTUnwrap(runtime.plan.consumerHosts).gateway
            let policy = original.codePolicy
            let release = try NativeHostReleaseFixture.make(policy: policy) { component in
                var formats = try component.formats.map { format in
                    if format.name == GatewaySettingsConsumerHostConfiguration.formatName {
                        let readsVersionTwo = component.role != .authority || authorityReadsReleaseBoundHost
                        let readers = readsVersionTwo ? format.readers.union([2]) : format.readers
                        return try ReleaseFormat(name: format.name, readers: readers,
                            writers: component.role == .setupController ? format.writers.union([2]) : format.writers)
                    }
                    return format
                }
                if [AuthorityCodeRole.authority, .transport, .notificationGateway].contains(component.role) {
                    formats.append(try .init(name: MachineUpdateConsumerHealthReleaseValidation.formatName, readers: [1], writers: [1]))
                }
                return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                    relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                    build: component.build, teamID: component.teamID, formats: formats)
            }
            let base = try MachineUpdateRoleChallengeTests.Fixture().requirement().binding
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: base.encoded) as? [String: Any])
            fields["macID"] = original.runtime.services.macID.base64EncodedString()
            fields["installationID"] = original.runtime.services.installationID.base64EncodedString()
            fields["accountID"] = original.runtime.services.accountID.base64EncodedString()
            fields["runtimeReferenceDigest"] = try MachineUpdateActivationRecord.digest(original.runtime.encoded).base64EncodedString()
            fields["previousInstalledReleaseDigest"] = original.runtime.services.releaseDigest.base64EncodedString()
            fields["installedReleaseDigest"] = try InstallationInventory.digest(release).base64EncodedString()
            let policyDigest = try MachineUpdateActivationRecord.digest(policy.bytes).base64EncodedString()
            fields["startupPolicyDigest"] = policyDigest; fields["completionPolicyDigest"] = policyDigest
            let binding = try RuntimeReleaseBinding.decode(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]))
            self.runtime = runtime; self.release = release; self.original = original
            startup = try .init(role: .gateway, runtime: original.runtime, bundlePath: original.bundlePath,
                codePolicy: policy, releaseBinding: binding, policyStage: .startup)
            completion = try .init(role: .gateway, runtime: original.runtime, bundlePath: original.bundlePath,
                codePolicy: policy, releaseBinding: binding, policyStage: .completion)
        }
    }
    private func select(_ role: GatewaySettingsConsumerRole, from host: GatewaySettingsConsumerHostConfiguration) throws
        -> GatewaySettingsConsumerHostConfiguration {
        try .init(role: role, runtime: host.runtime, bundlePath: host.bundlePath, codePolicy: host.codePolicy,
            releaseBinding: host.releaseBinding, policyStage: host.policyStage)
    }
    private func editing(_ fixture: Fixture, _ edit: (ReleaseComponent) throws -> ReleaseComponent) throws -> SignedReleaseEvidence {
        let components = try fixture.release.manifest.components.map(edit)
        let manifest = try ReleaseManifest(release: fixture.release.manifest.release, build: fixture.release.manifest.build, components: components)
        return .init(manifest: manifest, codeDirectoryHashes: fixture.release.codeDirectoryHashes)
    }
    private func formats(_ component: ReleaseComponent, _ value: [ReleaseFormat]) throws -> ReleaseComponent {
        try .init(role: component.role, identifier: component.identifier, generation: component.generation,
            relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
            build: component.build, teamID: component.teamID, formats: value)
    }
    func testStartupModeKeepsCompletionOutOfTheCurrentNativePaths() throws {
        let fixture = try Fixture()
        for role in GatewaySettingsConsumerRole.allCases {
            let ordinary = try select(role, from: fixture.original)
            let startup = try select(role, from: fixture.startup)
            let completion = try select(role, from: fixture.completion)
            XCTAssertEqual(try GatewaySettingsConsumerStartupMode.select(ordinary), .ordinary)
            XCTAssertEqual(try GatewaySettingsConsumerStartupMode.select(startup), .updateHealth)
            XCTAssertThrowsError(try GatewaySettingsConsumerStartupMode.select(completion))
        }
    }

    func testGatewayHealthReaderAcceptsOnlyTheProtectedStartupHost() throws {
        let fixture = try Fixture()
        let startup = try fixture.startup.encoded
        XCTAssertEqual(try GatewaySettingsConsumerHostConfiguration.decodeForUpdateHealthStartup(startup), fixture.startup)
        XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decode(startup))
        let ordinary = try fixture.original.encoded, completion = try fixture.completion.encoded
        XCTAssertEqual(try GatewaySettingsConsumerHostConfiguration.decode(ordinary), fixture.original)
        XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decodeForUpdateHealthStartup(ordinary))
        XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decodeForUpdateHealthStartup(completion))
        XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decode(completion))
        let path = try fixture.startup.gatewayConfigurationPath
        let selected = try GatewaySettingsConsumerNativeScope.decodeGatewayStartup(startup, path: path)
        XCTAssertEqual(selected.host, fixture.startup)
        XCTAssertEqual(selected.mode, .updateHealth)
        XCTAssertEqual(try GatewaySettingsConsumerNativeScope.decodeGatewayStartup(ordinary, path: path).mode, .ordinary)
        XCTAssertThrowsError(try GatewaySettingsConsumerNativeScope.decodeGatewayStartup(completion, path: path))
        XCTAssertThrowsError(try GatewaySettingsConsumerNativeScope.decodeGatewayStartup(startup, path: path + ".other"))

        let retained = try RetainedSetupConsumerHostArchiveTests.Fixture()
        for version in [UInt64(3), UInt64(4)] {
            let bytes = try retained.bytes(stage: version, role: .gateway)
            let host = try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(bytes)
            let path = try host.gatewayConfigurationPath
            let ordinary = try retained.f.host(.gateway, runtime: retained.reference)
            XCTAssertEqual(try GatewaySettingsConsumerNativeScope.decodeGatewayStartup(ordinary.encoded, path: path).mode, .ordinary)
            XCTAssertThrowsError(try GatewaySettingsConsumerNativeScope.decodeGatewayStartup(bytes, path: path)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
        }
    }

    func testTransportHealthReaderPreservesTheStartupHostAndRejectsOrdinaryAndCompletion() throws {
        let fixture = try Fixture(), base = fixture.runtime.plan.transport
        func encode(_ host: GatewaySettingsConsumerHostConfiguration) throws -> Data {
            let transportHost = try select(.transport, from: host)
            return try TransportPairingStartupConfiguration(transport: base.transport, control: base.control,
                wake: base.wake, relayPort: base.relayPort, settingsHost: transportHost).canonicalBytes
        }
        let startup = try encode(fixture.startup)
        let decoded = try TransportSettingsConsumerBootstrap.decodeForUpdateHealthStartup(startup)
        XCTAssertEqual(decoded.host, try select(.transport, from: fixture.startup))
        XCTAssertEqual(decoded.base.canonicalBytes, startup)
        XCTAssertThrowsError(try TransportSettingsConsumerBootstrap.decode(startup))
        let ordinary = try encode(fixture.original), completion = try encode(fixture.completion)
        XCTAssertEqual(try TransportSettingsConsumerBootstrap.decode(ordinary).host, try select(.transport, from: fixture.original))
        XCTAssertThrowsError(try TransportSettingsConsumerBootstrap.decodeForUpdateHealthStartup(ordinary))
        XCTAssertThrowsError(try TransportSettingsConsumerBootstrap.decodeForUpdateHealthStartup(completion))
        XCTAssertThrowsError(try TransportSettingsConsumerBootstrap.decode(completion))
        let path = try decoded.configurationPath
        let selected = try GatewaySettingsConsumerNativeScope.decodeTransportStartup(startup, path: path)
        XCTAssertEqual(selected.bootstrap.base.canonicalBytes, startup)
        XCTAssertEqual(selected.mode, .updateHealth)
        XCTAssertEqual(try GatewaySettingsConsumerNativeScope.decodeTransportStartup(ordinary, path: path).mode, .ordinary)
        XCTAssertThrowsError(try GatewaySettingsConsumerNativeScope.decodeTransportStartup(completion, path: path))
        XCTAssertThrowsError(try GatewaySettingsConsumerNativeScope.decodeTransportStartup(startup, path: path + ".other"))

        let retained = try RetainedSetupConsumerHostArchiveTests.Fixture(), source = retained.f.f.plan.transport
        for version in [UInt64(3), UInt64(4)] {
            let host = try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(retained.bytes(stage: version))
            let encoded = try TransportPairingStartupConfiguration(transport: source.transport, control: source.control,
                wake: source.wake, relayPort: source.relayPort, settingsHost: host).canonicalBytes
            let bootstrap = try TransportSettingsConsumerBootstrap(base: .decodeForReleaseArchive(encoded))
            let path = try bootstrap.configurationPath
            XCTAssertNoThrow(try bootstrap.validatePath(path))
            let ordinaryHost = try retained.f.host(.transport, runtime: retained.reference)
            let ordinary = try TransportPairingStartupConfiguration(transport: source.transport, control: source.control,
                wake: source.wake, relayPort: source.relayPort, settingsHost: ordinaryHost)
            XCTAssertEqual(try GatewaySettingsConsumerNativeScope.decodeTransportStartup(ordinary.canonicalBytes, path: path).mode, .ordinary)
            XCTAssertThrowsError(try GatewaySettingsConsumerNativeScope.decodeTransportStartup(encoded, path: path)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
        }
    }

    func testHealthPeerPolicyUsesTheSuccessorReleaseAndRetainedConsumerAccount() throws {
        let fixture = try Fixture()
        XCTAssertNotEqual(try InstallationInventory.digest(fixture.release), fixture.original.runtime.services.releaseDigest)
        for role in GatewaySettingsConsumerRole.allCases {
            let startup = try select(role, from: fixture.startup)
            let policy = try GatewaySettingsRecoveryNativePolicy(host: startup, release: fixture.release)
            XCTAssertEqual(policy.consumer, startup.consumerCode)
            XCTAssertEqual(policy.serviceUID, startup.serviceUID)
            XCTAssertEqual(policy.authority, try XCTUnwrap(startup.codePolicy.entries.first { $0.role == .authority && $0.active }))
            let expected = try XCTUnwrap(fixture.runtime.services.claims.first { $0.role == startup.serviceRole })
            func retain(_ claim: ServiceAccountClaim, _: ServiceDirectoryKind) throws -> ServiceDirectoryState {
                claim == expected ? .retained : .absent
            }
            try GatewaySettingsConsumerNativeScope.requireRetainedAccount(host: startup, state: retain)
            let foreignAccount = try ServiceAccountClaim(accountID: expected.accountID, role: expected.role,
                number: expected.number, userID: UUID(), groupID: UUID())
            XCTAssertThrowsError(try GatewaySettingsConsumerNativeScope.requireRetainedAccount(host: startup,
                state: { claim, _ in claim == foreignAccount ? .retained : .absent })) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
            let ordinary = try select(role, from: fixture.original)
            XCTAssertThrowsError(try GatewaySettingsRecoveryNativePolicy(host: ordinary, release: fixture.release))
            var hashes = fixture.release.codeDirectoryHashes
            hashes[.authority] = Data(repeating: 99, count: 20)
            let foreign = SignedReleaseEvidence(manifest: fixture.release.manifest, codeDirectoryHashes: hashes)
            XCTAssertThrowsError(try GatewaySettingsRecoveryNativePolicy(host: startup, release: foreign))
        }
    }

    func testNativeParticipantChecksPreserveStartupBindingsAndAcceptOrdinaryHosts() throws {
        let fixture = try Fixture(), ordinaryRelease = try XCTUnwrap(fixture.runtime.nativeRelease)
        for role in GatewaySettingsConsumerRole.allCases {
            let startup = try select(role, from: fixture.startup)
            let ordinary = try select(role, from: fixture.original)
            try GatewaySettingsConsumerNativeScope.validateParticipants(host: startup, release: fixture.release)
            try GatewaySettingsConsumerNativeScope.validateParticipants(host: ordinary, release: ordinaryRelease)
            XCTAssertThrowsError(try GatewaySettingsConsumerNativeScope.validateParticipants(host: startup, release: ordinaryRelease))
        }
    }

    func testStartupChannelPinsTheSelectedTransportAndRefusesForeignIdentity() throws {
        let fixture = try Fixture()
        let host = try select(.transport, from: fixture.startup)
        let binding = try XCTUnwrap(host.releaseBinding)
        let seed = try MachineUpdateRoleChallengeTests.Fixture().requirement()
        func requirement(uid: UInt32, key: Data) -> MachineUpdateRestartHealthPlan.Requirement {
            .init(binding: binding, configurationEpoch: seed.configurationEpoch,
                configurationRevision: seed.configurationRevision, backendEpoch: seed.backendEpoch,
                backendRevision: seed.backendRevision, role: .transport, executionUID: uid,
                code: host.consumerCode, publicKey: key)
        }
        let key = try host.runtime.transportPublicKeyX963
        let expected = requirement(uid: host.serviceUID, key: key)
        let pins = try MachineUpdateConsumerHealthChannel.peerPins(host: host, requirement: expected,
            registration: nil, release: fixture.release)
        XCTAssertEqual(pins.consumer, expected.code)
        XCTAssertEqual(pins.serviceUID, expected.executionUID)
        XCTAssertEqual(pins.authority, host.codePolicy.entries.first { $0.role == .authority && $0.active })
        for foreign in [requirement(uid: host.serviceUID + 1, key: key),
                        requirement(uid: host.serviceUID, key: seed.publicKey)] {
            XCTAssertThrowsError(try MachineUpdateConsumerHealthChannel.peerPins(host: host, requirement: foreign,
                registration: nil, release: fixture.release)) {
                XCTAssertEqual($0 as? MachineUpdateConsumerHealthChannelError, .changedScope)
            }
        }
        XCTAssertThrowsError(try MachineUpdateConsumerHealthChannel.peerPins(
            host: select(.transport, from: fixture.completion), requirement: expected, registration: nil, release: fixture.release)) {
            XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
        }
    }

    func testStartupChannelRequiresTheExactGatewayRegistration() throws {
        let fixture = try Fixture(), host = fixture.startup
        let seed = try MachineUpdateRoleChallengeTests.Fixture().requirement(role: .notificationGateway, uid: host.serviceUID)
        let expected = try MachineUpdateRestartHealthPlan.Requirement(binding: XCTUnwrap(host.releaseBinding),
            configurationEpoch: seed.configurationEpoch, configurationRevision: seed.configurationRevision,
            backendEpoch: seed.backendEpoch, backendRevision: seed.backendRevision, role: .notificationGateway,
            executionUID: host.serviceUID, code: host.consumerCode, publicKey: seed.publicKey)
        let registration = host.runtime.gateway
        _ = try MachineUpdateConsumerHealthChannel.peerPins(host: host, requirement: expected,
            registration: registration, release: fixture.release)
        let wrongRole = MachineUpdateRestartHealthPlan.Requirement(binding: expected.binding,
            configurationEpoch: expected.configurationEpoch, configurationRevision: expected.configurationRevision,
            backendEpoch: expected.backendEpoch, backendRevision: expected.backendRevision, role: .transport,
            executionUID: expected.executionUID, code: expected.code, publicKey: expected.publicKey)
        let foreignCode = MachineUpdateRestartHealthPlan.Requirement(binding: expected.binding,
            configurationEpoch: expected.configurationEpoch, configurationRevision: expected.configurationRevision,
            backendEpoch: expected.backendEpoch, backendRevision: expected.backendRevision, role: expected.role,
            executionUID: expected.executionUID, code: seed.code, publicKey: expected.publicKey)
        XCTAssertNotEqual(foreignCode.code, expected.code)
        for invalid in [wrongRole, foreignCode] {
            XCTAssertThrowsError(try MachineUpdateConsumerHealthChannel.peerPins(host: host, requirement: invalid,
                registration: registration, release: fixture.release)) {
                XCTAssertEqual($0 as? MachineUpdateConsumerHealthChannelError, .changedScope)
            }
        }
        let foreign = try GatewayRegistrationIdentity(ownerID: registration.ownerID, macID: registration.macID,
            accountID: registration.accountID, gatewayID: registration.gatewayID,
            lifecycleEpoch: Data(repeating: 247, count: 16), rootPublicKey: registration.rootPublicKey)
        for invalid in [nil, foreign] as [GatewayRegistrationIdentity?] {
            XCTAssertThrowsError(try MachineUpdateConsumerHealthChannel.peerPins(host: host, requirement: expected,
                registration: invalid, release: fixture.release)) {
                XCTAssertEqual($0 as? MachineUpdateConsumerHealthChannelError, .changedScope)
            }
        }
    }

    func testInstalledReadinessPinsOnlyTheCompletionPolicyStage() throws {
        let fixture = try Fixture(), host = fixture.completion
        let seed = try MachineUpdateRoleChallengeTests.Fixture().requirement(role: .notificationGateway, uid: host.serviceUID)
        let expected = try MachineUpdateRestartHealthPlan.Requirement(binding: XCTUnwrap(host.releaseBinding),
            configurationEpoch: seed.configurationEpoch, configurationRevision: seed.configurationRevision,
            backendEpoch: seed.backendEpoch, backendRevision: seed.backendRevision, role: .notificationGateway,
            executionUID: host.serviceUID, code: host.consumerCode, publicKey: seed.publicKey)
        let pins = try MachineUpdateConsumerHealthChannel.peerPins(host: host, requirement: expected,
            registration: host.runtime.gateway, release: fixture.release, purpose: .installedReadiness)
        XCTAssertEqual(pins.consumer, expected.code)
        XCTAssertEqual(pins.serviceUID, expected.executionUID)

        for foreign in [fixture.original, fixture.startup] {
            XCTAssertThrowsError(try MachineUpdateConsumerHealthChannel.peerPins(host: foreign, requirement: expected,
                registration: host.runtime.gateway, release: fixture.release, purpose: .installedReadiness)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
        }
    }

    func testInstalledTransportPinsAndRefusesForeignHistoricalRuntime() throws {
        let fixture = try Fixture(), host = try select(.transport, from: fixture.completion)
        let binding = try XCTUnwrap(host.releaseBinding)
        let seed = try MachineUpdateRoleChallengeTests.Fixture().requirement()
        let requirement = MachineUpdateRestartHealthPlan.Requirement(binding: binding,
            configurationEpoch: seed.configurationEpoch, configurationRevision: seed.configurationRevision,
            backendEpoch: seed.backendEpoch, backendRevision: seed.backendRevision,
            role: .transport, executionUID: host.serviceUID, code: host.consumerCode,
            publicKey: try host.runtime.transportPublicKeyX963)
        let pins = try MachineUpdateConsumerHealthChannel.peerPins(host: host, requirement: requirement,
            registration: nil, release: fixture.release, purpose: .installedReadiness)
        XCTAssertEqual(pins.consumer, host.consumerCode)
        let foreign = try Fixture()
        XCTAssertThrowsError(try binding.requireHistoricalRuntime(foreign.completion.runtime)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
        guard getuid() != 0 || geteuid() != 0 else { return }
        let releases = Mutex(0)
        XCTAssertThrowsError(try MachineUpdateConsumerHealthChannel.nativeConsumer(host: host, requirement: requirement,
            registration: nil, release: fixture.release, purpose: .installedReadiness,
            verifyCurrent: { XCTFail("Root check did not run first") }, releaseScope: { releases.withLock { $0 += 1 } })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(releases.withLock { $0 }, 1)
    }

    func testInstalledNativeInventoryRejectsForeignRootGatewayAndBundle() throws {
        let fixture = try Fixture(), candidate = fixture.release
        let old = try select(.transport, from: fixture.completion)
        let transport = try GatewaySettingsConsumerHostConfiguration(role: .transport, runtime: old.runtime,
            bundlePath: MachineBootstrap.bundlePath, codePolicy: old.codePolicy,
            releaseBinding: old.releaseBinding, policyStage: .completion)
        let binding = try XCTUnwrap(transport.releaseBinding)
        let seed = try MachineUpdateRoleChallengeTests.Fixture().requirement()
        func requirement(_ role: AuthorityCodeRole, uid: UInt32, code: AuthorityCodeEntry, key: Data)
            -> MachineUpdateRestartHealthPlan.Requirement {
            .init(binding: binding, configurationEpoch: seed.configurationEpoch, configurationRevision: seed.configurationRevision,
                backendEpoch: seed.backendEpoch, backendRevision: seed.backendRevision,
                role: role, executionUID: uid, code: code, publicKey: key)
        }
        let root = requirement(.authority, uid: 0,
            code: try XCTUnwrap(transport.codePolicy.entries.first(where: { $0.role == .authority })), key: seed.publicKey)
        let consumer = requirement(.transport, uid: transport.serviceUID, code: transport.consumerCode,
            key: try transport.runtime.transportPublicKeyX963)
        let owner = MachineUpdateNativeInstalledReadinessAccount.self
        _ = try owner.nativeInventory(root: root, requirements: [root, consumer], transport: transport,
            gateway: nil, registration: nil, release: candidate)
        let invalid: [(MachineUpdateRestartHealthPlan.Requirement, GatewaySettingsConsumerHostConfiguration, GatewaySettingsConsumerHostConfiguration?)] =
            [(seed, transport, nil), (root, transport, fixture.completion), (root, old, nil)]
        for (authority, host, gateway) in invalid {
            XCTAssertThrowsError(try owner.nativeInventory(root: authority, requirements: [root, consumer], transport: host,
                gateway: gateway, registration: gateway?.runtime.gateway, release: candidate)) {
                XCTAssertEqual($0 as? MachineUpdateHealthCoordinatorError, .invalidInventory)
            }
        }
        let invalidChallenges: [(AuthorityCodeRole, Data?)] = [(.transport, Data([1])), (.notificationGateway, nil), (.authority, nil)]
        for (role, nonce) in invalidChallenges {
            XCTAssertThrowsError(try owner.consumerSelection(role: role, rootRequest: nonce, transport: transport,
                gateway: fixture.completion, registration: fixture.completion.runtime.gateway)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
        }
    }

    func testBothNativeParticipantsMustDeclareTheHealthReaderAndWriter() throws {
        let fixture = try Fixture(), name = MachineUpdateConsumerHealthReleaseValidation.formatName
        for consumer in [AuthorityCodeRole.transport, .notificationGateway] {
            try MachineUpdateConsumerHealthReleaseValidation.validateDeclarations(fixture.release, policy: fixture.startup.codePolicy, consumer: consumer)
            for participant in [AuthorityCodeRole.authority, consumer] {
                for mode in 0..<3 {
                    let value = try editing(fixture) { component in
                        guard component.role == participant else { return component }
                        var selected = component.formats.filter { $0.name != name }
                        if mode == 1 { selected.append(try .init(name: name, readers: [2], writers: [2])) }
                        if mode == 2 { selected.append(try .init(name: name, readers: [1], writers: [])) }
                        return try formats(component, selected)
                    }
                    XCTAssertThrowsError(try MachineUpdateConsumerHealthReleaseValidation.validateDeclarations(value,
                        policy: fixture.startup.codePolicy, consumer: consumer))
                }
            }
        }
    }
    func testAnUnselectedConsumerCannotAddAHealthRequirement() throws {
        let fixture = try Fixture(), name = MachineUpdateConsumerHealthReleaseValidation.formatName
        let value = try editing(fixture) { component in
            try formats(component, component.role == .transport ? component.formats.filter { $0.name != name } : component.formats)
        }
        try MachineUpdateConsumerHealthReleaseValidation.validateDeclarations(value, policy: fixture.startup.codePolicy, consumer: .notificationGateway)
        XCTAssertThrowsError(try MachineUpdateConsumerHealthReleaseValidation.validateDeclarations(value,
            policy: fixture.startup.codePolicy, consumer: .transport))
    }
    func testHealthDeclarationsCannotSubstituteForAnotherRoleOrSignatureHash() throws {
        let fixture = try Fixture()
        for consumer in [AuthorityCodeRole.authority, .app, .setupController] {
            XCTAssertThrowsError(try MachineUpdateConsumerHealthReleaseValidation.validateDeclarations(fixture.release,
                policy: fixture.startup.codePolicy, consumer: consumer))
        }
        for participant in [AuthorityCodeRole.authority, .transport, .notificationGateway] {
            var hashes = fixture.release.codeDirectoryHashes; hashes[participant] = Data(repeating: 99, count: 20)
            let value = SignedReleaseEvidence(manifest: fixture.release.manifest, codeDirectoryHashes: hashes)
            XCTAssertThrowsError(try MachineUpdateConsumerHealthReleaseValidation.validateDeclarations(value,
                policy: fixture.startup.codePolicy, consumer: participant == .authority ? .transport : participant))
        }
    }
    func testStartupHealthRequiresAuthorityToReadTheReleaseBoundHost() throws {
        let fixture = try Fixture(authorityReadsReleaseBoundHost: false)
        for role in GatewaySettingsConsumerRole.allCases {
            let host = try select(role, from: fixture.startup)
            try host.validateRelease(fixture.release)
            try MachineUpdateConsumerHealthReleaseValidation.validateDeclarations(fixture.release,
                policy: host.codePolicy, consumer: role.codeRole)
            XCTAssertThrowsError(try MachineUpdateConsumerHealthReleaseValidation.validate(fixture.release, host: host)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
        }
    }
    func testStartupHostRejectsABindingForADifferentStartupPolicy() throws {
        let fixture = try Fixture(), host = fixture.startup
        let encoded = try XCTUnwrap(host.releaseBinding).encoded
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        fields["startupPolicyDigest"] = Data(repeating: 99, count: 32).base64EncodedString()
        let binding = try RuntimeReleaseBinding.decode(JSONSerialization.data(withJSONObject: fields,
            options: [.sortedKeys, .withoutEscapingSlashes]))
        try binding.requireCompletionPolicy(host.codePolicy)
        XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration(role: host.role, runtime: host.runtime,
            bundlePath: host.bundlePath, codePolicy: host.codePolicy, releaseBinding: binding, policyStage: .startup)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
    }

    func testCompleteNativeValidationRequiresTheExactStartupHostAndInspectedRelease() throws {
        let fixture = try Fixture()
        for role in GatewaySettingsConsumerRole.allCases {
            let startup = try select(role, from: fixture.startup)
            try MachineUpdateConsumerHealthReleaseValidation.validate(fixture.release, host: startup)
            XCTAssertThrowsError(try MachineUpdateConsumerHealthReleaseValidation.validate(fixture.release, host: select(role, from: fixture.original)))
            XCTAssertThrowsError(try MachineUpdateConsumerHealthReleaseValidation.validate(fixture.release, host: select(role, from: fixture.completion)))
        }
        let changed = try editing(fixture) { component in
            try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                build: "2", teamID: component.teamID, formats: component.formats)
        }
        XCTAssertThrowsError(try MachineUpdateConsumerHealthReleaseValidation.validate(changed, host: fixture.startup))
    }
}
