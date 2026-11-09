import Darwin
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class InstalledAuthorityReadinessHostTests: XCTestCase {
    private let limits = try! CBORLimits(maxBytes: 262144, maxDepth: 1, maxItems: 32)
    private func fixture(readiness: Bool = true, host4: Bool = true,
        missingWriter: AuthorityCodeRole? = nil) throws -> RuntimeActivationFixture {
        try .init(nativeConsumerHosts: true, releaseEdit: { component in
            var formats = try component.formats.map { format in
                guard host4, format.name == "authority.command-host-config" else { return format }
                return try ReleaseFormat(name: format.name, readers: format.readers.union([4]),
                    writers: component.role == missingWriter ? format.writers : format.writers.union([4]),
                    migrations: format.migrations)
            }
            if readiness, component.role == .authority {
                formats.append(try .init(name: MachineUpdateAuthorityReadinessDeclaration.formatName,
                    readers: [1], writers: [1]))
            }
            return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                build: component.build, teamID: component.teamID, formats: formats, requests: component.requests)
        })
    }
    private func host(_ old: InstalledAuthorityCommandConfiguration,
        placement: InstalledCommandJobPlacement? = nil, control: Bool? = nil, readiness: Bool? = nil) throws
        -> InstalledAuthorityCommandConfiguration {
        try .init(machineDirectory: old.machineDirectory, installationID: old.installationID,
            releaseDigest: old.releaseDigest, codePolicy: old.codePolicy, command: old.command,
            label: old.label, plistName: old.plistName, jobPlacement: placement ?? old.jobPlacement,
            gatewaySettingsControlEnabled: control ?? old.gatewaySettingsControlEnabled,
            installedReadinessEnabled: readiness ?? old.installedReadinessEnabled)
    }
    private func selected(_ f: RuntimeActivationFixture) throws -> InstalledAuthorityCommandConfiguration {
        try f.plan.host.enablingInstalledReadiness(release: XCTUnwrap(f.nativeRelease))
    }
    private func fields(_ value: InstalledAuthorityCommandConfiguration) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(value.canonicalBytes, limits: limits) else {
            throw InstalledAuthorityCommandError.invalidConfiguration
        }
        return fields
    }
    private func encode(_ fields: [UInt64: CBORValue]) throws -> Data {
        try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    func testLegacyVersionsRetainTheirExactOriginalEncoding() throws {
        let f = try fixture()
        for placement in [InstalledCommandJobPlacement.bundled, .systemAccount] {
            let old = try host(f.plan.host, placement: placement, control: false, readiness: false)
            var expected: [UInt64: CBORValue] = [0: .unsigned(placement.rawValue),
                1: .text(old.machineDirectory), 2: .bytes(old.installationID), 3: .bytes(old.releaseDigest),
                4: .bytes(try old.codePolicy.bytes), 5: .bytes(old.command.canonicalBytes),
                6: .text(old.label), 7: .text(old.plistName)]
            if placement == .systemAccount { expected[8] = .text("protected-system-account-v1") }
            XCTAssertEqual(old.canonicalBytes, try encode(expected))
            XCTAssertFalse(old.installedReadinessEnabled)
            XCTAssertEqual(try InstalledAuthorityCommandConfiguration.decode(old.canonicalBytes).canonicalBytes,
                old.canonicalBytes)
        }
    }
    func testGatewayControlRemainsVersionThreeUntilReadinessIsSelected() throws {
        let f = try fixture(), value = f.plan.host
        XCTAssertEqual(value.formatVersion, 3)
        XCTAssertTrue(value.gatewaySettingsControlEnabled)
        XCTAssertFalse(value.installedReadinessEnabled)
        XCTAssertEqual(Set(try fields(value).keys), Set(UInt64(0)...9))
    }
    func testSelectedVersionFourRoundTripsTheExactReadinessService() throws {
        let f = try fixture(), value = try selected(f)
        XCTAssertEqual(value.formatVersion, 4)
        XCTAssertTrue(value.installedReadinessEnabled)
        XCTAssertEqual(value.jobPlacement, .systemAccount)
        XCTAssertTrue(value.gatewaySettingsControlEnabled)
        XCTAssertEqual(try fields(value)[10], .text(try MachineUpdateAuthorityReadinessDeclaration.serviceName(
            accountID: value.command.accountID)))
        XCTAssertEqual(Set(try fields(value).keys), Set(UInt64(0)...10))
        XCTAssertEqual(try InstalledAuthorityCommandConfiguration.decode(value.canonicalBytes).canonicalBytes,
            value.canonicalBytes)
    }
    func testSelectionPreservesAllExistingHostAndCommandInputs() throws {
        let f = try fixture(), before = f.plan.host, after = try selected(f)
        XCTAssertEqual(after.machineDirectory, before.machineDirectory)
        XCTAssertEqual(after.installationID, before.installationID)
        XCTAssertEqual(after.releaseDigest, before.releaseDigest)
        XCTAssertEqual(try after.codePolicy.bytes, try before.codePolicy.bytes)
        XCTAssertEqual(after.command.canonicalBytes, before.command.canonicalBytes)
        XCTAssertEqual(after.label, before.label)
        XCTAssertEqual(after.plistName, before.plistName)
        XCTAssertEqual(after.jobPlacement, before.jobPlacement)
    }
    func testReadinessRequiresProtectedSystemPlacementAndGatewayControl() throws {
        let f = try fixture()
        XCTAssertThrowsError(try host(f.plan.host, placement: .bundled, control: false, readiness: true))
        XCTAssertThrowsError(try host(f.plan.host, placement: .systemAccount, control: false, readiness: true))
        XCTAssertThrowsError(try host(f.plan.host, placement: .bundled, control: true, readiness: true))
    }
    func testSelectionRequiresAnExplicitSignedReadinessDeclaration() throws {
        let f = try fixture(readiness: false)
        XCTAssertThrowsError(try selected(f)) {
            XCTAssertEqual($0 as? InstalledAuthorityCommandError, .wrongRelease)
        }
    }
    func testSelectionRequiresBothParticipantsToWriteHostVersionFour() throws {
        for role in [AuthorityCodeRole.authority, .setupController] {
            let f = try fixture(missingWriter: role)
            XCTAssertThrowsError(try selected(f)) {
                XCTAssertEqual($0 as? InstalledAuthorityCommandError, .wrongRelease)
            }
        }
    }
    func testSelectionRejectsAnotherSignedReleaseDigest() throws {
        let f = try fixture(), value = f.plan.host
        let other = try NativeHostReleaseFixture.make(policy: value.codePolicy)
        XCTAssertNotEqual(try InstallationInventory.digest(other), value.releaseDigest)
        XCTAssertThrowsError(try value.enablingInstalledReadiness(release: other)) {
            XCTAssertEqual($0 as? InstalledAuthorityCommandError, .wrongRelease)
        }
    }
    func testTheReadinessServiceCannotBeSubstitutedInEncodedBytes() throws {
        let f = try fixture(), value = try selected(f)
        var changed = try fields(value)
        changed[10] = .text(try MachineUpdateAuthorityReadinessDeclaration.serviceName(
            accountID: Data(repeating: 255, count: 16)))
        XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.decode(encode(changed)))
    }
    func testMissingAndUnknownVersionFourFieldsAreRejected() throws {
        let f = try fixture(), original = try fields(selected(f))
        var missing = original; missing.removeValue(forKey: 10)
        XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.decode(encode(missing)))
        var unknown = original; unknown[11] = .null
        XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.decode(encode(unknown)))
    }
    func testVersionFourRetainsBothExistingPlacementAndControlBindings() throws {
        let f = try fixture(), original = try fields(selected(f))
        for (key, value) in [(UInt64(8), CBORValue.text("bundled")),
            (UInt64(9), CBORValue.text("dev.remozio.foreign.control"))] {
            var changed = original; changed[key] = value
            XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.decode(encode(changed)))
        }
    }
    func testVersionChangesCannotReinterpretTheVersionFourPayload() throws {
        let f = try fixture(), original = try fields(selected(f))
        for version in [UInt64(0), 1, 2, 3, 5] {
            var changed = original; changed[0] = .unsigned(version)
            XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.decode(encode(changed)))
        }
    }
    func testVersionThreeCannotCarryAnUndeclaredReadinessField() throws {
        let f = try fixture()
        var changed = try fields(f.plan.host)
        changed[10] = .text(try MachineUpdateAuthorityReadinessDeclaration.serviceName(
            accountID: f.account.accountID))
        XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.decode(encode(changed)))
    }
    func testGatewayControlSelectionPreservesRecordedReadiness() throws {
        let f = try fixture(), value = try selected(f)
        let repeated = try value.enablingGatewaySettingsControl(release: XCTUnwrap(f.nativeRelease))
        XCTAssertTrue(repeated.installedReadinessEnabled)
        XCTAssertEqual(repeated.canonicalBytes, value.canonicalBytes)
    }
    func testDecodedReadinessStillRequiresReleaseValidation() throws {
        let f = try fixture(readiness: false)
        let proposed = try host(f.plan.host, readiness: true)
        let decoded = try InstalledAuthorityCommandConfiguration.decode(proposed.canonicalBytes)
        XCTAssertTrue(decoded.installedReadinessEnabled)
        XCTAssertThrowsError(try decoded.validateRelease(XCTUnwrap(f.nativeRelease), bundlePath: f.plan.bundlePath)) {
            XCTAssertEqual($0 as? InstalledAuthorityCommandError, .wrongRelease)
        }
    }
    private final class ReadinessActivity: OwnedReleaseActivity, Sendable {
        let closes = Mutex(0)
        func validate() throws {}
        func close() { closes.withLock { $0 += 1 } }
    }

    func testNativeRootReadinessRefusesAnOrdinaryProcessAndReleasesItsLoan() throws {
        guard getuid() != 0 || geteuid() != 0 else { throw XCTSkip("Ordinary-owner guard") }
        let f = try fixture(), base = try selected(f), release = try XCTUnwrap(f.nativeRelease)
        let monitor = try XCTUnwrap(release.manifest.components.first(where: { $0.role == .commandMonitor }))
        let child = try XCTUnwrap(release.manifest.components.first(where: { $0.role == .commandChild }))
        let execution = try AuthorityCommandExecutionConfiguration(
            monitorPath: MachineBootstrap.bundlePath + "/" + monitor.relativePath,
            childPath: MachineBootstrap.bundlePath + "/" + child.relativePath)
        let old = base.command
        let command = try AuthorityCommandStartupConfiguration(presence: old.presence, serviceName: old.serviceName,
            policyPath: old.policyPath, environment: old.environment, submissionLimits: old.submissionLimits,
            captureLimits: old.captureLimits, execution: execution)
        let host = try InstalledAuthorityCommandConfiguration(machineDirectory: base.machineDirectory,
            installationID: base.installationID, releaseDigest: base.releaseDigest, codePolicy: base.codePolicy,
            command: command, label: base.label, plistName: base.plistName, jobPlacement: base.jobPlacement,
            gatewaySettingsControlEnabled: true, installedReadinessEnabled: true)
        let seed = try MachineUpdateRoleChallengeTests.Fixture().requirement()
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: seed.binding.encoded) as? [String: Any])
        fields["macID"] = command.macID.base64EncodedString()
        fields["accountID"] = command.accountID.base64EncodedString()
        fields["installationID"] = host.installationID.base64EncodedString()
        fields["installedReleaseDigest"] = host.releaseDigest.base64EncodedString()
        fields["completionPolicyDigest"] = try MachineUpdateActivationRecord.digest(host.codePolicy.bytes).base64EncodedString()
        let binding = try RuntimeReleaseBinding.decode(JSONSerialization.data(withJSONObject: fields,
            options: [.sortedKeys, .withoutEscapingSlashes]))
        let requirement = MachineUpdateRestartHealthPlan.Requirement(binding: binding,
            configurationEpoch: seed.configurationEpoch, configurationRevision: seed.configurationRevision,
            backendEpoch: seed.backendEpoch, backendRevision: seed.backendRevision, role: .authority,
            executionUID: 0, code: try XCTUnwrap(host.codePolicy.entries.first(where: { $0.role == .authority })),
            publicKey: command.presence.wake.request.authorityPublicKey)
        let loan = ReadinessActivity()
        let scope = try MachineUpdateAuthorityReadinessScope(host: host, requirement: requirement, release: release,
            verifySelection: { XCTFail("Root check did not run first") }, acquireActivity: { loan })
        XCTAssertThrowsError(try MachineUpdateConsumerHealthChannel.nativeAuthorityReadiness(scope: scope)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(loan.closes.withLock { $0 }, 1)
        let consumers = try XCTUnwrap(f.plan.consumerHosts)
        XCTAssertThrowsError(try MachineUpdateNativeInstalledReadinessAccount.native(scope: scope,
            requirements: [requirement], transport: consumers.transport, gateway: nil, registration: nil, release: release)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(loan.closes.withLock { $0 }, 1)
    }

    func testReadinessJobTransitionAddsOnlyThePinnedMachService() throws {
        let f = try fixture(), startup = f.plan.host, completion = try selected(f)
        let transition = try MachineUpdateAuthorityReadinessJobTransition(startup: startup,
            completion: completion, bundlePath: f.plan.bundlePath)
        XCTAssertEqual(transition.startup.declaration, transition.completion.declaration)
        XCTAssertEqual(transition.startup.arguments, transition.completion.arguments)
        XCTAssertEqual(transition.completion.machServices.subtracting(transition.startup.machServices),
            [try MachineUpdateAuthorityReadinessDeclaration.serviceName(accountID: startup.command.accountID)])
        XCTAssertThrowsError(try MachineUpdateAuthorityReadinessJobTransition(startup: completion,
            completion: completion, bundlePath: f.plan.bundlePath)) {
            XCTAssertEqual($0 as? InstalledAuthorityCommandError, .changedConfiguration)
        }
    }

    func testReadinessJobTransitionRejectsForeignReleasePathAndMissingVersionTwo() throws {
        let f = try fixture(), candidate = try XCTUnwrap(f.nativeRelease), policy = f.plan.host.codePolicy
        func edited(path: String, publicationVersions: Set<UInt64>) throws -> SignedReleaseEvidence {
            let components = try candidate.manifest.components.map { component in
                var formats = component.formats
                if [.authority, .setupController].contains(component.role) {
                    formats.append(try .init(name: MachineUpdateCompletionPublicationRecord.formatName,
                        readers: publicationVersions, writers: publicationVersions))
                }
                return try ReleaseComponent(role: component.role, identifier: component.identifier,
                    generation: component.generation, relativePath: component.role == .authority ? path : component.relativePath,
                    codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                    teamID: component.teamID, formats: formats, requests: component.requests)
            }
            let manifest = try ReleaseManifest(release: candidate.manifest.release, build: candidate.manifest.build, components: components)
            return .init(manifest: manifest, codeDirectoryHashes: candidate.codeDirectoryHashes)
        }
        let expected = InstalledAuthorityCommandConfiguration.executablePath
        try MachineUpdateAuthorityReadinessJobTransition.requireRelease(edited(path: expected, publicationVersions: [1, 2]), policy: policy)
        for (path, versions) in [(expected, Set<UInt64>([1])),
                                 ("Contents/Library/LaunchServices/ForeignAuthority", Set<UInt64>([1, 2]))] {
            let release = try edited(path: path, publicationVersions: versions)
            XCTAssertThrowsError(try MachineUpdateAuthorityReadinessJobTransition.requireRelease(release, policy: policy)) {
                XCTAssertEqual($0 as? InstalledAuthorityCommandError, .wrongRelease)
            }
        }
    }

    func testReadinessJobTransitionRejectsChangedHostIdentity() throws {
        let f = try fixture(), startup = f.plan.host, completion = try selected(f)
        let foreign = try selected(fixture())
        let wrongInstallation = try InstalledAuthorityCommandConfiguration(machineDirectory: completion.machineDirectory,
            installationID: Data(repeating: 77, count: 16), releaseDigest: completion.releaseDigest,
            codePolicy: completion.codePolicy, command: completion.command, label: completion.label,
            plistName: completion.plistName, jobPlacement: .systemAccount, gatewaySettingsControlEnabled: true,
            installedReadinessEnabled: true)
        let wrongRelease = try InstalledAuthorityCommandConfiguration(machineDirectory: completion.machineDirectory,
            installationID: completion.installationID, releaseDigest: Data(repeating: 77, count: 32),
            codePolicy: completion.codePolicy, command: completion.command, label: completion.label,
            plistName: completion.plistName, jobPlacement: .systemAccount, gatewaySettingsControlEnabled: true,
            installedReadinessEnabled: true)
        for invalid in [foreign, wrongInstallation, wrongRelease] {
            XCTAssertThrowsError(try MachineUpdateAuthorityReadinessJobTransition(startup: startup,
                completion: invalid, bundlePath: f.plan.bundlePath)) {
                XCTAssertEqual($0 as? InstalledAuthorityCommandError, .changedConfiguration)
            }
        }
        let bundled = try host(startup, placement: .bundled, control: false)
        XCTAssertThrowsError(try MachineUpdateAuthorityReadinessJobTransition(startup: bundled,
            completion: completion, bundlePath: f.plan.bundlePath)) {
            XCTAssertEqual($0 as? InstalledAuthorityCommandError, .changedConfiguration)
        }
    }

    func testTheNativeLoaderRefusesAnOrdinaryOwnerBeforeOpeningAPath() throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner guard") }
        XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.load(
            path: "/nonexistent-remozio-readiness-host-fixture.cbor")) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
    func testDescriptionsDoNotExposeTheHostInputs() throws {
        let f = try fixture(), value = try selected(f)
        XCTAssertEqual(String(describing: value), "InstalledAuthorityCommandConfiguration(redacted)")
    }
    func testRepeatedSelectionLeavesTheOriginalValueUnchanged() throws {
        let f = try fixture(), original = f.plan.host, before = f.plan.host.canonicalBytes
        let one = try selected(f), two = try selected(f)
        XCTAssertEqual(one.canonicalBytes, two.canonicalBytes)
        XCTAssertEqual(original.canonicalBytes, before)
        XCTAssertFalse(original.installedReadinessEnabled)
    }
}
