import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Value preparation only. No test publishes a live configuration or registers a service.
final class RuntimeAuditUpgradeConfigurationTests: XCTestCase {
    private let limits = try! CBORLimits(maxBytes: 262_144, maxDepth: 3, maxItems: 512)
    private func fields(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let values) = try DeterministicCBOR.decode(bytes, limits: limits) else {
            throw RuntimeActivationError.invalidPlan
        }
        return values
    }
    private func changing(_ bytes: Data, _ edits: [UInt64: CBORValue]) throws -> Data {
        var values = try fields(bytes)
        for (key, value) in edits { values[key] = value }
        return try DeterministicCBOR.encode(.map(values), limits: limits)
    }
    private func intent(_ f: RuntimeActivationFixture, source: RuntimeMaterialReference? = nil) throws -> RuntimeAuditUpgradeIntent {
        let source = try source ?? f.material.reference
        let material = try RuntimePreparationMaterial(materialID: f.material.materialID, services: f.services,
            transportIdentity: f.material.transportIdentity, transportPublicKeyInfo: f.material.transportPublicKeyInfo,
            gateway: f.material.gateway, serviceActivity: source.serviceActivity)
        let target = try RuntimeAuditMaterialUpgrade.prepare(material: material, expected: source, account: f.account,
            activity: XCTUnwrap(f.material.serviceActivity), installedRelease: XCTUnwrap(f.nativeRelease), policy: f.plan.host.codePolicy)
        return try .init(source: source, target: target.reference, policy: f.plan.host.codePolicy)
    }
    private func prepare(_ source: RuntimeActivationPlan, _ f: RuntimeActivationFixture,
                         intent requested: RuntimeAuditUpgradeIntent? = nil) throws -> RuntimeActivationPlan {
        try source.preparingAuditUpgrade(requested ?? intent(f, source: source.reference),
            installedRelease: XCTUnwrap(f.nativeRelease), currentPolicy: f.plan.host.codePolicy)
    }
    private func assertOnlyChildChanges(_ source: Data, _ target: Data, file: StaticString = #filePath, line: UInt = #line) throws {
        var before = try fields(source), after = try fields(target)
        XCTAssertNotEqual(before.removeValue(forKey: 1), after.removeValue(forKey: 1), file: file, line: line)
        XCTAssertEqual(before, after, file: file, line: line)
    }
    func testNativeUpgradeKeepsPairingServicesJobsAndRoutingSelection() throws {
        for routing in [false, true] {
            let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneRouting: routing,
                phoneAudit: true, auditDelivery: true, materialAuditDelivery: false)
            let original = try f.plan.encoded, requested = try intent(f), next = try prepare(f.plan, f, intent: requested)
            XCTAssertEqual(next.reference, requested.target); XCTAssertEqual(next.reference.materialID, f.material.materialID)
            XCTAssertEqual(next.reference.services, f.services); XCTAssertEqual(next.reference.gateway, f.material.gateway)
            XCTAssertEqual(next.phoneRoutingVersion, f.plan.phoneRoutingVersion); XCTAssertEqual(next.phoneAuditVersion, 1)
            XCTAssertEqual(next.host.command.presence.wake.request.service.auditVersions, [1])
            XCTAssertEqual(next.authorityJob.bytes, f.plan.authorityJob.bytes)
            XCTAssertEqual(next.transportJob.bytes, f.plan.transportJob.bytes)
            XCTAssertEqual(next.transport.transport.canonicalBytes, f.plan.transport.transport.canonicalBytes)
            XCTAssertEqual(next.transport.control.canonicalBytes, f.plan.transport.control.canonicalBytes)
            XCTAssertEqual(next.gatewaySettingsHost?.runtime, requested.target)
            XCTAssertEqual(next.transport.settingsHost?.runtime, requested.target)
            XCTAssertEqual(try prepare(f.plan, f, intent: requested).encoded, try next.encoded)
            XCTAssertEqual(try RuntimeActivationPlan.decode(next.encoded).encoded, try next.encoded)
            XCTAssertEqual(try f.plan.encoded, original)
            XCTAssertEqual(try f.machine.runtimePreparation(accountID: f.account.accountID).reference, requested.source)
        }
    }
    func testNondefaultSettingsAndOptionalPushWakeAndRelaySurviveExactly() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneRouting: true,
            phoneAudit: true, auditDelivery: true, materialAuditDelivery: false)
        let command = f.plan.host.command, presence = command.presence, wake = presence.wake, request = wake.request
        let push = try AuthorityPhonePushStartupConfiguration(projectID: "remozio-fixture", senderID: "123456789",
            packageName: "dev.remozio.phone", gatewayReceiptPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            maximumControls: 77, candidateLifetimeMilliseconds: 98765)
        let service = try changing(request.service.canonicalBytes, [9: .unsigned(524288), 10: .unsigned(2),
            12: .unsigned(13), 13: .unsigned(4321), 14: .unsigned(19)])
        let nextRequest = try changing(request.canonicalBytes, [1: .bytes(service), 4: .unsigned(777)])
        let nextWake = try changing(wake.canonicalBytes, [0: .unsigned(2), 1: .bytes(nextRequest),
            8: .unsigned(20000), 9: .unsigned(333), 10: .unsigned(1234), 11: .bytes(push.canonicalBytes)])
        let nextPresence = try changing(presence.canonicalBytes, [1: .bytes(nextWake), 7: .unsigned(123000),
            8: .unsigned(9000), 9: .unsigned(41000)])
        let execution = try changing(XCTUnwrap(command.execution).canonicalBytes, [3: .unsigned(7000), 4: .unsigned(0o027),
            5: .unsigned(7), 6: .unsigned(33), 7: .unsigned(123)])
        let environment: CBORValue = .array([.map([0: .bytes(Data("LANG".utf8)), 1: .bytes(Data("en_GB.UTF-8".utf8))]),
            .map([0: .bytes(Data("PATH".utf8)), 1: .bytes(Data("/opt/homebrew/bin:/usr/bin:/bin".utf8))])])
        let nextCommand = try changing(command.canonicalBytes, [1: .bytes(nextPresence), 4: environment,
            5: .map([0: .unsigned(70000), 1: .unsigned(17), 2: .unsigned(9000)]),
            6: .map([0: .unsigned(80000), 1: .unsigned(18), 2: .unsigned(10000)]),
            7: .unsigned(17), 8: .unsigned(333), 9: .unsigned(7777), 10: .unsigned(23),
            11: .unsigned(95000), 13: .bytes(execution)])
        let direct = try changing(f.plan.transport.transport.canonicalBytes, [11: .unsigned(13), 12: .unsigned(23456), 13: .unsigned(7777)])
        let gateway = try XCTUnwrap(f.plan.host.codePolicy.entries.first { $0.role == .notificationGateway && $0.active })
        let registration = f.material.gateway
        let binding = try GatewaySubmissionBinding(ownerID: registration.ownerID, macID: registration.macID,
            accountID: registration.accountID, gatewayID: registration.gatewayID, lifecycleEpoch: registration.lifecycleEpoch)
        let signer = try GatewayWakeSignerConfiguration(binding: binding, credentialID: Data(repeating: 42, count: 16),
            transportUID: f.plan.transport.transport.serviceUID, ownerUID: f.services.ownerUID,
            gatewayUID: wake.gatewayPolicy.expectedUserID, serviceName: RuntimePreparationPaths(accountID: f.services.accountID).gatewayWakeService,
            teamID: gateway.teamID, gatewayIdentifier: gateway.identifier, gatewayHashes: [gateway.codeDirectoryHash],
            custody: .protectedFile, keyRecordPath: "/tmp/remozio-owned-fixture/wake-key.cbor",
            publicKey: P256.Signing.PrivateKey().publicKey.x963Representation, timeoutMilliseconds: 4321)
        let transportWake = try TransportWakeStartupConfiguration(transport: .decode(direct), wake: signer, pollMilliseconds: 444).canonicalBytes
        let transport = try changing(f.plan.transport.canonicalBytes,
            [1: .bytes(direct), 2: .bytes(transportWake), 3: .unsigned(45678)])
        let host = try changing(f.plan.host.canonicalBytes, [5: .bytes(nextCommand)])
        let source = try RuntimeActivationPlan.decode(changing(f.plan.encoded, [3: .bytes(host), 4: .bytes(transport)]))
        let original = try source.encoded, target = try prepare(source, f)
        let before = source.host.command, after = target.host.command
        try assertOnlyChildChanges(before.canonicalBytes, after.canonicalBytes)
        try assertOnlyChildChanges(before.presence.canonicalBytes, after.presence.canonicalBytes)
        try assertOnlyChildChanges(before.presence.wake.canonicalBytes, after.presence.wake.canonicalBytes)
        try assertOnlyChildChanges(before.presence.wake.request.canonicalBytes, after.presence.wake.request.canonicalBytes)
        var expectedService = try fields(before.presence.wake.request.service.canonicalBytes)
        expectedService[11] = .array([.unsigned(1)])
        XCTAssertEqual(try fields(after.presence.wake.request.service.canonicalBytes), expectedService)
        XCTAssertEqual(after.execution?.canonicalBytes, execution)
        XCTAssertEqual(after.presence.wake.phonePush?.canonicalBytes, push.canonicalBytes)
        XCTAssertEqual(target.transport.transport.canonicalBytes, direct)
        XCTAssertEqual(target.transport.wake?.canonicalBytes, transportWake)
        XCTAssertEqual(target.transport.relayPort, 45678)
        XCTAssertEqual(target.transport.control.canonicalBytes, source.transport.control.canonicalBytes)
        XCTAssertEqual(try source.encoded, original)
    }
    func testLegacyPlanGainsNativeHostsWithoutReplacingItsAccountOrKey() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneAudit: true,
            auditDelivery: true, materialAuditDelivery: false)
        let material = try RuntimePreparationMaterial(materialID: f.material.materialID, services: f.services,
            transportIdentity: f.material.transportIdentity, transportPublicKeyInfo: f.material.transportPublicKeyInfo, gateway: f.material.gateway)
        let oldHost = f.plan.host
        let host = try InstalledAuthorityCommandConfiguration(machineDirectory: oldHost.machineDirectory,
            installationID: oldHost.installationID, releaseDigest: oldHost.releaseDigest, codePolicy: oldHost.codePolicy,
            command: oldHost.command, label: oldHost.label, plistName: oldHost.plistName, jobPlacement: .systemAccount)
        let transport = try TransportPairingStartupConfiguration(transport: f.plan.transport.transport,
            control: f.plan.transport.control, wake: f.plan.transport.wake, relayPort: f.plan.transport.relayPort)
        let source = try RuntimeActivationPlan.decode(DeterministicCBOR.encode(.map([0: .unsigned(1),
            1: .bytes(material.reference.encoded), 2: .text(f.plan.bundlePath), 3: .bytes(host.canonicalBytes),
            4: .bytes(transport.canonicalBytes)]), limits: limits))
        let target = try prepare(source, f)
        XCTAssertEqual(source.reference.formatVersion, 1); XCTAssertEqual(target.reference.formatVersion, 3)
        XCTAssertEqual(target.reference.services, source.reference.services)
        XCTAssertEqual(target.reference.transportPublicKeyInfo, source.reference.transportPublicKeyInfo)
        XCTAssertEqual(target.reference.materialID, source.reference.materialID)
        XCTAssertEqual(target.authorityJob.declaration, source.authorityJob.declaration)
        XCTAssertEqual(target.transportJob.declaration, source.transportJob.declaration)
        XCTAssertNotEqual(target.authorityJob.bytes, source.authorityJob.bytes)
        XCTAssertNotEqual(target.transportJob.bytes, source.transportJob.bytes)
        XCTAssertTrue(target.host.gatewaySettingsControlEnabled); XCTAssertNotNil(target.transport.settingsHost)
        XCTAssertNil(target.phoneRoutingVersion); XCTAssertEqual(target.phoneAuditVersion, 1)
    }
    func testWrongSourceOrCurrentPolicyCannotPrepareAConfiguration() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneAudit: true,
            auditDelivery: true, materialAuditDelivery: false)
        let other = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneAudit: true,
            auditDelivery: true, materialAuditDelivery: false)
        XCTAssertThrowsError(try prepare(f.plan, f, intent: intent(other)))
        let current = try AuthorityCodePolicy(entries: f.plan.host.codePolicy.entries.map { entry in
            try .init(role: entry.role, teamID: entry.teamID, identifier: entry.identifier,
                installedGeneration: 2, minimumGeneration: 2, codeDirectoryHash: entry.codeDirectoryHash, active: entry.active)
        })
        XCTAssertThrowsError(try f.plan.preparingAuditUpgrade(intent(f), installedRelease: XCTUnwrap(f.nativeRelease), currentPolicy: current))
        let target = try prepare(f.plan, f)
        XCTAssertThrowsError(try prepare(target, f, intent: intent(f)))
    }
    private func omittingTargetReader(_ c: ReleaseComponent) throws -> ReleaseComponent {
        guard c.role == .transport else { return c }
        let formats = try c.formats.map { value in
            try ReleaseFormat(name: value.name,
                readers: value.name == RuntimeMaterialReference.formatName ? value.readers.subtracting([3]) : value.readers,
                writers: value.writers)
        }
        return try .init(role: c.role, identifier: c.identifier, generation: c.generation, relativePath: c.relativePath,
            codeDirectoryHash: c.codeDirectoryHash, build: c.build, teamID: c.teamID, formats: formats, requests: c.requests)
    }
    func testCurrentReleaseMissingTargetReaderRefusesEvenWithItsMatchingDigest() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneAudit: true,
            auditDelivery: true, materialAuditDelivery: false, releaseEdit: omittingTargetReader)
        let target = try RuntimePreparationMaterial(materialID: f.material.materialID, services: f.services,
            transportIdentity: f.material.transportIdentity, transportPublicKeyInfo: f.material.transportPublicKeyInfo,
            gateway: f.material.gateway, serviceActivity: f.material.serviceActivity, auditDeliveryVersion: 1)
        let requested = try RuntimeAuditUpgradeIntent(source: f.material.reference, target: target.reference, policy: f.plan.host.codePolicy)
        XCTAssertEqual(try InstallationInventory.digest(XCTUnwrap(f.nativeRelease)), requested.source.services.releaseDigest)
        XCTAssertThrowsError(try prepare(f.plan, f, intent: requested)) { error in
            guard case ReleaseCompatibilityError.missingReader = error else { return XCTFail("The target reader must be required: \(error)") }
        }
        XCTAssertEqual(f.plan.host.command.presence.wake.request.service.auditVersions, [])
    }
    func testChangedReleaseAndMissingRequiredReadersCannotBorrowSourceCapabilities() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneAudit: true,
            auditDelivery: true, materialAuditDelivery: false)
        let changed = try NativeHostReleaseFixture.make(policy: f.plan.host.codePolicy,
            phoneAudit: true, auditDelivery: true, edit: omittingTargetReader)
        XCTAssertThrowsError(try f.plan.preparingAuditUpgrade(intent(f), installedRelease: changed, currentPolicy: f.plan.host.codePolicy))
        XCTAssertNil(f.plan.reference.auditDeliveryVersion)
        XCTAssertEqual(f.plan.host.command.presence.wake.request.service.auditVersions, [])
    }

    func testMissingPreparationCapabilitiesRefuseValuePreparation() throws {
        for role in [AuthorityCodeRole.authority, .setupController] {
            for missing in 0..<(role == .setupController ? 4 : 3) {
                let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneAudit: true,
                    auditDelivery: true, materialAuditDelivery: false, releaseEdit: { component in
                        guard component.role == role else { return component }
                        let formats: [ReleaseFormat]
                        if missing == 2 {
                            formats = component.formats.filter { $0.name != RuntimeAuditUpgradeRecord.formatName }
                        } else {
                            let name = missing == 3 ? RuntimeAuditUpgradeRecord.formatName : "authority.installation-preparation"
                            let version: UInt64 = missing == 3 ? 1 : 12
                            formats = try component.formats.map { value in
                                guard value.name == name else { return value }
                                return try .init(name: value.name,
                                    readers: missing == 0 ? value.readers.subtracting([version]) : value.readers,
                                    writers: missing == 0 ? value.writers : value.writers.subtracting([version]))
                            }
                        }
                        return try .init(role: component.role, identifier: component.identifier,
                            generation: component.generation, relativePath: component.relativePath,
                            codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                            teamID: component.teamID, formats: formats, requests: component.requests)
                    })
                let before = try f.plan.encoded
                XCTAssertThrowsError(try prepare(f.plan, f)) { error in
                    XCTAssertTrue(error is ReleaseCompatibilityError)
                }
                XCTAssertEqual(try f.plan.encoded, before)
                XCTAssertEqual(f.plan.host.command.presence.wake.request.service.auditVersions, [])
            }
        }
    }

}
