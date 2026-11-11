import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Uses owned fixture values and synthetic receipts. It proves no protected publication or native startup.
final class RetainedSetupCompletionConfigurationTests: XCTestCase {
    final class Fixture {
        let completion: RetainedSetupCompletionArchiveTests.Fixture
        let archive: RuntimeRetainedSetupCompletionArchive
        let host: InstalledAuthorityCommandConfiguration
        let transport: TransportPairingStartupConfiguration
        let gateway: GatewaySettingsConsumerHostConfiguration
        let clients: RuntimeActivationClients
        let sourceDigest: Data
        let fields: [UInt64: CBORValue]
        let limits = try! CBORLimits(maxBytes: 4_194_304, maxDepth: 4, maxItems: 4096)

        init(changedPolicy: Bool = false) throws {
            let f = try RetainedSetupCompletionArchiveTests.Fixture(changedPolicy: changedPolicy)
            let archive = try RuntimeRetainedSetupCompletionArchive.decode(f.bytes())
            let original = try archive.originalActivation()
            let policy = f.completionPolicy.policy
            let limits = try CBORLimits(maxBytes: 131072, maxDepth: 4, maxItems: 512)
            func completed(_ previous: GatewaySettingsConsumerHostConfiguration) throws -> GatewaySettingsConsumerHostConfiguration {
                guard case .map(var fields) = try DeterministicCBOR.decode(previous.encoded, limits: limits) else {
                    throw RuntimeActivationError.invalidPlan
                }
                fields[0] = .unsigned(4); fields[5] = .bytes(try policy.bytes)
                fields[6] = .bytes(try archive.binding.encoded); fields[7] = .unsigned(RuntimeReleasePolicyStage.completion.rawValue)
                return try .decodeForReleaseArchive(DeterministicCBOR.encode(.map(fields), limits: limits))
            }
            let gateway = try completed(original.gatewaySettingsHost)
            let settings = try completed(XCTUnwrap(original.transport.settingsHost))
            let host = try InstalledAuthorityCommandConfiguration(machineDirectory: original.host.machineDirectory,
                installationID: original.host.installationID, releaseDigest: original.host.releaseDigest, codePolicy: policy,
                command: original.host.command, label: original.host.label, plistName: original.host.plistName,
                jobPlacement: original.host.jobPlacement, gatewaySettingsControlEnabled: true,
                installedReadinessEnabled: original.host.installedReadinessEnabled)
            let transport = try TransportPairingStartupConfiguration(transport: original.transport.transport,
                control: original.transport.control, wake: original.transport.wake,
                relayPort: original.transport.relayPort, settingsHost: settings)
            let runtime = f.activationFixture.source.f.f
            let initialization = try XCTUnwrap(runtime.machine.initialization(accountID: runtime.account.accountID))
            let inventory = try XCTUnwrap(runtime.machine.inventory())
            let bundle = try runtime.plan.configurationBundle(account: runtime.account,
                initialization: initialization, inventory: inventory)
            let clients = RuntimeActivationClients(presence: bundle.presenceClient, pairing: bundle.pairingClient,
                frontend: bundle.frontendClient)
            let sourceDigest = try RuntimeReleaseConfigurationSource(host: original.host, transport: original.transport,
                gateway: original.gatewaySettingsHost, clients: clients).digest
            self.completion = f; self.archive = archive; self.host = host; self.transport = transport
            self.gateway = gateway; self.clients = clients; self.sourceDigest = sourceDigest
            // The donor source defines this map. No bytes were produced by executing the donor.
            fields = [0: .unsigned(1), 1: .text("runtime.retained-setup-completion-configuration"),
                2: .bytes(try archive.encoded), 3: .bytes(sourceDigest), 4: .bytes(host.canonicalBytes),
                5: .bytes(transport.canonicalBytes), 6: .bytes(try gateway.encoded),
                7: .bytes(clients.presence.canonicalBytes), 8: .bytes(clients.pairing.canonicalBytes),
                9: .bytes(clients.frontend.canonicalBytes)]
        }
        func bytes(_ fields: [UInt64: CBORValue]? = nil) throws -> Data {
            try DeterministicCBOR.encode(.map(fields ?? self.fields), limits: limits)
        }
        func withBinding(_ binding: RuntimeRetainedSetupCompletionBinding,
                         role: GatewaySettingsConsumerRole) throws -> GatewaySettingsConsumerHostConfiguration {
            let original: GatewaySettingsConsumerHostConfiguration
            if role == .gateway { original = gateway }
            else { original = try XCTUnwrap(transport.settingsHost) }
            guard case .map(var fields) = try DeterministicCBOR.decode(original.encoded, limits: limits) else {
                throw RuntimeActivationError.invalidPlan
            }
            fields[6] = .bytes(try binding.encoded)
            return try .decodeForReleaseArchive(DeterministicCBOR.encode(.map(fields), limits: limits))
        }
        func authority(release: Data? = nil, policy: AuthorityCodePolicy? = nil,
                       control: Bool = true) throws -> InstalledAuthorityCommandConfiguration {
            try .init(machineDirectory: host.machineDirectory, installationID: host.installationID,
                releaseDigest: release ?? host.releaseDigest, codePolicy: policy ?? host.codePolicy,
                command: host.command, label: host.label, plistName: host.plistName,
                jobPlacement: host.jobPlacement, gatewaySettingsControlEnabled: control)
        }
    }

    func testRoundTripsTheSourceDerivedWireMapAndAllCompletedValues() throws {
        for changed in [false, true] {
            let f = try Fixture(changedPolicy: changed), bytes = try f.bytes()
            let value = try RuntimeRetainedSetupCompletionConfiguration.decode(bytes)
            XCTAssertEqual(try value.encoded, bytes)
            XCTAssertEqual(value.archive, f.archive)
            XCTAssertEqual(value.sourceDigest, f.sourceDigest)
            XCTAssertEqual(value.host.canonicalBytes, f.host.canonicalBytes)
            XCTAssertEqual(value.transport.canonicalBytes, f.transport.canonicalBytes)
            XCTAssertEqual(value.gateway, f.gateway)
            XCTAssertEqual(value.clients.presence.canonicalBytes, f.clients.presence.canonicalBytes)
            XCTAssertEqual(value.clients.pairing.canonicalBytes, f.clients.pairing.canonicalBytes)
            XCTAssertEqual(value.clients.frontend.canonicalBytes, f.clients.frontend.canonicalBytes)
            XCTAssertEqual(value.host.codePolicy, f.completion.completionPolicy.policy)
            XCTAssertEqual(value.host.codePolicy == (try value.archive.originalActivation().host.codePolicy), !changed)
            XCTAssertEqual(value.gateway.formatVersion, 4)
            XCTAssertEqual(value.gateway.policyStage, .completion)
            XCTAssertEqual(value.description, "RuntimeRetainedSetupCompletionConfiguration(redacted)")
            XCTAssertEqual(value.debugDescription, value.description)
        }
    }

    func testArchivedConfigurationCannotBecomeAnExecutablePlanOrNativeStartup() throws {
        let f = try Fixture(), value = try RuntimeRetainedSetupCompletionConfiguration.decode(f.bytes())
        XCTAssertThrowsError(try RuntimeReleaseConfigurationPlan.decode(value.encoded))
        XCTAssertThrowsError(try RuntimeActivationPlan.decode(value.archive.originalActivationBytes))
        XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decode(value.gateway.encoded))
        XCTAssertThrowsError(try GatewaySettingsConsumerNativeScope.decodeGatewayStartup(
            value.gateway.encoded, path: value.gateway.gatewayConfigurationPath)) {
            XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
        }
        let paths = try RuntimePreparationPaths(accountID: value.gateway.runtime.services.accountID)
        XCTAssertThrowsError(try GatewaySettingsConsumerNativeScope.decodeTransportStartup(
            value.transport.canonicalBytes, path: paths.transportConfiguration)) {
            XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
        }
    }

    func testRejectsEveryForeignArchiveHostTransportAndClientPayload() throws {
        let f = try Fixture(), other = try Fixture()
        for key in [UInt64(2), 4, 5, 6, 7, 8, 9] {
            var fields = f.fields; fields[key] = other.fields[key]
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionConfiguration.decode(f.bytes(fields)))
        }
    }

    func testRequiresCompletedHostsWithTheExactArchiveBinding() throws {
        let f = try Fixture(), startup = try f.archive.originalActivation()
        for (key, bytes): (UInt64, Data) in [
            (5, startup.transport.canonicalBytes), (6, try startup.gatewaySettingsHost.encoded),
        ] {
            var fields = f.fields; fields[key] = .bytes(bytes)
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionConfiguration.decode(f.bytes(fields)))
        }
        var bindingFields = f.completion.bindingFields
        bindingFields["completionPolicyRevision"] = UUID().uuidString
        let other = try RuntimeRetainedSetupCompletionBinding.decode(f.completion.json(bindingFields))
        let gateway = try f.withBinding(other, role: .gateway)
        var fields = f.fields; fields[6] = .bytes(try gateway.encoded)
        XCTAssertThrowsError(try RuntimeRetainedSetupCompletionConfiguration.decode(f.bytes(fields)))
        let settings = try f.withBinding(other, role: .transport)
        let transport = try TransportPairingStartupConfiguration(transport: f.transport.transport, control: f.transport.control,
            wake: f.transport.wake, relayPort: f.transport.relayPort, settingsHost: settings)
        XCTAssertNoThrow(try TransportPairingStartupConfiguration.decodeForReleaseArchive(transport.canonicalBytes))
        fields = f.fields; fields[5] = .bytes(transport.canonicalBytes)
        XCTAssertThrowsError(try RuntimeRetainedSetupCompletionConfiguration.decode(f.bytes(fields)))
    }

    func testRejectsAuthorityReleasePolicyAndControlMismatches() throws {
        let f = try Fixture(changedPolicy: true)
        for host in [
            try f.authority(release: f.archive.binding.startupBinding.provisioningReleaseDigest),
            try f.authority(policy: f.completion.startupPolicy.policy),
            try f.authority(control: false),
        ] {
            XCTAssertNoThrow(try InstalledAuthorityCommandConfiguration.decode(host.canonicalBytes))
            var fields = f.fields; fields[4] = .bytes(host.canonicalBytes)
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionConfiguration.decode(f.bytes(fields)))
        }
    }

    func testRejectsClientPolicyPinsEvenWhenAccountAndServicesMatch() throws {
        let f = try Fixture(), policy = f.host.codePolicy
        let authority = try XCTUnwrap(policy.entries.first { $0.role == .authority })
        let app = try XCTUnwrap(policy.entries.first { $0.role == .app })
        let transport = try XCTUnwrap(policy.entries.first { $0.role == .transport })
        let wrong = Data(repeating: 99, count: 20), p = f.clients.presence, pair = f.clients.pairing, front = f.clients.frontend
        let presence = try AuthorityPresenceClientConfiguration(macID: p.macID, accountID: p.accountID, ownerUID: p.ownerUID,
            serviceName: p.serviceName, teamID: authority.teamID, rootIdentifier: authority.identifier,
            rootHashes: [wrong], timeoutMilliseconds: p.timeoutMilliseconds)
        let pairing = try TransportPairingControlConfiguration(macID: pair.macID, accountID: pair.accountID,
            ownerUID: pair.ownerUID, transportUID: pair.transportUID, serviceName: pair.serviceName,
            teamID: app.teamID, appIdentifier: app.identifier, appHashes: [wrong],
            transportIdentifier: transport.identifier, transportHashes: [transport.codeDirectoryHash],
            timeoutMilliseconds: pair.timeoutMilliseconds, setupTimeoutMilliseconds: pair.setupTimeoutMilliseconds,
            maximumCandidates: pair.maximumCandidates)
        let frontend = try CommandFrontendConfiguration(macID: front.macID, accountID: front.accountID,
            serviceName: front.serviceName, teamID: authority.teamID, authorityIdentifier: authority.identifier,
            authorityHashes: [wrong], submissionLimits: front.submissionLimits, defaultIOMode: front.defaultIOMode,
            defaultDisconnectBehavior: front.defaultDisconnectBehavior, readiness: front.readiness)
        XCTAssertNoThrow(try AuthorityPresenceClientConfiguration.decode(presence.canonicalBytes))
        XCTAssertNoThrow(try TransportPairingControlConfiguration.decode(pairing.canonicalBytes))
        XCTAssertNoThrow(try CommandFrontendConfiguration.decode(frontend.canonicalBytes))
        for (key, bytes): (UInt64, Data) in [
            (7, presence.canonicalBytes), (8, pairing.canonicalBytes), (9, frontend.canonicalBytes),
        ] {
            var fields = f.fields; fields[key] = .bytes(bytes)
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionConfiguration.decode(f.bytes(fields)))
        }
    }

    func testSourceDigestIsBoundedMetadataAndGrantsNoCurrentSourceProof() throws {
        let f = try Fixture()
        for count in [0, 31, 33] {
            var fields = f.fields; fields[3] = .bytes(Data(repeating: 1, count: count))
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionConfiguration.decode(f.bytes(fields)))
        }
        let different = MachineUpdateActivationRecord.digest(Data("another recorded source".utf8))
        XCTAssertNotEqual(different, f.sourceDigest)
        var fields = f.fields; fields[3] = .bytes(different)
        let value = try RuntimeRetainedSetupCompletionConfiguration.decode(f.bytes(fields))
        XCTAssertEqual(value.sourceDigest, different)
        XCTAssertEqual(try value.encoded, try f.bytes(fields))
    }

    func testRejectsWrongPurposeVersionMissingUnknownMalformedAndOversizedFields() throws {
        let f = try Fixture()
        for key in f.fields.keys {
            var fields = f.fields; fields[key] = nil
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionConfiguration.decode(f.bytes(fields)))
        }
        for (key, value): (UInt64, CBORValue) in [
            (0, .unsigned(0)), (0, .unsigned(2)), (1, .text("wrong-purpose")), (10, .null),
        ] {
            var fields = f.fields; fields[key] = value
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionConfiguration.decode(f.bytes(fields)))
        }
        for key in UInt64(2)...9 {
            for value in [CBORValue.null, .bytes(Data([0]))] {
                var fields = f.fields; fields[key] = value
                XCTAssertThrowsError(try RuntimeRetainedSetupCompletionConfiguration.decode(f.bytes(fields)))
            }
        }
        for bytes in [Data(), try f.bytes() + Data([0]),
                      Data(repeating: 0, count: RuntimeRetainedSetupCompletionConfiguration.maximumBytes + 1)] {
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionConfiguration.decode(bytes)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .invalidPlan)
            }
        }
    }
}
