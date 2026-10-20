import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Synthetic public metadata decisions. No retained Root material or native dedicated account is asserted.
final class GatewaySettingsInitialPublicationTests: XCTestCase, @unchecked Sendable {
    private struct Refused: Error {}
    private let limits = try! CBORLimits(maxBytes: 262144, maxDepth: 5, maxItems: 128)
    private struct Fixture {
        let retained: GatewayJournalSetupExchangeTests.Fixture
        let host: GatewaySettingsConsumerHostConfiguration
        let files: [String: Data]
        init() throws {
            retained = try .init()
            let r = retained.runtime, old = retained.intent.material
            let activity = try ServiceReleaseActivityReference(services: r.services, identities: [
                .transport: .init(device: 1, inode: 100), .gateway: .init(device: 1, inode: 101)])
            let runtime = try RuntimePreparationMaterial(materialID: r.material.materialID, services: r.services,
                transportIdentity: r.material.transportIdentity, transportPublicKeyInfo: r.material.transportPublicKeyInfo,
                gateway: r.material.gateway, serviceActivity: activity).reference
            let material = try GatewayMaterialReference(materialID: old.materialID, runtime: runtime, phonePush: old.phonePush,
                materialDigest: old.materialDigest, wakeCredentialID: old.wakeCredentialID, wakePublicKey: old.wakePublicKey)
            host = try .init(role: .gateway, runtime: runtime, bundlePath: r.plan.bundlePath, codePolicy: r.plan.host.codePolicy)
            let transportHost = try GatewaySettingsConsumerHostConfiguration(role: .transport, runtime: runtime,
                bundlePath: host.bundlePath, codePolicy: host.codePolicy)
            let base = try TransportPairingStartupConfiguration(transport: r.plan.transport.transport, control: r.plan.transport.control,
                wake: r.plan.transport.wake, relayPort: r.plan.transport.relayPort, settingsHost: transportHost)
            let oldPair = try GatewayRuntimeExtensions(journal: .init(intent: retained.intent, initialized: true),
                foreground: r.plan, inventory: XCTUnwrap(r.machine.inventory()))
            let intent = try GatewayJournalSetupIntent(id: retained.intent.id, material: material,
                configuration: retained.intent.configuration, files: retained.intent.files)
            func role(_ original: GatewayRuntimeExtension) throws -> GatewayRuntimeExtension {
                try .init(target: original.target, intentID: intent.id, intentDigest: intent.digest,
                    foregroundDigest: original.foregroundDigest,
                    baseDigest: original.target == .transport ? Data(SHA256.hash(data: base.canonicalBytes)) : original.baseDigest,
                    material: material, codePolicy: original.codePolicy, wake: original.wake)
            }
            let pair = try GatewayRuntimeExtensions.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .text("remozio-gateway-runtime-extensions"),
                2: .bytes(role(oldPair.authority).encoded), 3: .bytes(role(oldPair.transport).encoded)]),
                limits: CBORLimits(maxBytes: 262144, maxDepth: 1, maxItems: 9)))
            let journal = try GatewayJournalSetupServiceConfiguration(intent: intent, bundlePath: host.bundlePath, codePolicy: host.codePolicy)
            files = [AdministrativeSetupPublication.File.gatewayRuntimeCommit.name: try GatewayRuntimeCommit(pair).encoded,
                AdministrativeSetupPublication.File.transportConfiguration.name: base.canonicalBytes,
                AdministrativeSetupPublication.File.transportGatewayRuntime.name: try pair.transport.encoded,
                AdministrativeSetupPublication.File.gatewayJournalService.name: journal.canonicalBytes,
                AdministrativeSetupPublication.File.gatewayConfiguration.name: intent.configuration.canonicalBytes]
        }
        func read(_ file: AdministrativeSetupPublication.File) throws -> Data {
            guard let data = files[file.name] else { throw JournalLeaseError.system(ENOENT) }; return data
        }
        func load() throws -> GatewaySettingsInitialPublication? {
            try .load(host: host, readFence: { nil }, read: read, verifyCurrent: {})
        }
    }
    private func changed(_ bytes: Data, key: UInt64, value: CBORValue) throws -> Data {
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw Refused() }
        fields[key] = value; return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    func testNativeInitialEntryRejectsTheOrdinaryCallerBeforeItsPublicationGuardOrCredentials() async throws {
        let f = try Fixture(), publication = try XCTUnwrap(f.load())
        do {
            _ = try await GatewayService.openInitial(publication: publication, verifyCurrent: { XCTFail("Native account admission must run first") })
            XCTFail()
        } catch { XCTAssertEqual(error as? GatewayServiceError, .wrongAccount) }
    }
    func testInitialMarkerAndRetainedIntentBindTheExactGatewayWithoutOpeningAnyPrivateFile() throws {
        let f = try Fixture(), publication = try XCTUnwrap(f.load())
        XCTAssertNil(publication.commit.settingsSequence)
        XCTAssertEqual(publication.configuration.canonicalBytes, f.retained.intent.configuration.canonicalBytes)
        try publication.verifyPublished(readFence: { nil }, read: f.read, verifyCurrent: {})
    }
    func testAbsentMarkerAndPendingFenceNeverReadBackendInputs() throws {
        let f = try Fixture(), fence = try GatewaySettingsConsumerControlFixture().fence
        XCTAssertNil(try GatewaySettingsInitialPublication.load(host: f.host, readFence: { fence },
            read: { _ in XCTFail("Pending settings must stay paused"); throw Refused() }, verifyCurrent: {}))
        XCTAssertNil(try GatewaySettingsInitialPublication.load(host: f.host, readFence: { nil }, read: {
            guard $0.name == AdministrativeSetupPublication.File.gatewayRuntimeCommit.name else { XCTFail(); throw Refused() }
            throw JournalLeaseError.system(ENOENT)
        }, verifyCurrent: {}))
    }
    func testCompletedSettingsMarkerCannotRestoreAnInitialRuntime() throws {
        let f = try Fixture(), marker = try f.read(.gatewayRuntimeCommit)
        guard case .map(var fields) = try DeterministicCBOR.decode(marker, limits: limits) else { return XCTFail() }
        fields[0] = .unsigned(2); fields[8] = .unsigned(1)
        for key in UInt64(9)...11 { fields[key] = .bytes(Data(repeating: 7, count: 32)) }
        let settings = try DeterministicCBOR.encode(.map(fields), limits: limits)
        XCTAssertNil(try GatewaySettingsInitialPublication.load(host: f.host, readFence: { nil }, read: {
            guard $0.name == AdministrativeSetupPublication.File.gatewayRuntimeCommit.name else { XCTFail(); throw Refused() }; return settings
        }, verifyCurrent: {}))
        let publication = try XCTUnwrap(f.load())
        XCTAssertThrowsError(try publication.verifyPublished(readFence: { nil }, read: {
            $0.name == AdministrativeSetupPublication.File.gatewayRuntimeCommit.name ? settings : try f.read($0)
        }, verifyCurrent: {}))
    }
    func testMalformedDeniedAndMissingCommittedInputsNeverBecomeOptionalAbsence() throws {
        let f = try Fixture()
        let names = [AdministrativeSetupPublication.File.gatewayRuntimeCommit, .transportConfiguration,
            .transportGatewayRuntime, .gatewayJournalService, .gatewayConfiguration]
        for file in names {
            for code in [EACCES, EIO, ENOENT] {
                if code == ENOENT && file.name == names[0].name { continue }
                XCTAssertThrowsError(try GatewaySettingsInitialPublication.load(host: f.host, readFence: { nil }, read: {
                    if $0.name == file.name { throw JournalLeaseError.system(code) }; return try f.read($0)
                }, verifyCurrent: {}))
            }
            XCTAssertThrowsError(try GatewaySettingsInitialPublication.load(host: f.host, readFence: { nil }, read: {
                $0.name == file.name ? Data() : try f.read($0)
            }, verifyCurrent: {}))
        }
    }
    func testInitialCommitCannotAuthorizeAChangedGatewayConfiguration() throws {
        let f = try Fixture()
        let original = try f.read(.gatewayConfiguration)
        // A valid configuration with changed tuning still has no binding to the retained initial intent.
        let old = try GatewayServiceConfiguration.decode(original)
        let root = try XCTUnwrap(f.host.codePolicy.entries.first { $0.role == .authority && $0.active })
        let settings = try GatewayServiceSettings(delivery: old.settings.delivery, probe: old.settings.probe,
            wake: old.settings.wake, schedulerRetryMillis: old.settings.schedulerRetryMillis + 1)
        let different = try GatewayServiceConfiguration(registration: old.registration, receiptPublicKey: old.receiptPublicKey,
            directoryPath: old.directoryPath, providerPath: old.providerPath, receiptKeyPath: old.receiptKeyPath,
            serviceUID: old.serviceUID, ownerUID: old.ownerUID, serviceName: old.serviceName,
            teamID: root.teamID, authorityIdentifier: root.identifier, authorityHashes: [root.codeDirectoryHash],
            project: old.project, packageName: old.packageName, settings: settings, wakeEndpoint: old.wakeEndpoint)
        XCTAssertNotEqual(different.canonicalBytes, original)
        XCTAssertThrowsError(try GatewaySettingsInitialPublication.load(host: f.host, readFence: { nil }, read: {
            $0.name == AdministrativeSetupPublication.File.gatewayConfiguration.name ? different.canonicalBytes : try f.read($0)
        }, verifyCurrent: {}))
    }
    func testRetainedIntentCannotBeReplacedEvenWhenTheConfigurationIsIdentical() throws {
        let f = try Fixture(), original = try GatewayJournalSetupServiceConfiguration.decode(f.read(.gatewayJournalService))
        let intent = try GatewayJournalSetupIntent(id: Data(repeating: 91, count: 16), material: original.intent.material,
            configuration: original.intent.configuration, files: original.intent.files)
        let changed = try GatewayJournalSetupServiceConfiguration(intent: intent, bundlePath: original.bundlePath, codePolicy: original.codePolicy)
        XCTAssertThrowsError(try GatewaySettingsInitialPublication.load(host: f.host, readFence: { nil }, read: {
            $0.name == AdministrativeSetupPublication.File.gatewayJournalService.name ? changed.canonicalBytes : try f.read($0)
        }, verifyCurrent: {}))
    }
    func testImmutableHostMustMatchRoleRuntimeBundleAndCodePolicy() throws {
        let f = try Fixture(), h = f.host
        let noSetup = try AuthorityCodePolicy(entries: h.codePolicy.entries.filter { $0.role != .app })
        // The retained service accepts this policy subset; the immutable host must still reject the mismatch.
        let original = try GatewayJournalSetupServiceConfiguration.decode(f.read(.gatewayJournalService))
        let changedJournal = try GatewayJournalSetupServiceConfiguration(intent: original.intent, bundlePath: original.bundlePath, codePolicy: noSetup)
        XCTAssertThrowsError(try GatewaySettingsInitialPublication.load(host: h, readFence: { nil }, read: {
            $0.name == AdministrativeSetupPublication.File.gatewayJournalService.name ? changedJournal.canonicalBytes : try f.read($0)
        }, verifyCurrent: {}))
        for host in [try GatewaySettingsConsumerHostConfiguration(role: .transport, runtime: h.runtime,
            bundlePath: h.bundlePath, codePolicy: h.codePolicy),
            try GatewaySettingsConsumerHostConfiguration(role: .gateway, runtime: h.runtime,
            bundlePath: "/Library/Other.app", codePolicy: h.codePolicy)] {
            XCTAssertThrowsError(try GatewaySettingsInitialPublication.load(host: host, readFence: { nil }, read: f.read, verifyCurrent: {}))
        }
    }
    func testChangedFilesDuringAndAfterLoadStopTheInitialPublication() throws {
        let f = try Fixture()
        for name in f.files.keys {
            var reads = 0
            XCTAssertThrowsError(try GatewaySettingsInitialPublication.load(host: f.host, readFence: { nil }, read: {
                if $0.name == name { reads += 1; if reads > 1 { return Data() } }; return try f.read($0)
            }, verifyCurrent: {}))
            let publication = try XCTUnwrap(f.load())
            XCTAssertThrowsError(try publication.verifyPublished(readFence: { nil }, read: {
                $0.name == name ? Data() : try f.read($0)
            }, verifyCurrent: {}))
        }
    }
    func testNewFenceAndUnreadableFenceStopAnExistingSnapshot() throws {
        let f = try Fixture(), fence = try GatewaySettingsConsumerControlFixture().fence, publication = try XCTUnwrap(f.load())
        var count = 0
        XCTAssertThrowsError(try GatewaySettingsInitialPublication.load(host: f.host, readFence: {
            count += 1; return count == 1 ? nil : fence
        }, read: f.read, verifyCurrent: {}))
        XCTAssertThrowsError(try publication.verifyPublished(readFence: { fence }, read: f.read, verifyCurrent: {}))
        XCTAssertThrowsError(try publication.verifyPublished(readFence: { throw JournalLeaseError.system(EACCES) }, read: f.read, verifyCurrent: {}))
    }
    func testCurrentScopeChecksPrecedeAccessAndBracketEverySuccessfulLoad() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try GatewaySettingsInitialPublication.load(host: f.host,
            readFence: { XCTFail(); return nil }, read: { _ in XCTFail(); throw Refused() }, verifyCurrent: { throw Refused() }))
        var count = 0
        XCTAssertNotNil(try GatewaySettingsInitialPublication.load(host: f.host, readFence: { nil }, read: f.read, verifyCurrent: { count += 1 }))
        XCTAssertGreaterThanOrEqual(count, 4)
        for failure in 2...count {
            var checks = 0
            XCTAssertThrowsError(try GatewaySettingsInitialPublication.load(host: f.host, readFence: { nil }, read: f.read, verifyCurrent: {
                checks += 1; if checks == failure { throw Refused() }
            }))
        }
    }
}
