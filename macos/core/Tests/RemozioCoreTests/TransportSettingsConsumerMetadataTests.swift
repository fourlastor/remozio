import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Synthetic public role and host metadata. It does not establish native Root retention or installed code custody.
struct TransportConsumerMetadataFixture {
    let retained: GatewayJournalSetupExchangeTests.Fixture
    let bootstrap: TransportSettingsConsumerBootstrap
    let files: [String: Data]
    init() throws {
        retained = try .init()
        let r = retained.runtime, old = retained.intent.material
        let activity = try ServiceReleaseActivityReference(services: r.services, identities: [
            .transport: .init(device: 1, inode: 100), .gateway: .init(device: 1, inode: 101)])
        let reference = try RuntimePreparationMaterial(materialID: r.material.materialID, services: r.services,
            transportIdentity: r.material.transportIdentity, transportPublicKeyInfo: r.material.transportPublicKeyInfo,
            gateway: r.material.gateway, serviceActivity: activity).reference
        let host = try GatewaySettingsConsumerHostConfiguration(role: .transport, runtime: reference,
            bundlePath: r.plan.bundlePath, codePolicy: r.plan.host.codePolicy)
        let transportBase = try TransportSettingsConsumerBootstrap(base: .init(transport: r.plan.transport.transport, control: r.plan.transport.control,
            wake: r.plan.transport.wake, relayPort: r.plan.transport.relayPort, settingsHost: host))
        bootstrap = transportBase
        let material = try GatewayMaterialReference(materialID: old.materialID, runtime: reference, phonePush: old.phonePush,
            materialDigest: old.materialDigest, wakeCredentialID: old.wakeCredentialID, wakePublicKey: old.wakePublicKey)
        let intent = try GatewayJournalSetupIntent(id: retained.intent.id, material: material,
            configuration: retained.intent.configuration, files: retained.intent.files)
        let oldPair = try GatewayRuntimeExtensions(journal: .init(intent: retained.intent, initialized: true),
            foreground: r.plan, inventory: XCTUnwrap(r.machine.inventory()))
        func role(_ old: GatewayRuntimeExtension) throws -> GatewayRuntimeExtension {
            try .init(target: old.target, intentID: intent.id, intentDigest: intent.digest,
                foregroundDigest: old.foregroundDigest,
                baseDigest: old.target == .transport ? Data(SHA256.hash(data: transportBase.base.canonicalBytes)) : old.baseDigest,
                material: material, codePolicy: old.codePolicy, wake: old.wake)
        }
        let pair = try GatewayRuntimeExtensions.decode(DeterministicCBOR.encode(.map([0: .unsigned(1),
            1: .text("remozio-gateway-runtime-extensions"), 2: .bytes(role(oldPair.authority).encoded),
            3: .bytes(role(oldPair.transport).encoded)]), limits: CBORLimits(maxBytes: 262144, maxDepth: 1, maxItems: 9)))
        files = [AdministrativeSetupPublication.File.gatewayRuntimeCommit.name: try GatewayRuntimeCommit(pair).encoded,
            AdministrativeSetupPublication.File.transportConfiguration.name: transportBase.base.canonicalBytes,
            AdministrativeSetupPublication.File.transportGatewayRuntime.name: try pair.transport.encoded]
    }
    func read(_ file: AdministrativeSetupPublication.File) throws -> Data {
        guard let value = files[file.name] else { throw JournalLeaseError.system(ENOENT) }; return value
    }
    func load() throws -> TransportSettingsInitialPublication? {
        try .load(bootstrap: bootstrap, readFence: { nil }, readCommit: { try read(.gatewayRuntimeCommit) }, read: read, verifyCurrent: {})
    }
}

final class TransportSettingsConsumerMetadataTests: XCTestCase, @unchecked Sendable {
    private struct Refused: Error {}
    private let limits = try! CBORLimits(maxBytes: 262144, maxDepth: 5, maxItems: 128)
    func testImmutableTransportBootstrapHasFixedRoleAccountPathAndExecutable() throws {
        let f = try TransportConsumerMetadataFixture(), base = f.bootstrap
        XCTAssertEqual(try TransportSettingsConsumerBootstrap.decode(base.base.canonicalBytes).host, base.host)
        XCTAssertEqual(try base.configurationPath, try RuntimePreparationPaths(accountID: base.host.runtime.services.accountID).transportConfiguration)
        try base.validatePath(base.configurationPath)
        for path in ["relative.cbor", "/tmp/transport-host.cbor", try base.configurationPath + "/"] { XCTAssertThrowsError(try base.validatePath(path)) }
        XCTAssertEqual(base.host.consumerExecutableRelativePath, "Contents/Library/LaunchServices/RemozioTransport")
        let gateway = try GatewaySettingsConsumerHostConfiguration(role: .gateway, runtime: base.host.runtime,
            bundlePath: base.host.bundlePath, codePolicy: base.host.codePolicy)
        XCTAssertEqual(gateway.consumerExecutableRelativePath, GatewayJournalSetupServiceConfiguration.executableRelativePath)
    }
    func testLegacyBaseAndMalformedOrWrongRoleMetadataCannotEnterNativeHost() throws {
        let f = try TransportConsumerMetadataFixture(), old = f.retained.runtime.plan.transport
        XCTAssertThrowsError(try TransportSettingsConsumerBootstrap(base: old))
        for bytes in [Data(), old.canonicalBytes, f.bootstrap.base.canonicalBytes + Data([0])] {
            XCTAssertThrowsError(try TransportSettingsConsumerBootstrap.decode(bytes))
        }
        guard case .map(var fields) = try DeterministicCBOR.decode(f.bootstrap.base.canonicalBytes, limits: limits) else { return XCTFail() }
        let h = f.bootstrap.host, gateway = try GatewaySettingsConsumerHostConfiguration(role: .gateway, runtime: h.runtime,
            bundlePath: h.bundlePath, codePolicy: h.codePolicy)
        fields[5] = .bytes(try gateway.encoded)
        XCTAssertThrowsError(try TransportSettingsConsumerBootstrap.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
    }
    func testNativeTransportScopeRefusesOrdinaryOwnedMetadataWithoutChangingIt() throws {
        let f = try TransportConsumerMetadataFixture(), files = try ServiceReleaseActivityFixture()
        let path = files.root.appendingPathComponent("transport-host.cbor"), bytes = f.bootstrap.base.canonicalBytes
        try bytes.write(to: path); try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path.path)
        XCTAssertThrowsError(try GatewaySettingsConsumerNativeScope.openTransport(path: path.path))
        XCTAssertEqual(try Data(contentsOf: path), bytes)
    }
    func testInitialRoleLoadsOnlyItsExactCommitAndImmutableBase() throws {
        let f = try TransportConsumerMetadataFixture(), loaded = try XCTUnwrap(f.load())
        XCTAssertEqual(try loaded.configuration.encoded, try f.read(.transportGatewayRuntime)); XCTAssertNil(loaded.commit.settingsSequence)
        try loaded.verifyPublished(readFence: { nil }, readCommit: { try f.read(.gatewayRuntimeCommit) }, read: f.read, verifyCurrent: {})
    }
    func testPendingFenceAndVerifiedMissingMarkerCannotOpenRoleOrPrivateFiles() throws {
        let f = try TransportConsumerMetadataFixture(), fence = try GatewaySettingsConsumerControlFixture().fence
        XCTAssertNil(try TransportSettingsInitialPublication.load(bootstrap: f.bootstrap, readFence: { fence },
            readCommit: { XCTFail(); return nil }, read: { _ in XCTFail(); throw Refused() }, verifyCurrent: {}))
        XCTAssertNil(try TransportSettingsInitialPublication.load(bootstrap: f.bootstrap, readFence: { nil },
            readCommit: { nil }, read: { _ in XCTFail(); throw Refused() }, verifyCurrent: {}))
    }
    func testCompletedSettingsCommitNeverRestoresAnInitialBackend() throws {
        let f = try TransportConsumerMetadataFixture()
        guard case .map(var fields) = try DeterministicCBOR.decode(f.read(.gatewayRuntimeCommit), limits: limits) else { return XCTFail() }
        fields[0] = .unsigned(2); fields[8] = .unsigned(1)
        for key in UInt64(9)...11 { fields[key] = .bytes(Data(repeating: 9, count: 32)) }
        let settings = try DeterministicCBOR.encode(.map(fields), limits: limits)
        XCTAssertNil(try TransportSettingsInitialPublication.load(bootstrap: f.bootstrap, readFence: { nil },
            readCommit: { settings }, read: { _ in XCTFail(); throw Refused() }, verifyCurrent: {}))
        let loaded = try XCTUnwrap(f.load())
        XCTAssertThrowsError(try loaded.verifyPublished(readFence: { nil }, readCommit: { settings }, read: f.read, verifyCurrent: {}))
    }
    func testDeniedAndAncestorMissingMarkerErrorsRemainErrors() throws {
        let f = try TransportConsumerMetadataFixture()
        for code in [ENOENT, EACCES, EIO] {
            XCTAssertThrowsError(try TransportSettingsInitialPublication.load(bootstrap: f.bootstrap, readFence: { nil },
                readCommit: { throw JournalLeaseError.system(code) }, read: f.read, verifyCurrent: {}))
        }
    }
    func testMalformedAndChangedCommittedFilesNeverBecomeOptionalAbsence() throws {
        let f = try TransportConsumerMetadataFixture()
        for name in f.files.keys {
            XCTAssertThrowsError(try TransportSettingsInitialPublication.load(bootstrap: f.bootstrap, readFence: { nil },
                readCommit: { name == AdministrativeSetupPublication.File.gatewayRuntimeCommit.name ? Data() : try f.read(.gatewayRuntimeCommit) },
                read: { $0.name == name ? Data() : try f.read($0) }, verifyCurrent: {}))
            var reads = 0
            XCTAssertThrowsError(try TransportSettingsInitialPublication.load(bootstrap: f.bootstrap, readFence: { nil },
                readCommit: { try f.read(.gatewayRuntimeCommit) }, read: {
                    if $0.name == name { reads += 1; if reads > (name == AdministrativeSetupPublication.File.gatewayRuntimeCommit.name ? 0 : 1) { return Data() } }
                    return try f.read($0)
                }, verifyCurrent: {}))
        }
    }
    func testRoleAndHostScopeCannotBeSubstituted() throws {
        let f = try TransportConsumerMetadataFixture(), other = try TransportConsumerMetadataFixture()
        XCTAssertThrowsError(try TransportSettingsInitialPublication.load(bootstrap: other.bootstrap, readFence: { nil },
            readCommit: { try f.read(.gatewayRuntimeCommit) }, read: f.read, verifyCurrent: {}))
        let h = f.bootstrap.host
        let moved = try GatewaySettingsConsumerHostConfiguration(role: .transport, runtime: h.runtime,
            bundlePath: "/Library/Other.app", codePolicy: h.codePolicy)
        let base = try TransportSettingsConsumerBootstrap(base: .init(transport: f.bootstrap.base.transport,
            control: f.bootstrap.base.control, settingsHost: moved))
        XCTAssertThrowsError(try TransportSettingsInitialPublication.load(bootstrap: base, readFence: { nil },
            readCommit: { try f.read(.gatewayRuntimeCommit) }, read: f.read, verifyCurrent: {}))
    }
    func testChangedMarkerFenceOrScopeRetiresAnExistingSnapshot() throws {
        let f = try TransportConsumerMetadataFixture(), loaded = try XCTUnwrap(f.load()), fence = try GatewaySettingsConsumerControlFixture().fence
        XCTAssertThrowsError(try loaded.verifyPublished(readFence: { fence }, readCommit: { try f.read(.gatewayRuntimeCommit) }, read: f.read, verifyCurrent: {}))
        XCTAssertThrowsError(try loaded.verifyPublished(readFence: { nil }, readCommit: { nil }, read: f.read, verifyCurrent: {}))
        XCTAssertThrowsError(try loaded.verifyPublished(readFence: { nil }, readCommit: { try f.read(.gatewayRuntimeCommit) }, read: f.read, verifyCurrent: { throw Refused() }))
        var count = 0
        XCTAssertThrowsError(try TransportSettingsInitialPublication.load(bootstrap: f.bootstrap, readFence: {
            count += 1; return count == 1 ? nil : fence
        }, readCommit: { try f.read(.gatewayRuntimeCommit) }, read: f.read, verifyCurrent: {}))
    }
    func testInitialNativeAdapterChecksAccountBeforePrivateWakeKeyRestoration() async throws {
        let f = try TransportConsumerMetadataFixture(), loaded = try XCTUnwrap(f.load())
        let runtime = try GatewaySettingsTransportRuntime(initial: loaded, verifyCurrent: {})
        do { try await runtime.start(); XCTFail() } catch { XCTAssertEqual(error as? ApprovalTransportStartupError, .wrongAccount) }
        try await runtime.closeAndWait()
    }
    func testScopeValidationPrecedesAllReadsAndBracketsSuccessfulLoad() throws {
        let f = try TransportConsumerMetadataFixture()
        XCTAssertThrowsError(try TransportSettingsInitialPublication.load(bootstrap: f.bootstrap,
            readFence: { XCTFail(); return nil }, readCommit: { XCTFail(); return nil }, read: { _ in XCTFail(); throw Refused() },
            verifyCurrent: { throw Refused() }))
        var count = 0
        XCTAssertNotNil(try TransportSettingsInitialPublication.load(bootstrap: f.bootstrap, readFence: { nil },
            readCommit: { try f.read(.gatewayRuntimeCommit) }, read: f.read, verifyCurrent: { count += 1 }))
        XCTAssertGreaterThanOrEqual(count, 4)
    }
}
