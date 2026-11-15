import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// The real wake service and phone push capability. The journal boundary is the supplied closure, because these
/// fixtures do not open the protected journal pair. Installed Root identity and launchd startup are not proved here.
final class AuthorityHealthyMaintenanceReadinessTests: XCTestCase, @unchecked Sendable {
    private typealias Fixture = AuthorityWakeSettingsTests.Fixture
    private typealias Driver = AuthorityWakeSettingsTests.Driver
    private typealias Readiness = AuthorityHealthyMaintenanceReadiness
    private struct Denied: Error {}

    private func configured(_ f: Fixture) -> Data { Data(SHA256.hash(data: f.options.canonicalBytes)) }
    private func binding(_ f: Fixture, account: Data? = nil) throws -> GatewaySettingsControlBinding {
        try .init(accountID: account ?? f.h.registration.accountID, rootEpoch: f.h.clock)
    }
    private func ready(_ service: AuthorityWakeService, _ expected: Readiness,
                       boundary: @escaping @Sendable () throws -> Void = {}) async -> Bool {
        do { try await service.requireHealthyReadiness(expected, boundary: boundary); return true } catch { return false }
    }

    func testDeclaredPhonePushNeedsTheConfiguredCommitInstalledAndRetained() async throws {
        let f = try Fixture(install: false)
        try f.capability.install(f.options, commitDigest: configured(f), verifyCurrent: {})
        let service = try f.service([Driver()], binding: binding(f))
        let expected = try Readiness(accountID: f.h.registration.accountID, phonePush: f.options)
        XCTAssertEqual(expected.phonePush, .installed(commitDigest: configured(f)))
        let beforeStart = await ready(service, expected); XCTAssertFalse(beforeStart)
        try await service.start()
        let accepted = await ready(service, expected); XCTAssertTrue(accepted)
        let boundaryRefused = await ready(service, expected, boundary: { throw Denied() }); XCTAssertFalse(boundaryRefused)
        let otherAccount = await ready(service, try Readiness(accountID: Data(repeating: 9, count: 16), phonePush: f.options))
        XCTAssertFalse(otherAccount)
        // A suspended provider keeps its retained commit but has no installed commit.
        f.capability.suspend()
        XCTAssertNil(f.capability.installedCommitDigest); XCTAssertEqual(f.capability.retainedCommitDigest, configured(f))
        let suspended = await ready(service, expected); XCTAssertFalse(suspended)
        try f.capability.install(f.options, commitDigest: configured(f), verifyCurrent: {})
        let reinstalled = await ready(service, expected); XCTAssertTrue(reinstalled)
        try await service.close()
        let closed = await ready(service, expected); XCTAssertFalse(closed)
    }
    func testDeclaredPhonePushRefusesAMissingOrAnotherCommit() async throws {
        let missing = try Fixture(install: false), missingService = try missing.service([Driver()], binding: binding(missing))
        try await missingService.start()
        let noCommit = await ready(missingService, try Readiness(accountID: missing.h.registration.accountID, phonePush: missing.options))
        XCTAssertFalse(noCommit); XCTAssertNil(missing.capability.retainedCommitDigest)
        try await missingService.close()
        // This fixture installs a commit that is not the digest of the configured options.
        let other = try Fixture(), otherService = try other.service([Driver()], binding: binding(other))
        try await otherService.start()
        XCTAssertEqual(other.capability.installedCommitDigest, other.old); XCTAssertNotEqual(other.old, configured(other))
        let otherCommit = await ready(otherService, try Readiness(accountID: other.h.registration.accountID, phonePush: other.options))
        XCTAssertFalse(otherCommit)
        try await otherService.close()
    }
    func testUndeclaredPhonePushNeedsNoInstalledOrRetainedCommit() async throws {
        let empty = try Fixture(install: false), emptyService = try empty.service([Driver()], binding: binding(empty))
        let absent = try Readiness(accountID: empty.h.registration.accountID, gatewayRuntimeCommit: nil)
        XCTAssertEqual(absent.phonePush, .absent)
        try await emptyService.start()
        let accepted = await ready(emptyService, absent); XCTAssertTrue(accepted)
        try await emptyService.close()
        let installed = try Fixture(), installedService = try installed.service([Driver()], binding: binding(installed))
        let expected = try Readiness(accountID: installed.h.registration.accountID, gatewayRuntimeCommit: nil)
        try await installedService.start()
        let present = await ready(installedService, expected); XCTAssertFalse(present)
        installed.capability.suspend(); XCTAssertNil(installed.capability.installedCommitDigest)
        let retained = await ready(installedService, expected); XCTAssertFalse(retained)
        try await installedService.close()
    }
    func testTheGatewaySettingsBindingMustExistForTheMaintenanceAccount() async throws {
        let f = try Fixture(install: false), unbound = try f.service([Driver()])
        let expected = try Readiness(accountID: f.h.registration.accountID, gatewayRuntimeCommit: nil)
        try await unbound.start()
        let missing = await ready(unbound, expected); XCTAssertFalse(missing)
        try await unbound.close()
        // The service cannot hold a binding for another account, so the maintenance account is the only other mismatch.
        XCTAssertThrowsError(try f.service([Driver()], binding: binding(f, account: Data(repeating: 9, count: 16))))
        XCTAssertThrowsError(try Readiness(accountID: Data(repeating: 9, count: 15), gatewayRuntimeCommit: nil))
        XCTAssertThrowsError(try Readiness(accountID: f.h.registration.accountID, gatewayRuntimeCommit: Data(repeating: 1, count: 31)))
    }

    // A real published gateway runtime, read with the loader and authority validation that the extension monitor uses.
    private struct Runtime {
        let gateway: GatewayJournalSetupExchangeTests.Fixture, pair: GatewayRuntimeExtensions, directory: ProtectedSetupDirectory
        var host: InstalledAuthorityCommandConfiguration { gateway.runtime.plan.host }
        init() throws {
            gateway = try .init()
            try gateway.retainCompletion(.decode(gateway.initialize()))
            pair = try GatewayRuntimeExtensions(journal: gateway.state(), foreground: gateway.runtime.plan,
                inventory: XCTUnwrap(gateway.runtime.machine.inventory()))
            directory = try ProtectedSetupDirectory(anchor: gateway.root.path, relativePath: "Runtime", owner: getuid(), visibility: .sharedMetadata)
        }
        func publish() throws {
            _ = try GatewayRuntimePublication.publish(pair, directory: directory, owner: getuid(), mode: .publishPending,
                verifyCurrent: {}, didPublish: { _ in })
        }
        func read(_ file: AdministrativeSetupPublication.File) throws -> Data {
            let privateFile: Bool
            switch file { case .authorityGatewayRuntime: privateFile = true; default: privateFile = false }
            return try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name, owner: getuid(),
                privateFile: privateFile)
        }
        func expected(read: ((AdministrativeSetupPublication.File) throws -> Data)? = nil) throws -> Readiness {
            try Readiness.current(accountID: host.command.accountID, configuredPhonePush: host.command.presence.wake.phonePush) {
                try GatewayRuntimeLoader.load(target: .authority, read: read ?? self.read, verifyCurrent: {},
                    validate: { try $0.validate(authority: host) })
            }
        }
    }
    /// One fresh service on the runtime account. The capability holds `installed` before the service starts, if given.
    private func check(_ r: Runtime, installed: Data?, _ expected: Readiness) async throws -> Bool {
        let f = try Fixture(install: false, macID: r.host.command.macID, accountID: r.host.command.accountID)
        if let installed { try f.capability.install(f.options, commitDigest: installed, verifyCurrent: {}) }
        let service = try f.service([Driver()], binding: binding(f))
        try await service.start()
        let result = await ready(service, expected)
        try await service.close()
        return result
    }
    func testUndeclaredPhonePushFollowsThePublishedGatewayRuntime() async throws {
        let r = try Runtime(); defer { r.directory.close() }
        XCTAssertNil(r.host.command.presence.wake.phonePush)
        let unpublished = try r.expected()
        XCTAssertEqual(unpublished.phonePush, .absent)
        let absentAccepted = try await check(r, installed: nil, unpublished); XCTAssertTrue(absentAccepted)
        try r.publish()
        let loaded = try XCTUnwrap(GatewayRuntimeLoader.load(target: .authority, read: r.read, verifyCurrent: {},
            validate: { try $0.validate(authority: r.host) }))
        let published = try r.expected(), digest = try loaded.commit.observationDigest
        XCTAssertEqual(published.phonePush, .installed(commitDigest: digest))
        let installedAccepted = try await check(r, installed: digest, published); XCTAssertTrue(installedAccepted)
        let notInstalledYet = try await check(r, installed: nil, published); XCTAssertFalse(notInstalledYet)
        let otherCommit = Data(repeating: 71, count: 32); XCTAssertNotEqual(otherCommit, digest)
        let otherRefused = try await check(r, installed: otherCommit, published); XCTAssertFalse(otherRefused)
        // Each check reads the runtime again, so the expectation from before the publication is not reused.
        XCTAssertNotEqual(try r.expected(), unpublished)
    }
    func testAnUnreadableGatewayRuntimeRefusesInsteadOfLookingAbsent() throws {
        let r = try Runtime(); defer { r.directory.close() }
        try r.publish()
        XCTAssertThrowsError(try r.expected(read: { _ in throw JournalLeaseError.system(EACCES) }))
        let good = try r.read(.gatewayRuntimeCommit)
        let marker = r.directory.path + "/" + AdministrativeSetupPublication.File.gatewayRuntimeCommit.name
        try Data("malformed".utf8).write(to: URL(fileURLWithPath: marker))
        XCTAssertThrowsError(try r.expected())
        try FileManager.default.removeItem(atPath: r.directory.path + "/" + AdministrativeSetupPublication.File.authorityGatewayRuntime.name)
        XCTAssertThrowsError(try r.expected(read: { file in
            if case .gatewayRuntimeCommit = file { return good }
            return try r.read(file)
        }))
    }
    func testDeclaredPhonePushNeverReadsTheGatewayRuntime() throws {
        let f = try Fixture(install: false)
        let expected = try Readiness.current(accountID: f.h.registration.accountID, configuredPhonePush: f.options) {
            XCTFail("The runner starts no gateway monitor when the configuration declares phone push"); return nil
        }
        XCTAssertEqual(expected.phonePush, .installed(commitDigest: configured(f)))
    }
}
