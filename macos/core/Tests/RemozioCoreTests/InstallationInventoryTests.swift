import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class InstallationInventoryTests: XCTestCase {
    private func id(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
    private func account(_ n: UInt8 = 1, uid: uid_t = 501) throws -> InstallationAccount {
        try .init(accountID: id(n), ownerUID: uid)
    }
    private func daemon(_ role: AuthorityCodeRole = .authority, uid: uid_t = 0, label: String = "dev.remozio.authority", accountID: Data = Data(repeating: 1, count: 16)) throws -> InstallationService {
        try .init(role: role, kind: .daemon, domainUID: nil, executionUID: uid, label: label, plistName: label + ".plist", accountID: accountID)
    }
    private func app(_ uid: uid_t = 501, label: String = "dev.remozio.mac", accountID: Data? = nil) throws -> InstallationService {
        try .init(role: .app, kind: .mainApp, domainUID: uid, executionUID: uid, label: label, plistName: nil, accountID: accountID ?? id(uid == 502 ? 2 : 1))
    }
    private func inventory(accounts: [InstallationAccount]? = nil, services: [InstallationService]? = nil,
                           path: String = "/Library/Remozio/Remozio.app", digest: Data = Data(repeating: 3, count: 32)) throws -> InstallationInventory {
        try .init(macID: id(1), installationID: id(2), revision: id(3), bundlePath: path, releaseDigest: digest,
                  accounts: accounts ?? [account()], services: services ?? [daemon(), app()])
    }
    private func evidence(appHash: UInt8 = 1, authorityHash: UInt8 = 2) throws -> SignedReleaseEvidence {
        let app = try ReleaseComponent(role: .app, identifier: "dev.remozio.mac", generation: 1,
            relativePath: "Contents/MacOS/Remozio", codeDirectoryHash: nil, build: "1", teamID: nil, formats: [])
        let authority = try ReleaseComponent(role: .authority, identifier: "dev.remozio.authority", generation: 1,
            relativePath: "Contents/Helpers/authority", codeDirectoryHash: Data(repeating: authorityHash, count: 20),
            build: "1", teamID: nil, formats: [])
        return .init(manifest: try .init(release: "1", build: "1", components: [app, authority]),
            codeDirectoryHashes: [.app: Data(repeating: appHash, count: 20), .authority: Data(repeating: authorityHash, count: 20)])
    }

    func testRoundTripRetainsEveryAccountAndRegistrationDomain() throws {
        let value = try inventory(accounts: [account(2, uid: 502), account()], services: [app(502), daemon(), app()])
        XCTAssertEqual(try InstallationInventory.decode(value.canonicalBytes, expectedMacID: id(1)), value)
        XCTAssertEqual(value.accounts.map(\.ownerUID), [501, 502])
        XCTAssertEqual(value.services.map(\.domainUID), [nil, 501, 502])
        XCTAssertEqual(value.description, "InstallationInventory(redacted)")
        XCTAssertEqual(try inventory(accounts: value.accounts.reversed(), services: value.services.reversed()).canonicalBytes, value.canonicalBytes)
    }

    func testRejectsDuplicateAccountIDsUIDsAndUnknownUserDomains() throws {
        XCTAssertThrowsError(try inventory(accounts: [account(), account(2, uid: 501)]))
        XCTAssertThrowsError(try inventory(accounts: [account(), account(1, uid: 502)]))
        XCTAssertThrowsError(try inventory(services: [daemon(), app(502)]))
        for uid in [uid_t(0), uid_t(UInt32.max)] { XCTAssertThrowsError(try account(uid: uid)) }
        XCTAssertThrowsError(try InstallationAccount(accountID: Data(), ownerUID: 501))
    }

    func testRejectsDuplicateLabelsAndRolesInsideOneDomain() throws {
        XCTAssertThrowsError(try inventory(services: [daemon(), daemon(label: "dev.remozio.other"), app()]))
        XCTAssertThrowsError(try inventory(services: [daemon(), daemon(.transport, uid: 401), app()]))
        // A shared app label is valid across two distinct user domains.
        _ = try inventory(accounts: [account(), account(2, uid: 502)], services: [daemon(), app(), app(502)])
    }

    func testAgentScopeMustUseItsConfiguredUserAndPlist() throws {
        let agent = try InstallationService(role: .guiAgent, kind: .agent, domainUID: 501, executionUID: 501,
            label: "dev.remozio.gui", plistName: "dev.remozio.gui.plist", accountID: id(1))
        _ = try inventory(services: [daemon(), app(), agent])
        for (domain, execution): (uid_t?, uid_t) in [(nil, 501), (0, 0), (501, 502), (UInt32.max, UInt32.max)] {
            XCTAssertThrowsError(try InstallationService(role: .guiAgent, kind: .agent, domainUID: domain, executionUID: execution,
                label: "dev.remozio.gui", plistName: "dev.remozio.gui.plist", accountID: id(1)))
        }
        XCTAssertThrowsError(try InstallationService(role: .guiAgent, kind: .agent, domainUID: 501, executionUID: 501,
            label: "dev.remozio.gui", plistName: nil))
    }

    func testDaemonCredentialsAndRoleKindsCannotImpersonateOwners() throws {
        XCTAssertThrowsError(try daemon(uid: 401))
        XCTAssertThrowsError(try daemon(.transport, uid: 0))
        XCTAssertThrowsError(try daemon(.commandFrontend, uid: 401))
        XCTAssertThrowsError(try inventory(services: [daemon(), daemon(.transport, uid: 501, label: "dev.remozio.transport")]))
        XCTAssertThrowsError(try inventory(services: [app()]))
        XCTAssertThrowsError(try InstallationService(role: .authority, kind: .daemon, domainUID: 501, executionUID: 0,
            label: "dev.remozio.authority", plistName: "dev.remozio.authority.plist"))
    }

    func testRejectsTraversalLabelsAndInvalidBundlePaths() throws {
        for path in ["relative.app", "/", "/Library/../Remozio.app", "/Library//Remozio.app", "/Library/Remozio.app/",
                     "/Library/Remozio", "/Library/\u{0}Remozio.app"] { XCTAssertThrowsError(try inventory(path: path)) }
        for name in ["other.label", "dev.remozio/label", "dev.remozio.\u{0}", "dev.remozio." + String(repeating: "a", count: 256)] {
            XCTAssertThrowsError(try daemon(label: name))
        }
        XCTAssertThrowsError(try InstallationService(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
            label: "dev.remozio.authority", plistName: "../dev.remozio.authority.plist"))
    }

    func testRejectsEmptyAndOversizedInventoriesWithoutTruncation() throws {
        XCTAssertThrowsError(try inventory(accounts: []))
        XCTAssertThrowsError(try inventory(services: []))
        let accounts = try (1...65).map { try account(UInt8($0), uid: uid_t(500 + $0)) }
        XCTAssertThrowsError(try inventory(accounts: accounts))
        XCTAssertThrowsError(try inventory(services: Array(repeating: daemon(), count: 257)))
        XCTAssertThrowsError(try inventory(digest: Data(repeating: 0, count: 31)))
    }

    func testDecodeRejectsUnknownMissingVersionAndReorderedRecords() throws {
        let value = try inventory(accounts: [account(), account(2, uid: 502)], services: [daemon(), app(), app(502)])
        guard case .map(let original) = try DeterministicCBOR.decode(value.canonicalBytes, limits: InstallationInventory.limits),
              case .array(let accounts) = original[6], case .array(let services) = original[7] else { return XCTFail() }
        var changed = original; changed[0] = .unsigned(3)
        var missing = original; missing.removeValue(forKey: 3)
        var unknown = original; unknown[8] = .null
        var reordered = original; reordered[6] = .array(accounts.reversed())
        var serviceOrder = original; serviceOrder[7] = .array(services.reversed())
        for fields in [changed, missing, unknown, reordered, serviceOrder] {
            XCTAssertThrowsError(try InstallationInventory.decode(DeterministicCBOR.encode(.map(fields), limits: InstallationInventory.limits), expectedMacID: id(1)))
        }
        XCTAssertThrowsError(try InstallationInventory.decode(Data(value.canonicalBytes.dropLast()), expectedMacID: id(1)))
        XCTAssertThrowsError(try InstallationInventory.decode(value.canonicalBytes + Data([0]), expectedMacID: id(1)))
    }

    func testDecodeRejectsCrossMacAndOverflowedUID() throws {
        let value = try inventory()
        XCTAssertThrowsError(try InstallationInventory.decode(value.canonicalBytes, expectedMacID: id(9))) {
            XCTAssertEqual($0 as? InstallationInventoryError, .wrongMac)
        }
        guard case .map(var fields) = try DeterministicCBOR.decode(value.canonicalBytes, limits: InstallationInventory.limits),
              case .array(var accounts) = fields[6], case .map(var account) = accounts[0] else { return XCTFail() }
        account[1] = .unsigned(UInt64.max); accounts[0] = .map(account); fields[6] = .array(accounts)
        XCTAssertThrowsError(try InstallationInventory.decode(DeterministicCBOR.encode(.map(fields), limits: InstallationInventory.limits), expectedMacID: id(1)))
    }

    func testFreshReleaseComparisonRejectsChangedCodeAndAbsentRoles() throws {
        let signed = try evidence(), value = try inventory(digest: InstallationInventory.digest(signed))
        try value.compareRelease(signed)
        XCTAssertThrowsError(try value.compareRelease(evidence(appHash: 4)))
        XCTAssertThrowsError(try value.compareRelease(evidence(authorityHash: 4)))
        let missing = try inventory(services: [daemon(), app(), daemon(.transport, uid: 401, label: "dev.remozio.transport")],
                                    digest: InstallationInventory.digest(signed))
        XCTAssertThrowsError(try missing.compareRelease(signed))
        let wrongApp = try inventory(services: [daemon(), app(label: "dev.remozio.other")], digest: InstallationInventory.digest(signed))
        XCTAssertThrowsError(try wrongApp.compareRelease(signed))
    }

    func testIncompleteOrInconsistentSigningEvidenceCannotConstructDigest() throws {
        let signed = try evidence()
        for hashes: [AuthorityCodeRole: Data] in [[:], [.app: Data(repeating: 1, count: 20)],
            [.app: Data(repeating: 1, count: 19), .authority: Data(repeating: 2, count: 20)],
            [.app: Data(repeating: 1, count: 20), .authority: Data(repeating: 3, count: 20)]] {
            XCTAssertThrowsError(try InstallationInventory.digest(.init(manifest: signed.manifest, codeDirectoryHashes: hashes)))
        }
        XCTAssertThrowsError(try InstallationInventory.digest(.init(manifest: signed.manifest,
            codeDirectoryHashes: signed.codeDirectoryHashes, dependencyCodeDirectoryHashes: ["unexpected": Data(repeating: 2, count: 20)])))
    }

    func testDecodeRejectsUnknownNestedRolesKindsAndFields() throws {
        let value = try inventory()
        guard case .map(let original) = try DeterministicCBOR.decode(value.canonicalBytes, limits: InstallationInventory.limits),
              case .array(let services) = original[7], case .map(let service) = services[0] else { return XCTFail() }
        for (key, value): (UInt64, CBORValue?) in [(0, .unsigned(99)), (1, .unsigned(99)), (2, .unsigned(0)),
                                                (3, .unsigned(UInt64.max)), (5, nil), (6, nil), (7, .null)] {
            var changed = service; changed[key] = value
            var entries = services; entries[0] = .map(changed)
            var fields = original; fields[7] = .array(entries)
            XCTAssertThrowsError(try InstallationInventory.decode(DeterministicCBOR.encode(.map(fields), limits: InstallationInventory.limits), expectedMacID: id(1)))
        }
    }

    func testDigestBindsDeclaredDependenciesAndRejectsMissingHashEvidence() throws {
        let base = try evidence(), path = "Contents/Frameworks/vendor-tool"
        let dependency = try ReleaseDependency(owner: .app, kind: .tool, signaturePath: path, executablePath: path,
            identifier: "org.example.vendor", codeDirectoryHash: Data(repeating: 5, count: 20), teamID: nil, build: nil)
        let manifest = try ReleaseManifest(release: "1", build: "1", components: base.manifest.components, dependencies: [dependency])
        let complete = SignedReleaseEvidence(manifest: manifest, codeDirectoryHashes: base.codeDirectoryHashes,
                                            dependencyCodeDirectoryHashes: [path: dependency.codeDirectoryHash])
        XCTAssertNotEqual(try InstallationInventory.digest(complete), try InstallationInventory.digest(base))
        try inventory(digest: InstallationInventory.digest(complete)).compareRelease(complete)
        XCTAssertThrowsError(try InstallationInventory.digest(.init(manifest: manifest, codeDirectoryHashes: base.codeDirectoryHashes)))
        XCTAssertThrowsError(try InstallationInventory.digest(.init(manifest: manifest, codeDirectoryHashes: base.codeDirectoryHashes,
            dependencyCodeDirectoryHashes: [path: Data(repeating: 6, count: 20)])))
    }

    func testAccountScopedDaemonsRetainEveryAuthorityAndTransportInstance() throws {
        let services = try [daemon(), daemon(label: "dev.remozio.authority.two", accountID: id(2)),
            daemon(.transport, uid: 401, label: "dev.remozio.transport.one"),
            daemon(.transport, uid: 402, label: "dev.remozio.transport.two", accountID: id(2)), app(), app(502)]
        let value = try inventory(accounts: [account(), account(2, uid: 502)], services: services)
        let decoded = try InstallationInventory.decode(value.canonicalBytes, expectedMacID: id(1))
        XCTAssertEqual(decoded.services.filter { $0.role == .authority }.map(\.accountID), [id(1), id(2)])
        XCTAssertEqual(decoded.services.filter { $0.role == .transport }.map(\.executionUID), [401, 402])
        XCTAssertEqual(decoded.services.count, 6)
        XCTAssertEqual(decoded.canonicalBytes, try inventory(accounts: value.accounts.reversed(), services: services.reversed()).canonicalBytes)
    }

    func testAccountAssociationCannotBeMissingUnknownOrCrossUser() throws {
        for role: AuthorityCodeRole in [.authority, .transport, .notificationGateway] {
            XCTAssertThrowsError(try InstallationService(role: role, kind: .daemon, domainUID: nil,
                executionUID: role == .authority ? 0 : 401, label: "dev.remozio.service", plistName: "dev.remozio.service.plist"))
        }
        XCTAssertThrowsError(try inventory(services: [daemon(accountID: id(9)), app()]))
        XCTAssertThrowsError(try inventory(accounts: [account(), account(2, uid: 502)],
            services: [daemon(), app(502, accountID: id(1))]))
        XCTAssertThrowsError(try InstallationService(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
            label: "dev.remozio.authority", plistName: "dev.remozio.authority.plist", accountID: Data([1])))
    }

    func testNativeLoaderRejectsOrdinaryUserBeforeReadingAnyPath() throws {
        guard getuid() != 0 else { throw XCTSkip("Ordinary-user refusal") }
        XCTAssertThrowsError(try InstallationInventory.load(path: "/not/read/by/this/test", expectedMacID: id(1))) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
    func testMachineBootstrapRetainsOnlyTheFixedSetupDeclaration() throws {
        let value = try InstallationInventory.machineBootstrap(macID: id(1), installationID: id(2), revision: id(3),
            bundlePath: "/Library/Remozio/Remozio.app", releaseDigest: Data(repeating: 3, count: 32))
        XCTAssertEqual(value.formatVersion, 2)
        XCTAssertTrue(value.accounts.isEmpty)
        XCTAssertEqual(value.services.count, 1)
        XCTAssertEqual(value.services[0].role, .setupController)
        XCTAssertEqual(value.services[0].executionUID, 0)
        XCTAssertNil(value.services[0].accountID)
        XCTAssertEqual(try InstallationInventory.decode(value.canonicalBytes, expectedMacID: id(1)), value)
    }

    func testLegacyFormatCannotDecodeAnAccountlessBootstrapRecord() throws {
        let value = try InstallationInventory.machineBootstrap(macID: id(1), installationID: id(2), revision: id(3),
            bundlePath: "/Library/Remozio/Remozio.app", releaseDigest: Data(repeating: 3, count: 32))
        guard case .map(var fields) = try DeterministicCBOR.decode(value.canonicalBytes, limits: InstallationInventory.limits) else { return XCTFail() }
        fields[0] = .unsigned(1)
        XCTAssertThrowsError(try InstallationInventory.decode(
            DeterministicCBOR.encode(.map(fields), limits: InstallationInventory.limits), expectedMacID: id(1)))
    }

    func testBootstrapRejectsExtraServicesAndAlteredSetupIdentity() throws {
        let setup = try InstallationService(role: .setupController, kind: .daemon, domainUID: nil, executionUID: 0,
            label: AdministrativeSetupConfiguration.serviceName, plistName: AdministrativeSetupConfiguration.plistName)
        let otherName = try InstallationService(role: .setupController, kind: .daemon, domainUID: nil, executionUID: 0,
            label: "dev.remozio.other", plistName: AdministrativeSetupConfiguration.plistName)
        let otherPlist = try InstallationService(role: .setupController, kind: .daemon, domainUID: nil, executionUID: 0,
            label: AdministrativeSetupConfiguration.serviceName, plistName: "dev.remozio.other.plist")
        let tunnel = try InstallationService(role: .tunnelClient, kind: .daemon, domainUID: nil, executionUID: 401,
            label: "dev.remozio.tunnel", plistName: "dev.remozio.tunnel.plist")
        for services in [[], [otherName], [otherPlist], [setup, tunnel]] {
            XCTAssertThrowsError(try InstallationInventory(macID: id(1), installationID: id(2), revision: id(3),
                bundlePath: "/Library/Remozio/Remozio.app", releaseDigest: Data(repeating: 3, count: 32),
                accounts: [], services: services, formatVersion: 2))
        }
    }

    func testConfiguredFormatTwoPreservesLegacyAccountAndServiceScope() throws {
        let legacy = try inventory()
        XCTAssertEqual(legacy.formatVersion, 1)
        let current = try InstallationInventory(macID: legacy.macID, installationID: legacy.installationID,
            revision: legacy.revision, bundlePath: legacy.bundlePath, releaseDigest: legacy.releaseDigest,
            accounts: legacy.accounts, services: legacy.services, formatVersion: 2)
        XCTAssertEqual(current.accounts, legacy.accounts)
        XCTAssertEqual(current.services, legacy.services)
        XCTAssertEqual(try InstallationInventory.decode(legacy.canonicalBytes, expectedMacID: id(1)), legacy)
        XCTAssertEqual(try InstallationInventory.decode(current.canonicalBytes, expectedMacID: id(1)), current)
        XCTAssertThrowsError(try InstallationInventory(macID: id(1), installationID: id(2), revision: id(3),
            bundlePath: legacy.bundlePath, releaseDigest: legacy.releaseDigest,
            accounts: legacy.accounts, services: [app()], formatVersion: 2))
    }

    func testBootstrapReleaseComparisonRequiresItsDeclaredSetupCode() throws {
        let base = try evidence()
        let setup = try ReleaseComponent(role: .setupController, identifier: "dev.remozio.setup-controller", generation: 1,
            relativePath: AdministrativeSetupConfiguration.executablePath, codeDirectoryHash: Data(repeating: 3, count: 20),
            build: "1", teamID: nil, formats: [])
        let manifest = try ReleaseManifest(release: "1", build: "1", components: base.manifest.components + [setup])
        let signed = SignedReleaseEvidence(manifest: manifest,
            codeDirectoryHashes: base.codeDirectoryHashes.merging([.setupController: Data(repeating: 3, count: 20)]) { _, new in new })
        let value = try InstallationInventory.machineBootstrap(macID: id(1), installationID: id(2), revision: id(3),
            bundlePath: "/Library/Remozio/Remozio.app", releaseDigest: InstallationInventory.digest(signed))
        try value.compareRelease(signed)
        XCTAssertThrowsError(try value.compareRelease(base))
    }

}
