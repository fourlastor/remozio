import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RuntimeActivationPlanTests: XCTestCase {
    private func fixture() throws -> RuntimeActivationFixture {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner activation fixture") }
        return try .init()
    }
    func testPlanRestoresThePublishedIdentityAndExactJobBytesWithoutSecrets() throws {
        let f = try fixture(), p = f.plan, bytes = try p.encoded, decoded = try RuntimeActivationPlan.decode(bytes)
        XCTAssertEqual(try decoded.encoded, bytes)
        XCTAssertEqual(decoded.reference, try f.material.reference)
        XCTAssertEqual(decoded.authorityJob.bytes, p.authorityJob.bytes); XCTAssertEqual(decoded.transportJob.bytes, p.transportJob.bytes)
        XCTAssertEqual(decoded.host.jobPlacement, .systemAccount)
        XCTAssertEqual(decoded.host.command.presence.wake.registration, f.material.gateway)
        XCTAssertEqual(decoded.transport.transport.identityPublicKeyInfo, f.material.transportPublicKeyInfo)
        XCTAssertNil(bytes.range(of: f.material.transportIdentity))
        XCTAssertEqual(String(reflecting: decoded), "RuntimeActivationPlan(redacted)")
        XCTAssertNoThrow(try decoded.validate(account: f.account, reference: f.material.reference))
    }
    func testEnrollmentAddsOnlyTheExactAccountAndJobsAndIsIdempotent() throws {
        let f = try fixture(), original = try XCTUnwrap(f.machine.inventory())
        let added = try f.plan.enrolledInventory(original)
        XCTAssertEqual(added.accounts, [try .init(accountID: f.account.accountID, ownerUID: f.account.ownerUID)])
        XCTAssertEqual(added.services.count, original.services.count + 2)
        for declaration in original.services { XCTAssertTrue(added.services.contains(declaration)) }
        XCTAssertTrue(added.services.contains(f.plan.authorityJob.declaration)); XCTAssertTrue(added.services.contains(f.plan.transportJob.declaration))
        XCTAssertEqual(try f.plan.enrolledInventory(added), added)
        XCTAssertTrue(try XCTUnwrap(f.machine.inventory()).accounts.isEmpty)
        XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 6)
    }
    func testUnrelatedAccountDeclarationsSurviveAndConflictingJobsCannotBeAdopted() throws {
        let f = try fixture(), original = try XCTUnwrap(f.machine.inventory())
        let otherID = Data(repeating: 99, count: 16)
        let other = try InstallationAccount(accountID: otherID, ownerUID: f.account.ownerUID + 1)
        let otherJob = try InstallationService(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
            label: "dev.remozio.other.authority", plistName: "dev.remozio.other.authority.plist", accountID: otherID)
        func inventory(_ accounts: [InstallationAccount], _ services: [InstallationService]) throws -> InstallationInventory {
            try .init(macID: original.macID, installationID: original.installationID, revision: original.revision,
                bundlePath: original.bundlePath, releaseDigest: original.releaseDigest, accounts: accounts, services: services, formatVersion: 2)
        }
        let withOther = try inventory([other], original.services + [otherJob]), added = try f.plan.enrolledInventory(withOther)
        XCTAssertTrue(added.accounts.contains(other)); XCTAssertTrue(added.services.contains(otherJob))
        let mine = try InstallationAccount(accountID: f.account.accountID, ownerUID: f.account.ownerUID)
        let conflicting = try InstallationService(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
            label: "dev.remozio.wrong.authority", plistName: "dev.remozio.wrong.authority.plist", accountID: mine.accountID)
        XCTAssertThrowsError(try f.plan.enrolledInventory(inventory([mine], original.services + [conflicting]))) {
            XCTAssertEqual($0 as? RuntimeActivationError, .conflictingPlan)
        }
        let wrongOwner = try InstallationAccount(accountID: otherID, ownerUID: f.account.ownerUID)
        XCTAssertThrowsError(try f.plan.enrolledInventory(inventory([wrongOwner], original.services + [otherJob])))
    }
    func testUnpublishedRuntimeCannotCreateAnActivationPlan() throws {
        let f = try fixture(), initial = try XCTUnwrap(f.machine.initialization(accountID: f.account.accountID))
        for state in [RuntimePreparationState(reference: nil, configurationPublished: false),
                      .init(reference: try f.material.reference, configurationPublished: false)] {
            XCTAssertThrowsError(try RuntimeActivationPlan(account: f.account, initialization: initial,
                runtime: state, inventory: XCTUnwrap(f.machine.inventory()))) { XCTAssertEqual($0 as? RuntimeActivationError, .incomplete) }
        }
    }
    func testChangedScopeUnknownFieldsAndWrongHostKindCannotDecode() throws {
        let f = try fixture(), limits = try RuntimeActivationPlan.limits
        guard case .map(let fields) = try DeterministicCBOR.decode(f.plan.encoded, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (5, .null), (2, .text("relative.app")), (4, .bytes(Data()))] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try RuntimeActivationPlan.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        let p = f.plan.host
        let legacy = try InstalledAuthorityCommandConfiguration(machineDirectory: p.machineDirectory, installationID: p.installationID,
            releaseDigest: p.releaseDigest, codePolicy: p.codePolicy, command: p.command, label: p.label, plistName: p.plistName)
        var changed = fields; changed[3] = .bytes(legacy.canonicalBytes)
        XCTAssertThrowsError(try RuntimeActivationPlan.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
    }
}
