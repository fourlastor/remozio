import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RuntimeServiceActivityPreparationTests: XCTestCase {
    private struct Interrupted: Error {}
    // Actual owned files and SQLite with injected directory records and artifact publication.
    // These fixtures do not prove Root ownership transfer or dedicated service account isolation.
    private final class Fixture {
        let f: AccountPreparationFixture
        let machine: PreparationIntentStore
        let account: AccountPreparationIntent
        let services: ServiceAccountPlan
        let privateDirectory: ProtectedSetupDirectory
        let shared: ProtectedSetupDirectory
        let auditRelease: SignedReleaseEvidence?
        var lastAuditVersions: Set<UInt64>?
        var auditSelectionOverride: ((RuntimeMaterialReference?) throws -> UInt64?)?
        var serviceValid = true
        var directServiceCheck: (() throws -> Void)?
        var materialCreations = 0, publications = 0, activityChecks = 0
        init(audited: Bool = false) throws {
            let roles: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway, .setupController, .commandFrontend, .commandMonitor, .commandChild]
            let policy = try AuthorityCodePolicy(entries: roles.map {
                try .init(role: $0, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.role-\($0.rawValue)", installedGeneration: 1,
                    minimumGeneration: 1, codeDirectoryHash: Data(repeating: UInt8($0.rawValue), count: 20), active: true)
            })
            auditRelease = audited ? try NativeHostReleaseFixture.make(policy: policy, phoneAudit: true, auditDelivery: true) : nil
            f = try .init(policy: policy, releaseDigest: auditRelease.map { try InstallationInventory.digest($0) })
            // Only this new fixture parent is public. Its machine and runtime directories stay private.
            guard chmod(f.root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            machine = try f.open(initialize: true)
            account = try f.resume(machine, f.begin(machine))
            services = try .init(account: account, planID: AccountPreparationIntent.randomID(), claims: [
                .init(accountID: account.accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
                .init(accountID: account.accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())])
            try machine.retainServiceAccountPlan(services); try machine.completeServiceAccountPlan(services)
            privateDirectory = try .init(anchor: f.root.path, relativePath: "Runtime", owner: getuid())
            shared = try .init(anchor: f.root.path, relativePath: "Service", owner: getuid(), visibility: .sharedMetadata)
        }
        deinit { privateDirectory.close(); shared.close(); try? machine.close() }
        var state: RuntimePreparationState { get throws { try machine.runtimePreparation(accountID: account.accountID) } }
        var privatePath: String { privateDirectory.path + "/" + AdministrativeSetupPublication.File.runtimeRecord.name }
        func path(_ role: ServiceAccountRole) -> String { shared.path + "/" + ServiceReleaseActivityBarrier.fileName(role) }
        func provision(expected: [ServiceAccountRole: PreparationFileIdentity]? = nil) throws -> ServiceReleaseActivityFileProvisioning.Result {
            try ServiceReleaseActivityFileProvisioning.prepare(parent: shared, owner: getuid(), groups: [.transport: getgid(), .gateway: getgid()],
                mode: expected == nil ? .createIfAbsent : .requireExisting, expected: expected, verifyCurrent: { try self.verifyServices(self.services) })
        }
        func verifyServices(_ current: ServiceAccountPlan) throws {
            guard serviceValid, current == services else { throw RuntimePreparationError.changedScope }
        }
        func validate(_ reference: ServiceReleaseActivityReference) throws {
            activityChecks += 1; try reference.validate(services: services); try verifyServices(services)
            _ = try provision(expected: reference.identities)
        }
        func auditSelection(_ reference: RuntimeMaterialReference?) throws -> UInt64? {
            if let auditSelectionOverride { return try auditSelectionOverride(reference) }
            guard let auditRelease else { return nil }
            return try RuntimeAuditDeliverySupport.selectedVersion(reference: reference, release: auditRelease, policy: account.initialAuthority.codePolicy)
        }
        func restore(_ reference: RuntimeMaterialReference?, _ verify: () throws -> Void) throws -> RuntimePreparationMaterial {
            try RuntimeMaterialPreparation.restoreOrCreate(directory: privateDirectory, owner: getuid(), account: account,
                services: services, expected: reference, selectAuditDelivery: auditSelection, verifyCurrent: verify, verifyMaterial: { material in
                    guard let activity = material.serviceActivity else { throw RuntimePreparationError.conflictingMaterial }
                    try self.validate(activity)
                }, make: { auditDeliveryVersion in
                    let files = try self.provision(), activity = try ServiceReleaseActivityReference(services: self.services, identities: files.identities)
                    let now = Date(); self.materialCreations += 1
                    return try .create(services: self.services, notValidBefore: now.addingTimeInterval(-60),
                        notValidAfter: now.addingTimeInterval(600), serviceActivity: activity, auditDeliveryVersion: auditDeliveryVersion)
                })
        }
        func prepare(stage: (RuntimePublicationController.Stage) throws -> Void = { _ in }) throws -> RuntimePreparationState {
            try RuntimePublicationController.prepare(machine: machine, account: account, expected: state,
                verifyCurrent: {}, verifyServices: { services in
                    try self.directServiceCheck?(); try self.verifyServices(services)
                }, verifyAuthority: { XCTAssertEqual($0.authorityPublicKey, self.account.authorityPublicKey) },
                restoreMaterial: { try self.restore($1, $2) }, verifyActivity: validate,
                publish: { bundle, material, verify in
                    try verify(); try self.validate(XCTUnwrap(material.serviceActivity))
                    if self.auditRelease != nil {
                        _ = try AdministrativeSetupPublication.publish(bundle.command.canonicalBytes, file: .commandConfiguration,
                            directory: self.privateDirectory, owner: getuid(), verify: verify)
                    }
                    self.lastAuditVersions = bundle.command.presence.wake.request.service.auditVersions
                    self.publications += 1
                }, didStage: stage)
        }
        func reader(_ role: ServiceAccountRole, reference: ServiceReleaseActivityReference) throws -> ServiceReleaseActivityToken {
            let barrier = try ServiceReleaseActivityBarrier(directory: .init(anchor: f.root.path, relativeDirectory: "Service", owner: getuid()),
                role: role, owner: getuid(), group: getgid(), reader: getuid(), expected: reference.identity(for: role), exclusiveAllowed: false)
            return try barrier.acquireShared()
        }
        func replace(_ role: ServiceAccountRole) throws {
            let file = path(role); guard rename(file, file + ".original") == 0 else { throw JournalLeaseError.system(errno) }
            let replacement = open(file, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            guard replacement >= 0 else { throw JournalLeaseError.system(errno) }; defer { _ = close(replacement) }
            guard fchown(replacement, getuid(), getgid()) == 0, fchmod(replacement, 0o440) == 0 else { throw JournalLeaseError.system(errno) }
        }
    }
    private func fixture(audited: Bool = false) throws -> Fixture {
        guard getuid() > 0, getuid() == geteuid(), getgid() > 0, getgid() != 80 else { throw XCTSkip("Ordinary-owned service file fixture") }
        return try .init(audited: audited)
    }
    func testAuditedPublicationAndEachInterruptedStageKeepOneMaterialAndThePublishedConfiguration() throws {
        for stop in [RuntimePublicationController.Stage.materialRestored, .referenceRetained, .filesPublished, .completed] {
            let f = try fixture(audited: true)
            XCTAssertThrowsError(try f.prepare { if $0 == stop { throw Interrupted() } }) { XCTAssertTrue($0 is Interrupted) }
            let before = try Data(contentsOf: URL(fileURLWithPath: f.privatePath))
            let result = try f.prepare()
            XCTAssertTrue(result.configurationPublished); XCTAssertEqual(result.reference?.auditDeliveryVersion, 1)
            XCTAssertEqual(f.materialCreations, 1); XCTAssertEqual(f.lastAuditVersions, [1])
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.privatePath)), before)
            let bytes = try Data(contentsOf: URL(fileURLWithPath: f.privateDirectory.path + "/" + AdministrativeSetupPublication.File.commandConfiguration.name))
            XCTAssertEqual(try AuthorityCommandStartupConfiguration.decode(bytes).presence.wake.request.service.auditVersions, [1])
            XCTAssertTrue(try XCTUnwrap(f.machine.inventory()).accounts.isEmpty)
        }
    }
    func testUnreferencedLegacyNativeMaterialDoesNotBecomeAuditedDuringRecovery() throws {
        let f = try fixture(audited: true), now = Date()
        let activity = try ServiceReleaseActivityReference(services: f.services, identities: f.provision().identities)
        let legacy = try RuntimePreparationMaterial.create(services: f.services, notValidBefore: now.addingTimeInterval(-60),
            notValidAfter: now.addingTimeInterval(600), serviceActivity: activity)
        _ = try RuntimeMaterialPreparation.restoreOrCreate(directory: f.privateDirectory, owner: getuid(), account: f.account,
            services: f.services, expected: nil, verifyCurrent: {}, make: { legacy })
        let before = try Data(contentsOf: URL(fileURLWithPath: f.privatePath)); XCTAssertNil(try f.state.reference)
        let result = try f.prepare()
        XCTAssertTrue(result.configurationPublished); XCTAssertNil(result.reference?.auditDeliveryVersion)
        XCTAssertEqual(result.reference?.formatVersion, 2); XCTAssertEqual(f.lastAuditVersions, [])
        XCTAssertEqual(f.materialCreations, 0); XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.privatePath)), before)
    }
    func testUnreferencedAuditedMaterialRecoversWithoutASecondFreshSelectionOrKey() throws {
        let f = try fixture(audited: true), original = try f.restore(nil, {})
        let before = try Data(contentsOf: URL(fileURLWithPath: f.privatePath)); XCTAssertNil(try f.state.reference)
        f.auditSelectionOverride = { [weak f] reference in
            let f = try XCTUnwrap(f)
            let reference = try XCTUnwrap(reference, "Recovery must not select fresh material")
            return try RuntimeAuditDeliverySupport.selectedVersion(reference: reference, release: XCTUnwrap(f.auditRelease),
                policy: f.account.initialAuthority.codePolicy)
        }
        let result = try f.prepare()
        XCTAssertEqual(result.reference, try original.reference); XCTAssertEqual(result.reference?.auditDeliveryVersion, 1)
        XCTAssertEqual(f.materialCreations, 1); XCTAssertEqual(f.lastAuditVersions, [1])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.privatePath)), before)
    }
    func testAuditSelectionRefusalCreatesNoMaterialOrRoleFilesAndDoesNotRetainAReference() throws {
        let f = try fixture(audited: true)
        f.auditSelectionOverride = { _ in throw Interrupted() }
        XCTAssertThrowsError(try f.prepare()) { XCTAssertTrue($0 is Interrupted) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.privatePath))
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: f.shared.path).isEmpty)
        XCTAssertEqual(f.materialCreations, 0); XCTAssertEqual(f.publications, 0); XCTAssertNil(try f.state.reference)
    }
    func testRefusedRetainedAuditSelectionPreservesTheExistingPrivateMaterialAndKeys() throws {
        let f = try fixture(audited: true), original = try f.restore(nil, {})
        let before = try Data(contentsOf: URL(fileURLWithPath: f.privatePath))
        f.auditSelectionOverride = { _ in throw Interrupted() }
        XCTAssertThrowsError(try f.prepare()) { XCTAssertTrue($0 is Interrupted) }
        XCTAssertEqual(f.materialCreations, 1); XCTAssertEqual(f.publications, 0)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.privatePath)), before)
        XCTAssertEqual(try RuntimePreparationMaterial.decode(before).reference, try original.reference)
    }
    func testEveryRetentionStageRecoversTheSameActualFilesKeysAndDatabaseReference() throws {
        for stop in [RuntimePublicationController.Stage.materialRestored, .referenceRetained, .filesPublished, .completed] {
            let f = try fixture()
            XCTAssertThrowsError(try f.prepare { if $0 == stop { throw Interrupted() } }) { XCTAssertTrue($0 is Interrupted) }
            let privateBytes = try Data(contentsOf: URL(fileURLWithPath: f.privatePath)), material = try RuntimePreparationMaterial.decode(privateBytes)
            let activity = try XCTUnwrap(material.serviceActivity), result = try f.prepare()
            XCTAssertTrue(result.configurationPublished); XCTAssertEqual(result.reference, try material.reference)
            XCTAssertEqual(result.reference?.serviceActivity, activity); XCTAssertEqual(f.materialCreations, 1)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.privatePath)), privateBytes)
            XCTAssertEqual(try f.provision(expected: activity.identities).identities, activity.identities)
            XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: f.shared.path)),
                Set(ServiceAccountPlan.roles.map(ServiceReleaseActivityBarrier.fileName)))
            XCTAssertTrue(try XCTUnwrap(f.machine.inventory()).accounts.isEmpty)
        }
    }
    func testFinalRetentionRejectsAFileReplacedAfterPrivateMaterialRecovery() throws {
        let f = try fixture()
        XCTAssertThrowsError(try f.prepare { if $0 == .materialRestored { try f.replace(.transport) } }) {
            XCTAssertEqual($0 as? JournalLeaseError, .identityChanged)
        }
        XCTAssertNil(try f.state.reference); XCTAssertEqual(f.publications, 0); XCTAssertEqual(f.materialCreations, 1)
        XCTAssertThrowsError(try f.prepare()); XCTAssertEqual(f.materialCreations, 1)
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.path(.transport) + ".original"))
    }
    func testFileValidationFollowsTheFinalServiceAccountCheckBeforeRetention() throws {
        let f = try fixture()
        var finalChecks = 0
        XCTAssertThrowsError(try f.prepare { if $0 == .materialRestored {
            f.directServiceCheck = {
                finalChecks += 1
                if finalChecks == 2 { try f.replace(.transport) }
            }
        } }) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertNil(try f.state.reference, "Reject the replaced file before retaining its identity")
        XCTAssertEqual(f.publications, 0); XCTAssertEqual(f.materialCreations, 1)
    }
    func testAccountLossAtTheFinalBoundaryCannotRetainTheReference() throws {
        let f = try fixture()
        XCTAssertThrowsError(try f.prepare { if $0 == .materialRestored { f.serviceValid = false } }) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
        XCTAssertNil(try f.state.reference); XCTAssertEqual(f.publications, 0)
        f.serviceValid = true; XCTAssertTrue(try f.prepare().configurationPublished); XCTAssertEqual(f.materialCreations, 1)
    }
    func testKnownLostReplyRecoveryAndCompletedRetryWorkWhileRealReadersHoldBothRoles() throws {
        let f = try fixture()
        XCTAssertThrowsError(try f.prepare { if $0 == .materialRestored { throw Interrupted() } })
        let material = try RuntimePreparationMaterial.decode(Data(contentsOf: URL(fileURLWithPath: f.privatePath)))
        let activity = try XCTUnwrap(material.serviceActivity), transport = try f.reader(.transport, reference: activity)
        let gateway = try f.reader(.gateway, reference: activity); defer { transport.close(); gateway.close() }
        XCTAssertThrowsError(try f.provision()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        let result = try f.prepare(); XCTAssertTrue(result.configurationPublished); XCTAssertEqual(result.reference, try material.reference)
        let publications = f.publications; XCTAssertEqual(try f.prepare(), result); XCTAssertEqual(f.publications, publications)
        try transport.validate(); try gateway.validate(); XCTAssertEqual(f.materialCreations, 1)
    }
    func testUnknownBusyFilesCannotBeAdoptedToCreateNewMaterial() throws {
        let f = try fixture(), activity = try ServiceReleaseActivityReference(services: f.services, identities: f.provision().identities)
        let reader = try f.reader(.transport, reference: activity)
        XCTAssertThrowsError(try f.prepare()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        XCTAssertNil(try f.state.reference); XCTAssertEqual(f.materialCreations, 0); XCTAssertFalse(FileManager.default.fileExists(atPath: f.privatePath))
        reader.close(); XCTAssertTrue(try f.prepare().configurationPublished); XCTAssertEqual(f.materialCreations, 1)
    }
    func testMissingRetainedFilesNeverInvokeCreationOrResetThePendingReference() throws {
        let f = try fixture()
        XCTAssertThrowsError(try f.prepare { if $0 == .referenceRetained { throw Interrupted() } })
        let before = try f.state.reference
        XCTAssertEqual(rename(f.path(.gateway), f.path(.gateway) + ".original"), 0)
        XCTAssertThrowsError(try f.prepare())
        XCTAssertEqual(try f.state.reference, before); XCTAssertFalse(try f.state.configurationPublished)
        XCTAssertEqual(f.materialCreations, 1); XCTAssertEqual(f.publications, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.path(.gateway)))
    }
    func testChangedFileOrAccountAfterArtifactPublicationCannotMarkCompletion() throws {
        for replace in [false, true] {
            let f = try fixture()
            XCTAssertThrowsError(try f.prepare { if $0 == .filesPublished {
                if replace { try f.replace(.gateway) } else { f.serviceValid = false }
            } })
            XCTAssertNotNil(try f.state.reference); XCTAssertFalse(try f.state.configurationPublished)
            XCTAssertEqual(f.materialCreations, 1)
            if !replace { f.serviceValid = true; XCTAssertTrue(try f.prepare().configurationPublished); XCTAssertEqual(f.materialCreations, 1) }
        }
    }
    func testLegacyMaterialIsNotRekeyedOrSilentlyUpgraded() throws {
        let f = try fixture(), now = Date()
        let legacy = try RuntimePreparationMaterial.create(services: f.services, notValidBefore: now.addingTimeInterval(-60),
            notValidAfter: now.addingTimeInterval(600))
        _ = try RuntimeMaterialPreparation.restoreOrCreate(directory: f.privateDirectory, owner: getuid(), account: f.account,
            services: f.services, expected: nil, verifyCurrent: {}, make: { legacy })
        let before = try Data(contentsOf: URL(fileURLWithPath: f.privatePath))
        XCTAssertThrowsError(try f.prepare()) { XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial) }
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.privatePath)), before)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: f.shared.path).isEmpty)
        XCTAssertNil(try f.state.reference); XCTAssertEqual(f.materialCreations, 0)
    }
    func testExtendedMaterialRequiresAnExplicitActivityValidatorBeforeDatabaseRetention() throws {
        let f = try fixture(), material = try f.restore(nil, {})
        XCTAssertThrowsError(try RuntimePublicationController.prepare(machine: f.machine, account: f.account, expected: f.state,
            verifyCurrent: {}, verifyServices: f.verifyServices, verifyAuthority: { _ in }, restoreMaterial: { _, _, _ in material },
            publish: { _, _, _ in XCTFail("No artifact publication before activity validation") })) {
            XCTAssertEqual($0 as? RuntimePreparationError, .incomplete)
        }
        XCTAssertNil(try f.state.reference); XCTAssertEqual(f.publications, 0)
    }
    func testNativeEntryPointsRefuseTheOrdinaryCallerBeforeAnyActivityFileAccess() throws {
        let f = try fixture(), activity = try ServiceReleaseActivityReference(services: f.services, identities: f.provision().identities)
        XCTAssertThrowsError(try RuntimeMaterialPreparation.prepareFileIdentity(account: f.account, services: f.services,
            expected: nil, fileCustodyAccepted: true, serviceActivityEnabled: true,
            selectAuditDelivery: { _ in XCTFail("Root admission must precede audit selection"); return 1 },
            verifyCurrent: { XCTFail("The Root guard must precede scope access") })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertThrowsError(try RuntimeMaterialPreparation.validateServiceActivity(account: f.account, activity: activity,
            verifyCurrent: { XCTFail("The Root guard must precede scope access") })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertThrowsError(try RuntimePublicationController.prepare(machine: f.machine, account: f.account, expected: f.state,
            fileCustodyAccepted: true, serviceActivityEnabled: true,
            selectAuditDelivery: { _ in XCTFail("Root admission must precede audit selection"); return 1 },
            verifyCurrent: { XCTFail("The Root guard must precede scope access") })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
    }
}
