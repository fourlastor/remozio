import Darwin
import Foundation
import RemozioProtocol
import Security
import XCTest
@testable import RemozioCore

final class RuntimeSetupTests: XCTestCase {
    private enum Interrupted: Error { case injected }
    // These actual SQLite/file fixtures do not prove Root ownership, native accounts, or service registration.
    private final class Fixture {
        let f: AccountPreparationFixture
        let machine: PreparationIntentStore
        let account: AccountPreparationIntent
        let plan: ServiceAccountPlan
        let directory: ProtectedSetupDirectory
        var creations = 0, publications = 0
        init() throws {
            let roles: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway, .commandFrontend, .commandMonitor, .commandChild]
            let policy = try AuthorityCodePolicy(entries: roles.map { role in
                try .init(role: role, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.role-\(role.rawValue)",
                    installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: UInt8(role.rawValue), count: 20), active: true)
            })
            f = try .init(policy: policy); machine = try f.open(initialize: true)
            account = try f.resume(machine, f.begin(machine))
            plan = try .init(account: account, planID: AccountPreparationIntent.randomID(), claims: [
                .init(accountID: account.accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
                .init(accountID: account.accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())])
            try machine.retainServiceAccountPlan(plan); try machine.completeServiceAccountPlan(plan)
            directory = try .init(anchor: f.root.path, relativePath: "runtime", owner: getuid())
        }
        deinit { directory.close(); try? machine.close() }
        var state: RuntimePreparationState { get throws { try machine.runtimePreparation(accountID: account.accountID) } }
        func prepare(_ expected: RuntimePreparationState, verify: @escaping () throws -> Void = {},
                     stage: (RuntimePublicationController.Stage) throws -> Void = { _ in }) throws -> RuntimePreparationState {
            try RuntimePublicationController.prepare(machine: machine, account: account, expected: expected,
                verifyCurrent: verify, verifyServices: { services in XCTAssertEqual(services, self.plan) },
                verifyAuthority: { XCTAssertEqual($0.authorityPublicKey, self.account.authorityPublicKey) },
                restoreMaterial: { services, reference, check in
                    try RuntimeMaterialPreparation.restoreOrCreate(directory: self.directory, owner: getuid(), account: self.account,
                        services: services, expected: reference, verifyCurrent: check, make: {
                            self.creations += 1
                            let now = Date()
                            return try .create(services: services, notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
                        })
                }, publish: { bundle, material, check in
                    try check(); self.publications += 1
                    XCTAssertEqual(bundle.transport.transport.identityPublicKeyInfo, material.transportPublicKeyInfo)
                    XCTAssertEqual(bundle.command.presence.pairing?.transportPublicKey, try material.reference.transportPublicKeyX963)
                    XCTAssertEqual(bundle.frontendClient.serviceName, bundle.command.serviceName)
                }, didStage: stage)
        }
        func owner() throws -> SetupAccountOwner {
            try .init(machine: machine, expectedReleaseDigest: f.release, resume: { _, _ in throw Interrupted.injected },
                accountCodePolicy: f.policy, lookupAccount: { uid in
                    guard uid == self.f.identity.uid else { throw AdministrativeSetupError.wrongAccount }; return self.f.identity
                }, prepareRuntime: { machine, account, expected, accepted, verify in
                    XCTAssertTrue(machine === self.machine); XCTAssertEqual(account, self.account); XCTAssertTrue(accepted)
                    return try withoutActuallyEscaping(verify) { try self.prepare(expected, verify: $0) }
                })
        }
    }
    private func fixture() throws -> Fixture {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner setup fixture") }
        return try .init()
    }
    func testEveryInterruptedStageResumesTheSameIdentityWithoutResettingCompletion() throws {
        let stages: [RuntimePublicationController.Stage] = [.materialRestored, .referenceRetained, .filesPublished, .completed]
        for stop in stages {
            let f = try fixture(), before = try f.state
            XCTAssertThrowsError(try f.prepare(before, stage: { if $0 == stop { throw Interrupted.injected } })) {
                XCTAssertTrue($0 is Interrupted)
            }
            let privateBytes = try Data(contentsOf: URL(fileURLWithPath: f.directory.path + "/runtime-material.cbor"))
            let reference = try RuntimePreparationMaterial.decode(privateBytes).reference
            let done = try f.prepare(f.state)
            XCTAssertTrue(done.configurationPublished); XCTAssertEqual(done.reference, reference); XCTAssertEqual(f.creations, 1)
            let publications = f.publications
            XCTAssertEqual(try f.prepare(done), done); XCTAssertEqual(f.publications, publications)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.directory.path + "/runtime-material.cbor")), privateBytes)
            XCTAssertTrue(try XCTUnwrap(f.machine.inventory()).accounts.isEmpty)
        }
    }
    func testMissingEstablishedMaterialCannotBeRecreated() throws {
        let f = try fixture()
        XCTAssertThrowsError(try f.prepare(f.state, stage: { if $0 == .referenceRetained { throw Interrupted.injected } }))
        try FileManager.default.removeItem(atPath: f.directory.path + "/runtime-material.cbor")
        XCTAssertThrowsError(try f.prepare(f.state)) { XCTAssertEqual($0 as? RuntimePreparationError, .missingMaterial) }
        XCTAssertEqual(f.creations, 1); XCTAssertEqual(f.publications, 0); XCTAssertFalse(try f.state.configurationPublished)
    }
    func testChangedInventoryStopsBeforePublicationAndRetainsRecoveryMaterial() throws {
        let f = try fixture()
        XCTAssertThrowsError(try f.prepare(f.state, stage: { stage in
            if stage == .referenceRetained {
                let old = try XCTUnwrap(f.machine.inventory())
                _ = try f.machine.writeInventory(.init(macID: old.macID, installationID: old.installationID,
                    revision: AccountPreparationIntent.randomID(), bundlePath: old.bundlePath, releaseDigest: old.releaseDigest,
                    accounts: old.accounts, services: old.services, formatVersion: old.formatVersion), expectedRevision: old.revision)
            }
        })) { XCTAssertEqual($0 as? RuntimePreparationError, .changedScope) }
        XCTAssertEqual(f.publications, 0); XCTAssertNotNil(try f.state.reference); XCTAssertFalse(try f.state.configurationPublished)
    }
    func testOwnerRequiresCurrentProgressCallerAndExplicitCustodyConsent() throws {
        let f = try fixture(), owner = try f.owner(); defer { try? owner.close() }
        let before = try XCTUnwrap(owner.runtimeProgress(callerUID: getuid()))
        XCTAssertNil(before.materialID); XCTAssertFalse(before.configurationPublished)
        XCTAssertThrowsError(try owner.resumeRuntime(callerUID: getuid(), expected: before, fileCustodyAccepted: false)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .custodyNotAccepted)
        }
        XCTAssertThrowsError(try owner.resumeRuntime(callerUID: getuid() + 1, expected: before, fileCustodyAccepted: true))
        XCTAssertEqual(f.creations, 0)
        let done = try owner.resumeRuntime(callerUID: getuid(), expected: before, fileCustodyAccepted: true)
        XCTAssertTrue(done.configurationPublished); XCTAssertNotNil(done.materialID)
        XCTAssertThrowsError(try owner.resumeRuntime(callerUID: getuid(), expected: before, fileCustodyAccepted: true)) {
            XCTAssertEqual($0 as? AdministrativeSetupError, .staleProgress)
        }
        XCTAssertEqual(try owner.resumeRuntime(callerUID: getuid(), expected: done, fileCustodyAccepted: true), done)
        XCTAssertEqual(f.creations, 1); XCTAssertEqual(f.publications, 1)
    }
    private final class Driver: SetupClientDriver, @unchecked Sendable {
        let endpoint: AdministrativeSetupXPCEndpoint
        init(_ endpoint: AdministrativeSetupXPCEndpoint) { self.endpoint = endpoint }
        func start(closed: @escaping @Sendable () -> Void) {}
        func close() { endpoint.close() }
        func invoke(_ call: SetupClientCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            switch call {
            case .runtimeHello: endpoint.runtimeHello { reply(.version($0)) }
            case .runtimeProgress: endpoint.runtimeProgress { reply(.progress($0)) }
            case .prepareRuntime(let expected, let accepted, let form):
                do { endpoint.prepareRuntime(try expected.bytes, fileCustodyAccepted: accepted, authorization: form) { reply(.progress($0)) } }
                catch { reply(.failed) }
            default: reply(.failed)
            }
        }
    }
    func testVersionFourChannelReadsWithoutAuthorizationAndPreparesOnlyOnExplicitCall() async throws {
        let f = try fixture(), owner = try f.owner(); defer { try? owner.close() }
        var authorizations = 0
        let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in authorizations += 1 }, invalidate: {})
        let channel = AdministrativeSetupChannel(driver: Driver(endpoint), runtime: true)
        try await channel.start()
        let read = try await channel.runtimeProgress(), before = try XCTUnwrap(read)
        XCTAssertEqual(authorizations, 0); XCTAssertEqual(f.creations, 0)
        let done = try await channel.prepareRuntime(before, fileCustodyAccepted: true,
            authorization: Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size))
        XCTAssertTrue(done.configurationPublished); XCTAssertEqual(authorizations, 1)
        let after = try await channel.runtimeProgress(); XCTAssertEqual(after, done); XCTAssertEqual(authorizations, 1)
        let bytes = try done.bytes
        XCTAssertNil(bytes.range(of: Data(f.directory.path.utf8)))
        XCTAssertNil(bytes.range(of: try Data(contentsOf: URL(fileURLWithPath: f.directory.path + "/runtime-material.cbor"))))
        await channel.close()
    }
    func testOldHandshakeAndDeniedAdministratorCannotCreateMaterial() throws {
        for version in [1, 2, 3, 4] {
            let f = try fixture(), owner = try f.owner(); defer { try? owner.close() }
            let before = try XCTUnwrap(owner.runtimeProgress(callerUID: getuid()))
            var authorizations = 0
            let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in
                authorizations += 1; throw Interrupted.injected
            }, invalidate: {})
            switch version {
            case 1: endpoint.hello { _ in }
            case 2: endpoint.enrollmentHello { _ in }
            case 3: endpoint.serviceAccountsHello { _ in }
            default: endpoint.runtimeHello { _ in }
            }
            endpoint.prepareRuntime(try before.bytes, fileCustodyAccepted: true,
                authorization: Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)) { XCTAssertNil($0) }
            XCTAssertEqual(authorizations, version == 4 ? 1 : 0)
            XCTAssertEqual(f.creations, 0); XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 5)
        }
    }
    func testProgressCodecRejectsUnknownVersionsFieldsAndImpossibleCompletion() throws {
        let f = try fixture(), owner = try f.owner(); defer { try? owner.close() }
        let before = try XCTUnwrap(owner.runtimeProgress(callerUID: getuid()))
        XCTAssertEqual(try SetupRuntimeProgress.decode(before.bytes), before)
        let limits = try CBORLimits(maxBytes: 384, maxDepth: 2, maxItems: 28)
        guard case .map(let fields) = try DeterministicCBOR.decode(before.bytes, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (9, .null), (8, .boolean(true)), (6, .bytes(Data())), (5, .unsigned(0))] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try SetupRuntimeProgress.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
    }
    func testNativeControllerRefusesOrdinaryUsersBeforeAnyProtectedWork() throws {
        let f = try fixture()
        XCTAssertThrowsError(try RuntimePublicationController.prepare(machine: f.machine, account: f.account, expected: f.state,
            fileCustodyAccepted: true, verifyCurrent: { XCTFail("Root check must precede operations") })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
