import Darwin
import Foundation
import RemozioProtocol
import Security
import XCTest
@testable import RemozioCore

final class ServiceAccountSetupTests: XCTestCase {
    private enum Failure: Error { case interrupted }
    private let form = Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)
    private func fixture() throws -> AccountPreparationFixture {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner setup fixture") }
        return try .init()
    }
    private func owner(_ f: AccountPreparationFixture, _ machine: PreparationIntentStore,
                       _ directory: ServiceAccountDirectoryFixture) throws -> SetupAccountOwner {
        try .init(machine: machine, expectedReleaseDigest: f.release, resume: { _, _ in throw Failure.interrupted },
            accountCodePolicy: f.policy, lookupAccount: { uid in
                guard uid == f.identity.uid else { throw AdministrativeSetupError.wrongAccount }; return f.identity
            }, prepareServices: { machine, account, verify in
                let storage = try ServiceAccountPlanStorage(machine: machine, account: account)
                var candidate: UInt32 = 19999
                _ = try ServiceAccountPreparation.resume(account: account, storage: storage, directory: directory,
                    makePlan: { try ServiceAccountAllocator.plan(account: account, reserved: machine.reservedServiceAccountNumbers(),
                        candidate: { candidate += 1; return candidate }, available: { _ in true }) }, verifyCurrent: verify)
                return try storage.load()
            })
    }
    func testAllocatorSkipsReservationsOwnerAndDirectoryConflicts() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let account = try f.resume(machine, f.begin(machine))
        var candidates: [UInt32] = [0, 80, account.ownerUID, 19999, 60001, 20000, 20001, 20002, 20002, 20003]
        var queried: [UInt32] = []
        let plan = try ServiceAccountAllocator.plan(account: account, reserved: [20000], candidate: { candidates.removeFirst() },
            available: { queried.append($0.number); return $0.number != 20001 })
        XCTAssertEqual(plan.claims.map(\.number), [20002, 20003]); XCTAssertEqual(queried, [20001, 20002, 20003])
        XCTAssertEqual(plan.claims.map(\.role), [.transport, .gateway])
    }
    func testAllocatorBoundsDirectoryQueriesAndPropagatesUnknownResults() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let account = try f.resume(machine, f.begin(machine))
        var count = 0
        XCTAssertThrowsError(try ServiceAccountAllocator.plan(account: account, reserved: [], candidate: { 20000 },
            available: { _ in count += 1; return false })) { XCTAssertEqual($0 as? ServiceAccountProvisioningError, .exhausted) }
        XCTAssertEqual(count, 128)
        XCTAssertThrowsError(try ServiceAccountAllocator.plan(account: account, reserved: [], candidate: { 20000 },
            available: { _ in throw Failure.interrupted })) { XCTAssertTrue($0 is Failure) }
        XCTAssertTrue(try machine.reservedServiceAccountNumbers().isEmpty)
    }
    func testOwnerRequiresCurrentAccountScopeAndRejectsAStalePlanRead() throws {
        let f = try fixture(), machine = try f.open(initialize: true), directory = ServiceAccountDirectoryFixture()
        let prepared = try f.resume(machine, f.begin(machine)), owner = try owner(f, machine, directory)
        defer { try? owner.close() }
        let before = try XCTUnwrap(owner.serviceAccountsProgress(callerUID: getuid()))
        XCTAssertNil(before.planID); XCTAssertFalse(before.complete); XCTAssertTrue(directory.writes.isEmpty)
        let done = try owner.resumeServiceAccounts(callerUID: getuid(), expected: before)
        XCTAssertTrue(done.complete); XCTAssertNotNil(done.planID)
        XCTAssertEqual(try owner.serviceAccountsProgress(callerUID: getuid()), done)
        XCTAssertThrowsError(try owner.resumeServiceAccounts(callerUID: getuid() + 1, expected: done))
        XCTAssertThrowsError(try owner.resumeServiceAccounts(callerUID: getuid(), expected: before)) {
            XCTAssertEqual($0 as? AdministrativeSetupError, .staleProgress)
        }
        XCTAssertEqual(try owner.resumeServiceAccounts(callerUID: getuid(), expected: done), done)
        XCTAssertEqual(directory.writes.count, 4)
        XCTAssertEqual(done.accountID, prepared.accountID)
        XCTAssertTrue(try XCTUnwrap(machine.inventory()).accounts.isEmpty)
    }
    func testProgressDoesNotUpgradeStorageOrClaimUnpreparedAccountsAreReady() throws {
        let f = try fixture(), machine = try f.open(initialize: true), directory = ServiceAccountDirectoryFixture()
        let owner = try owner(f, machine, directory); defer { try? owner.close() }
        XCTAssertNil(try owner.serviceAccountsProgress(callerUID: getuid()))
        _ = try f.begin(machine)
        XCTAssertNil(try owner.serviceAccountsProgress(callerUID: getuid()))
        XCTAssertEqual(try f.sql("PRAGMA user_version"), 4); XCTAssertTrue(directory.writes.isEmpty)
    }
    func testNativeCompositionRefusesOrdinaryUsersBeforeDirectoryAccess() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let account = try f.resume(machine, f.begin(machine))
        XCTAssertThrowsError(try ServiceAccountPreparation.prepare(machine: machine, account: account,
            verifyCurrent: { XCTFail("Root guard must precede all access") })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertEqual(try f.sql("PRAGMA user_version"), 4)
    }
    private final class LocalDriver: SetupClientDriver, @unchecked Sendable {
        let endpoint: AdministrativeSetupXPCEndpoint
        init(_ endpoint: AdministrativeSetupXPCEndpoint) { self.endpoint = endpoint }
        func start(closed: @escaping @Sendable () -> Void) { }
        func close() { endpoint.close() }
        func invoke(_ call: SetupClientCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            switch call {
            case .serviceAccountsHello: endpoint.serviceAccountsHello { reply(.version($0)) }
            case .serviceAccountsProgress: endpoint.serviceAccountsProgress { reply(.progress($0)) }
            case .prepareServiceAccounts(let expected, let authorization):
                do { endpoint.prepareServiceAccounts(try expected.bytes, authorization: authorization) { reply(.progress($0)) } }
                catch { reply(.failed) }
            case .enrollmentHello: endpoint.enrollmentHello { reply(.version($0)) }
            default: reply(.failed)
            }
        }
    }
    private final class Reply<Value>: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: Value?
        func put(_ value: Value) { lock.withLock { stored = value } }
        var value: Value? { lock.withLock { stored } }
    }
    func testVersionThreeChannelAuthorizesOnlyExplicitPreparationAndReturnsScopedCompletion() async throws {
        let f = try fixture(), machine = try f.open(initialize: true), directory = ServiceAccountDirectoryFixture()
        let prepared = try f.resume(machine, f.begin(machine)), owner = try owner(f, machine, directory)
        defer { try? owner.close() }
        var authorizations = 0
        let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() },
            authorize: { _ in authorizations += 1 }, invalidate: {})
        let channel = AdministrativeSetupChannel(driver: LocalDriver(endpoint), serviceAccounts: true)
        try await channel.start()
        let progress = try await channel.serviceAccountsProgress()
        let before = try XCTUnwrap(progress)
        XCTAssertEqual(authorizations, 0); XCTAssertTrue(directory.writes.isEmpty)
        let done = try await channel.prepareServiceAccounts(before, authorization: form)
        XCTAssertEqual(authorizations, 1); XCTAssertEqual(done.accountID, prepared.accountID); XCTAssertTrue(done.complete)
        let read = try await channel.serviceAccountsProgress()
        XCTAssertEqual(read, done); XCTAssertEqual(authorizations, 1)
        XCTAssertNil(try done.bytes.range(of: Data(f.root.path.utf8)))
        await channel.close()
    }
    func testOlderHandshakeCannotInvokeServicePreparation() throws {
        let f = try fixture(), machine = try f.open(initialize: true), directory = ServiceAccountDirectoryFixture()
        let account = try f.resume(machine, f.begin(machine)), owner = try owner(f, machine, directory)
        defer { try? owner.close() }
        let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() },
            authorize: { _ in XCTFail("Old handshake cannot export service authorization") }, invalidate: {})
        let version = Reply<UInt64>(); endpoint.enrollmentHello { version.put($0) }
        XCTAssertEqual(version.value, 2)
        let result = Reply<Data?>(), expected = try SetupServiceAccountProgress(account: account, state: .init(plan: nil, complete: false))
        endpoint.prepareServiceAccounts(try expected.bytes, authorization: form) { result.put($0) }
        XCTAssertNotNil(result.value as Any?); XCTAssertNil(result.value!)
        XCTAssertTrue(directory.writes.isEmpty); XCTAssertTrue(try machine.reservedServiceAccountNumbers().isEmpty)
    }
    func testDeniedAdministratorAuthorizationCannotReserveIDsOrCreateRecords() throws {
        let f = try fixture(), machine = try f.open(initialize: true), directory = ServiceAccountDirectoryFixture()
        let account = try f.resume(machine, f.begin(machine)), owner = try owner(f, machine, directory)
        defer { try? owner.close() }
        let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() },
            authorize: { _ in throw Failure.interrupted }, invalidate: {})
        endpoint.serviceAccountsHello { _ in }
        let result = Reply<Data?>(), expected = try SetupServiceAccountProgress(account: account, state: .init(plan: nil, complete: false))
        endpoint.prepareServiceAccounts(try expected.bytes, authorization: form) { result.put($0) }
        XCTAssertNil(result.value!); XCTAssertTrue(directory.writes.isEmpty)
        XCTAssertEqual(try f.sql("PRAGMA user_version"), 4)
    }
    func testProgressCodecRejectsUnknownFieldsAndImpossibleCompletion() throws {
        let f = try fixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let account = try f.resume(machine, f.begin(machine))
        let expected = try SetupServiceAccountProgress(account: account, state: .init(plan: nil, complete: false))
        XCTAssertEqual(try SetupServiceAccountProgress.decode(expected.bytes), expected)
        let limits = try CBORLimits(maxBytes: 384, maxDepth: 2, maxItems: 24)
        guard case .map(let fields) = try DeterministicCBOR.decode(expected.bytes, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (8, .null), (7, .boolean(true)), (6, .bytes(Data())), (5, .unsigned(0))] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try SetupServiceAccountProgress.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
    }
}
