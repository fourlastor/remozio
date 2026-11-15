import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class SetupRetainedCallerBindingTests: XCTestCase, @unchecked Sendable {
    private typealias Binding = SetupRetainedCallerBinding
    private typealias Fixture = RetainedMaterialWriterFixture

    private func values(_ f: Fixture) throws -> (Binding.State, MachineUpdateRetainedSetupInitialRuntimeEntry, XPCPeerCredentials, XPCPeerPolicy) {
        let machine = try f.machine(), state = try machine.retainedSetupCallerState(candidate: f.candidate)
        let entry = try machine.retainedSetupInitialRuntimeEntry(owner: f.owner, candidate: f.candidate)
        let member = try XCTUnwrap(state.source.actual.inventory.accounts.first)
        let (_, host) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(runtime: entry.runtime, accountID: member.accountID)
        let app = try XCTUnwrap(host.codePolicy.entries.first { $0.role == .app && $0.active })
        let peer = XPCPeerCredentials(processID: getpid(), userID: member.ownerUID, auditSessionID: 1)
        let accepted = try XPCPeerPolicy(teamID: app.teamID, componentIdentifier: app.identifier,
            approvedCodeDirectoryHashes: [app.codeDirectoryHash], expectedUserID: peer.userID)
        return (state, entry, peer, accepted)
    }
    private func identity(_ state: Binding.State, _ uid: UInt32) throws -> LocalAccountIdentity {
        let account = try XCTUnwrap(state.source.preparations.first { $0.ownerUID == uid })
        return .init(uid: uid, primaryGroupID: getgid(), directoryID: account.directoryID)
    }
    private func resolve(_ state: Binding.State, _ entry: MachineUpdateRetainedSetupInitialRuntimeEntry,
        _ peer: XPCPeerCredentials, _ accepted: XPCPeerPolicy, incarnation: UUID,
        lookup: ((UInt32) throws -> LocalAccountIdentity)? = nil) throws -> Binding {
        try .resolve(state: state, peer: peer, incarnation: incarnation, accepted: accepted, entry: entry,
            lookup: lookup ?? { try self.identity(state, $0) })
    }
    private func replacing(_ state: Binding.State, runtimes: [Binding.Runtime]) -> Binding.State {
        .init(source: state.source, runtimes: runtimes, sharedImport: state.sharedImport)
    }

    func testProtectedStateSelectsDistinctAuthorityAndRetainedTargetWithoutWrites() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            var commits = 0; try f.reopen { commits += 1 }
            let (state, entry, peer, accepted) = try values(f), incarnation = UUID()
            let binding = try resolve(state, entry, peer, accepted, incarnation: incarnation)
            XCTAssertEqual(binding.targetOwner, f.owner)
            XCTAssertNotEqual(binding.authorityOwner.uid, binding.targetOwner.uid)
            XCTAssertNotEqual(binding.authorityAccountID, entry.runtime.preparation.accountID)
            XCTAssertFalse(try XCTUnwrap(entry.runtime.setup.account).inInventory)
            XCTAssertNil(entry.runtime.state.reference)
            let (_, host) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(
                runtime: entry.runtime, accountID: binding.authorityAccountID)
            XCTAssertEqual(binding.publishedAuthorityPolicy, host.codePolicy)
            let historical = try entry.runtime.preparation.initialAuthority.codePolicy
            XCTAssertNotEqual(binding.publishedAuthorityPolicy, historical)
            XCTAssertNotEqual(binding.publishedAuthorityPolicy.entries.map(\.minimumGeneration),
                historical.entries.map(\.minimumGeneration))
            try binding.requireSame(as: resolve(state, entry, peer, accepted, incarnation: incarnation))
            XCTAssertEqual(binding.description, "SetupRetainedCallerBinding(redacted)")
            XCTAssertEqual(binding.debugDescription, binding.description)
            XCTAssertEqual(commits, 0)
        }
    }

    func testForgedPeerPolicyRecycledUIDAndChangedTargetDirectoryRefuse() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let (state, entry, peer, accepted) = try values(f), incarnation = UUID()
            for uid in [UInt32(0), UInt32.max, f.owner.uid, peer.userID &+ 9876] {
                let forged = XPCPeerCredentials(processID: peer.processID, userID: uid, auditSessionID: peer.auditSessionID)
                XCTAssertThrowsError(try resolve(state, entry, forged, accepted, incarnation: incarnation))
            }
            for changed in [peer.userID, f.owner.uid] {
                XCTAssertThrowsError(try resolve(state, entry, peer, accepted, incarnation: incarnation, lookup: { uid in
                    let actual = try self.identity(state, uid)
                    return uid == changed ? .init(uid: uid, primaryGroupID: actual.primaryGroupID, directoryID: UUID()) : actual
                })) { XCTAssertEqual($0 as? LocalAccountLookupError, .ownershipChanged) }
            }
            let app = try XCTUnwrap(entry.runtime.preparation.initialAuthority.codePolicy.entries.first { $0.role == .app })
            let wrongHash = try XPCPeerPolicy(teamID: app.teamID, componentIdentifier: app.identifier,
                approvedCodeDirectoryHashes: [Data(repeating: 219, count: 20)], expectedUserID: peer.userID)
            XCTAssertThrowsError(try resolve(state, entry, peer, wrongHash, incarnation: incarnation)) {
                if case XPCPeerPolicyError.wrongPeer = $0 {} else { XCTFail("Unexpected failure: \($0)") }
            }
            let member = try XCTUnwrap(state.source.actual.inventory.accounts.first { $0.ownerUID == peer.userID })
            let (_, currentHost) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(
                runtime: entry.runtime, accountID: member.accountID)
            let currentApp = try XCTUnwrap(currentHost.codePolicy.entries.first { $0.role == .app && $0.active })
            let wrongSession = try XPCPeerPolicy(teamID: currentApp.teamID, componentIdentifier: currentApp.identifier,
                approvedCodeDirectoryHashes: [currentApp.codeDirectoryHash], expectedUserID: peer.userID,
                expectedAuditSessionID: peer.auditSessionID &+ 1)
            XCTAssertEqual(wrongSession.requirement, accepted.requirement)
            XCTAssertThrowsError(try resolve(state, entry, peer, wrongSession, incarnation: incarnation)) {
                XCTAssertEqual($0 as? AdministrativeSetupError, .wrongAccount)
            }
            let invalidPID = XPCPeerCredentials(processID: 0, userID: peer.userID, auditSessionID: peer.auditSessionID)
            XCTAssertThrowsError(try resolve(state, entry, invalidPID, accepted, incarnation: incarnation))
        }
    }

    func testTwoActualUnfinishedRetainedAccountsRefuseInsteadOfSelectingOne() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture(additionalRetainedAccount: true) { f in
            let machine = try f.machine(), state = try machine.retainedSetupCallerState(candidate: f.candidate)
            let peer = try XCTUnwrap(state.source.actual.inventory.accounts.first).ownerUID
            let retained = state.source.accounts.filter { $0.origin == .retained && !$0.inInventory }
            XCTAssertEqual(retained.count, 2)
            XCTAssertEqual(Set(retained.map(\.ownerUID)).count, 2)
            XCTAssertTrue(retained.allSatisfy { $0.preparation?.storagePrepared == true && $0.initialization?.complete == true })
            XCTAssertThrowsError(try state.target(peerUID: peer)) {
                XCTAssertEqual($0 as? AdministrativeSetupError, .wrongAccount)
            }
            try machine.retainedSetupCallerState(candidate: f.candidate).requireSame(as: state)
        }
    }

    func testCompletedRuntimeWithoutPendingImportIsNotAnUnfinishedTarget() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture(hasReference: true) { f in
            let (state, entry, peer, accepted) = try values(f), incarnation = UUID()
            let original = try resolve(state, entry, peer, accepted, incarnation: incarnation)
            XCTAssertEqual(try state.target(peerUID: peer.userID).accountID, entry.runtime.preparation.accountID)
            let targetID = entry.runtime.preparation.accountID
            let completed = replacing(state, runtimes: state.runtimes.map {
                .init(accountID: $0.accountID,
                    state: .init(reference: $0.state.reference,
                        configurationPublished: $0.accountID == targetID ? true : $0.state.configurationPublished),
                    activationRecord: $0.activationRecord, jobsRegistered: $0.jobsRegistered)
            })
            XCTAssertFalse(completed.sharedImport?.records.contains {
                $0.accountID == targetID && $0.phase == SharedSetupImportIntent.Phase.retained.rawValue
            } == true)
            XCTAssertThrowsError(try completed.target(peerUID: peer.userID))
            XCTAssertThrowsError(try completed.requireSame(as: state)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertThrowsError(try original.requireSame(as: resolve(state, entry, peer, accepted, incarnation: UUID()))) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
        }
    }

    func testNativeCaptureRequiresAnActualExportedInvocationBeforeReadingTheOwner() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let (_, _, _, accepted) = try values(f)
            let connection = NSXPCConnection(machServiceName: AdministrativeSetupConfiguration.serviceName, options: [])
            let invocation = XPCInvocationGuard(connection: connection, policy: accepted)
            let owner = try SetupAccountOwner(machine: f.machine(), expectedReleaseDigest: InstallationInventory.digest(f.candidate),
                resume: { _, value in value })
            defer { try? owner.close(); connection.invalidate() }
            var reads = 0; let machine = try f.machine()
            machine.observeStoreRead = { _ in reads += 1 }; defer { machine.observeStoreRead = nil }
            XCTAssertThrowsError(try owner.retainedCallerBinding(invocation: invocation, candidate: f.candidate)) {
                if case XPCPeerPolicyError.wrongConnection = $0 {} else { XCTFail("Unexpected failure: \($0)") }
            }
            XCTAssertEqual(reads, 0)
        }
    }
    func testActualRecordOnlyStopCaptureCannotRecaptureWithoutItsBindingReceipt() async throws {
        let stop = try MaintenanceStopTestFixture(), client = try stop.client()
        let capture = try await stop.capture(client)
        XCTAssertNil(capture.bindingTransition)
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let (state, entry, peer, accepted) = try values(f)
            let binding = try resolve(state, entry, peer, accepted, incarnation: UUID())
            XCTAssertThrowsError(try binding.recapturing(state: state, entry: entry, transitions: [], candidate: f.candidate,
                capture: capture, lookup: { _ in XCTFail("A record-only capture reached lookup"); throw RuntimePreparationError.changedScope })) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
        }
        await client.close()
    }

}
