import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class SetupRetainedStatusV1GoldenTests: XCTestCase {
    private typealias Status = SetupRetainedInvocationStatus
    private typealias Wire = SetupRetainedStatusWire
    private struct Golden: Decodable { let baselineCommit: String; let vectors: [String: String] }
    private let baseline = "4d5d3485bc8380278da61498ea3d6a2642aea3fc"

    private func vectors() throws -> [String: Data] {
        var result: [String: Data] = [:]
        let request = try Wire.Request(requestID: Data(repeating: 7, count: 16))
        result["request"] = try request.bytes
        result["unavailable"] = try Wire.reply(request, .unavailable)
        let identity = Status.Identity(reservationID: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            incarnation: UUID(uuidString: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")!)
        result["reserved-unbound"] = try Wire.reply(request, .reservation(.reserved, identity: identity, binding: nil,
            expectedWindow: nil, worker: .observed(.idle), cleanup: .observed(.noneRegistered)))
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { fixture in
            let machine = try fixture.machine()
            let state = try machine.retainedSetupCallerState(candidate: fixture.candidate)
            let entry = try machine.retainedSetupInitialRuntimeEntry(owner: fixture.owner, candidate: fixture.candidate)
            let member = try XCTUnwrap(state.source.actual.inventory.accounts.first)
            let (_, host) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(runtime: entry.runtime, accountID: member.accountID)
            let app = try XCTUnwrap(host.codePolicy.entries.first { $0.role == .app && $0.active })
            let peer = XPCPeerCredentials(processID: getpid(), userID: member.ownerUID, auditSessionID: 1)
            let policy = try XPCPeerPolicy(teamID: app.teamID, componentIdentifier: app.identifier,
                approvedCodeDirectoryHashes: [app.codeDirectoryHash], expectedUserID: peer.userID)
            let caller = try SetupRetainedCallerBinding.resolve(state: state, peer: peer, incarnation: identity.incarnation,
                accepted: policy, entry: entry, lookup: { uid in
                    let account = try XCTUnwrap(state.source.preparations.first { $0.ownerUID == uid })
                    return .init(uid: uid, primaryGroupID: getgid(), directoryID: account.directoryID)
                })
            let binding = try Status.capturedBinding(caller)
            let digest = Data(repeating: 9, count: 32)
            let scope = try RuntimeMaintenanceWindowRecord.Scope(macID: binding.macID, installationID: binding.installationID,
                authority: binding.authority, target: binding.target, releaseDigest: binding.releaseDigest,
                candidateDigest: digest, authorityPolicyDigest: digest, operationDigest: digest, restorationDigest: digest,
                mutationFootprintDigest: digest, authorityGrantDigest: digest, targetConsentDigest: digest, administratorIntentDigest: digest)
            let row = try RuntimeMaintenanceWindowRecord(id: Data(repeating: 0xab, count: 16), revision: Data(repeating: 0xcd, count: 16),
                purpose: .retainedRuntime, scope: scope, phase: .needsOwnerRecovery, operation: .committed,
                service: .unknown, failure: .cleanupPending)
            func snapshot(_ reservation: Status.Reservation, worker: Status.Worker = .idle,
                cleanup: Status.Cleanup = .noneRegistered) -> Status {
                .reservation(reservation, identity: identity, binding: binding, expectedWindow: .init(row),
                    worker: .observed(worker), cleanup: .observed(cleanup))
            }
            result["reserved-bound"] = try Wire.reply(request, snapshot(.reserved))
            result["settled"] = try Wire.reply(request, snapshot(.settled, cleanup: .settled))
            let observed = snapshot(.attached).observing(row)
            result["captured-row"] = try Wire.reply(request, observed)
            let reader = Status.Reader()
            defer { reader.close() }
            reader.publishRecovery(row)
            let supervisor = reader.read(authenticatedPeer: peer, currentOwner: caller.authorityOwner)
            result["supervisor-row"] = try Wire.reply(request, supervisor)
            let cases: [(String, Status.Supervisor)] = [("recovering", .recovering), ("joining", .joining),
                ("busy", .busy), ("cancelled", .cancelled), ("retired", .retired), ("no-window", .noWindow)]
            for (name, observation) in cases {
                result["supervisor-" + name] = try Wire.reply(request, supervisor.observing(supervisor: observation))
            }
            for phase in RuntimeMaintenanceWindowRecord.Phase.allCases {
                result["supervisor-phase-\(phase.rawValue)"] = try Wire.reply(request, supervisor.observing(supervisor: .phase(phase)))
            }
            for failure in RuntimeMaintenanceWindowRecord.Failure.allCases {
                result["supervisor-failure-\(failure.rawValue)"] = try Wire.reply(request, supervisor.observing(supervisor: .failed(failure)))
            }
        }
        return result
    }

    func testUnchangedBaseV1GoldenBytes() throws {
        let actual = try vectors().mapValues { $0.map { String(format: "%02x", $0) }.joined() }
        let url = try XCTUnwrap(Bundle.module.url(forResource: "retained-setup-status-v1", withExtension: "json", subdirectory: "Fixtures"))
        let expected = try JSONDecoder().decode(Golden.self, from: Data(contentsOf: url))
        XCTAssertEqual(expected.baselineCommit, baseline)
        XCTAssertEqual(actual.count, 31)
        XCTAssertEqual(actual, expected.vectors)
    }
}
