import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned protected fixtures and synthetic HTTP only. Administrator/XPC admission is not exercised.
final class SharedSetupAccessApplicationOwnerTests: XCTestCase, @unchecked Sendable {
    private func metadata(_ f: AccessApplicationFixture) throws -> RelayIngressProbe.Step {
        RelayIngressProbe.reply(try RelayIngressProviderFixture.metadata(configuration: XCTUnwrap(f.h.f.proposal().cloudflare), plan: f.plan))
    }
    private func empty() throws -> RelayIngressProbe.Step { RelayIngressProbe.reply(try RelayPrivateRouteReplies.page()) }
    private func creationSteps(_ f: AccessApplicationFixture, outcome: RelayIngressProbe.Step? = nil) throws -> [RelayIngressProbe.Step] {
        try [metadata(f), empty(), outcome ?? RelayIngressProbe.reply(f.applicationReply())]
    }
    private func readSteps(_ f: AccessApplicationFixture) throws -> [RelayIngressProbe.Step] {
        try [metadata(f), RelayIngressProbe.reply(f.applicationReply()), empty()]
    }
    func testOwnerRetainsDispatchBeforePostAndDoesNotAdvanceImportOrHoldDatabaseLeases() async throws {
        let f = try AccessApplicationFixture(), owner = try f.h.owner(); defer { try? owner.close() }
        let expected = try f.h.progress(owner), proposal = try f.h.f.proposal()
        let probe = try RelayIngressProbe(creationSteps(f), hook: { _, request in
            try f.h.machine { machine in try machine.withSharedImportJournal { journal in XCTAssertEqual(try journal?.records(), [f.h.intent]) } }
            if request.httpMethod == "POST" { XCTAssertEqual(try f.read()?.phase, .dispatched) }
        })
        let record = try await owner.createImportedAccessApplication(callerUID: getuid(), expected: expected, proposal: proposal, send: { try await probe.send($0) })
        XCTAssertEqual(record.phase, .created); XCTAssertEqual(try f.read(), record); XCTAssertEqual(try f.h.progress(owner), expected)
        let requests = await probe.all(); XCTAssertEqual(requests.map(\.httpMethod), ["GET", "GET", "POST"])
        let repeatProbe = try RelayIngressProbe([metadata(f)])
        let repeated = try await owner.createImportedAccessApplication(callerUID: getuid(), expected: expected, proposal: proposal, send: { try await repeatProbe.send($0) })
        XCTAssertEqual(repeated, record); let repeatedRequests = await repeatProbe.all(); XCTAssertEqual(repeatedRequests.count, 1)
    }
    func testLostCreationReplyIsDurableAndCannotRetryOrAdoptByName() async throws {
        let f = try AccessApplicationFixture(), owner = try f.h.owner(); defer { try? owner.close() }
        let expected = try f.h.progress(owner), proposal = try f.h.f.proposal(), probe = try RelayIngressProbe(creationSteps(f, outcome: .lost))
        let result = try await owner.createImportedAccessApplication(callerUID: getuid(), expected: expected, proposal: proposal, send: { try await probe.send($0) })
        XCTAssertEqual(result.phase, .unknown); XCTAssertEqual(try f.read(), result)
        let repeatProbe = try RelayIngressProbe([metadata(f)])
        do { _ = try await owner.createImportedAccessApplication(callerUID: getuid(), expected: expected, proposal: proposal, send: { try await repeatProbe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
        let requests = await repeatProbe.all(); XCTAssertEqual(requests.count, 1)
    }
    func testCancellationAtCreationAcknowledgementPersistsIdentityBeforeReportingCancellation() async throws {
        let f = try AccessApplicationFixture(), owner = try f.h.owner(); defer { try? owner.close() }
        let expected = try f.h.progress(owner), proposal = try f.h.f.proposal()
        let probe = try RelayIngressProbe(creationSteps(f), hook: { _, request in if request.httpMethod == "POST" { withUnsafeCurrentTask { $0?.cancel() } } })
        let task = Task { @Sendable in try await owner.createImportedAccessApplication(callerUID: getuid(), expected: expected, proposal: proposal, send: { try await probe.send($0) }) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let retained = try XCTUnwrap(f.read()); XCTAssertEqual(retained.phase, .created)
        XCTAssertEqual(retained.applicationID, "22222222-2222-4222-8222-222222222222")
    }
    func testCancelledPostWithoutAcknowledgementPersistsUnknownOutcome() async throws {
        let f = try AccessApplicationFixture(), owner = try f.h.owner(); defer { try? owner.close() }
        let expected = try f.h.progress(owner), proposal = try f.h.f.proposal()
        let probe = try RelayIngressProbe(creationSteps(f, outcome: .cancelled), hook: { _, request in if request.httpMethod == "POST" { withUnsafeCurrentTask { $0?.cancel() } } })
        let task = Task { @Sendable in try await owner.createImportedAccessApplication(callerUID: getuid(), expected: expected, proposal: proposal, send: { try await probe.send($0) }) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(try f.read()?.phase, .unknown)
    }
    func testCancellationDuringPreflightLeavesPreparedStateWithoutAPost() async throws {
        let f = try AccessApplicationFixture(), owner = try f.h.owner(); defer { try? owner.close() }
        let expected = try f.h.progress(owner), proposal = try f.h.f.proposal()
        let probe = try RelayIngressProbe(creationSteps(f), hook: { count, _ in if count == 2 { withUnsafeCurrentTask { $0?.cancel() } } })
        let task = Task { @Sendable in try await owner.createImportedAccessApplication(callerUID: getuid(), expected: expected, proposal: proposal, send: { try await probe.send($0) }) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(try f.read()?.phase, .prepared); let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testPreexistingApplicationIsNotAdoptedAndDoesNotTriggerAPost() async throws {
        let f = try AccessApplicationFixture(), owner = try f.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe([metadata(f), RelayIngressProbe.reply(RelayPrivateRouteReplies.page(results: [["domain": f.plan.hostname]]))])
        do { _ = try await owner.createImportedAccessApplication(callerUID: getuid(), expected: f.h.progress(owner), proposal: f.h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        XCTAssertEqual(try f.read()?.phase, .prepared); let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testInventoryChangedDuringPreflightStopsBeforeDispatch() async throws {
        let f = try AccessApplicationFixture(), owner = try f.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(creationSteps(f), hook: { count, _ in if count == 2 {
            try f.h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
        } })
        do { _ = try await owner.createImportedAccessApplication(callerUID: getuid(), expected: f.h.progress(owner), proposal: f.h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        XCTAssertEqual(try f.read()?.phase, .prepared); let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testIdenticalPreparedRecordReplacementStopsBeforeDispatch() async throws {
        let f = try AccessApplicationFixture(), owner = try f.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(creationSteps(f), hook: { count, _ in if count == 2 {
            let record = try XCTUnwrap(f.read()), temp = f.path + ".replacement"; try record.bytes.write(to: URL(fileURLWithPath: temp))
            XCTAssertEqual(chmod(temp, 0o600), 0); XCTAssertEqual(rename(temp, f.path), 0)
        } })
        do { _ = try await owner.createImportedAccessApplication(callerUID: getuid(), expected: f.h.progress(owner), proposal: f.h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
        XCTAssertEqual(try f.read()?.phase, .prepared); let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testShutdownDuringPostLeavesDispatchUnresolvedWithoutAnotherAttempt() async throws {
        let f = try AccessApplicationFixture(), owner = try f.h.owner()
        let expected = try f.h.progress(owner), proposal = try f.h.f.proposal()
        let probe = try RelayIngressProbe(creationSteps(f), hook: { _, request in if request.httpMethod == "POST" {
            XCTAssertThrowsError(try owner.close()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
        } })
        do { _ = try await owner.createImportedAccessApplication(callerUID: getuid(), expected: expected, proposal: proposal, send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
        XCTAssertNoThrow(try owner.close()); XCTAssertEqual(try f.read()?.phase, .dispatched)
        let reopened = try f.h.owner(); defer { try? reopened.close() }; let repeated = try RelayIngressProbe([metadata(f)])
        do { _ = try await reopened.createImportedAccessApplication(callerUID: getuid(), expected: expected, proposal: proposal, send: { try await repeated.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
        let requests = await repeated.all(); XCTAssertEqual(requests.count, 1)
    }
    func testWrongCallerAndChangedProposalHaveNoAccessStateOrNetworkEffects() async throws {
        let f = try AccessApplicationFixture(), owner = try f.h.owner(); defer { try? owner.close() }
        let expected = try f.h.progress(owner), proposal = try f.h.f.proposal(), probe = RelayIngressProbe([])
        for (uid, selected) in [(getuid() + 1, proposal), (getuid(), PortableSetup(defaults: proposal.defaults))] {
            do { _ = try await owner.createImportedAccessApplication(callerUID: uid, expected: expected, proposal: selected, send: { try await probe.send($0) }); XCTFail() } catch {}
        }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty); XCTAssertNil(try f.read())
    }
    func testInitialReadbackRechecksTheExactCreatedAppAndPoliciesWithoutChangingProgress() async throws {
        let f = try AccessApplicationFixture(), application = try f.retainCreated(), owner = try f.h.owner(); defer { try? owner.close() }
        let expected = try f.h.progress(owner), probe = try RelayIngressProbe(readSteps(f), hook: { _, _ in
            try f.h.machine { machine in try machine.withSharedImportJournal { journal in XCTAssertEqual(try journal?.records(), [f.h.intent]) } }
        })
        let observed = try await owner.inspectImportedInitialAccessApplication(callerUID: getuid(), expected: expected, proposal: f.h.f.proposal(), send: { try await probe.send($0) })
        XCTAssertNoThrow(try observed.validate(expected: f.h.intent, plan: f.plan, createdTunnel: f.tunnel, application: application))
        XCTAssertEqual(try f.h.progress(owner), expected); XCTAssertEqual(try f.read(), application)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 3); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
    }
    func testIdenticalCreatedRecordReplacementStopsPolicyCredentialTransmission() async throws {
        let f = try AccessApplicationFixture(), application = try f.retainCreated(), owner = try f.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(readSteps(f), hook: { count, _ in if count == 2 {
            let temp = f.path + ".replacement"; try application.bytes.write(to: URL(fileURLWithPath: temp))
            XCTAssertEqual(chmod(temp, 0o600), 0); XCTAssertEqual(rename(temp, f.path), 0)
        } })
        do { _ = try await owner.inspectImportedInitialAccessApplication(callerUID: getuid(), expected: f.h.progress(owner), proposal: f.h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testLateInventoryChangeCannotReturnDefaultDenyEvidence() async throws {
        let f = try AccessApplicationFixture(), _ = try f.retainCreated(), owner = try f.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(readSteps(f), hook: { count, _ in if count == 3 {
            try f.h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
        } })
        do { _ = try await owner.inspectImportedInitialAccessApplication(callerUID: getuid(), expected: f.h.progress(owner), proposal: f.h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
    }
    func testMissingApplicationDoesNotCreateStateOrQueryAccess() async throws {
        let f = try AccessApplicationFixture(), owner = try f.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe([metadata(f)])
        do { _ = try await owner.inspectImportedInitialAccessApplication(callerUID: getuid(), expected: f.h.progress(owner), proposal: f.h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
        XCTAssertNil(try f.read()); let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
}
