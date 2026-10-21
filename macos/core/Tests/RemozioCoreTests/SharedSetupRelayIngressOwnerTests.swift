import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Protected owned fixtures and synthetic provider replies only. No app endpoint or service is exercised.
final class SharedSetupRelayIngressOwnerTests: XCTestCase, @unchecked Sendable {
    private func retain(_ h: RelayProvisioningFixture, plan: SharedSetupImportRelayPlan,
                        phase: SharedSetupRelayProvisioningRecord.Phase = .created) throws -> SharedSetupRelayProvisioningRecord {
        try h.directory { directory in
            let prepared = try SharedSetupRelayProvisioningStorage.begin(expected: h.intent, plan: plan, directory: directory, owner: getuid(), verifyCurrent: {})
            if phase == .prepared { return prepared }
            let sent = try prepared.transition(to: .dispatched)
            try SharedSetupRelayProvisioningStorage.replace(sent, previous: prepared, expected: h.intent, plan: plan,
                directory: directory, owner: getuid(), verifyCurrent: {})
            if phase == .dispatched { return sent }
            let value: SharedSetupRelayProvisioningRecord
            if phase == .created { value = try sent.transition(to: .created, tunnelID: "11111111-1111-4111-8111-111111111111") }
            else if phase == .rejected { value = try sent.transition(to: .rejected, refusal: .unauthorized) }
            else { value = try sent.transition(to: .unknown) }
            try SharedSetupRelayProvisioningStorage.replace(value, previous: sent, expected: h.intent, plan: plan,
                directory: directory, owner: getuid(), verifyCurrent: {})
            return value
        }
    }
    private func steps(_ h: RelayProvisioningFixture, plan: SharedSetupImportRelayPlan, lost: Bool = false) throws -> [RelayIngressProbe.Step] {
        let config = try XCTUnwrap(h.f.proposal().cloudflare)
        let routes = RelayIngressProbe.reply(try RelayPrivateRouteReplies.page())
        return [RelayIngressProbe.reply(try RelayIngressProviderFixture.metadata(configuration: config, plan: plan)), routes, routes,
            lost ? .lost : RelayIngressProbe.reply(Data("untrusted-acknowledgement".utf8)),
            RelayIngressProbe.reply(try RelayIngressProviderFixture.ingress(configuration: config, plan: plan)), routes, routes]
    }
    private func statePath(_ h: RelayProvisioningFixture) -> String {
        URL(fileURLWithPath: h.path).deletingLastPathComponent().path + "/" + AdministrativeSetupPublication.File.importRelayProvisioning(accountID: h.intent.scope.accountID).name
    }
    private func read(_ h: RelayProvisioningFixture, plan: SharedSetupImportRelayPlan) throws -> SharedSetupRelayProvisioningRecord? {
        try h.directory { try SharedSetupRelayProvisioningStorage.read(expected: h.intent, plan: plan, directory: $0, owner: getuid()) }
    }
    func testOwnerUsesTheCreatedUuidAndReleasesDatabaseLeasesAcrossAllThreeRequests() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), created = try retain(h, plan: plan), owner = try h.owner(); defer { try? owner.close() }
        let progress = try h.progress(owner), proposal = try h.f.proposal()
        let probe = try RelayIngressProbe(steps(h, plan: plan), hook: { _, _ in
            try h.machine { machine in try machine.withSharedImportJournal { journal in XCTAssertEqual(try journal?.records(), [h.intent]) } }
            XCTAssertEqual(try self.read(h, plan: plan), created)
        })
        let result = try await owner.applyImportedRelayIngress(callerUID: getuid(), expected: progress, proposal: proposal, send: { try await probe.send($0) })
        let requests = await probe.all(); XCTAssertEqual(requests.map(\.httpMethod), ["GET", "GET", "GET", "PUT", "GET", "GET", "GET"])
        XCTAssertEqual(result.tunnelID, created.tunnelID); XCTAssertEqual(result.providerVersion, 3)
        XCTAssertEqual(try h.progress(owner), progress); XCTAssertEqual(try read(h, plan: plan), created)
    }
    func testLostIngressReplyUsesReadbackAndDoesNotCreateAnotherTunnel() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), created = try retain(h, plan: plan), owner = try h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(steps(h, plan: plan, lost: true))
        _ = try await owner.applyImportedRelayIngress(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), send: { try await probe.send($0) })
        let requests = await probe.all(); XCTAssertEqual(requests.map(\.httpMethod), ["GET", "GET", "GET", "PUT", "GET", "GET", "GET"])
        XCTAssertEqual(try read(h, plan: plan), created)
    }
    func testEveryUnresolvedCreationStateStopsBeforeSendingCredentials() async throws {
        for phase: SharedSetupRelayProvisioningRecord.Phase in [.prepared, .dispatched, .unknown, .rejected] {
            let h = try RelayProvisioningFixture(), plan = try h.prepare(), record = try retain(h, plan: plan, phase: phase), owner = try h.owner(); defer { try? owner.close() }
            let probe = RelayIngressProbe([])
            do { _ = try await owner.applyImportedRelayIngress(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
            catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
            let requests = await probe.all(); XCTAssertTrue(requests.isEmpty); XCTAssertEqual(try read(h, plan: plan), record)
        }
    }
    func testMissingCreationRecordIsNotCreatedByIngressApplication() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), owner = try h.owner(); defer { try? owner.close() }
        let probe = RelayIngressProbe([])
        do { _ = try await owner.applyImportedRelayIngress(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty); XCTAssertNil(try read(h, plan: plan))
    }
    func testWrongCallerAndChangedProposalHaveNoNetworkEffects() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), _ = try retain(h, plan: plan), owner = try h.owner(); defer { try? owner.close() }
        let progress = try h.progress(owner), proposal = try h.f.proposal(), probe = RelayIngressProbe([])
        for (uid, selected) in [(getuid() + 1, proposal), (getuid(), PortableSetup(defaults: proposal.defaults))] {
            do { _ = try await owner.applyImportedRelayIngress(callerUID: uid, expected: progress, proposal: selected, send: { try await probe.send($0) }); XCTFail() } catch {}
        }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
    func testCrossedRemoteIdentityStopsBeforeAnyWrite() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), created = try retain(h, plan: plan), owner = try h.owner(); defer { try? owner.close() }
        let config = try XCTUnwrap(h.f.proposal().cloudflare)
        let probe = try RelayIngressProbe([RelayIngressProbe.reply(RelayIngressProviderFixture.metadata(configuration: config, plan: plan,
            id: "22222222-2222-4222-8222-222222222222"))])
        do { _ = try await owner.applyImportedRelayIngress(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1); XCTAssertEqual(try read(h, plan: plan), created)
    }
    func testInventoryChangeDuringMetadataReadStopsBeforeWrite() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), _ = try retain(h, plan: plan), owner = try h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(steps(h, plan: plan), hook: { count, _ in if count == 1 {
            try h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
        } })
        do { _ = try await owner.applyImportedRelayIngress(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
    func testIdenticalCreationRecordReplacementStopsBeforeWrite() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), created = try retain(h, plan: plan), owner = try h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(steps(h, plan: plan), hook: { count, _ in if count == 1 {
            let path = self.statePath(h), temp = path + ".replacement"; try created.bytes.write(to: URL(fileURLWithPath: temp))
            XCTAssertEqual(chmod(temp, 0o600), 0); XCTAssertEqual(rename(temp, path), 0)
        } })
        do { _ = try await owner.applyImportedRelayIngress(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
    func testShutdownDuringMetadataReadStopsBeforeWrite() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), _ = try retain(h, plan: plan), owner = try h.owner()
        let probe = try RelayIngressProbe(steps(h, plan: plan), hook: { count, _ in if count == 1 {
            XCTAssertThrowsError(try owner.close()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
        } })
        do { _ = try await owner.applyImportedRelayIngress(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
        XCTAssertNoThrow(try owner.close()); let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
    func testInventoryChangeDuringWritePreventsFurtherCredentialTransmission() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), created = try retain(h, plan: plan), owner = try h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(steps(h, plan: plan), hook: { _, request in if request.httpMethod == "PUT" {
            try h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
        } })
        do { _ = try await owner.applyImportedRelayIngress(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), send: { try await probe.send($0) }); XCTFail() } catch {}
        let requests = await probe.all(); XCTAssertEqual(requests.count, 4); XCTAssertEqual(try read(h, plan: plan), created)
    }
    func testLateScopeChangeCannotReturnSuccessfulReadback() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), _ = try retain(h, plan: plan), owner = try h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(steps(h, plan: plan), hook: { count, _ in if count == 5 {
            try h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
        } })
        do { _ = try await owner.applyImportedRelayIngress(callerUID: getuid(), expected: h.progress(owner), proposal: h.f.proposal(), send: { try await probe.send($0) }); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 5)
    }
    func testCancelledWriteCannotClaimIngressReadinessAndCanResumeTheSameResource() async throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), created = try retain(h, plan: plan), owner = try h.owner(); defer { try? owner.close() }
        let progress = try h.progress(owner), proposal = try h.f.proposal()
        let cancelled = try RelayIngressProbe(steps(h, plan: plan), hook: { _, request in if request.httpMethod == "PUT" { withUnsafeCurrentTask { $0?.cancel() } } })
        let task = Task { @Sendable in try await owner.applyImportedRelayIngress(callerUID: getuid(), expected: progress, proposal: proposal, send: { try await cancelled.send($0) }) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let requests = await cancelled.all(); XCTAssertEqual(requests.count, 4); XCTAssertEqual(try read(h, plan: plan), created)
        let resumed = try RelayIngressProbe(steps(h, plan: plan))
        let result = try await owner.applyImportedRelayIngress(callerUID: getuid(), expected: progress, proposal: proposal, send: { try await resumed.send($0) })
        XCTAssertEqual(result.tunnelID, created.tunnelID); XCTAssertEqual(try read(h, plan: plan), created)
    }
}
