import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Temporary owned state and synthetic provider replies. No credential is written to runtime storage.
final class SharedSetupRelayTokenOwnerTests: XCTestCase, @unchecked Sendable {
    private let tunnelID = "11111111-1111-4111-8111-111111111111"
    private struct Fixture: Sendable {
        let host: RelayProvisioningFixture
        let plan: SharedSetupImportRelayPlan
        let created: SharedSetupRelayProvisioningRecord
        let owner: SetupAccountOwner
        let expected: SetupPortableImportProgress
        let proposal: PortableSetup
    }
    private func fixture() throws -> Fixture {
        let h = try RelayProvisioningFixture(), plan = try h.prepare()
        let created = try h.directory { directory -> SharedSetupRelayProvisioningRecord in
            let prepared = try SharedSetupRelayProvisioningStorage.begin(expected: h.intent, plan: plan,
                directory: directory, owner: getuid(), verifyCurrent: {})
            let sent = try prepared.transition(to: .dispatched)
            try SharedSetupRelayProvisioningStorage.replace(sent, previous: prepared, expected: h.intent, plan: plan,
                directory: directory, owner: getuid(), verifyCurrent: {})
            let created = try sent.transition(to: .created, tunnelID: tunnelID)
            try SharedSetupRelayProvisioningStorage.replace(created, previous: sent, expected: h.intent, plan: plan,
                directory: directory, owner: getuid(), verifyCurrent: {})
            return created
        }
        let owner = try h.owner()
        return try .init(host: h, plan: plan, created: created, owner: owner, expected: h.progress(owner), proposal: h.f.proposal())
    }
    private func replies(_ f: Fixture) throws -> [RelayIngressProbe.Step] {
        let configuration = try XCTUnwrap(f.proposal.cloudflare)
        let metadata = try RelayIngressProviderFixture.metadata(configuration: configuration, plan: f.plan)
        let token = try JSONSerialization.data(withJSONObject: ["a": configuration.accountID, "t": tunnelID,
            "s": Data(repeating: 0x71, count: 32).base64EncodedString()]).base64EncodedString()
        let body = try JSONSerialization.data(withJSONObject: ["success": true, "errors": [], "result": token])
        return [RelayIngressProbe.reply(metadata), RelayIngressProbe.reply(metadata), RelayIngressProbe.reply(body), RelayIngressProbe.reply(metadata)]
    }
    private func read(_ f: Fixture, send: @escaping CloudflareProvisioningScopeClient.Send) async throws -> CloudflareTunnelRunCredential {
        try await f.owner.readImportedRelayRunCredential(callerUID: getuid(), expected: f.expected, proposal: f.proposal, send: send)
    }
    private func resourcePath(_ f: Fixture) -> String {
        URL(fileURLWithPath: f.host.path).deletingLastPathComponent().appendingPathComponent(
            AdministrativeSetupPublication.File.importRelayProvisioning(accountID: f.host.intent.scope.accountID).name).path
    }

    func testScopedReadReleasesTheMachineLeaseAndPreservesImportState() async throws {
        let f = try fixture(); defer { try? f.owner.close() }
        let probe = try RelayIngressProbe(replies(f), hook: { _, _ in try f.host.machine { _ in } })
        let before = try f.host.directory { try FileManager.default.contentsOfDirectory(atPath: $0.path).sorted() }
        let credential = try await read(f, send: { try await probe.send($0) })
        XCTAssertEqual(credential.tunnel, try f.created.createdTunnel(expected: f.host.intent, plan: f.plan))
        XCTAssertEqual(try f.host.progress(f.owner), f.expected)
        let after = try f.host.directory { try FileManager.default.contentsOfDirectory(atPath: $0.path).sorted() }
        XCTAssertEqual(before, after)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 4)
        XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" && $0.httpBody == nil })
    }

    func testWrongCallerAndChangedProposalSendNothing() async throws {
        let f = try fixture(); defer { try? f.owner.close() }; let probe = RelayIngressProbe([])
        for (uid, proposal) in [(getuid() + 1, f.proposal), (getuid(), PortableSetup(defaults: f.proposal.defaults))] {
            do {
                _ = try await f.owner.readImportedRelayRunCredential(callerUID: uid, expected: f.expected, proposal: proposal,
                    send: { try await probe.send($0) }); XCTFail("A different scope was accepted")
            } catch {}
        }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }

    func testInventoryChangeDuringAnyNetworkReplyPreventsCredentialReturn() async throws {
        for changedAt in 1...4 {
            let f = try fixture(); defer { try? f.owner.close() }
            let probe = try RelayIngressProbe(replies(f), hook: { count, _ in
                if count == changedAt {
                    try f.host.machine { machine in
                        let inventory = try XCTUnwrap(machine.inventory())
                        _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision)
                    }
                }
            })
            do { _ = try await read(f, send: { try await probe.send($0) }); XCTFail("A stale import returned a credential") }
            catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, changedAt)
        }
    }

    func testIdenticalPlanOrResourceReplacementCannotReceiveTheCredential() async throws {
        for replacePlan in [true, false] {
            let f = try fixture(); defer { try? f.owner.close() }
            let path = replacePlan ? f.host.path : resourcePath(f)
            let bytes = replacePlan ? f.plan.bytes : f.created.bytes
            let probe = try RelayIngressProbe(replies(f), hook: { count, _ in
                if count == 3 {
                    let replacement = path + ".replacement"; try bytes.write(to: URL(fileURLWithPath: replacement))
                    XCTAssertEqual(chmod(replacement, 0o600), 0); XCTAssertEqual(rename(replacement, path), 0)
                }
            })
            do { _ = try await read(f, send: { try await probe.send($0) }); XCTFail("Replaced state returned a credential") }
            catch {
                if replacePlan { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
                else { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
            }
            let requests = await probe.all(); XCTAssertEqual(requests.count, 3)
        }
    }

    private actor ReplyGate {
        private var opened = false
        private var waiter: CheckedContinuation<Void, Never>?
        func wait() async {
            if opened { return }
            await withCheckedContinuation { waiter = $0 }
        }
        func open() { opened = true; waiter?.resume(); waiter = nil }
    }
    func testClosingWaitsForTheActualReplyAndRefusesItsCredential() async throws {
        let f = try fixture(); defer { try? f.owner.close() }
        let arrived = expectation(description: "The token reply is suspended"), gate = ReplyGate()
        let probe = try RelayIngressProbe(replies(f))
        let task = Task { @Sendable in
            try await self.read(f, send: { request in
                let reply = try await probe.send(request)
                if request.url?.path.hasSuffix("/token") == true { arrived.fulfill(); await gate.wait() }
                return reply
            })
        }
        await fulfillment(of: [arrived], timeout: 5)
        XCTAssertThrowsError(try f.owner.close()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
        let closing = Task { try await f.owner.closeWhenIdle() }
        do { _ = try await read(f, send: { try await probe.send($0) }); XCTFail("Closing admitted new work") }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
        await gate.open()
        do { _ = try await task.value; XCTFail("Closing returned the credential") }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
        try await closing.value
        let requests = await probe.all(); XCTAssertEqual(requests.count, 3)
    }

    func testCancelledAdmissionSendsNothing() async throws {
        let f = try fixture(); defer { try? f.owner.close() }; let probe = RelayIngressProbe([])
        let task = Task { @Sendable in
            withUnsafeCurrentTask { $0?.cancel() }
            return try await self.read(f, send: { try await probe.send($0) })
        }
        do { _ = try await task.value; XCTFail("Cancelled work returned a credential") }
        catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
}
