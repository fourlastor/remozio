import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Synthetic replies and owned files only. The internal path grants no Ready state or production admission.
final class SharedSetupDNSCreationOwnerTests: XCTestCase, @unchecked Sendable {
    private func steps(_ f: DNSRecordFixture) throws -> [RelayIngressProbe.Step] {
        try RelayPublicationReplies.ownerSteps(f) + [RelayIngressProbe.reply(f.dnsReply())]
    }
    private func create(_ owner: SetupAccountOwner, f: DNSRecordFixture, expected: SetupPortableImportProgress,
                        probe: RelayIngressProbe) async throws -> SharedSetupDNSRecord {
        try await owner.createImportedDNSRecord(callerUID: getuid(), expected: expected, proposal: f.base.h.f.proposal(), send: { try await probe.send($0) })
    }
    private func replaceFile(_ path: String, bytes: Data) throws {
        let temp = path + ".replacement"; try bytes.write(to: URL(fileURLWithPath: temp))
        XCTAssertEqual(chmod(temp, 0o600), 0); XCTAssertEqual(rename(temp, path), 0)
    }
    func testDispatchIsDurableBeforeOnePOSTAndDatabaseLeasesAreReleased() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let expected = try f.base.h.progress(owner), probe = try RelayIngressProbe(steps(f), hook: { count, request in
            try f.base.h.machine { machine in try machine.withSharedImportJournal { journal in XCTAssertEqual(try journal?.records(), [f.base.h.intent]) } }
            if count == 13 { XCTAssertEqual(request.httpMethod, "POST"); XCTAssertEqual(try f.read()?.phase, .dispatched) }
        })
        let record = try await create(owner, f: f, expected: expected, probe: probe)
        XCTAssertEqual(record.phase, .created); XCTAssertEqual(record.dnsRecordID, DNSRecordFixture.providerID)
        XCTAssertEqual(try f.read(), record); XCTAssertEqual(try f.base.h.progress(owner), expected)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 13)
        XCTAssertEqual(requests.filter { $0.httpMethod == "POST" }.count, 1)
        XCTAssertTrue(requests.dropLast().allSatisfy { $0.httpMethod == "GET" })
    }
    func testCreatedHistoryReturnsWithoutAnotherPOSTOrClaimingReadback() async throws {
        let f = try DNSRecordFixture(), record = try f.retainCreated(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe([steps(f)[0]])
        let result = try await create(owner, f: f, expected: f.base.h.progress(owner), probe: probe)
        XCTAssertEqual(result, record); let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
    func testDispatchedUnknownAndRejectedHistoryCannotRetryAutomatically() async throws {
        for selected in 0..<3 {
            let f = try DNSRecordFixture(), prepared = try f.begin(), sent = try prepared.transition(to: .dispatched)
            try f.replace(sent, previous: prepared); var retained = sent
            if selected > 0 {
                retained = selected == 1 ? try sent.transition(to: .unknown) : try sent.transition(to: .rejected, refusal: .unauthorized)
                try f.replace(retained, previous: sent)
            }
            let owner = try f.base.h.owner(); defer { try? owner.close() }; let probe = try RelayIngressProbe([steps(f)[0]])
            do { _ = try await create(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
            catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
            XCTAssertEqual(try f.read(), retained); let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
        }
    }
    func testLostAcknowledgementRetainsUnknownWithoutReplay() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }; var replies = try steps(f); replies[12] = .lost
        let probe = RelayIngressProbe(replies), expected = try f.base.h.progress(owner)
        let record = try await create(owner, f: f, expected: expected, probe: probe)
        XCTAssertEqual(record.phase, .unknown); XCTAssertEqual(try f.read(), record)
        let again = try RelayIngressProbe([steps(f)[0]])
        do { _ = try await create(owner, f: f, expected: expected, probe: again); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
        let requests = await again.all(); XCTAssertEqual(requests.count, 1)
    }
    func testTypedProviderRefusalsRemainDurableAndDoNotChangeTheImport() async throws {
        for (status, refusal): (Int, SharedSetupDNSRecord.Refusal) in [(403, .unauthorized), (429, .rateLimited), (400, .providerRejected)] {
            let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }; var replies = try steps(f)
            replies[12] = RelayIngressProbe.reply(Data(), status: status); let expected = try f.base.h.progress(owner)
            let result = try await create(owner, f: f, expected: expected, probe: RelayIngressProbe(replies))
            XCTAssertEqual(result.phase, .rejected); XCTAssertEqual(result.refusal, refusal); XCTAssertEqual(try f.read(), result)
            XCTAssertEqual(try f.base.h.progress(owner), expected)
        }
    }
    func testMalformedSuccessfulReplyRetainsUnknownInsteadOfAdoptingAnIdentifier() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }; var replies = try steps(f)
        replies[12] = RelayIngressProbe.reply(try f.dnsReply(changes: ["content": "another-tunnel.invalid"]))
        let result = try await create(owner, f: f, expected: f.base.h.progress(owner), probe: RelayIngressProbe(replies))
        XCTAssertEqual(result.phase, .unknown); XCTAssertNil(result.dnsRecordID)
    }
    func testCancellationAfterAcknowledgementRetainsCreatedBeforeReportingCancellation() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let expected = try f.base.h.progress(owner), probe = try RelayIngressProbe(steps(f), hook: { count, _ in
            if count == 13 { withUnsafeCurrentTask { $0?.cancel() } }
        })
        let task = Task { @Sendable in try await self.create(owner, f: f, expected: expected, probe: probe) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(try f.read()?.phase, .created); XCTAssertEqual(try f.read()?.dnsRecordID, DNSRecordFixture.providerID)
    }
    func testShutdownDuringPOSTLeavesDispatchUnresolvedAndDrainsTheOperation() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner()
        let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == 13 {
            XCTAssertThrowsError(try owner.close()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
        } })
        do { _ = try await create(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
        XCTAssertEqual(try f.read()?.phase, .dispatched); XCTAssertNoThrow(try owner.close())
    }
    func testScopeChangeAtEveryReceiptStopsFurtherRequestsAndAcknowledgementRetention() async throws {
        for index in 1...13 {
            let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
            let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == index {
                try f.base.h.machine { machine in let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision) }
            } })
            do { _ = try await create(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail(String(index)) }
            catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, index)
            XCTAssertEqual(try f.read()?.phase, index == 1 ? nil : index == 13 ? .dispatched : .prepared)
        }
    }
    func testIdenticalDNSReplacementAtEveryPreflightReceiptCannotDispatch() async throws {
        for index in 2...12 {
            let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
            let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == index {
                try self.replaceFile(f.path, bytes: XCTUnwrap(f.read()).bytes)
            } })
            do { _ = try await create(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail(String(index)) }
            catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
            XCTAssertEqual(try f.read()?.phase, .prepared); let requests = await probe.all(); XCTAssertEqual(requests.count, index)
        }
    }
    func testIdenticalDNSReplacementDuringPOSTCannotRetainAnAcknowledgement() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == 13 {
            try self.replaceFile(f.path, bytes: XCTUnwrap(f.read()).bytes)
        } })
        do { _ = try await create(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
        XCTAssertEqual(try f.read()?.phase, .dispatched)
    }
    func testIdenticalAccessReplacementDuringPOSTLeavesDispatchUnresolved() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == 13 { try self.replaceFile(f.base.path, bytes: f.access.bytes) } })
        do { _ = try await create(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
        XCTAssertEqual(try f.read()?.phase, .dispatched)
    }
    func testIdenticalTunnelReplacementDuringPOSTLeavesDispatchUnresolved() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let path = URL(fileURLWithPath: f.path).deletingLastPathComponent().appendingPathComponent(AdministrativeSetupPublication.File.importRelayProvisioning(accountID: f.base.h.intent.scope.accountID).name).path
        let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == 13 { try self.replaceFile(path, bytes: f.base.tunnel.bytes) } })
        do { _ = try await create(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() } catch {}
        XCTAssertEqual(try f.read()?.phase, .dispatched)
    }
    func testIdenticalPlanReplacementDuringPOSTLeavesDispatchUnresolved() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(steps(f), hook: { count, _ in if count == 13 { try self.replaceFile(f.base.h.path, bytes: f.base.plan.bytes) } })
        do { _ = try await create(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() } catch {}
        XCTAssertEqual(try f.read()?.phase, .dispatched)
    }
    func testBroaderWildcardRootDoesNotBlockDNSOrChangeExistingAccessApplications() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let wildcard = "*." + f.base.plan.hostname.split(separator: ".").dropFirst().joined(separator: ".")
        let replies = try RelayPublicationReplies.ownerSteps(f, extraApplications: [AccessHostnameReplies.row(1, uri: wildcard)]) +
            [RelayIngressProbe.reply(f.dnsReply())]
        let expected = try f.base.h.progress(owner), probe = RelayIngressProbe(replies)
        let result = try await create(owner, f: f, expected: expected, probe: probe)
        XCTAssertEqual(result.phase, .created); XCTAssertEqual(try f.base.read(), f.access)
        XCTAssertEqual(try f.base.h.progress(owner), expected)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 13)
        XCTAssertTrue(requests.dropLast().allSatisfy { $0.httpMethod == "GET" })
        XCTAssertTrue(requests.last?.url?.path.hasSuffix("/dns_records") == true)
    }
    func testAnExactPathCompetitorCannotDispatchDNSOrChangeExistingAccessApplications() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let replies = try RelayPublicationReplies.ownerSteps(f, extraApplications: [AccessHostnameReplies.row(1, uri: f.base.plan.hostname + "/admin")])
        let probe = RelayIngressProbe(replies)
        do { _ = try await create(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
        XCTAssertEqual(try f.read()?.phase, .prepared); XCTAssertEqual(try f.base.read(), f.access)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 12); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
    }
    func testAHostnameCompetitorOnALaterPageCannotDispatchDNS() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        var replies = try RelayPublicationReplies.ownerSteps(f)
        replies[7] = RelayIngressProbe.reply(try AccessHostnameReplies.page(
            [AccessHostnameReplies.row(1, uri: f.base.plan.hostname)], number: 2))
        replies.insert(RelayIngressProbe.reply(try AccessHostnameReplies.page([], number: 3)), at: 8)
        let probe = RelayIngressProbe(replies)
        do { _ = try await create(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
        XCTAssertEqual(try f.read()?.phase, .prepared)
        let requests = await probe.all()
        XCTAssertEqual(requests.filter { $0.url?.path.hasSuffix("/access/apps") == true }.count, 3)
        XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
    }
    func testALostTerminalInventoryReadCannotDispatchDNS() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        var replies = try RelayPublicationReplies.ownerSteps(f); replies[7] = .lost
        let probe = RelayIngressProbe(replies)
        do { _ = try await create(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? CloudflareProvisioningError, .unavailable) }
        XCTAssertEqual(try f.read()?.phase, .prepared)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 8)
        XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
        XCTAssertFalse(requests.contains { $0.url?.path.hasSuffix("/dns_records") == true })
    }
    func testFailedPreflightCannotLeaveDispatchedOrSendPOST() async throws {
        for index in 1...11 {
            let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }; var replies = try steps(f)
            replies[index] = RelayIngressProbe.reply(Data(), status: 403); let probe = RelayIngressProbe(replies)
            do { _ = try await create(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
            catch { XCTAssertEqual(error as? CloudflareProvisioningError, .unauthorized) }
            XCTAssertEqual(try f.read()?.phase, .prepared); let requests = await probe.all(); XCTAssertEqual(requests.count, index + 1)
        }
    }
    func testAlreadyCancelledCallCreatesNoRecordAndSendsNoRequest() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let expected = try f.base.h.progress(owner), probe = RelayIngressProbe([])
        let task = Task { @Sendable in withUnsafeCurrentTask { $0?.cancel() }; return try await self.create(owner, f: f, expected: expected, probe: probe) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertNil(try f.read()); let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
    func testWrongCallerAndChangedProposalHaveNoEffects() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let proposal = try f.base.h.f.proposal(), expected = try f.base.h.progress(owner), probe = RelayIngressProbe([])
        for (uid, selected) in [(getuid() + 1, proposal), (getuid(), PortableSetup(defaults: proposal.defaults))] {
            do { _ = try await owner.createImportedDNSRecord(callerUID: uid, expected: expected, proposal: selected, send: { try await probe.send($0) }); XCTFail() } catch {}
        }
        XCTAssertNil(try f.read()); let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
    func testPreflightTransportFailureCannotHideALateDNSReplacement() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }; var replies = try steps(f); replies[11] = .lost
        let probe = RelayIngressProbe(replies, hook: { count, _ in if count == 12 { try self.replaceFile(f.path, bytes: XCTUnwrap(f.read()).bytes) } })
        do { _ = try await create(owner, f: f, expected: f.base.h.progress(owner), probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
        XCTAssertEqual(try f.read()?.phase, .prepared)
    }
    func testCreatedRecordStillNeedsIndependentExactIDReadback() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }; let expected = try f.base.h.progress(owner)
        let record = try await create(owner, f: f, expected: expected, probe: RelayIngressProbe(steps(f)))
        let probe = try RelayIngressProbe([steps(f)[0], RelayIngressProbe.reply(f.dnsReply())])
        let observed = try await owner.inspectImportedDNSRecord(callerUID: getuid(), expected: expected, proposal: f.base.h.f.proposal(), send: { try await probe.send($0) })
        XCTAssertNoThrow(try observed.validate(expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel, application: f.access, record: record))
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
    }
    func testMissingShadowMetadataRetainsUnknownAndCannotReplayCreation() async throws {
        for null in [false, true] {
            let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
            var replies = try steps(f)
            let body = null ? try f.dnsReply(changes: ["meta": NSNull()]) : try f.dnsReply(omitting: ["meta"])
            replies[12] = RelayIngressProbe.reply(body)
            let expected = try f.base.h.progress(owner), probe = RelayIngressProbe(replies)
            let record = try await create(owner, f: f, expected: expected, probe: probe)
            XCTAssertEqual(record.phase, .unknown); XCTAssertNil(record.dnsRecordID)
            XCTAssertEqual(try f.read(), record)
            let requests = await probe.all(); XCTAssertEqual(requests.filter { $0.httpMethod == "POST" }.count, 1)
            let again = try RelayIngressProbe([steps(f)[0]])
            do { _ = try await create(owner, f: f, expected: expected, probe: again); XCTFail() }
            catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
            let repeated = await again.all(); XCTAssertEqual(repeated.count, 1)
            XCTAssertTrue(repeated.allSatisfy { $0.httpMethod == "GET" })
        }
    }

}
