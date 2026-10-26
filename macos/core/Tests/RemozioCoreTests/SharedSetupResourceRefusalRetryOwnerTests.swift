import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned files and synthetic GET replies only. Native administrator and XPC admission are not exercised.
final class SharedSetupResourceRefusalRetryOwnerTests: XCTestCase, @unchecked Sendable {
    private struct Refused: Error {}
    private enum Resource: CaseIterable, Sendable { case accessApplication, dnsRecord }
    private struct Record: Equatable, Sendable {
        let bytes: Data
        let id: Data
        let revision: Data
        let attempt: Data
        let number: UInt64
        let phase: UInt64
        let requestDigest: Data
        let refusalCleared: Bool
        var digest: Data { Data(SHA256.hash(data: bytes)) }
        init(_ value: SharedSetupAccessApplicationRecord) {
            bytes = value.bytes; id = value.recordID; revision = value.revision; attempt = value.attemptID
            number = value.attemptNumber; phase = value.phase.rawValue; requestDigest = value.requestDigest; refusalCleared = value.refusal == nil
        }
        init(_ value: SharedSetupDNSRecord) {
            bytes = value.bytes; id = value.recordID; revision = value.revision; attempt = value.attemptID
            number = value.attemptNumber; phase = value.phase.rawValue; requestDigest = value.requestDigest; refusalCleared = value.refusal == nil
        }
    }
    private final class Fixture: @unchecked Sendable {
        let resource: Resource
        let application: AccessApplicationFixture
        let dns: DNSRecordFixture?
        let original: Record
        var host: RelayProvisioningFixture { application.h }
        var path: String { dns?.path ?? application.path }
        var parentPath: String {
            if dns != nil { return application.path }
            return URL(fileURLWithPath: host.path).deletingLastPathComponent().appendingPathComponent(AdministrativeSetupPublication.File.importRelayProvisioning(accountID: host.intent.scope.accountID).name).path
        }
        var parentBytes: Data { dns?.access.bytes ?? application.tunnel.bytes }
        init(_ resource: Resource, phase: UInt64 = 4) throws {
            self.resource = resource
            if resource == .accessApplication {
                let f = try AccessApplicationFixture(); application = f; dns = nil
                let first = try f.begin()
                if phase == 1 { original = Record(first); return }
                let sent = try first.transition(to: .dispatched); try f.replace(sent, first)
                if phase == 2 { original = Record(sent); return }
                let next: SharedSetupAccessApplicationRecord
                switch phase {
                case 3: next = try sent.transition(to: .created, applicationID: "22222222-2222-4222-8222-222222222222", audience: String(repeating: "a", count: 64))
                case 4: next = try sent.transition(to: .rejected, refusal: .unauthorized)
                case 5: next = try sent.transition(to: .unknown)
                default: throw Refused()
                }
                try f.replace(next, sent); original = Record(next)
            } else {
                let f = try DNSRecordFixture(); application = f.base; dns = f
                let first = try f.begin()
                if phase == 1 { original = Record(first); return }
                let sent = try first.transition(to: .dispatched); try f.replace(sent, previous: first)
                if phase == 2 { original = Record(sent); return }
                let next: SharedSetupDNSRecord
                switch phase {
                case 3: next = try sent.transition(to: .created, dnsRecordID: DNSRecordFixture.providerID)
                case 4: next = try sent.transition(to: .rejected, refusal: .unauthorized)
                case 5: next = try sent.transition(to: .unknown)
                default: throw Refused()
                }
                try f.replace(next, previous: sent); original = Record(next)
            }
        }
        func read() throws -> Record {
            if let dns { return try Record(XCTUnwrap(dns.read())) }
            return try Record(XCTUnwrap(application.read()))
        }
        func steps() throws -> [RelayIngressProbe.Step] {
            if let dns { return try RelayPublicationReplies.ownerSteps(dns) }
            return try [RelayIngressProbe.reply(RelayIngressProviderFixture.metadata(configuration: XCTUnwrap(host.f.proposal().cloudflare), plan: application.plan)),
                RelayIngressProbe.reply(RelayPrivateRouteReplies.page())]
        }
        func retry(_ owner: SetupAccountOwner, expected: SetupPortableImportProgress, probe: RelayIngressProbe,
                   uid: uid_t = getuid(), digest: Data? = nil, proposal: PortableSetup? = nil) async throws -> Record {
            let selected = try proposal ?? host.f.proposal(), digest = digest ?? original.digest
            let send: CloudflareProvisioningScopeClient.Send = { request in
                guard request.httpMethod == "GET", request.httpBody == nil else { XCTFail("Retry preparation attempted a provider mutation"); throw Refused() }
                return try await probe.send(request)
            }
            switch resource {
            case .accessApplication:
                return try Record(await owner.prepareRefusedImportedAccessApplicationRetry(callerUID: uid, expected: expected,
                    proposal: selected, expectedRecordDigest: digest, send: send))
            case .dnsRecord:
                return try Record(await owner.prepareRefusedImportedDNSRecordRetry(callerUID: uid, expected: expected,
                    proposal: selected, expectedRecordDigest: digest, send: send))
            }
        }
    }
    private func replace(_ path: String, bytes: Data) throws {
        let replacement = path + ".replacement"; try bytes.write(to: URL(fileURLWithPath: replacement))
        guard chmod(replacement, 0o600) == 0, rename(replacement, path) == 0 else { throw Refused() }
    }
    func testFreshReadOnlyPreflightPreparesOnlyTheExactRefusedAttempt() async throws {
        for resource in Resource.allCases {
            let f = try Fixture(resource), owner = try f.host.owner(); defer { try? owner.close() }
            let expected = try f.host.progress(owner), probe = try RelayIngressProbe(f.steps(), hook: { _, _ in
                try f.host.machine { machine in try machine.withSharedImportJournal { journal in XCTAssertEqual(try journal?.records(), [f.host.intent]) } }
                XCTAssertEqual(try f.read(), f.original)
            })
            let result = try await f.retry(owner, expected: expected, probe: probe)
            XCTAssertEqual(result.phase, 1); XCTAssertEqual(result.id, f.original.id); XCTAssertEqual(result.number, 2)
            XCTAssertNotEqual(result.attempt, f.original.attempt); XCTAssertNotEqual(result.revision, f.original.revision)
            XCTAssertEqual(result.requestDigest, f.original.requestDigest); XCTAssertTrue(result.refusalCleared)
            XCTAssertEqual(try f.read(), result); XCTAssertEqual(try f.host.progress(owner), expected)
            let requests = await probe.all(); XCTAssertEqual(requests.count, resource == .accessApplication ? 2 : 12)
            XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" && $0.httpBody == nil })
            let empty = RelayIngressProbe([])
            do { _ = try await f.retry(owner, expected: expected, probe: empty); XCTFail("Former digest rearmed another attempt") }
            catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
            let replay = await empty.all(); XCTAssertTrue(replay.isEmpty); XCTAssertEqual(try f.read(), result)
        }
    }
    func testNonrefusedRecordsCannotReadOrMutateTheProvider() async throws {
        for resource in Resource.allCases {
            for phase: UInt64 in [1, 2, 3, 5] {
                let f = try Fixture(resource, phase: phase), owner = try f.host.owner(); defer { try? owner.close() }
                let probe = RelayIngressProbe([])
                do { _ = try await f.retry(owner, expected: f.host.progress(owner), probe: probe); XCTFail("Nonrefused record was rearmed") }
                catch { XCTAssertEqual(error as? RelayProvisioningError, .invalidTransition) }
                let calls = await probe.all(); XCTAssertTrue(calls.isEmpty); XCTAssertEqual(try f.read(), f.original)
            }
        }
    }
    func testWrongCallerDigestAndProposalHaveNoEffects() async throws {
        for resource in Resource.allCases {
            let f = try Fixture(resource), owner = try f.host.owner(); defer { try? owner.close() }
            let expected = try f.host.progress(owner)
            for variant in 0..<4 {
                let probe = RelayIngressProbe([])
                do {
                    _ = try await f.retry(owner, expected: expected, probe: probe, uid: variant == 2 ? getuid() + 1 : getuid(),
                        digest: variant == 0 ? Data() : variant == 1 ? Data(repeating: 0, count: 32) : nil,
                        proposal: variant == 3 ? PortableSetup(defaults: f.host.f.proposal().defaults) : nil)
                    XCTFail("Wrong request scope was accepted")
                } catch {}
                let calls = await probe.all(); XCTAssertTrue(calls.isEmpty); XCTAssertEqual(try f.read(), f.original)
            }
        }
    }
    func testProviderReadFailureAtEveryReceiptRetainsTheRefusal() async throws {
        for resource in Resource.allCases {
            let count = resource == .accessApplication ? 2 : 12
            for index in 0..<count {
                let f = try Fixture(resource), owner = try f.host.owner(); defer { try? owner.close() }
                var steps = try f.steps(); steps[index] = .lost; let probe = RelayIngressProbe(steps)
                do { _ = try await f.retry(owner, expected: f.host.progress(owner), probe: probe); XCTFail("Uncertain read prepared a retry") } catch {}
                let calls = await probe.all(); XCTAssertEqual(calls.count, index + 1); XCTAssertEqual(try f.read(), f.original)
            }
        }
    }
    func testScopeChangeAtEveryReceiptStopsBeforeAnotherReadOrWrite() async throws {
        for resource in Resource.allCases {
            let count = resource == .accessApplication ? 2 : 12
            for index in 1...count {
                let f = try Fixture(resource), owner = try f.host.owner(); defer { try? owner.close() }
                let expected = try f.host.progress(owner), probe = try RelayIngressProbe(f.steps(), hook: { number, _ in
                    if number == index { try f.host.machine { machine in
                        let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision)
                    } }
                })
                do { _ = try await f.retry(owner, expected: expected, probe: probe); XCTFail("Changed scope prepared a retry") }
                catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
                let calls = await probe.all(); XCTAssertEqual(calls.count, index); XCTAssertEqual(try f.read(), f.original)
            }
        }
    }
    func testReplacementOfTheRecordOrItsParentStopsAfterTheCurrentRead() async throws {
        for resource in Resource.allCases {
            for parent in [false, true] {
                let f = try Fixture(resource), owner = try f.host.owner(); defer { try? owner.close() }
                let expected = try f.host.progress(owner), probe = try RelayIngressProbe(f.steps(), hook: { number, _ in
                    if number == 1 { try self.replace(parent ? f.parentPath : f.path, bytes: parent ? f.parentBytes : f.original.bytes) }
                })
                do { _ = try await f.retry(owner, expected: expected, probe: probe); XCTFail("Replaced file prepared a retry") }
                catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord, "Refusal: \(String(reflecting: error)); resource: \(resource); parent: \(parent)") }
                let calls = await probe.all(); XCTAssertEqual(calls.count, 1); XCTAssertEqual(try f.read(), f.original)
            }
        }
    }
    func testProviderConflictsAndUnresolvedCoverageLeaveTheRefusalIntact() async throws {
        for resource in Resource.allCases {
            let f = try Fixture(resource), owner = try f.host.owner(); defer { try? owner.close() }
            var steps = try f.steps(); let conflict = resource == .accessApplication ? 1 : 8
            steps[conflict] = try RelayIngressProbe.reply(RelayPrivateRouteReplies.page(results: [["id": "existing-resource", "domain": f.application.plan.hostname]]))
            let probe = RelayIngressProbe(steps)
            do { _ = try await f.retry(owner, expected: f.host.progress(owner), probe: probe); XCTFail("Observed conflict prepared a retry") } catch {}
            let calls = await probe.all(); XCTAssertEqual(calls.count, conflict + 1); XCTAssertEqual(try f.read(), f.original)
        }
        let f = try Fixture(.dnsRecord), owner = try f.host.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe(RelayPublicationReplies.ownerSteps(XCTUnwrap(f.dns),
            extraApplications: [AccessHostnameReplies.row(1, uri: f.application.plan.hostname)]))
        do { _ = try await f.retry(owner, expected: f.host.progress(owner), probe: probe); XCTFail("Unresolved coverage prepared a retry") }
        catch { XCTAssertEqual(error as? RelayProvisioningError, .requiresReconciliation) }
        XCTAssertEqual(try f.read(), f.original)
    }
    func testFailedFinalReadDoesNotHideAChangedLocalRecord() async throws {
        for resource in Resource.allCases {
            let f = try Fixture(resource), owner = try f.host.owner(); defer { try? owner.close() }
            var steps = try f.steps(); let count = steps.count; steps[count - 1] = .lost
            let probe = RelayIngressProbe(steps, hook: { number, _ in
                if number == count { try self.replace(f.path, bytes: f.original.bytes) }
            })
            do { _ = try await f.retry(owner, expected: f.host.progress(owner), probe: probe); XCTFail("Changed local record was accepted") }
            catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
            let calls = await probe.all(); XCTAssertEqual(calls.count, count); XCTAssertEqual(try f.read(), f.original)
        }
    }
    func testShutdownDuringReadRetainsTheRefusalAndDrainsTheOperation() async throws {
        for resource in Resource.allCases {
            let f = try Fixture(resource), owner = try f.host.owner(); defer { try? owner.close() }
            let probe = try RelayIngressProbe(f.steps(), hook: { number, _ in
                if number == 1 { XCTAssertThrowsError(try owner.close()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) } }
            })
            do { _ = try await f.retry(owner, expected: f.host.progress(owner), probe: probe); XCTFail("Closed owner prepared a retry") }
            catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
            XCTAssertEqual(try f.read(), f.original); XCTAssertNoThrow(try owner.close())
        }
    }
    func testCancellationDoesNotPrepareTheNextAttempt() async throws {
        for resource in Resource.allCases {
            let f = try Fixture(resource), owner = try f.host.owner(); defer { try? owner.close() }
            let expected = try f.host.progress(owner), probe = try RelayIngressProbe(f.steps(), hook: { _, _ in withUnsafeCurrentTask { $0?.cancel() } })
            let attempt = Task { try await f.retry(owner, expected: expected, probe: probe) }
            do { _ = try await attempt.value; XCTFail("Cancellation prepared a retry") }
            catch { XCTAssertTrue(error is CancellationError) }
            let calls = await probe.all(); XCTAssertEqual(calls.count, 1); XCTAssertEqual(try f.read(), f.original)
        }
    }
}
