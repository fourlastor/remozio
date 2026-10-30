import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Synthetic credentials and owned state test the request boundary. No native endpoint or provider is contacted.
final class SetupPortableImportOperationTests: XCTestCase, @unchecked Sendable {
    private struct Fixture {
        let h: RelayProvisioningFixture
        let owner: SetupAccountOwner
        let expected: SetupPortableImportProgress
        let proposal: PortableSetup
        init() throws {
            let host = try RelayProvisioningFixture(), endpointOwner = try host.owner()
            h = host; owner = endpointOwner; expected = try host.progress(endpointOwner); proposal = try host.f.proposal()
        }
    }
    private func request(_ f: Fixture, action: SetupPortableImportOperation.Action = .retain,
                         accepted: Bool = false) throws -> SetupPortableImportOperation {
        try .init(action: action, expected: f.expected, proposal: f.proposal, fileCustodyAccepted: accepted, expectedRejectedRecordDigest: action.retryResource == nil ? nil : Data(repeating: 7, count: 32))
    }
    func testEveryActionHasACanonicalBoundedRequestAndRedactedInspection() throws {
        let f = try Fixture(); defer { try? f.owner.close() }
        for action in SetupPortableImportOperation.Action.allCases where action != .activateGateway {
            let value = try request(f, action: action, accepted: action.needsCustody), bytes = try value.bytes
            XCTAssertLessThanOrEqual(bytes.count, SetupPortableImportOperation.maximumBytes)
            XCTAssertEqual(try SetupPortableImportOperation.decode(bytes).bytes, bytes)
            XCTAssertNotNil(bytes.range(of: Data("synthetic-provider-token-only".utf8)))
            XCTAssertEqual(String(reflecting: value), "SetupPortableImportOperation(redacted)")
            var inspected = ""; dump(value, to: &inspected)
            XCTAssertLessThan(inspected.count, 100); XCTAssertFalse(inspected.contains("synthetic-provider-token-only"))
        }
    }
    func testVersionOneBytesRemainExactAndRefusalRequestsUseClosedVersionTwo() throws {
        let f = try Fixture(); defer { try? f.owner.close() }
        for action in SetupPortableImportOperation.Action.allCases where action != .activateGateway {
            let value = try request(f, action: action, accepted: action.needsCustody)
            var fields: [UInt64: CBORValue] = [0: .unsigned(action.retryResource == nil ? 1 : 2),
                1: .text("remozio-portable-import-operation"), 2: .unsigned(action.rawValue), 3: .bytes(try f.expected.bytes),
                4: .bytes(try f.proposal.canonicalBytes()), 5: .boolean(action.needsCustody)]
            if action.retryResource != nil { fields[6] = .bytes(Data(repeating: 7, count: 32)) }
            XCTAssertEqual(try value.bytes, try DeterministicCBOR.encode(.map(fields), limits: .init(maxBytes: 70_000, maxDepth: 1, maxItems: 15)))
            XCTAssertEqual(value.requiresRecoveryHandshake, action.retryResource != nil)
        }
        for action: SetupPortableImportOperation.Action in [.prepareRefusedTunnelRetry, .prepareRefusedAccessRetry, .prepareRefusedDNSRetry] {
            for digest: Data? in [nil, Data(), Data(repeating: 0, count: 31), Data(repeating: 0, count: 33)] {
                XCTAssertThrowsError(try SetupPortableImportOperation(action: action, expected: f.expected, proposal: f.proposal, expectedRejectedRecordDigest: digest))
            }
            let value = try request(f, action: action)
            guard case .map(let original) = try DeterministicCBOR.decode(value.bytes, limits: SetupPortableImportOperation.limits) else { return XCTFail() }
            for (key, field): (UInt64, CBORValue) in [(0, .unsigned(1)), (0, .unsigned(3)), (2, .unsigned(0)), (5, .boolean(true)),
                (6, .null), (6, .bytes(Data(repeating: 0, count: 31))), (7, .null)] {
                var changed = original; changed[key] = field
                XCTAssertThrowsError(try SetupPortableImportOperation.decode(DeterministicCBOR.encode(.map(changed), limits: .init(maxBytes: 70_000, maxDepth: 1, maxItems: 20))))
            }
            var missing = original; missing.removeValue(forKey: 6)
            XCTAssertThrowsError(try SetupPortableImportOperation.decode(DeterministicCBOR.encode(.map(missing), limits: SetupPortableImportOperation.limits)))
        }
        XCTAssertThrowsError(try SetupPortableImportOperation(action: .retain, expected: f.expected, proposal: f.proposal, expectedRejectedRecordDigest: Data(repeating: 0, count: 32)))
    }
    func testRetryFactoryRequiresAReviewedProposalAndAnActuallyRejectedResource() throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let prepared = try f.begin(), sent = try prepared.transition(to: .dispatched), rejected = try sent.transition(to: .rejected, refusal: .unauthorized)
        try f.replace(sent, previous: prepared); try f.replace(rejected, previous: sent)
        let recovery = try XCTUnwrap(owner.portableImportRecovery(callerUID: getuid()))
        let reviewed = ReviewedSetupFile(proposal: try f.base.h.f.proposal()); defer { reviewed.close() }
        for resource: SetupPortableImportRecovery.Resource in [.tunnel, .accessApplication] {
            XCTAssertThrowsError(try reviewed.refusalRetryOperation(resource: resource, recovery: recovery))
        }
        let value = try reviewed.refusalRetryOperation(resource: .dnsRecord, recovery: recovery)
        XCTAssertEqual(value.action, .prepareRefusedDNSRetry); XCTAssertEqual(value.expected, recovery.progress)
        XCTAssertEqual(value.expectedRejectedRecordDigest, recovery.rejectedRecord(for: .dnsRecord)?.recordDigest)
        let result = try SetupPortableImportOperationResult(request: value, progress: value.expected, status: .applied)
        let changed = try SetupPortableImportOperation(action: value.action, expected: value.expected, proposal: f.base.h.f.proposal(), expectedRejectedRecordDigest: Data(repeating: 0, count: 32))
        XCTAssertThrowsError(try SetupPortableImportOperationResult.decode(result.bytes, request: changed))
        for status: SetupPortableImportOperationResult.Status in [.waitingForCleanup, .requiresReconciliation, .providerRejected] {
            XCTAssertThrowsError(try SetupPortableImportOperationResult(request: value, progress: value.expected, status: status))
        }
        let other = ReviewedSetupFile(proposal: PortableSetup(defaults: value.proposal.defaults)); defer { other.close() }
        XCTAssertThrowsError(try other.refusalRetryOperation(resource: .dnsRecord, recovery: recovery))
        reviewed.close(); XCTAssertThrowsError(try reviewed.refusalRetryOperation(resource: .dnsRecord, recovery: recovery))
    }
    func testDispatcherRefusesEveryChangedResourceDigestBeforeProviderReads() async throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }
        let first = try f.begin(), sent = try first.transition(to: .dispatched), rejected = try sent.transition(to: .rejected, refusal: .unauthorized)
        try f.replace(sent, previous: first); try f.replace(rejected, previous: sent)
        let before = try XCTUnwrap(owner.portableImportRecovery(callerUID: getuid()))
        for action: SetupPortableImportOperation.Action in [.prepareRefusedTunnelRetry, .prepareRefusedAccessRetry, .prepareRefusedDNSRetry] {
            let value = try SetupPortableImportOperation(action: action, expected: before.progress, proposal: f.base.h.f.proposal(), expectedRejectedRecordDigest: Data(repeating: 0, count: 32))
            do { _ = try await owner.performPortableImportOperation(callerUID: getuid(), request: value); XCTFail() }
            catch { XCTAssertEqual(error as? RelayProvisioningError, .staleRecord) }
            XCTAssertEqual(try owner.portableImportRecovery(callerUID: getuid()), before)
        }
    }
    func testUnknownVersionsActionsFieldsAndMalformedPayloadsRefuse() throws {
        let f = try Fixture(); defer { try? f.owner.close() }
        let bytes = try request(f).bytes
        guard case .map(let original) = try DeterministicCBOR.decode(bytes, limits: SetupPortableImportOperation.limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("other-purpose")), (2, .unsigned(999)),
            (3, .bytes(Data())), (4, .bytes(Data())), (5, .unsigned(1)), (6, .null)] {
            var fields = original; fields[key] = value
            XCTAssertThrowsError(try SetupPortableImportOperation.decode(DeterministicCBOR.encode(.map(fields), limits: .init(maxBytes: 100_000, maxDepth: 1, maxItems: 20))))
        }
        XCTAssertThrowsError(try SetupPortableImportOperation.decode(bytes + Data([0])))
        XCTAssertThrowsError(try SetupPortableImportOperation.decode(Data(repeating: 0, count: SetupPortableImportOperation.maximumBytes + 1)))
    }
    func testCustodyFlagsAndProviderChoicesCannotBeRepurposedForAnotherAction() throws {
        let f = try Fixture(); defer { try? f.owner.close() }
        for action in SetupPortableImportOperation.Action.allCases where !action.needsCustody {
            XCTAssertThrowsError(try request(f, action: action, accepted: true))
        }
        XCTAssertThrowsError(try request(f, action: .activateGateway))
        let different = PortableSetup(defaults: f.proposal.defaults)
        XCTAssertThrowsError(try SetupPortableImportOperation(action: .retain, expected: f.expected, proposal: different))
        for action in SetupPortableImportOperation.Action.allCases where action.usesCloudflare {
            XCTAssertThrowsError(try SetupPortableImportOperation(action: action, expected: f.expected, proposal: different))
        }
    }
    func testReplyBindsTheExactRequestAndContainsNoProviderCredential() throws {
        let f = try Fixture(); defer { try? f.owner.close() }
        let value = try request(f), result = try SetupPortableImportOperationResult(request: value, progress: f.expected, status: .applied)
        let bytes = try result.bytes
        XCTAssertEqual(try SetupPortableImportOperationResult.decode(bytes, request: value), result)
        XCTAssertNil(bytes.range(of: Data("synthetic-provider-token-only".utf8)))
        let other = try request(f, action: .prepareRelayPlan)
        XCTAssertThrowsError(try SetupPortableImportOperationResult.decode(bytes, request: other))
        XCTAssertThrowsError(try SetupPortableImportOperationResult(request: value, progress: f.expected, status: .waitingForCleanup))
        XCTAssertThrowsError(try SetupPortableImportOperationResult(request: value, progress: f.expected, status: .requiresReconciliation))
        let complete = try request(f, action: .complete)
        XCTAssertThrowsError(try SetupPortableImportOperationResult(request: complete, progress: f.expected, status: .applied))
    }
    func testResultRefusesAnotherAccountAndUnknownStatusOrRequestDigest() throws {
        let f = try Fixture(), other = try Fixture(); defer { try? f.owner.close(); try? other.owner.close() }
        let value = try request(f)
        XCTAssertThrowsError(try SetupPortableImportOperationResult(request: value, progress: other.expected, status: .applied))
        let result = try SetupPortableImportOperationResult(request: value, progress: f.expected, status: .applied)
        let limits = try CBORLimits(maxBytes: 1536, maxDepth: 1, maxItems: 20)
        guard case .map(let original) = try DeterministicCBOR.decode(result.bytes, limits: limits) else { return XCTFail() }
        for (key, changed): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("other-purpose")), (2, .bytes(Data(repeating: 0, count: 32))),
            (3, .unsigned(99)), (4, .bytes(Data())), (5, .unsigned(99)), (6, .null)] {
            var fields = original; fields[key] = changed
            XCTAssertThrowsError(try SetupPortableImportOperationResult.decode(DeterministicCBOR.encode(.map(fields), limits: limits), request: value))
        }
    }
    func testDispatcherRetainsOnlyTheReviewedOperationAndDoesNotReserveItsOwnAsyncSlot() async throws {
        let f = try Fixture(); defer { try? f.owner.close() }
        let value = try request(f)
        let result = try await f.owner.performPortableImportOperation(callerUID: getuid(), request: value)
        XCTAssertEqual(result.status, .applied); XCTAssertEqual(result.progress, f.expected)
        XCTAssertNoThrow(try result.validate(value))
        let repeated = try await f.owner.performPortableImportOperation(callerUID: getuid(), request: value)
        XCTAssertEqual(repeated, result); XCTAssertEqual(try f.h.progress(f.owner), f.expected)
    }
    func testWrongCallerStaleScopeAndCancellationCannotDispatchAnOperation() async throws {
        let f = try Fixture(); defer { try? f.owner.close() }; let value = try request(f)
        do { _ = try await f.owner.performPortableImportOperation(callerUID: getuid() + 1, request: value); XCTFail() } catch {}
        let cancelled = Task { @Sendable in
            withUnsafeCurrentTask { $0?.cancel() }
            return try await f.owner.performPortableImportOperation(callerUID: getuid(), request: value)
        }
        do { _ = try await cancelled.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        try f.h.machine { machine in
            let material = try RuntimePreparationMaterial.create(services: f.h.services,
                notValidBefore: Date().addingTimeInterval(-60), notValidAfter: Date().addingTimeInterval(600))
            try machine.retainRuntimeMaterial(material.reference)
        }
        do { _ = try await f.owner.performPortableImportOperation(callerUID: getuid(), request: value); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
    }
    func testAppliedRuntimeAndGatewayRepliesRequireTheirPublishedProgress() throws {
        let f = try Fixture(); defer { try? f.owner.close() }
        for action: SetupPortableImportOperation.Action in [.prepareRuntime, .prepareGateway] {
            let value = try request(f, action: action, accepted: true)
            XCTAssertThrowsError(try SetupPortableImportOperationResult(request: value, progress: f.expected, status: .applied))
        }
    }

}
