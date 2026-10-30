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
        try .init(action: action, expected: f.expected, proposal: f.proposal, fileCustodyAccepted: accepted)
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
