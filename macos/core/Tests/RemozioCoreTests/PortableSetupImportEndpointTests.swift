import Darwin
import Foundation
import Security
import Synchronization
import XCTest
@testable import RemozioCore

/// Same-owner storage and logical invocation/rights hooks do not prove native XPC or real administrator authorization.
final class PortableSetupImportEndpointTests: XCTestCase, @unchecked Sendable {
    private struct Refused: Error {}
    private struct Fixture: Sendable {
        let h: RelayProvisioningFixture
        let owner: SetupAccountOwner
        let request: SetupPortableImportOperation
        init(supported: Bool = true) throws {
            let host = try RelayProvisioningFixture(); h = host
            let f = host.f.accountFixture
            let bridge = GatewaySetupImportedRuntimeOperations(initialize: { _, _, _, _ in throw Refused() },
                activate: { _, _, _, _, _ in throw Refused() })
            owner = try .init(openMachine: { try f.open() }, expectedReleaseDigest: f.release,
                resume: { _, _ in throw Refused() }, accountCodePolicy: f.policy,
                lookupAccount: { uid in guard uid == f.identity.uid else { throw AdministrativeSetupError.wrongAccount }; return f.identity },
                importedGatewayOperation: supported ? bridge : nil)
            request = try .init(action: .retain, expected: host.progress(owner), proposal: host.f.proposal())
        }
    }
    private var form: Data { Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size) }
    func testHandshakeRequiresTheNativeImportDependencyAndOldHelloCannotAuthorizeImport() throws {
        for supported in [false, true] {
            let f = try Fixture(supported: supported); defer { try? f.owner.close() }
            let value = Mutex<UInt64?>(nil)
            let endpoint = AdministrativeSetupXPCEndpoint(owner: f.owner, verify: { getuid() }, authorize: { _ in XCTFail() }, invalidate: {})
            endpoint.portableImportHello { received in value.withLock { $0 = received } }
            XCTAssertEqual(value.withLock { $0 }, supported ? 9 : 0); endpoint.close()
        }
        let f = try Fixture(); defer { try? f.owner.close() }
        let endpoint = AdministrativeSetupXPCEndpoint(owner: f.owner, verify: { getuid() }, authorize: { _ in XCTFail() }, invalidate: {})
        endpoint.hello { XCTAssertEqual($0, 1) }
        let refused = expectation(description: "old hello cannot dispatch import")
        endpoint.performPortableImport(try f.request.bytes, authorization: form) { XCTAssertNil($0); refused.fulfill() }
        wait(for: [refused], timeout: 2)
    }
    func testAllLegacyHandshakesRefuseRecoveryBeforeRightsOrStorageMutation() throws {
        for version in 1...9 {
            let f = try Fixture(); defer { try? f.owner.close() }
            let endpoint = AdministrativeSetupXPCEndpoint(owner: f.owner, verify: { getuid() }, authorize: { _ in XCTFail() }, invalidate: {})
            let reply: @Sendable (UInt64) -> Void = { XCTAssertEqual($0, UInt64(version)) }
            switch version {
            case 1: endpoint.hello(reply: reply)
            case 2: endpoint.enrollmentHello(reply: reply)
            case 3: endpoint.serviceAccountsHello(reply: reply)
            case 4: endpoint.runtimeHello(reply: reply)
            case 5: endpoint.activationHello(reply: reply)
            case 6: endpoint.gatewayHello(reply: reply)
            case 7: endpoint.gatewayActivationHello(reply: reply)
            case 8: endpoint.gatewaySettingsHello(reply: reply)
            default: endpoint.portableImportHello(reply: reply)
            }
            let called = Mutex(false)
            endpoint.portableImportRecovery { XCTAssertNil($0); called.withLock { $0 = true } }
            XCTAssertTrue(called.withLock { $0 }); XCTAssertNil(try f.h.readPlan())
            XCTAssertEqual(try f.h.progress(f.owner), f.request.expected); endpoint.close()
        }
    }
    func testRecoveryNegotiationRequiresSupportAndReadRechecksInvocationWithoutRights() throws {
        let unsupported = try Fixture(supported: false); defer { try? unsupported.owner.close() }
        let denied = AdministrativeSetupXPCEndpoint(owner: unsupported.owner, verify: { getuid() }, authorize: { _ in XCTFail() }, invalidate: {})
        denied.portableImportRecoveryHello { XCTAssertEqual($0, 0) }; denied.close()
        let f = try Fixture(); defer { try? f.owner.close() }
        let uid = Mutex(getuid()), replies = Mutex(0), calls = Mutex(0)
        let endpoint = AdministrativeSetupXPCEndpoint(owner: f.owner, verify: { calls.withLock { $0 += 1 }; return uid.withLock { $0 } }, authorize: { _ in XCTFail() }, invalidate: {})
        endpoint.portableImportRecoveryHello { XCTAssertEqual($0, 10) }
        endpoint.portableImportRecovery { bytes in
            do { XCTAssertEqual(try SetupPortableImportRecovery.decode(XCTUnwrap(bytes)).progress, f.request.expected) }
            catch { XCTFail("Invalid recovery metadata") }
            replies.withLock { $0 += 1 }
        }
        XCTAssertEqual(replies.withLock { $0 }, 1); XCTAssertEqual(calls.withLock { $0 }, 2)
        XCTAssertNil(try f.h.readPlan()); XCTAssertEqual(try f.h.progress(f.owner), f.request.expected)
        uid.withLock { $0 += 1 }
        endpoint.portableImportRecovery { bytes in
            XCTAssertTrue(bytes == nil || bytes == Data()); replies.withLock { $0 += 1 }
        }
        XCTAssertEqual(replies.withLock { $0 }, 2); XCTAssertEqual(calls.withLock { $0 }, 3)
        endpoint.close()
    }
    func testAuthorizedRetentionRepliesWithTheBoundResultAndPinsAdmissionThroughCallback() async throws {
        let f = try Fixture(); defer { try? f.owner.close() }
        let rights = Mutex(0), replied = expectation(description: "reply")
        let endpoint = AdministrativeSetupXPCEndpoint(owner: f.owner, verify: { getuid() }, authorize: { _ in rights.withLock { $0 += 1 } }, invalidate: {})
        endpoint.portableImportHello { XCTAssertEqual($0, 9) }
        endpoint.performPortableImport(try f.request.bytes, authorization: form) { bytes in
            do {
                let result = try SetupPortableImportOperationResult.decode(XCTUnwrap(bytes), request: f.request)
                XCTAssertEqual(result.progress, f.request.expected)
                XCTAssertThrowsError(try f.owner.close()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
            } catch { XCTFail("Invalid bound result") }
            replied.fulfill()
        }
        await fulfillment(of: [replied], timeout: 5); XCTAssertEqual(rights.withLock { $0 }, 1)
        endpoint.close(); try await f.owner.closeWhenIdle()
    }
    func testMalformedWrongUIDAndRefusedRightsNeverRetainOrAdvanceAnything() async throws {
        for variant in 0..<4 {
            let f = try Fixture(); defer { try? f.owner.close() }
            let rights = Mutex(0), replied = expectation(description: "refused")
            let uid = Mutex(getuid())
            let endpoint = AdministrativeSetupXPCEndpoint(owner: f.owner, verify: { uid.withLock { $0 } }, authorize: { _ in
                rights.withLock { $0 += 1 }; throw Refused()
            }, invalidate: {})
            endpoint.portableImportHello { XCTAssertEqual($0, 9) }
            if variant == 2 { uid.withLock { $0 += 1 } }
            let bytes = variant == 0 ? Data() : variant == 1 ? Data(repeating: 0, count: SetupPortableImportOperation.maximumBytes + 1) : try f.request.bytes
            endpoint.performPortableImport(bytes, authorization: form) { XCTAssertNil($0); replied.fulfill() }
            await fulfillment(of: [replied], timeout: 3)
            XCTAssertEqual(rights.withLock { $0 }, variant == 3 ? 1 : 0)
            XCTAssertEqual(try f.h.progress(f.owner), f.request.expected)
        }
    }
}
