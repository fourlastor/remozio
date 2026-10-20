import CryptoKit
import Foundation
import XCTest
@testable import RemozioCore

enum RelayPublicationReplies {
    static func steps(_ f: DNSRecordFixture, extraApplications: [[String: Any]] = []) throws -> [RelayIngressProbe.Step] {
        let empty = RelayIngressProbe.reply(try RelayPrivateRouteReplies.page())
        return try [empty, empty, RelayIngressProbe.reply(RelayIngressProviderFixture.ingress(configuration: XCTUnwrap(f.base.h.f.proposal().cloudflare), plan: f.base.plan)),
            RelayIngressProbe.reply(f.base.applicationReply()), empty,
            RelayIngressProbe.reply(AccessHostnameReplies.page([AccessHostnameReplies.own(f.base)] + extraApplications)),
            empty, empty, empty, empty]
    }
    static func ownerSteps(_ f: DNSRecordFixture, extraApplications: [[String: Any]] = []) throws -> [RelayIngressProbe.Step] {
        try [RelayIngressProbe.reply(RelayIngressProviderFixture.metadata(configuration: XCTUnwrap(f.base.h.f.proposal().cloudflare), plan: f.base.plan))] + steps(f, extraApplications: extraApplications)
    }
}

/// Synthetic observations apply the vendor contract. No durable permission or edge propagation is established.
final class CloudflareRelayPublicationPreflightTests: XCTestCase, @unchecked Sendable {
    private func inspect(_ f: DNSRecordFixture, probe: RelayIngressProbe) async throws -> CloudflareRelayPublicationPreflight {
        try await CloudflareRelayPublicationPreflightClient(send: { try await probe.send($0) }).inspect(XCTUnwrap(f.base.h.f.proposal().cloudflare),
            expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel, application: f.access)
    }
    func testCompositionReadsIngressAccessInventoryDNSAndPrivateRoutesWithoutMutation() async throws {
        let f = try DNSRecordFixture(), probe = try RelayIngressProbe(RelayPublicationReplies.steps(f))
        let result = try await inspect(f, probe: probe), requests = await probe.all()
        XCTAssertNoThrow(try result.validate(expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel, application: f.access))
        XCTAssertEqual(result.hostnameAssessment, .noOtherMatchObserved)
        XCTAssertEqual(requests.count, 10); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" && $0.httpBody == nil })
        XCTAssertEqual(requests.filter { $0.url?.path.hasSuffix("/teamnet/routes") == true }.count, 2)
        XCTAssertEqual(requests.filter { $0.url?.path.hasSuffix("/zerotrust/routes/hostname") == true }.count, 2)
        XCTAssertTrue(requests[2].url?.path.hasSuffix("/configurations") == true)
        XCTAssertTrue(requests[4].url?.path.hasSuffix("/policies") == true)
        XCTAssertTrue(requests[5].url?.path.hasSuffix("/access/apps") == true)
        XCTAssertEqual(requests[6].url?.query?.contains("name.exact="), true)
        XCTAssertEqual(requests[7].url?.query?.contains("shadowing_name="), true)
        XCTAssertEqual(String(reflecting: result), "CloudflareRelayPublicationPreflight(redacted)"); XCTAssertNil(try f.read())
    }
    func testExactHostnamePrecedesAnOrdinaryWildcardWithoutChangingTheApplication() async throws {
        let f = try DNSRecordFixture(), wildcard = "*." + f.base.plan.hostname.split(separator: ".").dropFirst().joined(separator: ".")
        let probe = try RelayIngressProbe(RelayPublicationReplies.steps(f, extraApplications: [AccessHostnameReplies.row(1, uri: wildcard)]))
        let result = try await inspect(f, probe: probe)
        XCTAssertEqual(result.hostnameAssessment, .exactHostnamePrecedesBroaderWildcardRoots)
        XCTAssertEqual(result.hostnameInventory.matches.last?.uri, wildcard)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 10); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
    }
    func testUnresolvedApplicationTypesRemainExplicitAndOtherMacsDoNotRequireAnEmptyAccount() async throws {
        let f = try DNSRecordFixture()
        for unknown in [false, true] {
            let rows = [AccessHostnameReplies.row(1, uri: "other-mac.invalid", type: unknown ? "future-type" : "self_hosted")]
            let probe = try RelayIngressProbe(RelayPublicationReplies.steps(f, extraApplications: rows))
            let result = try await inspect(f, probe: probe)
            XCTAssertEqual(result.hostnameInventory.applicationCount, 2)
            XCTAssertEqual(result.hostnameAssessment, unknown ? .requiresPrecedenceVerification : .noOtherMatchObserved)
        }
    }
    func testPrivateRoutesBeforeOrAfterTheOtherChecksAndDNSConflictsStopTheComposition() async throws {
        let f = try DNSRecordFixture()
        for index in [0, 1, 6, 7, 8, 9] {
            var steps = try RelayPublicationReplies.steps(f)
            steps[index] = RelayIngressProbe.reply(try RelayPrivateRouteReplies.page(results: [["id": "existing-resource"]]))
            let probe = RelayIngressProbe(steps)
            do { _ = try await inspect(f, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, index + 1); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
        }
    }
    func testAnAllowingAccessPolicyStopsBeforeDNSInspection() async throws {
        let f = try DNSRecordFixture(); var steps = try RelayPublicationReplies.steps(f)
        steps[4] = RelayIngressProbe.reply(try RelayPrivateRouteReplies.page(results: [["decision": "bypass"]]))
        let probe = RelayIngressProbe(steps)
        do { _ = try await inspect(f, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 5)
    }
    func testDeniedRequestsAtEveryStageCannotReturnPartialEvidence() async throws {
        let f = try DNSRecordFixture()
        for index in 0..<10 {
            var steps = try RelayPublicationReplies.steps(f); steps[index] = RelayIngressProbe.reply(Data(), status: 403)
            let probe = RelayIngressProbe(steps)
            do { _ = try await inspect(f, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .unauthorized) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, index + 1)
        }
    }
    func testCancellationAtEveryReceiptStopsFurtherRequests() async throws {
        let f = try DNSRecordFixture()
        for index in 1...10 {
            let probe = try RelayIngressProbe(RelayPublicationReplies.steps(f), hook: { count, _ in if count == index { withUnsafeCurrentTask { $0?.cancel() } } })
            let task = Task { @Sendable in try await self.inspect(f, probe: probe) }
            do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, index)
        }
    }
    func testTheCompleteObservationBindsTheExactAccessCreationRecord() async throws {
        let f = try DNSRecordFixture(), probe = try RelayIngressProbe(RelayPublicationReplies.steps(f)), result = try await inspect(f, probe: probe)
        let other = try SharedSetupAccessApplicationRecord(expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel)
            .transition(to: .dispatched).transition(to: .created, applicationID: XCTUnwrap(f.access.applicationID), audience: XCTUnwrap(f.access.audience))
        XCTAssertThrowsError(try result.validate(expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel, application: other))
    }
    func testAChangedInventoryOwnDestinationDoesNotClaimNoOtherMatch() async throws {
        let f = try DNSRecordFixture(); var steps = try RelayPublicationReplies.steps(f)
        let own = AccessHostnameReplies.own(f.base, extra: ["destinations": [["type": "public", "uri": f.base.plan.hostname,
            "overrides": [["behavior": "public", "path_pattern": "/*"]]]]])
        steps[5] = RelayIngressProbe.reply(try AccessHostnameReplies.page([own]))
        let probe = RelayIngressProbe(steps), result = try await inspect(f, probe: probe)
        XCTAssertEqual(result.hostnameAssessment, .requiresPrecedenceVerification)
    }
    func testAlreadyCancelledCompositionSendsNoCredentials() async throws {
        let f = try DNSRecordFixture(), probe = RelayIngressProbe([])
        let task = Task { @Sendable in withUnsafeCurrentTask { $0?.cancel() }; return try await self.inspect(f, probe: probe) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
    func testSeveralBroaderWildcardRootsUseDocumentedHostnamePrecedence() async throws {
        let f = try DNSRecordFixture(), suffix = f.base.plan.hostname.split(separator: ".").dropFirst().joined(separator: ".")
        let rows = [AccessHostnameReplies.row(1, uri: "*." + suffix), AccessHostnameReplies.row(2, uri: "*." + suffix + "/*"),
            AccessHostnameReplies.row(3, uri: "*." + suffix + "/")]
        let probe = try RelayIngressProbe(RelayPublicationReplies.steps(f, extraApplications: rows))
        let observed = try await inspect(f, probe: probe)
        XCTAssertEqual(observed.hostnameAssessment, .exactHostnamePrecedesBroaderWildcardRoots)
        XCTAssertEqual(observed.hostnameInventory.matches.count, 4)
        let requests = await probe.all(); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
    }
    func testAnExactHostnameCompetitorNeverUsesTheWildcardException() async throws {
        let f = try DNSRecordFixture(), probe = try RelayIngressProbe(RelayPublicationReplies.steps(f,
            extraApplications: [AccessHostnameReplies.row(1, uri: f.base.plan.hostname)]))
        let observed = try await inspect(f, probe: probe)
        XCTAssertEqual(observed.hostnameAssessment, .requiresPrecedenceVerification)
    }
    func testPathSpecificExactOrWildcardDestinationsNeedSeparateAssessment() async throws {
        let f = try DNSRecordFixture(), wildcard = "*." + f.base.plan.hostname.split(separator: ".").dropFirst().joined(separator: ".")
        for uri in [f.base.plan.hostname + "/admin", wildcard + "/admin", wildcard + "/admin/*"] {
            let probe = try RelayIngressProbe(RelayPublicationReplies.steps(f, extraApplications: [AccessHostnameReplies.row(1, uri: uri)]))
            let observed = try await inspect(f, probe: probe)
            XCTAssertEqual(observed.hostnameAssessment, .requiresPrecedenceVerification)
        }
    }
    func testUnknownApplicationTypesStillPreventAWildcardAssessment() async throws {
        let f = try DNSRecordFixture(), wildcard = "*." + f.base.plan.hostname.split(separator: ".").dropFirst().joined(separator: ".")
        let probe = try RelayIngressProbe(RelayPublicationReplies.steps(f, extraApplications: [
            AccessHostnameReplies.row(1, uri: wildcard), AccessHostnameReplies.row(2, uri: "other.invalid", type: "future-type")]))
        let observed = try await inspect(f, probe: probe)
        XCTAssertEqual(observed.hostnameAssessment, .requiresPrecedenceVerification)
    }
    func testPublicOverridesOnBroaderWildcardsRemainExplicitlyUnresolved() async throws {
        let f = try DNSRecordFixture(), wildcard = "*." + f.base.plan.hostname.split(separator: ".").dropFirst().joined(separator: ".")
        var row = AccessHostnameReplies.row(1, uri: wildcard)
        row["destinations"] = [["type": "public", "uri": wildcard, "overrides": [["behavior": "public", "path_pattern": "/*"]]]]
        let probe = try RelayIngressProbe(RelayPublicationReplies.steps(f, extraApplications: [row]))
        let observed = try await inspect(f, probe: probe)
        XCTAssertEqual(observed.hostnameAssessment, .requiresPrecedenceVerification)
    }
    func testAdditionalOwnedDestinationsCannotReuseTheRootWildcardException() async throws {
        let f = try DNSRecordFixture(), wildcard = "*." + f.base.plan.hostname.split(separator: ".").dropFirst().joined(separator: ".")
        var steps = try RelayPublicationReplies.steps(f)
        let own = AccessHostnameReplies.own(f.base, extra: ["destinations": [["type": "public", "uri": f.base.plan.hostname],
            ["type": "public", "uri": wildcard]]])
        steps[5] = RelayIngressProbe.reply(try AccessHostnameReplies.page([own]))
        let observed = try await inspect(f, probe: RelayIngressProbe(steps))
        XCTAssertEqual(observed.hostnameAssessment, .requiresPrecedenceVerification)
    }

}
