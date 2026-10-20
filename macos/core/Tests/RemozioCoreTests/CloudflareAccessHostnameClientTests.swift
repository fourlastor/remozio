import CryptoKit
import Foundation
import XCTest
@testable import RemozioCore

enum AccessHostnameReplies {
    static func row(_ number: Int, uri: String, type: String = "self_hosted", extra: [String: Any] = [:]) -> [String: Any] {
        var result: [String: Any] = ["id": String(format: "%08x-1111-4111-8111-111111111111", number), "type": type, "domain": uri]
        for (key, value) in extra { result[key] = value }; return result
    }
    static func own(_ f: AccessApplicationFixture, extra: [String: Any] = [:]) -> [String: Any] {
        var result = row(0, uri: f.plan.hostname); result["id"] = "22222222-2222-4222-8222-222222222222"
        for (key, value) in extra { result[key] = value }; return result
    }
    static func page(_ rows: [[String: Any]], number: Int = 1, size: Int = 100, total: Int? = nil,
                     pages: Int? = nil, info changes: [String: Any] = [:], envelope extra: [String: Any] = [:]) throws -> Data {
        var info: [String: Any] = ["page": number, "per_page": size, "count": rows.count]
        if let total { info["total_count"] = total }; if let pages { info["total_pages"] = pages }
        for (key, value) in changes { info[key] = value }
        var result: [String: Any] = ["success": true, "errors": [], "result": rows, "result_info": info]
        for (key, value) in extra { result[key] = value }
        return try JSONSerialization.data(withJSONObject: result)
    }
}

/// Complete account inventory with synthetic replies. Routing precedence remains a separate provider gate.
final class CloudflareAccessHostnameClientTests: XCTestCase, @unchecked Sendable {
    private func inspect(_ f: AccessApplicationFixture, probe: RelayIngressProbe,
                         application: SharedSetupAccessApplicationRecord? = nil) async throws -> CloudflareAccessHostnameInventory {
        try await CloudflareAccessHostnameClient(send: { try await probe.send($0) }).inspect(XCTUnwrap(f.h.f.proposal().cloudflare),
            expected: f.h.intent, plan: f.plan, createdTunnel: f.tunnel, application: application ?? f.read() ?? f.retainCreated())
    }
    private func reply(_ rows: [[String: Any]], number: Int = 1, size: Int = 100, total: Int? = nil, pages: Int? = nil) throws -> RelayIngressProbe.Step {
        RelayIngressProbe.reply(try AccessHostnameReplies.page(rows, number: number, size: size, total: total, pages: pages))
    }
    func testEveryPageUsesTheBoundAccountWithoutDomainOrNameFilters() async throws {
        let f = try AccessApplicationFixture(), probe = try RelayIngressProbe([
            reply([AccessHostnameReplies.row(1, uri: "other.invalid"), AccessHostnameReplies.row(2, uri: "another.invalid")], size: 2, total: 3, pages: 2),
            reply([AccessHostnameReplies.own(f)], number: 2, size: 2, total: 3, pages: 2),
            reply([], number: 3, size: 2, total: 3, pages: 2)])
        let observed = try await inspect(f, probe: probe), requests = await probe.all()
        XCTAssertEqual(observed.applicationCount, 3); XCTAssertEqual(observed.matches.count, 1); XCTAssertEqual(requests.count, 3)
        for (index, request) in requests.enumerated() {
            XCTAssertEqual(request.httpMethod, "GET"); XCTAssertNil(request.httpBody)
            let url = try XCTUnwrap(URLComponents(url: XCTUnwrap(request.url), resolvingAgainstBaseURL: false))
            XCTAssertEqual(url.host, "api.cloudflare.com")
            XCTAssertEqual(url.path, "/client/v4/accounts/" + (try XCTUnwrap(f.h.f.proposal().cloudflare)).accountID + "/access/apps")
            XCTAssertEqual(Dictionary(uniqueKeysWithValues: (url.queryItems ?? []).map { ($0.name, $0.value ?? "") }),
                ["page": String(index + 1), "per_page": "100"])
        }
        XCTAssertEqual(String(reflecting: observed), "CloudflareAccessHostnameInventory(redacted)")
        XCTAssertEqual(String(reflecting: observed.matches[0]), "CloudflareAccessHostnameMatch(redacted)")
    }
    func testShortNonemptyPageCannotHideALaterHostnameOverlap() async throws {
        let f = try AccessApplicationFixture(), probe = try RelayIngressProbe([
            reply([AccessHostnameReplies.own(f)]),
            reply([AccessHostnameReplies.row(1, uri: f.plan.hostname)], number: 2),
            reply([], number: 3)])
        let observed = try await inspect(f, probe: probe)
        XCTAssertEqual(observed.applicationCount, 2)
        XCTAssertEqual(observed.matches.count, 2)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 3)
    }
    func testAdditionalDestinationFindsOverlapDespiteDifferentPrimaryDomain() async throws {
        let f = try AccessApplicationFixture()
        let alias = AccessHostnameReplies.row(1, uri: "unrelated.invalid", extra: ["destinations": [["type": "public", "uri": f.plan.hostname,
            "overrides": [["behavior": "public", "path_pattern": "/*"]]]]])
        let probe = try RelayIngressProbe([reply([AccessHostnameReplies.own(f), alias]), reply([], number: 2)])
        let observed = try await inspect(f, probe: probe)
        XCTAssertEqual(observed.matches.count, 2)
        XCTAssertEqual(observed.matches.last?.applicationID, "00000001-1111-4111-8111-111111111111")
        XCTAssertEqual(observed.matches.last?.hasPublicOverrides, true)
    }
    func testDestinationsSupersedeLegacyDomainsInsteadOfInventingOverlap() async throws {
        let f = try AccessApplicationFixture()
        let row = AccessHostnameReplies.row(1, uri: f.plan.hostname, extra: ["self_hosted_domains": [f.plan.hostname],
            "destinations": [["type": "public", "uri": "unrelated.invalid"]]])
        let probe = try RelayIngressProbe([reply([AccessHostnameReplies.own(f), row]), reply([], number: 2)])
        let observed = try await inspect(f, probe: probe); XCTAssertEqual(observed.matches.count, 1)
    }
    func testWildcardsMatchOnlyTheirOwnLabelsAndDoNotSelectAWinner() async throws {
        let f = try AccessApplicationFixture(), labels = f.plan.hostname.split(separator: "."), first = String(labels[0])
        let suffix = labels.dropFirst().joined(separator: ".")
        let patterns = ["*." + suffix, String(first.prefix(3)) + "*." + suffix,
            "*" + String(first.suffix(3)) + "." + suffix, f.plan.hostname.uppercased(), "*." + f.plan.hostname,
            "*." + labels.dropFirst(2).joined(separator: "."), "unrelated.invalid"]
        let rows = patterns.enumerated().map { AccessHostnameReplies.row($0.offset + 1, uri: $0.element) }
        let probe = try RelayIngressProbe([reply([AccessHostnameReplies.own(f)] + rows), reply([], number: 2)])
        let result = try await inspect(f, probe: probe)
        XCTAssertEqual(result.matches.map(\.uri), [f.plan.hostname] + Array(patterns.prefix(4)))
        XCTAssertEqual(result.matches.map(\.wildcardHostname), [false, true, true, true, false])
    }
    func testPathSpecificApplicationsRemainVisibleForLaterPrecedenceChecks() async throws {
        let f = try AccessApplicationFixture(), paths = ["/", "/*", "/admin", "/alpha/*", "/%2f"]
        let rows = paths.enumerated().map { AccessHostnameReplies.row($0.offset + 1, uri: f.plan.hostname + $0.element) }
        let probe = try RelayIngressProbe([reply([AccessHostnameReplies.own(f)] + rows), reply([], number: 2)])
        let result = try await inspect(f, probe: probe)
        XCTAssertEqual(result.matches.map(\.uri), [f.plan.hostname] + paths.map { f.plan.hostname + $0 })
    }
    func testLegacySecondaryDomainsAndSshOrVncDomainsAreIncluded() async throws {
        let f = try AccessApplicationFixture(), rows = [AccessHostnameReplies.own(f),
            AccessHostnameReplies.row(1, uri: "other.invalid", extra: ["self_hosted_domains": ["other.invalid", f.plan.hostname]]),
            AccessHostnameReplies.row(2, uri: f.plan.hostname, type: "ssh"), AccessHostnameReplies.row(3, uri: f.plan.hostname, type: "vnc"),
            AccessHostnameReplies.row(4, uri: f.plan.hostname, extra: ["self_hosted_domains": ["other.invalid"]])]
        let probe = try RelayIngressProbe([reply(rows), reply([], number: 2)]), result = try await inspect(f, probe: probe)
        XCTAssertEqual(result.matches.count, 5)
    }
    func testUnknownApplicationAndDestinationTypesRemainExplicitlyUnresolved() async throws {
        let f = try AccessApplicationFixture(), rows = [AccessHostnameReplies.own(f),
            AccessHostnameReplies.row(1, uri: "other.invalid", type: "future-app"),
            AccessHostnameReplies.row(2, uri: "other.invalid", extra: ["destinations": [["type": "future-destination"]]]),
            AccessHostnameReplies.row(3, uri: "other.invalid", extra: ["destinations": [["type": "private", "hostname": f.plan.hostname]]]),
            AccessHostnameReplies.row(4, uri: "other.invalid", extra: ["destinations": [["type": "public", "uri": f.plan.hostname, "future_routing_option": true]]])]
        let probe = try RelayIngressProbe([reply(rows), reply([], number: 2)]), result = try await inspect(f, probe: probe)
        XCTAssertEqual(result.unresolvedApplicationIDs, ["00000001-1111-4111-8111-111111111111", "00000002-1111-4111-8111-111111111111", "00000004-1111-4111-8111-111111111111"])
        XCTAssertEqual(result.matches.count, 2)
    }
    func testMissingRetainedApplicationNeverAdoptsAnotherAppWithTheSameHostname() async throws {
        let f = try AccessApplicationFixture(), probe = try RelayIngressProbe([reply([AccessHostnameReplies.row(1, uri: f.plan.hostname)]), reply([], number: 2)])
        do { _ = try await inspect(f, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .wrongScope) }
    }
    func testDuplicateOrMalformedApplicationIdentityInvalidatesTheInventory() async throws {
        let f = try AccessApplicationFixture()
        for row in [AccessHostnameReplies.own(f), AccessHostnameReplies.row(1, uri: "other.invalid", extra: ["id": "not-a-uuid"])] {
            let probe = try RelayIngressProbe([reply([AccessHostnameReplies.own(f), row])])
            do { _ = try await inspect(f, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .invalidResponse) }
        }
    }
    func testMalformedRoutingDestinationsCannotProduceAnEmptyOverlapReport() async throws {
        let f = try AccessApplicationFixture()
        for uri in ["https://" + f.plan.hostname, f.plan.hostname + ".", "bad..invalid", "-bad.invalid", "user@" + f.plan.hostname,
            f.plan.hostname + "?ignored", "two**stars.invalid", "bad invalid", "bad.invalid/#anchor"] {
            let probe = try RelayIngressProbe([reply([AccessHostnameReplies.own(f), AccessHostnameReplies.row(1, uri: uri)])])
            do { _ = try await inspect(f, probe: probe); XCTFail(uri) } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .invalidResponse) }
        }
    }
    func testAdvisoryTotalsCannotTruncateOrRejectTheObservedPages() async throws {
        let f = try AccessApplicationFixture(), probe = RelayIngressProbe([
            RelayIngressProbe.reply(try AccessHostnameReplies.page([AccessHostnameReplies.own(f)],
                info: ["total_count": 0, "total_pages": 0])),
            RelayIngressProbe.reply(try AccessHostnameReplies.page([AccessHostnameReplies.row(1, uri: f.plan.hostname)],
                number: 2, info: ["total_count": 5000, "total_pages": 101])),
            try reply([], number: 3)])
        let result = try await inspect(f, probe: probe)
        XCTAssertEqual(result.applicationCount, 2); XCTAssertEqual(result.matches.count, 2)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 3)
    }
    func testTerminalPageFailureCannotReturnAPartialInventory() async throws {
        let f = try AccessApplicationFixture(), probe = try RelayIngressProbe([reply([AccessHostnameReplies.own(f)]), .lost])
        do { _ = try await inspect(f, probe: probe); XCTFail() }
        catch { XCTAssertEqual(error as? CloudflareProvisioningError, .unavailable) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testMaximumDataPagesCanCompleteWithAnEmptyTerminalProbe() async throws {
        let f = try AccessApplicationFixture()
        var steps = try (1...CloudflareAccessHostnameClient.maximumPages).map { number in
            try reply(number == 1 ? [AccessHostnameReplies.own(f)] : [AccessHostnameReplies.row(number, uri: "other.invalid")],
                number: number, size: 1)
        }
        steps.append(try reply([], number: CloudflareAccessHostnameClient.maximumRequests, size: 1))
        let probe = RelayIngressProbe(steps), result = try await inspect(f, probe: probe)
        XCTAssertEqual(result.applicationCount, CloudflareAccessHostnameClient.maximumPages)
        let requests = await probe.all(); XCTAssertEqual(requests.count, CloudflareAccessHostnameClient.maximumRequests)
    }
    func testMalformedPaginationCannotTruncateTheInventory() async throws {
        let f = try AccessApplicationFixture()
        let variants: [[String: Any]] = [["page": 2], ["per_page": 0], ["per_page": 101],
            ["count": 0], ["count": 2], ["total_count": -1]]
        for info in variants {
            let probe = RelayIngressProbe([RelayIngressProbe.reply(try AccessHostnameReplies.page([AccessHostnameReplies.own(f)], info: info))])
            do { _ = try await inspect(f, probe: probe); XCTFail(String(describing: info)) } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .invalidResponse) }
        }
    }
    func testChangedPageSizeAndRepeatedPagesAreRejected() async throws {
        let f = try AccessApplicationFixture(), own = AccessHostnameReplies.own(f)
        let variants = try [AccessHostnameReplies.page([AccessHostnameReplies.row(1, uri: "other.invalid")], number: 2, size: 2, total: 2),
            AccessHostnameReplies.page([own], number: 1, size: 1, total: 2), AccessHostnameReplies.page([own], number: 2, size: 1, total: 2)]
        for next in variants {
            let probe = try RelayIngressProbe([reply([own], size: 1, total: 2), RelayIngressProbe.reply(next)])
            do { _ = try await inspect(f, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .invalidResponse) }
        }
    }
    func testMissingTotalsUsesTheTerminalEmptyPage() async throws {
        let f = try AccessApplicationFixture(), probe = try RelayIngressProbe([reply([AccessHostnameReplies.own(f)], size: 1), reply([], number: 2, size: 1)])
        let result = try await inspect(f, probe: probe); XCTAssertEqual(result.applicationCount, 1)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 2)
    }
    func testPageLimitStopsWithoutFollowingProviderLinksOrClaimingCompleteness() async throws {
        let f = try AccessApplicationFixture()
        let steps = try (1...CloudflareAccessHostnameClient.maximumRequests).map { number in
            RelayIngressProbe.reply(try AccessHostnameReplies.page([AccessHostnameReplies.row(number, uri: "other.invalid")], number: number, size: 1,
                envelope: ["next": "https://untrusted.invalid/steal-credentials"]))
        }
        let probe = RelayIngressProbe(steps)
        do { _ = try await inspect(f, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, .invalidResponse) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, CloudflareAccessHostnameClient.maximumRequests)
        XCTAssertTrue(requests.allSatisfy { $0.url?.host == "api.cloudflare.com" })
    }
    func testPermissionTransportAndOversizedFailuresNeverReturnAnInventory() async throws {
        let f = try AccessApplicationFixture()
        let cases: [(RelayIngressProbe.Step, CloudflareProvisioningError)] = [(.lost, .unavailable),
            (RelayIngressProbe.reply(Data(), status: 403), .unauthorized), (RelayIngressProbe.reply(Data(), status: 429), .rateLimited),
            (RelayIngressProbe.reply(Data("not-json".utf8)), .invalidResponse),
            (RelayIngressProbe.reply(Data(repeating: 32, count: FCMHTTPTransport.maximumResponseBytes + 1)), .responseTooLarge)]
        for (step, expected) in cases {
            let probe = RelayIngressProbe([step])
            do { _ = try await inspect(f, probe: probe); XCTFail() } catch { XCTAssertEqual(error as? CloudflareProvisioningError, expected) }
        }
    }
    func testUnknownCreationAndWrongAccountStopBeforeSendingCredentials() async throws {
        let f = try AccessApplicationFixture(), probe = RelayIngressProbe([]), prepared = try f.begin()
        do { _ = try await inspect(f, probe: probe, application: prepared); XCTFail() } catch {}
        let configuration = try XCTUnwrap(f.h.f.proposal().cloudflare), application = try f.retainCreated()
        let wrong = try SetupCloudflareConfiguration(accountID: String(repeating: "c", count: 32), zoneID: configuration.zoneID,
            dnsSuffix: configuration.dnsSuffix, apiToken: "synthetic-only")
        do { _ = try await CloudflareAccessHostnameClient(send: { try await probe.send($0) }).inspect(wrong, expected: f.h.intent,
            plan: f.plan, createdTunnel: f.tunnel, application: application); XCTFail() } catch {}
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }
    func testCancellationAfterOnePageStopsBeforeTheNextRequest() async throws {
        let f = try AccessApplicationFixture(), probe = try RelayIngressProbe([reply([AccessHostnameReplies.own(f)], size: 1, total: 2)],
            hook: { _, _ in withUnsafeCurrentTask { $0?.cancel() } })
        let task = Task { @Sendable in try await self.inspect(f, probe: probe) }
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1)
    }
    func testSaaSFederationAndBookmarkTilesDoNotCreateHostnameConflicts() async throws {
        let f = try AccessApplicationFixture()
        let rows = [AccessHostnameReplies.own(f),
            AccessHostnameReplies.row(1, uri: f.plan.hostname, type: "saas"),
            AccessHostnameReplies.row(2, uri: "https://" + f.plan.hostname, type: "bookmark")]
        let observed = try await inspect(f, probe: RelayIngressProbe([reply(rows), reply([], number: 2)]))
        XCTAssertEqual(observed.applicationCount, 3)
        XCTAssertTrue(observed.unresolvedApplicationIDs.isEmpty)
        XCTAssertEqual(observed.matches.count, 1)
        XCTAssertEqual(observed.matches.first?.applicationID, "22222222-2222-4222-8222-222222222222")
    }
    func testUnexpectedDestinationsOnNonroutingTypesRemainUnresolved() async throws {
        let f = try AccessApplicationFixture()
        for type in ["saas", "bookmark"] {
            for extra: [String: Any] in [
                ["destinations": [["type": "public", "uri": f.plan.hostname]]],
                ["self_hosted_domains": [f.plan.hostname]]
            ] {
                let rows = [AccessHostnameReplies.own(f), AccessHostnameReplies.row(1, uri: f.plan.hostname, type: type, extra: extra)]
                let observed = try await inspect(f, probe: RelayIngressProbe([reply(rows), reply([], number: 2)]))
                XCTAssertEqual(observed.unresolvedApplicationIDs.count, 1)
                XCTAssertEqual(observed.matches.count, 1)
            }
        }
    }

}
