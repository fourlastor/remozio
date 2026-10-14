import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityCommandStartupConfigurationTests: XCTestCase {
    private func id(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private func presence(pairing: AuthorityPairingSetupConfiguration? = nil) throws -> AuthorityPresenceStartupConfiguration {
        let key = P256.Signing.PrivateKey().publicKey.x963Representation
        let service = try AuthorityServiceConfiguration(macID: id(1), accountID: id(2), journalDirectory: "/Library/Remozio/journal",
            serviceName: "dev.remozio.authority", teamID: "TEAMID1234", transportIdentifier: "dev.remozio.transport",
            transportHashes: [id(3, 20)], transportUID: 401, maximumPayloadBytes: 262_144, continuityDirectory: "/Library/Remozio/continuity")
        let request = try AuthorityRequestStartupConfiguration(service: service, keyRecordPath: "/Library/Remozio/key.cbor", authorityPublicKey: key)
        let registration = try GatewayRegistrationIdentity(ownerID: id(3), macID: id(1), accountID: id(2), gatewayID: id(4),
            lifecycleEpoch: id(5), rootPublicKey: key)
        let wake = try AuthorityWakeStartupConfiguration(request: request, registration: registration,
            gatewayServiceName: "dev.remozio.gateway.root", gatewayUID: 402, teamID: "TEAMID1234",
            gatewayIdentifier: "dev.remozio.gateway", gatewayHashes: [id(4, 20)])
        return try .init(wake: wake, ownerUID: 501, appServiceName: "dev.remozio.presence", teamID: "TEAMID1234",
            appIdentifier: "dev.remozio.mac", appHashes: [id(6, 20)], policy: .init(observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 1000), pairing: pairing)
    }
    private func config(service: String = "dev.remozio.command", path: String = "/Library/Remozio/elevation.cbor",
                        environment: [CapturedEnvironmentEntry] = [], captureBytes: Int = 65_536,
                        ancestry: Int = 16, lifetime: UInt64 = 60_000) throws -> AuthorityCommandStartupConfiguration {
        try .init(presence: presence(), serviceName: service, policyPath: path, environment: environment,
            submissionLimits: .init(maxBytes: 8192, maxDepth: 8, maxItems: 1024),
            captureLimits: .init(maxBytes: captureBytes, maxDepth: 8, maxItems: 4096),
            maximumAncestryEntries: ancestry, approvalLifetimeMilliseconds: lifetime)
    }
    private func entry(_ name: String, _ value: Data = Data("value".utf8), source: EnvironmentSource = .minimal) -> CapturedEnvironmentEntry {
        .init(name: Data(name.utf8), value: value, source: source)
    }
    private var limits: CBORLimits { get throws { try .init(maxBytes: 65_536, maxDepth: 4, maxItems: 1024) } }

    func testPairingStartupPreservesLegacyVersionOneAndExplicitVersionTwo() throws {
        let legacy = try presence()
        guard case .map(let legacyFields) = try DeterministicCBOR.decode(legacy.canonicalBytes, limits: limits) else { return XCTFail("Map required") }
        XCTAssertEqual(legacyFields[0], .unsigned(1)); XCTAssertNil(legacyFields[10])
        XCTAssertNil(try AuthorityPresenceStartupConfiguration.decode(legacy.canonicalBytes).pairing)
        let setup = try AuthorityPairingSetupConfiguration(transportPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        let modern = try presence(pairing: setup), decoded = try AuthorityPresenceStartupConfiguration.decode(modern.canonicalBytes)
        XCTAssertEqual(decoded.canonicalBytes, modern.canonicalBytes)
        XCTAssertEqual(decoded.pairing?.canonicalBytes, setup.canonicalBytes)
        XCTAssertEqual(decoded.endpoint.serviceName, legacy.endpoint.serviceName)
        XCTAssertEqual(decoded.presence.ownerUID, legacy.presence.ownerUID)
        XCTAssertEqual(decoded.endpoint.appPolicy.requirement, legacy.endpoint.appPolicy.requirement)
        let command = try AuthorityCommandStartupConfiguration(presence: modern, serviceName: "dev.remozio.command",
            policyPath: "/Library/Remozio/elevation.cbor", environment: [], submissionLimits: .init(maxBytes: 8192, maxDepth: 8, maxItems: 1024),
            captureLimits: .init(maxBytes: 65536, maxDepth: 8, maxItems: 4096))
        XCTAssertEqual(try AuthorityCommandStartupConfiguration.decode(command.canonicalBytes).presence.pairing?.canonicalBytes, setup.canonicalBytes)
    }
    func testPairingStartupRejectsMixedMissingUnknownAndUncanonicalVersions() throws {
        let setup = try AuthorityPairingSetupConfiguration(transportPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        let modern = try presence(pairing: setup)
        guard case .map(let fields) = try DeterministicCBOR.decode(modern.canonicalBytes, limits: limits) else { return XCTFail("Map required") }
        for (field, value): (UInt64, CBORValue?) in [(0, .unsigned(1)), (0, .unsigned(3)), (10, nil), (10, .null), (10, .text("setup")), (11, .unsigned(1))] {
            var changed = fields; changed[field] = value
            XCTAssertThrowsError(try AuthorityPresenceStartupConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        XCTAssertThrowsError(try AuthorityPresenceStartupConfiguration.decode(modern.canonicalBytes + Data([0])))
    }

    func testRejectsPermanentlyUnusableProtocolBudgets() throws {
        let baseline = try config()
        for (submission, capture) in [
            (try CBORLimits(maxBytes: 1, maxDepth: 8, maxItems: 1024), baseline.captureLimits),
            (baseline.submissionLimits, try CBORLimits(maxBytes: 1, maxDepth: 8, maxItems: 4096)),
            (baseline.submissionLimits, try CBORLimits(maxBytes: 65_536, maxDepth: 8, maxItems: 128)),
            (baseline.submissionLimits, try CBORLimits(maxBytes: 65_536, maxDepth: 4, maxItems: 4096))
        ] {
            XCTAssertThrowsError(try AuthorityCommandStartupConfiguration(presence: baseline.presence,
                serviceName: baseline.serviceName, policyPath: baseline.policyPath, environment: [],
                submissionLimits: submission, captureLimits: capture))
        }
    }

    func testCanonicalCompositionKeepsOriginalScopeAndExplicitModernProtocolSupport() throws {
        let value = try config(environment: [entry("Z"), entry("A")]), decoded = try AuthorityCommandStartupConfiguration.decode(value.canonicalBytes)
        XCTAssertEqual(decoded.canonicalBytes, value.canonicalBytes)
        XCTAssertEqual(decoded.environment.map(\.name), [Data("A".utf8), Data("Z".utf8)])
        XCTAssertEqual(decoded.macID, id(1)); XCTAssertEqual(decoded.accountID, id(2)); XCTAssertEqual(decoded.callerUID, 501)
        XCTAssertEqual(try decoded.capabilities.wireVersions, [10, 11])
        XCTAssertEqual(try decoded.capabilities.submissionSchemaVersions, CommandSubmission.supportedSchemaVersions)
        XCTAssertEqual(AuthorityCommandStartupConfiguration.captureSchemaVersion, 3)
        XCTAssertEqual(decoded.approvalLifetimeMilliseconds, 60_000)
        XCTAssertEqual(decoded.description, "AuthorityCommandStartupConfiguration(redacted)")
        XCTAssertFalse(decoded.debugDescription.contains(decoded.policyPath))
        let old = decoded.presence
        XCTAssertEqual(try AuthorityPresenceStartupConfiguration.decode(old.canonicalBytes).canonicalBytes, old.canonicalBytes)
    }
    func testDecoderRejectsUnknownMissingUnsortedAndUnsupportedFields() throws {
        let original = try config(environment: [entry("A"), entry("Z")])
        guard case .map(let fields) = try DeterministicCBOR.decode(original.canonicalBytes, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (2, .text("outside.namespace")), (3, .text("relative/path")),
            (7, .unsigned(0)), (8, .unsigned(0)), (9, .unsigned(60_001)), (10, .unsigned(65)), (11, .unsigned(0)),
            (11, .unsigned(86_400_001)), (12, .unsigned(2)), (13, .null), (7, .unsigned(UInt64.max))] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try AuthorityCommandStartupConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        for key in fields.keys {
            var changed = fields; changed.removeValue(forKey: key)
            XCTAssertThrowsError(try AuthorityCommandStartupConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        guard case .array(let environment) = fields[4] else { return XCTFail() }
        for invalid in [Array(environment.reversed()), [environment[0], environment[0]]] {
            var changed = fields; changed[4] = .array(invalid)
            XCTAssertThrowsError(try AuthorityCommandStartupConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
    }
    func testDistinctServiceAndPolicyPathsAreRequired() throws {
        for service in ["dev.remozio.authority", "dev.remozio.presence", "dev.remozio.gateway.root", "dev.remozio." + String(repeating: "x", count: 255)] {
            XCTAssertThrowsError(try config(service: service))
        }
        for path in ["", "/", "/Library//elevation.cbor", "/Library/../elevation.cbor", "/Library/Remozio/./elevation.cbor",
                     "/Library/Remozio/key.cbor", "/Library/Remozio/\u{0}elevation", "/Library/" + String(repeating: "x", count: 256)] {
            XCTAssertThrowsError(try config(path: path))
        }
        XCTAssertThrowsError(try config(captureBytes: 262_144))
    }
    func testEnvironmentAcceptsFullBoundAndRejectsInheritedMalformedOrOversizedValues() throws {
        let full = try config(environment: (0..<64).map { entry("E\($0)") })
        XCTAssertEqual(try AuthorityCommandStartupConfiguration.decode(full.canonicalBytes).environment.count, 64)
        for environment in [[entry("A", source: .requested)], [entry("A"), entry("A")], [entry("")], [entry("A=B")],
            [entry("A\u{0}B")], [entry("A", Data([0]))], [entry("A", Data(repeating: 1, count: 16_385))], (0..<65).map { entry("E\($0)") },
            [entry("A", Data(repeating: 1, count: 16_384)), entry("B", Data(repeating: 1, count: 16_384))]] {
            XCTAssertThrowsError(try config(environment: environment))
        }
    }
    func testPolicyMustMatchMacAccountAndEnrolledCallerEvenWhenAllTargetsAreDisabled() throws {
        let config = try config()
        let valid = try CommandElevationPolicy(macID: id(1), accountID: id(2), callerUID: 501, allowedTargetUIDs: [],
            independentPolicyDisclosureAccepted: true)
        XCTAssertNoThrow(try config.validatePolicyScope(valid))
        for (mac, account, uid): (Data, Data, UInt32) in [(id(9), id(2), 501), (id(1), id(9), 501), (id(1), id(2), 502)] {
            let wrong = try CommandElevationPolicy(macID: mac, accountID: account, callerUID: uid, allowedTargetUIDs: [0],
                independentPolicyDisclosureAccepted: true)
            XCTAssertThrowsError(try config.validatePolicyScope(wrong)) {
                XCTAssertEqual($0 as? AuthorityCommandStartupError, .wrongPolicyScope)
            }
        }
    }
    func testConfiguredEnvironmentMustFitTheCaptureCodecBudget() throws {
        let baseline = try config()
        for (environment, limits) in [
            ([entry("A", Data(repeating: 1, count: 1024))], try CBORLimits(maxBytes: 1024, maxDepth: 8, maxItems: 4096)),
            ((0..<64).map { entry("E\($0)") }, try CBORLimits(maxBytes: 65_536, maxDepth: 8, maxItems: 256))
        ] {
            XCTAssertThrowsError(try AuthorityCommandStartupConfiguration(presence: baseline.presence,
                serviceName: baseline.serviceName, policyPath: baseline.policyPath, environment: environment,
                submissionLimits: baseline.submissionLimits, captureLimits: limits))
        }
        guard case .map(var fields) = try DeterministicCBOR.decode(baseline.canonicalBytes, limits: self.limits) else { return XCTFail() }
        fields[5] = .map([0: .unsigned(1), 1: .unsigned(8), 2: .unsigned(1024)])
        XCTAssertThrowsError(try AuthorityCommandStartupConfiguration.decode(DeterministicCBOR.encode(.map(fields), limits: self.limits)))
    }

    func testZeroAncestryAndTunableApprovalLifetimeDoNotSetCommandRuntimeLimit() throws {
        let value = try config(ancestry: 0, lifetime: 86_400_000)
        let decoded = try AuthorityCommandStartupConfiguration.decode(value.canonicalBytes)
        XCTAssertEqual(decoded.maximumAncestryEntries, 0); XCTAssertEqual(decoded.approvalLifetimeMilliseconds, 86_400_000)
        XCTAssertThrowsError(try config(ancestry: 65)); XCTAssertThrowsError(try config(lifetime: 0))
    }
    func testProductionReadsRejectOrdinaryAccountBeforeOpeningConfigurationOrGrantFile() throws {
        guard geteuid() != 0 else { throw XCTSkip("Ordinary-account gate") }
        XCTAssertThrowsError(try AuthorityCommandStartupConfiguration.load(path: "/tmp/remozio-command-startup.cbor")) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertThrowsError(try config().currentElevationPolicy()) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
    }
    private func compositionCapture(_ version: Int = 3) throws -> CommandCapture {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { root.deleteLastPathComponent() }
        let data = try Data(contentsOf: root.appendingPathComponent("protocol/vectors/command-capture-v\(version).json"))
        let vectors = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let row = (vectors["valid"] as! [[String: Any]])[0]
        let hex = row["hex"] as! String
        var bytes = Data(), cursor = hex.startIndex
        while cursor < hex.endIndex {
            let end = hex.index(cursor, offsetBy: 2); bytes.append(UInt8(hex[cursor..<end], radix: 16)!); cursor = end
        }
        return try CommandCapture(canonicalBytes: bytes, limits: .init(maxBytes: 65_536, maxDepth: 16, maxItems: 4096),
            expectedSchemaVersion: UInt64(version))
    }
    func testConfiguredDraftUsesSharedMomentAndExactConfiguredLifetime() throws {
        let configuration = try config(), capture = try compositionCapture(), moment = AuthorityMoment(epoch: UUID(), milliseconds: 500)
        let draft = try configuration.commandDraft(capture, observed: moment, unixMilliseconds: 1000)
        XCTAssertEqual(draft.capture, capture.canonicalBytes)
        XCTAssertEqual(draft.contract.requestKind, .command); XCTAssertEqual(draft.contract.schemaVersion, 3)
        XCTAssertEqual(draft.firstObservedAt, moment); XCTAssertEqual(draft.deadlineMilliseconds, 60_500)
        XCTAssertEqual(draft.createdUnixMilliseconds, 1000); XCTAssertEqual(draft.expiresUnixMilliseconds, 61_000)
        XCTAssertEqual(Set(draft.actions), [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)])
        XCTAssertNil(draft.observationID); XCTAssertNil(draft.estimatedLifetimeMilliseconds)
        for action in draft.actions {
            let policy = try ActionPolicy.requirement(for: action, requestKind: .command, retainedPermittedActions: Set(draft.actions))
            XCTAssertEqual(policy.keyClass, action.choice == .execute ? .biometric : .decision)
        }
    }
    func testConfiguredDraftChecksBothClockOverflowsAndUsesDaySetting() throws {
        let configuration = try config(lifetime: 86_400_000), capture = try compositionCapture(), epoch = UUID()
        let draft = try configuration.commandDraft(capture, observed: .init(epoch: epoch, milliseconds: 1), unixMilliseconds: 2)
        XCTAssertEqual(draft.deadlineMilliseconds, 86_400_001); XCTAssertEqual(draft.expiresUnixMilliseconds, 86_400_002)
        for (monotonic, unix): (UInt64, UInt64) in [(UInt64.max, 2), (1, UInt64.max)] {
            XCTAssertThrowsError(try configuration.commandDraft(capture, observed: .init(epoch: epoch, milliseconds: monotonic), unixMilliseconds: unix)) {
                XCTAssertEqual($0 as? ApprovalCoordinatorError, .invalidClock)
            }
        }
    }
    func testConfiguredDraftRejectsHistoricalCaptureProfiles() throws {
        let configuration = try config()
        for version in [1, 2] {
            XCTAssertThrowsError(try configuration.commandDraft(compositionCapture(version),
                observed: .init(epoch: UUID(), milliseconds: 1), unixMilliseconds: 2)) {
                XCTAssertEqual($0 as? ApprovalCoordinatorError, .invalidDraft)
            }
        }
    }
    func testConfiguredFactoryRefusesOrdinaryAccountBeforeReceiveRightOrPolicyRead() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-account gate") }
        let configuration = try config()
        XCTAssertThrowsError(try configuration.receiverFactory(takingRegisteredReceiveRight: { XCTFail("Unexpected registration read"); return mach_port_t(MACH_PORT_NULL) })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
    func testSharedCommandServiceRefusesOrdinaryAccountBeforeRegistration() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-account gate") }
        let configuration = try config()
        XCTAssertThrowsError(try AuthorityWakeService.open(configuration: configuration,
            takingRegisteredReceiveRight: { XCTFail("Unexpected registration read"); return mach_port_t(MACH_PORT_NULL) },
            reconcileExpired: { _ in XCTFail("Unexpected expiry reconciliation") })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
    @MainActor func testConfiguredRuntimeRefusesPrivateMetadataWithoutStartingRegistration() async throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-account gate") }
        let runner = try AuthorityRuntimeRunner(commandConfigurationPath: "/tmp/remozio-no-command-startup.cbor",
            takingRegisteredReceiveRight: { XCTFail("Unexpected registration read"); return mach_port_t(MACH_PORT_NULL) },
            monitorMilliseconds: 10, report: { _ in })
        try await runner.start()
        for _ in 0..<100 {
            if case .failed = runner.status { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertEqual(runner.status, .failed(.configurationFailure))
        try await runner.close(); XCTAssertEqual(runner.status, .closed)
    }
}
