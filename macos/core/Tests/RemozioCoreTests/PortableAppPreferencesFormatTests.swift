import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class PortableAppPreferencesFormatTests: XCTestCase {
    private let limits = try! CBORLimits(maxBytes: 65_536, maxDepth: 4, maxItems: 128)
    private static let pem = Result { () throws -> String in
        let p = Process(), pipe = Pipe()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        p.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        p.standardOutput = pipe; p.standardError = FileHandle.nullDevice
        try p.run(); let bytes = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        guard p.terminationStatus == 0 else { throw PortableSetupError.rejected }
        return String(decoding: bytes, as: UTF8.self)
    }
    private func defaults(expanded: Bool) throws -> SharedSetupDefaults {
        let presence = try PresenceConfiguration(idleMilliseconds: 120_000, observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 30_000)
        let selection = try GatewayRuntimeSettingsSelection(
            service: .init(delivery: .init(maximumFlights: 4, minimumSendIntervalMillis: 100),
                probe: .init(maximumAttempts: 5, minimumRetryDelayMillis: 1234, maximumTTLSeconds: 40),
                wake: .init(maximumEntries: 32, maximumAttempts: 3, minimumEnrollmentIntervalMillis: 1000,
                    maximumLifetimeMillis: 60_000, maximumTTLSeconds: 60), maximumOperations: 11),
            activation: .init(wakePollMilliseconds: 4321, wakeTimeoutMilliseconds: 6789))
        if expanded { return .init(presence: presence, gateway: selection) }
        return .init(presence: presence, wake: selection.service.wake, delivery: selection.service.delivery)
    }
    private func preferences() throws -> PortableAppPreferences {
        try .init(preferences: [PortableAppPreferences.menuBarKey: false,
            CommandFrontendCallerSettings.modeKey: "pipes", CommandFrontendCallerSettings.disconnectKey: "continue",
            CommandFrontendCallerSettings.timeoutKey: "50000", CommandFrontendCallerSettings.controlRetryKey: "17"])
    }
    private func provider() throws -> SetupFCMConfiguration {
        try .init(project: "synthetic-project", clientEmail: "fixture@fixture.iam.gserviceaccount.com",
            privateKeyID: "synthetic-key-id", privateKeyPEM: Self.pem.get())
    }
    private func client() throws -> SetupPushClientConfiguration {
        try .init(projectID: "synthetic-project", senderID: "123456789012", packageName: "dev.remozio.android")
    }
    private func fields(_ setup: PortableSetup) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(setup.canonicalBytes(), limits: limits) else { throw PortableSetupError.rejected }
        return fields
    }
    private func reject(_ fields: [UInt64: CBORValue]) throws {
        let bytes = try DeterministicCBOR.encode(.map(fields), limits: limits)
        XCTAssertThrowsError(try PortableSetup(canonicalBytes: bytes))
    }
    func testSettingsOnlyVersionFourPreservesUnsetServiceAndProviderScope() throws {
        let base = try PortableSetup(defaults: defaults(expanded: false))
        let original = try base.addingAppPreferences(preferences()), restored = try PortableSetup(canonicalBytes: original.canonicalBytes())
        XCTAssertEqual(try fields(restored)[0], .unsigned(4)); XCTAssertEqual(try Set(fields(restored).keys), Set(UInt64(0)...5))
        XCTAssertEqual(restored.appPreferences, try preferences()); XCTAssertEqual(restored.preview.appPreferences, try preferences())
        XCTAssertEqual(restored.preview.categories, [.sharedDefaults, .appPreferences])
        XCTAssertNil(restored.defaults.gateway); XCTAssertNil(restored.fcm); XCTAssertNil(restored.pushClient); XCTAssertNil(restored.cloudflare)
        XCTAssertEqual(try fields(restored)[4], .null)
        XCTAssertEqual(try restored.canonicalBytes(), try original.canonicalBytes())
    }
    func testExpandedVersionFourPreservesAllGatewayValuesAndDoesNotAddProviderCredentials() throws {
        let original = try PortableSetup(defaults: defaults(expanded: true)).addingAppPreferences(preferences())
        let restored = try PortableSetup(canonicalBytes: original.canonicalBytes())
        XCTAssertEqual(try restored.defaults.gateway?.bytes, try original.defaults.gateway?.bytes)
        XCTAssertEqual(restored.appPreferences, original.appPreferences)
        XCTAssertEqual(restored.preview.categories, [.sharedDefaults, .gatewayOperationalDefaults, .appPreferences])
        XCTAssertNil(restored.fcm); XCTAssertNil(restored.pushClient)
    }
    func testEncryptedCompositionPreservesProviderCredentialsAndSharedProvisioningScope() throws {
        let cloudflare = try SetupCloudflareConfiguration(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
            dnsSuffix: "remozio.example.invalid", apiToken: "synthetic-provider-token")
        let original = try PortableSetup(defaults: defaults(expanded: true), fcm: provider(), cloudflare: cloudflare, pushClient: client())
        let password = "synthetic export password", file = try original.encryptedFile(password: password)
        let captured = try PortableSetup(encryptedFile: file, password: password).addingAppPreferences(preferences())
        let encrypted = try captured.encryptedFile(password: password), restored = try PortableSetup(encryptedFile: encrypted, password: password)
        XCTAssertEqual(try restored.canonicalBytes(), try captured.canonicalBytes())
        XCTAssertEqual(restored.pushClient, try client()); XCTAssertEqual(restored.fcm?.project, original.fcm?.project)
        XCTAssertNoThrow(try restored.fcm?.serviceAccount()); XCTAssertEqual(restored.cloudflare?.accountID, cloudflare.accountID)
        XCTAssertEqual(restored.cloudflare?.dnsSuffix, cloudflare.dnsSuffix)
        let withoutPreferences = PortableSetup(defaults: restored.defaults, fcm: restored.fcm, cloudflare: restored.cloudflare, pushClient: restored.pushClient)
        XCTAssertEqual(try withoutPreferences.canonicalBytes(), try original.canonicalBytes())
        for displayed in [String(reflecting: restored), String(reflecting: restored.preview)] {
            XCTAssertFalse(displayed.contains("synthetic-provider-token")); XCTAssertFalse(displayed.contains("PRIVATE KEY"))
        }
        XCTAssertThrowsError(try PortableSetup(encryptedFile: encrypted, password: "incorrect password"))
    }
    func testLegacyPayloadsDoNotAcquirePreferencesOrChangeVersion() throws {
        for version in 1...3 {
            let original = try PortableSetup(defaults: defaults(expanded: version > 1), fcm: version == 3 ? provider() : nil,
                pushClient: version == 3 ? client() : nil)
            let bytes = try original.canonicalBytes(), restored = try PortableSetup(canonicalBytes: bytes)
            XCTAssertEqual(try fields(restored)[0], .unsigned(UInt64(version)))
            XCTAssertNil(restored.appPreferences); XCTAssertNil(restored.preview.appPreferences)
            XCTAssertEqual(try restored.canonicalBytes(), bytes)
        }
    }
    func testNewPreferenceScopeCannotBeSmuggledIntoAnyOlderVersionOrDroppedFromVersionFour() throws {
        let original = try fields(PortableSetup(defaults: defaults(expanded: true)).addingAppPreferences(preferences()))
        for version: UInt64 in [1, 2, 3, 5] { var changed = original; changed[0] = .unsigned(version); try reject(changed) }
        var changed = original; changed.removeValue(forKey: 5); try reject(changed)
        changed = original; changed[5] = .null; try reject(changed)
        changed = original; changed[6] = .text("approval grant"); try reject(changed)
        changed = original; changed[5] = .bytes(Data("opaque app state".utf8)); try reject(changed)
    }
    func testVersionFourDoesNotWeakenProviderAndSettingsBinding() throws {
        let legacy = try PortableSetup(defaults: defaults(expanded: false), fcm: provider(), pushClient: client(), appPreferences: preferences())
        XCTAssertThrowsError(try legacy.canonicalBytes())
        var changed = try fields(PortableSetup(defaults: defaults(expanded: false)).addingAppPreferences(preferences()))
        changed[4] = .array([.text("synthetic-project"), .text("123456789012"), .text("dev.remozio.android")]); try reject(changed)
        changed = try fields(PortableSetup(defaults: defaults(expanded: true), fcm: provider(), pushClient: client()).addingAppPreferences(preferences()))
        changed[4] = .array([.text("other-project"), .text("123456789012"), .text("dev.remozio.android")]); try reject(changed)
        changed[4] = .text("device token"); try reject(changed)
    }
    func testUnknownPreferenceFieldsCannotBecomeLocalIdentityOrAuthoritySettings() throws {
        let original = try PortableSetup(defaults: defaults(expanded: true)).addingAppPreferences(preferences())
        let prefs = try XCTUnwrap(original.appPreferences), prefsLimits = try CBORLimits(maxBytes: 2048, maxDepth: 2, maxItems: 32)
        guard case .map(var nested) = try DeterministicCBOR.decode(prefs.bytes, limits: prefsLimits), case .map(var values) = nested[2] else { return XCTFail() }
        values[99] = .text("authority key or pairing"); nested[2] = .map(values)
        var changed = try fields(original); changed[5] = .bytes(try DeterministicCBOR.encode(.map(nested), limits: prefsLimits)); try reject(changed)
    }
}
