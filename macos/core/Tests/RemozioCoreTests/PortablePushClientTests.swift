import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class PortablePushClientTests: XCTestCase {
    private static let pem = Result { () throws -> String in
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        try process.run(); let bytes = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw PortableSetupError.rejected }
        return String(decoding: bytes, as: UTF8.self)
    }
    private let limits = try! CBORLimits(maxBytes: 65_536, maxDepth: 4, maxItems: 128)
    private func defaults(expanded: Bool = true) throws -> SharedSetupDefaults {
        let presence = try PresenceConfiguration(idleMilliseconds: 120_000, observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 30_000)
        let wake = try GatewayWakePolicy(maximumEntries: 32, maximumAttempts: 3, minimumEnrollmentIntervalMillis: 1000, maximumLifetimeMillis: 60_000, maximumTTLSeconds: 60)
        let delivery = try GatewayDeliveryPolicy(maximumFlights: 4, minimumSendIntervalMillis: 100)
        if !expanded { return .init(presence: presence, wake: wake, delivery: delivery) }
        return try .init(presence: presence, gateway: .init(service: .init(delivery: delivery,
            probe: .init(maximumAttempts: 5, minimumRetryDelayMillis: 1234, maximumTTLSeconds: 40), wake: wake,
            maximumOperations: 11), activation: .init(wakePollMilliseconds: 4321, wakeTimeoutMilliseconds: 6789)))
    }
    private func provider(project: String = "synthetic-project") throws -> SetupFCMConfiguration {
        try .init(project: project, clientEmail: "fixture@fixture.iam.gserviceaccount.com",
            privateKeyID: "fixture-key", privateKeyPEM: Self.pem.get())
    }
    private func client(project: String = "synthetic-project") throws -> SetupPushClientConfiguration {
        try .init(projectID: project, senderID: "123456789012", packageName: "dev.remozio.android")
    }
    private func setup() throws -> PortableSetup {
        try .init(defaults: defaults(), fcm: provider(), pushClient: client())
    }
    private func fields(_ setup: PortableSetup) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(setup.canonicalBytes(), limits: limits) else { throw PortableSetupError.rejected }
        return fields
    }
    private func reject(_ fields: [UInt64: CBORValue], file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertThrowsError(try PortableSetup(canonicalBytes: DeterministicCBOR.encode(.map(fields), limits: limits)), file: file, line: line)
    }
    func testEncryptedExportRetainsTheExplicitProjectSenderAndPackageWithoutDeviceTokens() throws {
        let original = try setup(), encrypted = try original.encryptedFile(password: "synthetic export password")
        let restored = try PortableSetup(encryptedFile: encrypted, password: "synthetic export password")
        XCTAssertEqual(try restored.canonicalBytes(), try original.canonicalBytes())
        XCTAssertEqual(restored.pushClient, try client())
        XCTAssertEqual(restored.preview.pushClient, try client())
        XCTAssertEqual(restored.preview.firebaseProject, "synthetic-project")
        XCTAssertEqual(try fields(restored)[0], .unsigned(3))
        XCTAssertEqual(try Set(fields(restored).keys), Set(UInt64(0)...4))
        XCTAssertNil(restored.cloudflare)
        for value in [String(reflecting: restored), String(reflecting: restored.preview)] {
            XCTAssertFalse(value.contains("PRIVATE KEY")); XCTAssertFalse(value.contains("fixture-key"))
        }
    }
    func testOldFormatsKeepTheirVersionsAndCannotInventFirebaseClientScope() throws {
        for expanded in [false, true] {
            let original = try PortableSetup(defaults: defaults(expanded: expanded), fcm: provider())
            let bytes = try original.canonicalBytes(), restored = try PortableSetup(canonicalBytes: bytes)
            XCTAssertEqual(try fields(restored)[0], .unsigned(expanded ? 2 : 1))
            XCTAssertEqual(try restored.canonicalBytes(), bytes)
            XCTAssertNil(restored.pushClient); XCTAssertNil(restored.preview.pushClient)
        }
    }
    func testClientScopeRequiresMatchingCredentialsAndCompleteSharedDefaults() throws {
        for value in [
            try PortableSetup(defaults: defaults(), pushClient: client()),
            try PortableSetup(defaults: defaults(), fcm: provider(project: "other-project"), pushClient: client()),
            try PortableSetup(defaults: defaults(expanded: false), fcm: provider(), pushClient: client()),
        ] {
            XCTAssertThrowsError(try value.canonicalBytes())
        }
        var root = try fields(setup()); root[2] = .null; try reject(root)
        root = try fields(setup()); root[4] = .array(["other-project", "123456789012", "dev.remozio.android"].map(CBORValue.text)); try reject(root)
    }
    func testClientScopeRejectsInvalidSendersPackagesAndAdditionalDeviceData() throws {
        for sender in ["", "client-id-not-a-sender", "123\n", String(repeating: "1", count: 33)] {
            XCTAssertThrowsError(try SetupPushClientConfiguration(projectID: "synthetic-project", senderID: sender, packageName: "dev.remozio.android"))
        }
        for package in ["", "single", "dev.remozio/app", "1dev.remozio", "dev.remozio.\n"] {
            XCTAssertThrowsError(try SetupPushClientConfiguration(projectID: "synthetic-project", senderID: "123", packageName: package))
        }
        let invalid: [CBORValue] = [.null, .text("opaque"), .array([.text("synthetic-project"), .text("123")]),
            .array([.text("synthetic-project"), .text("123"), .text("dev.remozio.android"), .text("device-token")]),
            .array([.text("synthetic-project"), .unsigned(123), .text("dev.remozio.android")])]
        for value in invalid { var root = try fields(setup()); root[4] = value; try reject(root) }
    }
    func testClientScopeCannotBeSmuggledIntoOlderVersionsOrDroppedFromVersionThree() throws {
        for version: UInt64 in [1, 2, 4] { var root = try fields(setup()); root[0] = .unsigned(version); try reject(root) }
        var root = try fields(setup()); root.removeValue(forKey: 4); try reject(root)
        root = try fields(setup()); root[5] = .text("approval grant"); try reject(root)
        root = try fields(setup()); guard case .map(var settings) = root[1] else { return XCTFail() }
        settings.removeValue(forKey: 3); root[1] = .map(settings); try reject(root)
    }
}
