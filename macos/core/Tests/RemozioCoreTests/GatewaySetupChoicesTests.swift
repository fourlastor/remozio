import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewaySetupChoicesTests: XCTestCase {
    private static let pem = Result { () throws -> String in
        let process = Process(), output = Pipe(); process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run(); let bytes = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw GatewayPreparationError.invalidRecord }; return String(decoding: bytes, as: UTF8.self)
    }
    static func choices() throws -> GatewaySetupPreparationChoices {
        let provider = try SetupFCMConfiguration(project: "synthetic-project", clientEmail: "fixture@fixture.iam.gserviceaccount.com",
            privateKeyID: "fixture-key", privateKeyPEM: pem.get())
        let settings = try GatewayServiceSettings(delivery: .init(maximumFlights: 2, minimumSendIntervalMillis: 1000,
                retryBaseDelayMillis: 2000, maximumRetryBackoffMillis: 4000),
            probe: .init(maximumAttempts: 2, minimumRetryDelayMillis: 1000, maximumTTLSeconds: 300),
            wake: .init(maximumEntries: 16, maximumAttempts: 3, minimumEnrollmentIntervalMillis: 1000, maximumLifetimeMillis: 300000, maximumTTLSeconds: 300),
            maximumOperations: 5, handshakeTimeoutMillis: 3456, authorityLeaseMillis: 20000, providerTimeoutSeconds: 15,
            schedulerRetryMillis: 4321, maximumStoredControls: 5000, maximumPendingPerEnrollment: 3,
            maximumCandidateLifetimeMillis: 360000, databaseBusyMillis: 2000)
        return try .init(provider: provider, senderID: "123", packageName: "dev.remozio.android", settings: settings, fileWakeCustodyAccepted: true)
    }
    private let limits = try! CBORLimits(maxBytes: 65536, maxDepth: 8, maxItems: 256)
    private func changed(_ bytes: Data, _ edit: (inout [UInt64: CBORValue]) throws -> Void) throws -> Data {
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw GatewayPreparationError.invalidRecord }
        try edit(&fields); return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    func testChoicesAndAllSettingsRoundTripWithRedactedDescriptions() throws {
        let choices = try Self.choices(), restored = try GatewaySetupPreparationChoices.decode(choices.bytes)
        XCTAssertEqual(try restored.bytes, try choices.bytes)
        XCTAssertEqual(restored.provider.project, "synthetic-project"); XCTAssertEqual(restored.senderID, "123")
        XCTAssertEqual(restored.settings.maximumOperations, 5); XCTAssertEqual(restored.settings.providerTimeoutSeconds, 15)
        XCTAssertEqual(restored.settings.maximumCandidateLifetimeMillis, 360000); XCTAssertEqual(restored.settings.databaseBusyMillis, 2000)
        XCTAssertEqual(try restored.settings.setupBytes, try choices.settings.setupBytes)
        XCTAssertTrue(restored.fileWakeCustodyAccepted)
        XCTAssertEqual(String(describing: restored), "GatewaySetupPreparationChoices(redacted)")
        XCTAssertEqual(String(reflecting: restored), "GatewaySetupPreparationChoices(redacted)")
    }
    func testUnknownVersionsPurposesFieldsAndOversizedChoicesAreRejected() throws {
        let bytes = try Self.choices().bytes
        for edit: (inout [UInt64: CBORValue]) throws -> Void in [
            { $0[0] = .unsigned(2) }, { $0[1] = .text("foreign") }, { $0[7] = .null }, { $0[6] = .unsigned(1) },
            { $0[3] = .text("not-a-sender") }, { $0[4] = .text("invalid package") }, { $0[5] = .bytes(Data([0])) }
        ] { XCTAssertThrowsError(try GatewaySetupPreparationChoices.decode(changed(bytes, edit))) }
        XCTAssertThrowsError(try GatewaySetupPreparationChoices.decode(bytes + Data([0])))
        XCTAssertThrowsError(try GatewaySetupPreparationChoices.decode(Data(repeating: 0, count: 49153)))
    }
    func testCredentialFieldsCannotChangeTheProviderOriginOrUseNoncanonicalJSON() throws {
        let bytes = try Self.choices().bytes
        for alternate in ["https://attacker.invalid/token", "duplicate-field", "noncanonical"] {
            let altered = try changed(bytes) { fields in
                guard case .bytes(let data) = fields[2], var provider = try JSONSerialization.jsonObject(with: data) as? [String: String] else {
                    throw GatewayPreparationError.invalidRecord
                }
                if alternate == "duplicate-field" { provider["extra"] = "unexpected" }
                else if alternate != "noncanonical" { provider["token_uri"] = alternate }
                var json = try JSONSerialization.data(withJSONObject: provider, options: [.sortedKeys])
                if alternate == "noncanonical" { json.append(0x20) }; fields[2] = .bytes(json)
            }
            XCTAssertThrowsError(try GatewaySetupPreparationChoices.decode(altered))
        }
    }
    func testSettingsBoundsAndVersionAreCheckedIndependently() throws {
        let bytes = try Self.choices().settings.setupBytes
        XCTAssertThrowsError(try GatewayServiceSettings.decodeSetupBytes(changed(bytes) { $0[0] = .unsigned(2) }))
        let invalid = try changed(bytes) { fields in
            guard case .map(var settings) = fields[2] else { throw GatewayPreparationError.invalidRecord }
            settings[8] = .unsigned(UInt64(UInt32.max)); fields[2] = .map(settings)
        }
        XCTAssertThrowsError(try GatewayServiceSettings.decodeSetupBytes(invalid))
        XCTAssertThrowsError(try GatewayServiceSettings.decodeSetupBytes(Data(repeating: 0, count: 4097)))
    }
}
