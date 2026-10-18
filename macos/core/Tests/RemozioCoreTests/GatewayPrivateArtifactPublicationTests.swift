import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewayPrivateArtifactPublicationTests: XCTestCase {
    private struct Interrupted: Error {}
    private typealias Publication = GatewayPrivateArtifactPublication
    private static let pem = Result { () throws -> String in
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        try process.run(); let bytes = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw Interrupted() }
        return String(decoding: bytes, as: UTF8.self)
    }
    private func fixture(_ body: (RuntimeActivationFixture, GatewayPreparationMaterial, ProtectedSetupDirectory) throws -> Void) throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner publication fixture") }
        let f = try RuntimeActivationFixture()
        let provider = try SetupFCMConfiguration(project: "synthetic-project", clientEmail: "fixture@fixture.iam.gserviceaccount.com",
            privateKeyID: "fixture-key", privateKeyPEM: Self.pem.get())
        let material = try GatewayPreparationMaterial.create(runtime: f.material.reference, provider: provider,
            senderID: "123", packageName: "dev.remozio.android", fileWakeCustodyAccepted: true)
        let shared = URL(fileURLWithPath: "/private/tmp/remozio-gateway-files-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: shared, withIntermediateDirectories: false)
        defer { XCTAssertNoThrow(try FileManager.default.removeItem(at: shared)) }
        guard chmod(shared.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
        let directory = try ProtectedSetupDirectory(anchor: shared.path, relativePath: "Artifacts", owner: getuid(), visibility: .sharedMetadata)
        defer { directory.close() }
        try body(f, material, directory)
    }
    private func publish(_ material: GatewayPreparationMaterial, _ directory: ProtectedSetupDirectory,
                         mode: Publication.Mode = .prepareUnactivated, expected: GatewayMaterialReference? = nil,
                         verify: () throws -> Void = {}, stage: (Publication.Artifact) throws -> Void = { _ in }) throws -> Publication.Result {
        try Publication.publish(material: material, expected: expected ?? material.reference, directory: directory, owner: getuid(),
            gatewayUID: getuid(), gatewayGID: getgid(), transportUID: getuid(), transportGID: getgid(), mode: mode,
            verifyCurrent: verify, didPublish: stage)
    }
    private func file(_ directory: ProtectedSetupDirectory, _ name: String) -> URL {
        URL(fileURLWithPath: directory.path).appendingPathComponent(name)
    }
    private func snapshot(_ directory: ProtectedSetupDirectory) throws -> [String: Data] {
        try Dictionary(uniqueKeysWithValues: FileManager.default.contentsOfDirectory(atPath: directory.path).map {
            ($0, try Data(contentsOf: file(directory, $0)))
        })
    }

    func testPublishesOnlyRoleSpecificPrivateRecordsAndRetainsTheirInodes() throws {
        try fixture { _, material, directory in
            let first = try publish(material, directory)
            XCTAssertEqual(first.files, Dictionary(uniqueKeysWithValues: Publication.Artifact.allCases.map { ($0, .created) }))
            let before = try snapshot(directory)
            XCTAssertEqual(before, ["gateway-provider.json": material.providerJSON, "gateway-receipt-key.cbor": material.receiptKeyRecord,
                                    "transport-wake-key.cbor": try material.wakeKeyRecord.encode()])
            var inodes: [String: ino_t] = [:]
            for name in before.keys {
                var info = stat(); XCTAssertEqual(lstat(file(directory, name).path, &info), 0)
                XCTAssertEqual(info.st_mode & 0o7777, 0o600); XCTAssertEqual(info.st_uid, getuid()); XCTAssertEqual(info.st_gid, getgid())
                inodes[name] = info.st_ino
            }
            for mode in [Publication.Mode.prepareUnactivated, .validateRetained] {
                let retained = try publish(material, directory, mode: mode)
                XCTAssertEqual(retained.files, Dictionary(uniqueKeysWithValues: Publication.Artifact.allCases.map { ($0, .retained) }))
                XCTAssertEqual(try snapshot(directory), before)
                for name in before.keys {
                    var info = stat(); XCTAssertEqual(lstat(file(directory, name).path, &info), 0); XCTAssertEqual(info.st_ino, inodes[name])
                }
            }
        }
    }
    func testEveryInterruptedSubsetResumesWithoutReplacingMaterialOrForegroundState() throws {
        for stop in Publication.Artifact.allCases {
            try fixture { f, material, directory in
                let inventory = try f.machine.inventory(), runtime = try f.machine.runtimePreparation(accountID: f.account.accountID)
                let activation = try f.machine.runtimeActivation(accountID: f.account.accountID)
                XCTAssertThrowsError(try publish(material, directory, stage: { if $0 == stop { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
                let subset = try snapshot(directory)
                XCTAssertFalse(subset.isEmpty)
                _ = try publish(material, directory)
                let complete = try snapshot(directory)
                XCTAssertEqual(complete.count, 3)
                for (name, bytes) in subset { XCTAssertEqual(complete[name], bytes) }
                XCTAssertEqual(try f.machine.inventory(), inventory)
                XCTAssertEqual(try f.machine.runtimePreparation(accountID: f.account.accountID), runtime)
                XCTAssertEqual(try f.machine.runtimeActivation(accountID: f.account.accountID).plan?.encoded, try activation.plan?.encoded)
            }
        }
    }
    func testRetentionCannotCreateMissingFiles() throws {
        try fixture { _, material, directory in
            XCTAssertThrowsError(try publish(material, directory, mode: .validateRetained))
            XCTAssertEqual(try snapshot(directory), [:])
            _ = try publish(material, directory)
            try FileManager.default.removeItem(at: file(directory, "gateway-receipt-key.cbor"))
            let before = try snapshot(directory)
            XCTAssertThrowsError(try publish(material, directory, mode: .validateRetained))
            XCTAssertEqual(try snapshot(directory), before)
        }
    }
    func testPreflightRejectsConflictingOrUnsafeSiblingsBeforeCreatingOtherFiles() throws {
        for name in ["gateway-provider.json", "gateway-receipt-key.cbor", "transport-wake-key.cbor"] {
            for link in [false, true] {
                try fixture { _, material, directory in
                    let destination = file(directory, name)
                    if link { try FileManager.default.createSymbolicLink(atPath: destination.path, withDestinationPath: "/dev/null") }
                    else {
                        try Data("conflicting".utf8).write(to: destination); XCTAssertEqual(chmod(destination.path, 0o600), 0)
                    }
                    XCTAssertThrowsError(try publish(material, directory))
                    XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [name])
                    if !link { XCTAssertEqual(try Data(contentsOf: destination), Data("conflicting".utf8)) }
                }
            }
        }
    }
    func testChangedReferenceOrScopeCannotPublishAndPermissionsAreNeverRepaired() throws {
        try fixture { _, material, directory in
            XCTAssertThrowsError(try publish(material, directory, verify: { throw Interrupted() })) { XCTAssertTrue($0 is Interrupted) }
            XCTAssertEqual(try snapshot(directory), [:])
            let current = try material.reference
            let changed = try GatewayMaterialReference(materialID: AccountPreparationIntent.randomID(), runtime: current.runtime,
                phonePush: current.phonePush, materialDigest: current.materialDigest,
                wakeCredentialID: current.wakeCredentialID, wakePublicKey: current.wakePublicKey)
            XCTAssertThrowsError(try publish(material, directory, expected: changed)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .conflictingMaterial)
            }
            XCTAssertEqual(try snapshot(directory), [:])
            _ = try publish(material, directory)
            let target = file(directory, "gateway-provider.json")
            XCTAssertEqual(chmod(target.path, 0o644), 0)
            let before = try snapshot(directory)
            XCTAssertThrowsError(try publish(material, directory))
            XCTAssertEqual(try snapshot(directory), before)
            var info = stat(); XCTAssertEqual(lstat(target.path, &info), 0); XCTAssertEqual(info.st_mode & 0o7777, 0o644)
        }
    }
    func testFinalValidationDetectsAnEarlierArtifactChange() throws {
        try fixture { _, material, directory in
            XCTAssertThrowsError(try publish(material, directory, stage: {
                if $0 == .transportWake {
                    try Data("changed".utf8).write(to: file(directory, "gateway-provider.json"))
                }
            }))
            XCTAssertEqual(try Data(contentsOf: file(directory, "gateway-provider.json")), Data("changed".utf8))
        }
    }
    func testOrdinaryFixtureCannotPublishForAnotherServiceOwner() throws {
        try fixture { _, material, directory in
            XCTAssertThrowsError(try Publication.publish(material: material, expected: material.reference, directory: directory,
                owner: getuid(), gatewayUID: getuid() + 1000, gatewayGID: getgid(), transportUID: getuid(), transportGID: getgid(),
                mode: .prepareUnactivated, verifyCurrent: {}))
            XCTAssertEqual(try snapshot(directory), [:])
        }
    }
    func testNativeEntryRefusesOrdinaryIdentityBeforeAnyProtectedOperation() throws {
        try fixture { f, material, _ in
            XCTAssertThrowsError(try Publication.publish(account: f.account, expected: material.reference,
                mode: .prepareUnactivated, verifyCurrent: { XCTFail("No protected access") })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
    }
}
