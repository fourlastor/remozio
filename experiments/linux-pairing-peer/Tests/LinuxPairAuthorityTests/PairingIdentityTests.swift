import CPairingTLS
import Crypto
import Foundation
import PairingCommitState
import RemozioProtocol
import XCTest
@testable import LinuxPairAuthority

final class PairingIdentityTests: XCTestCase {
    private var root: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("linux-pair-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

    private var stateDirectory: URL { root.appendingPathComponent("state") }
    private var store: PairingCommitStore { PairingCommitStore(directory: stateDirectory) }

    func testCreatedIdentityLoadsBackWithTheSameInvitation() throws {
        let created = try PairingIdentity.create(in: store, label: "money-maker")
        let loaded = try PairingIdentity.load(from: store)
        XCTAssertEqual(try loaded.invitation().exportText(), try created.invitation().exportText())
        XCTAssertEqual(loaded.macID, created.macID)
        XCTAssertEqual(loaded.accountID, created.accountID)
        XCTAssertNotEqual(loaded.transportPublicKey, loaded.authorityPublicKey)
        let identity = stateDirectory.appendingPathComponent("identity.json")
        let mode = try FileManager.default.attributesOfItem(atPath: identity.path)[.posixPermissions] as? Int
        XCTAssertEqual(mode, 0o600)
        XCTAssertFalse(FileManager.default.fileExists(atPath: stateDirectory.appendingPathComponent("identity.json.tmp").path))
    }

    func testInvitationUsesTheSharedTextFormatAndPins() throws {
        let identity = try PairingIdentity.create(in: store, label: "money-maker")
        let text = try identity.invitation().exportText()
        XCTAssertTrue(text.hasPrefix("remozio-pairing:v1:"))
        let imported = try PairingInvitation.importText(text)
        XCTAssertEqual(imported.macID, identity.macID)
        XCTAssertEqual(imported.accountID, identity.accountID)
        XCTAssertEqual(imported.authorityPublicKey, identity.authorityPublicKey)
        XCTAssertEqual(imported.transportPublicKey, identity.transportPublicKey)
        XCTAssertEqual(imported.minimumEnvelopeVersion, 1)
        XCTAssertEqual(imported.label, "money-maker")
    }

    func testServiceNameMatchesTheAndroidPairingRouteName() throws {
        let identity = try PairingIdentity(macID: Data([0xFB, 0xFF] + Array(repeating: 0, count: 14)),
                                           accountID: Data(repeating: 0xFF, count: 16), label: "x",
                                           transportKey: P256.Signing.PrivateKey(), authorityKey: P256.Signing.PrivateKey())
        // URL-safe, unpadded, no wrap: the Android NO_PADDING | URL_SAFE | NO_WRAP encoding.
        XCTAssertEqual(identity.serviceName, "R--_8AAAAAAAAAAAAAAAAAAA-_____________________w")
        XCTAssertLessThanOrEqual(identity.serviceName.utf8.count, 63)
        XCTAssertEqual(PairingIdentity.serviceType, "_remozio-pairing._tcp")
    }

    func testInitNeverReplacesAnIdentity() throws {
        let first = try PairingIdentity.create(in: store, label: "first")
        XCTAssertThrowsError(try PairingIdentity.create(in: store, label: "second")) {
            XCTAssertEqual($0 as? PairingCommitError, .identityExists)
        }
        XCTAssertEqual(try PairingIdentity.load(from: store).macID, first.macID)
    }

    func testConcurrentInitCreatesExactlyOneIdentity() throws {
        let attempts = 8
        let results = Results()
        DispatchQueue.concurrentPerform(iterations: attempts) { index in
            do { results.add(.success(try PairingIdentity.create(in: self.store, label: "racer \(index)").macID)) }
            catch { results.add(.failure(error)) }
        }
        let winners = results.all.compactMap { try? $0.get() }
        XCTAssertEqual(winners.count, 1)
        XCTAssertEqual(results.all.count, attempts)
        for case .failure(let error) in results.all { XCTAssertEqual(error as? PairingCommitError, .identityExists) }
        XCTAssertEqual(try PairingIdentity.load(from: store).macID, winners.first)
    }

    func testInterruptedWriteLeavesNoIdentityAndALaterInitSucceeds() throws {
        _ = try store.trustRevision()  // creates the directory
        let leftover = stateDirectory.appendingPathComponent("identity.json.tmp")
        XCTAssertTrue(FileManager.default.createFile(atPath: leftover.path, contents: Data("{\"form".utf8),
                                                     attributes: [.posixPermissions: 0o600]))
        XCTAssertThrowsError(try PairingIdentity.load(from: store)) {
            XCTAssertEqual($0 as? PairingIdentityError, .notInitialized)
        }
        let identity = try PairingIdentity.create(in: store, label: "after crash")
        XCTAssertEqual(try PairingIdentity.load(from: store).macID, identity.macID)
        XCTAssertFalse(FileManager.default.fileExists(atPath: leftover.path))
    }

    func testCorruptOrTruncatedIdentityIsRefusedAndNeverReplaced() throws {
        _ = try store.trustRevision()
        let path = stateDirectory.appendingPathComponent("identity.json").path
        for contents in [Data("{\"format\":1".utf8), Data("{\"format\":2}".utf8), Data()] {
            try? FileManager.default.removeItem(atPath: path)
            XCTAssertTrue(FileManager.default.createFile(atPath: path, contents: contents, attributes: [.posixPermissions: 0o600]))
            XCTAssertThrowsError(try PairingIdentity.load(from: store))
            XCTAssertThrowsError(try PairingIdentity.create(in: store, label: "replacement"))
            XCTAssertEqual(FileManager.default.contents(atPath: path), contents)
        }
    }

    func testGroupReadableIdentityFileIsRefused() throws {
        _ = try PairingIdentity.create(in: store, label: "x")
        let path = stateDirectory.appendingPathComponent("identity.json").path
        try FileManager.default.setAttributes([.posixPermissions: 0o640], ofItemAtPath: path)
        XCTAssertThrowsError(try PairingIdentity.load(from: store)) {
            XCTAssertEqual($0 as? PairingCommitError, .corruptState)
        }
    }

    func testGroupAccessibleStateDirectoryIsRefused() throws {
        try FileManager.default.createDirectory(at: stateDirectory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o750])
        XCTAssertThrowsError(try PairingIdentity.create(in: store, label: "x")) {
            XCTAssertEqual($0 as? PairingCommitError, .unsafeDirectory)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: stateDirectory.appendingPathComponent("identity.json").path))
    }

    func testSymlinkedIdentityAndStateDirectoryAreRefused() throws {
        _ = try store.trustRevision()
        let target = root.appendingPathComponent("elsewhere.json")
        XCTAssertTrue(FileManager.default.createFile(atPath: target.path, contents: Data("{}".utf8),
                                                     attributes: [.posixPermissions: 0o600]))
        try FileManager.default.createSymbolicLink(atPath: stateDirectory.appendingPathComponent("identity.json").path,
                                                   withDestinationPath: target.path)
        XCTAssertThrowsError(try PairingIdentity.load(from: store)) {
            XCTAssertEqual($0 as? PairingCommitError, .unsafeDirectory)
        }

        let real = root.appendingPathComponent("real")
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let linked = root.appendingPathComponent("linked")
        try FileManager.default.createSymbolicLink(atPath: linked.path, withDestinationPath: real.path)
        XCTAssertThrowsError(try PairingIdentity.create(in: PairingCommitStore(directory: linked), label: "x")) {
            XCTAssertEqual($0 as? PairingCommitError, .unsafeDirectory)
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: real.path), [])
    }

    func testInvalidLabelIsRefusedBeforeAnythingIsWritten() throws {
        for label in ["", " ", String(repeating: "a", count: 201), "bad\u{202E}label"] {
            XCTAssertThrowsError(try PairingIdentity.create(in: store, label: label)) {
                XCTAssertEqual($0 as? PairingIdentityError, .invalidLabel)
            }
        }
        XCTAssertThrowsError(try PairingIdentity.load(from: store)) {
            XCTAssertEqual($0 as? PairingIdentityError, .notInitialized)
        }
    }

    func testTLSPresentsThePersistedTransportKeyUnderAFreshCertificate() throws {
        let identity = try PairingIdentity.create(in: store, label: "x")
        let now = Int64(Date().timeIntervalSince1970)
        let server = try TLSPairingServer(identity: identity, nowUnixSeconds: now, lifetimeSeconds: 600)
        var clientCert: UnsafeMutablePointer<UInt8>?, clientKey: UnsafeMutablePointer<UInt8>?
        var certLength = 0, keyLength = 0
        XCTAssertEqual(remozio_tls_make_identity("P-256", now - 60, now + 600, &clientCert, &certLength, &clientKey, &keyLength),
                       REMOZIO_TLS_OK)
        defer { remozio_tls_free(clientCert); remozio_tls_free(clientKey) }
        var options = RemozioTLSClientOptions()
        let client = try XCTUnwrap(remozio_tls_client_context_new(&options, clientCert, certLength, clientKey, keyLength))
        defer { remozio_tls_context_free(client) }
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds), 0)

        let accepted = Results()
        let done = DispatchSemaphore(value: 0)
        let serverFD = fds[0]
        Thread.detachNewThread {
            do {
                let (stream, point) = try server.accept(fd: serverFD, deadline: remozio_tls_now_ms() + 5000)
                accepted.add(.success(point))
                stream.close()
            } catch { accepted.add(.failure(error)) }
            done.signal()
        }
        var connection: OpaquePointer?
        var serverPoint = [UInt8](repeating: 0, count: Int(REMOZIO_TLS_POINT_LENGTH))
        XCTAssertEqual(remozio_tls_connect(client, fds[1], -1, remozio_tls_now_ms() + 5000, &connection, &serverPoint), REMOZIO_TLS_OK)
        XCTAssertEqual(Data(serverPoint), identity.transportPublicKey)
        done.wait()
        remozio_tls_connection_close(connection)
        let point = try XCTUnwrap(accepted.all.first).get()
        XCTAssertEqual(point.count, 65)
        XCTAssertEqual(point.first, 4)
    }

    func testCertificateIssuerRefusesOtherCurvesAndTrailingBytes() throws {
        var output: UnsafeMutablePointer<UInt8>?
        var length = 0
        let p384 = P384.Signing.PrivateKey().derRepresentation
        XCTAssertEqual(p384.withUnsafeBytes {
            remozio_tls_issue_certificate($0.bindMemory(to: UInt8.self).baseAddress, $0.count, 0, 100, &output, &length)
        }, REMOZIO_TLS_INVALID_ARGUMENT)
        XCTAssertNil(output)
        let padded = P256.Signing.PrivateKey().derRepresentation + Data([0])
        XCTAssertEqual(padded.withUnsafeBytes {
            remozio_tls_issue_certificate($0.bindMemory(to: UInt8.self).baseAddress, $0.count, 0, 100, &output, &length)
        }, REMOZIO_TLS_INVALID_ARGUMENT)
        XCTAssertNil(output)
    }
}

/// Thread-safe collection of outcomes from concurrent attempts.
final class Results: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Result<Data, Error>] = []
    func add(_ value: Result<Data, Error>) { lock.lock(); values.append(value); lock.unlock() }
    var all: [Result<Data, Error>] { lock.lock(); defer { lock.unlock() }; return values }
}
