import CryptoKit
import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class RelayRunCredentialFileTests: XCTestCase {
    private struct Rejected: Error {}
    private final class Fixture {
        let root: URL
        let directory: URL
        let bytes: Data
        let tunnel = CloudflareTunnelObservation(accountID: String(repeating: "a", count: 32),
            tunnelID: "12345678-1234-4234-9234-123456789012", name: "disposable")
        var path: String { directory.appendingPathComponent("transport-tunnel.token").path }
        init() throws {
            guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner file fixture") }
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw JournalLeaseError.system(errno) }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent("remozio-relay-token-" + UUID().uuidString)
            directory = root.appendingPathComponent("Services")
            bytes = try JSONSerialization.data(withJSONObject: ["a": tunnel.accountID, "t": tunnel.tunnelID,
                "s": Data(repeating: 0x71, count: 32).base64EncodedString()], options: [.sortedKeys, .withoutEscapingSlashes])
                .base64EncodedData()
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            try bytes.write(to: URL(fileURLWithPath: path))
            guard chmod(path, 0o600) == 0 else { throw JournalLeaseError.system(errno) }
        }
        func open(digest: Data? = nil, tunnel: CloudflareTunnelObservation? = nil,
                  group: gid_t? = nil, verify: @escaping @Sendable () throws -> Void = {}) throws -> RelayRunCredentialFile {
            try .init(directory: ReleaseDestinationLease(anchor: root.path, relativeDirectory: "Services", owner: getuid()),
                owner: getuid(), group: group ?? getgid(), tunnel: tunnel ?? self.tunnel,
                digest: digest ?? Data(SHA256.hash(data: bytes)), verifyCurrent: verify)
        }
        deinit { try? FileManager.default.removeItem(at: root) }
    }
    private func contents(_ fd: Int32) throws -> Data {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_size > 0, info.st_size <= 8192 else { throw Rejected() }
        var bytes = Data(count: Int(info.st_size))
        let count = bytes.withUnsafeMutableBytes { pread(fd, $0.baseAddress, $0.count, 0) }
        guard count == bytes.count else { throw Rejected() }
        return bytes
    }
    func testFreshSpawnDescriptionsKeepIndependentOffsetsAndSurviveTheParentBorrow() throws {
        let f = try Fixture(), file = try f.open()
        defer { file.close() }
        let retained = try file.withDescriptorForSpawn { fd in
            XCTAssertGreaterThanOrEqual(fd, 32)
            XCTAssertNotEqual(fcntl(fd, F_GETFD) & FD_CLOEXEC, 0)
            XCTAssertEqual(fcntl(fd, F_GETFL) & O_ACCMODE, O_RDONLY)
            XCTAssertEqual(lseek(fd, 0, SEEK_CUR), 0)
            var byte: UInt8 = 0
            XCTAssertEqual(read(fd, &byte, 1), 1)
            let copied = fcntl(fd, F_DUPFD_CLOEXEC, 32)
            guard copied >= 0 else { throw JournalLeaseError.system(errno) }
            return copied
        }
        defer { _ = Darwin.close(retained) }
        try file.validate()
        try file.withDescriptorForSpawn { fd in
            XCTAssertEqual(lseek(fd, 0, SEEK_CUR), 0)
            XCTAssertEqual(try contents(fd), f.bytes)
            XCTAssertEqual(lseek(fd, 3, SEEK_SET), 3)
        }
        XCTAssertEqual(lseek(retained, 0, SEEK_CUR), 1)
        file.close()
        XCTAssertEqual(try contents(retained), f.bytes)
        XCTAssertThrowsError(try file.withDescriptorForSpawn { _ in XCTFail("Closed file lent a descriptor") })
    }
    func testWrongDigestAndWrongTunnelCannotProduceASpawnDescriptor() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.open(digest: Data(repeating: 0, count: 32))) {
            XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
        }
        let crossed = CloudflareTunnelObservation(accountID: f.tunnel.accountID,
            tunnelID: "11111111-1111-4111-8111-111111111111", name: f.tunnel.name)
        XCTAssertThrowsError(try f.open(tunnel: crossed)) {
            XCTAssertEqual($0 as? CloudflareProvisioningError, .wrongScope)
        }
        XCTAssertThrowsError(try f.open(digest: Data()))
    }
    func testMatchingDigestDoesNotMakeMalformedOrNoncanonicalTokensValid() throws {
        for bytes in [Data("invalid-token".utf8), Data([0xff, 0xfe]) ] {
            let f = try Fixture()
            try bytes.write(to: URL(fileURLWithPath: f.path))
            XCTAssertThrowsError(try f.open(digest: Data(SHA256.hash(data: bytes)))) {
                XCTAssertEqual($0 as? CloudflareProvisioningError, .invalidResponse)
            }
        }
        let f = try Fixture(), changed = f.bytes + Data([10])
        try changed.write(to: URL(fileURLWithPath: f.path))
        XCTAssertThrowsError(try f.open(digest: Data(SHA256.hash(data: changed))))
    }
    func testMissingUnsafeAndSpecialLeavesAreNeverRepaired() throws {
        for kind in ["missing", "symlink", "hardlink", "fifo", "directory", "readable", "empty", "oversized"] {
            let f = try Fixture()
            switch kind {
            case "missing": XCTAssertEqual(unlink(f.path), 0)
            case "symlink":
                XCTAssertEqual(rename(f.path, f.path + ".old"), 0)
                XCTAssertEqual(symlink(f.path + ".old", f.path), 0)
            case "hardlink": XCTAssertEqual(link(f.path, f.path + ".alias"), 0)
            case "fifo": XCTAssertEqual(unlink(f.path), 0); XCTAssertEqual(mkfifo(f.path, 0o600), 0)
            case "directory": XCTAssertEqual(unlink(f.path), 0); XCTAssertEqual(mkdir(f.path, 0o700), 0)
            case "readable": XCTAssertEqual(chmod(f.path, 0o640), 0)
            case "empty": try Data().write(to: URL(fileURLWithPath: f.path))
            default: try Data(count: 8193).write(to: URL(fileURLWithPath: f.path))
            }
            var before = stat(); let exists = lstat(f.path, &before) == 0
            XCTAssertThrowsError(try f.open(), kind)
            var after = stat()
            if exists {
                XCTAssertEqual(lstat(f.path, &after), 0)
                XCTAssertEqual(before.st_ino, after.st_ino); XCTAssertEqual(before.st_mode, after.st_mode)
                XCTAssertEqual(before.st_size, after.st_size)
            } else { XCTAssertEqual(lstat(f.path, &after), -1); XCTAssertEqual(errno, ENOENT) }
        }
        let f = try Fixture()
        XCTAssertThrowsError(try f.open(group: getgid() + 1))
        XCTAssertEqual(chmod(f.directory.path, 0o770), 0)
        XCTAssertThrowsError(try f.open())
    }
    func testIdenticalReplacementRetiresTheFileAndCannotBeAdoptedAfterRestoration() throws {
        let f = try Fixture(), file = try f.open()
        defer { file.close() }
        XCTAssertEqual(rename(f.path, f.path + ".old"), 0)
        try f.bytes.write(to: URL(fileURLWithPath: f.path))
        XCTAssertEqual(chmod(f.path, 0o600), 0)
        XCTAssertThrowsError(try file.withDescriptorForSpawn { _ in XCTFail("Replacement reached spawn") }) {
            XCTAssertEqual($0 as? JournalLeaseError, .identityChanged)
        }
        XCTAssertEqual(rename(f.path + ".old", f.path), 0)
        XCTAssertThrowsError(try file.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
    }
    func testChangedContentAndLateScopeRefusalBlockSpawnPermanently() throws {
        do {
            let f = try Fixture(), file = try f.open()
            defer { file.close() }
            var changed = f.bytes; changed[0] ^= 1
            try changed.write(to: URL(fileURLWithPath: f.path))
            XCTAssertThrowsError(try file.withDescriptorForSpawn { _ in XCTFail("Changed token reached spawn") })
            try f.bytes.write(to: URL(fileURLWithPath: f.path))
            XCTAssertThrowsError(try file.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
        let f = try Fixture(), valid = Mutex(true)
        let file = try f.open(verify: { if !valid.withLock({ $0 }) { throw Rejected() } })
        defer { file.close() }
        valid.withLock { $0 = false }
        XCTAssertThrowsError(try file.withDescriptorForSpawn { _ in XCTFail("Stale scope reached spawn") }) {
            XCTAssertTrue($0 is Rejected)
        }
        valid.withLock { $0 = true }
        XCTAssertThrowsError(try file.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
    }
    func testSpawnFailureDoesNotInvalidateAnUnchangedCredential() throws {
        let f = try Fixture(), file = try f.open()
        defer { file.close() }
        XCTAssertThrowsError(try file.withDescriptorForSpawn { _ in throw Rejected() }) { XCTAssertTrue($0 is Rejected) }
        try file.validate()
        XCTAssertEqual(try file.withDescriptorForSpawn { try contents($0) }, f.bytes)
    }
    func testDescriptionsAndMirrorsDoNotIncludeTokenBytes() throws {
        let f = try Fixture(), file = try f.open()
        defer { file.close() }
        XCTAssertEqual(String(describing: file), "RelayRunCredentialFile(redacted)")
        XCTAssertEqual(String(reflecting: file), "RelayRunCredentialFile(redacted)")
        XCTAssertTrue(Mirror(reflecting: file).children.isEmpty)
        file.close(); file.close()
        XCTAssertThrowsError(try file.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
    }
}
