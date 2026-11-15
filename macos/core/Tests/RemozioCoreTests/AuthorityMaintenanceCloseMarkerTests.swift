import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityMaintenanceCloseMarkerTests: XCTestCase {
    private enum Fault: Error { case injected }
    private let wide = try! CBORLimits(maxBytes: 4096, maxDepth: 4, maxItems: 128)
    func testCanonicalRoundTripRejectsUnknownMissingVersionTypeAndOversizedValues() throws {
        let marker = try maintenanceCloseMarker(), bytes = try marker.encoded
        XCTAssertEqual(try AuthorityMaintenanceCloseMarker.decode(bytes), marker); XCTAssertLessThanOrEqual(bytes.count, 512)
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: wide) else { return XCTFail() }
        var unknown = fields; unknown[11] = .null
        var missing = fields; missing[10] = nil
        var version = fields; version[0] = .unsigned(2)
        var badUID = fields; badUID[8] = .unsigned(UInt64(UInt32.max))
        var zeroUID = fields; zeroUID[8] = .unsigned(0)
        var badDevice = fields; badDevice[9] = .unsigned(UInt64(UInt32.max) + 1)
        var badGate = fields; badGate[10] = .unsigned(0)
        for value in [unknown, missing, version, badUID, zeroUID, badDevice, badGate] {
            XCTAssertThrowsError(try AuthorityMaintenanceCloseMarker.decode(DeterministicCBOR.encode(.map(value), limits: wide)))
        }
        for key in UInt64(2)...7 {
            var wrongType = fields; wrongType[key] = .unsigned(1)
            XCTAssertThrowsError(try AuthorityMaintenanceCloseMarker.decode(DeterministicCBOR.encode(.map(wrongType), limits: wide)))
            var wrongLength = fields; wrongLength[key] = .bytes(Data())
            XCTAssertThrowsError(try AuthorityMaintenanceCloseMarker.decode(DeterministicCBOR.encode(.map(wrongLength), limits: wide)))
        }
        for invalid in [Data(bytes.dropLast()), bytes + Data([0]), Data(repeating: 0, count: 513)] {
            XCTAssertThrowsError(try AuthorityMaintenanceCloseMarker.decode(invalid))
        }
    }
    func testPrivateDurablePublicationAndReadbackRetainTheExactFile() throws {
        let f = try MaintenanceCloseFileFixture(); defer { try? f.close() }
        let marker = try maintenanceCloseMarker(); try f.publish(marker)
        var before = stat(); XCTAssertEqual(lstat(f.path, &before), 0)
        XCTAssertEqual(before.st_uid, getuid()); XCTAssertEqual(before.st_mode & 0o777, 0o600); XCTAssertEqual(before.st_nlink, 1)
        try f.readback(marker); try f.publish(marker)
        var after = stat(); XCTAssertEqual(lstat(f.path, &after), 0); XCTAssertEqual(before.st_ino, after.st_ino)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.path)), try marker.encoded)
    }
    func testReadbackCannotCreateAMissingMarker() throws {
        let f = try MaintenanceCloseFileFixture(); defer { try? f.close() }
        XCTAssertThrowsError(try f.readback(maintenanceCloseMarker()))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.path))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.directory.path), [])
    }
    func testPreviousIncarnationInstallationAndEveryOtherBoundValueRefuseReadback() throws {
        let f = try MaintenanceCloseFileFixture(); defer { try? f.close() }
        let marker = try maintenanceCloseMarker(); try f.publish(marker)
        guard case .map(let fields) = try DeterministicCBOR.decode(marker.encoded, limits: wide) else { return XCTFail() }
        for key in UInt64(3)...10 {
            var changed = fields
            switch key {
            case 5: changed[key] = .bytes(maintenanceCloseBytes(99, 32))
            case 6: changed[key] = .bytes(maintenanceCloseBytes(99, 20))
            case 8, 9, 10: changed[key] = .unsigned(99)
            default: changed[key] = .bytes(maintenanceCloseBytes(99))
            }
            XCTAssertThrowsError(try f.readback(AuthorityMaintenanceCloseMarker.decode(DeterministicCBOR.encode(.map(changed), limits: wide))))
        }
        let b = marker.binding
        for field in 0..<5 {
            var values = [b.accountID, b.attemptID, b.revision, b.incarnation, b.connectionID]; values[field] = maintenanceCloseBytes(99)
            let binding = try AuthorityMaintenanceBinding(accountID: values[0], attemptID: values[1], revision: values[2],
                incarnation: values[3], connectionID: values[4])
            XCTAssertThrowsError(try f.readback(maintenanceCloseMarker(binding: binding)))
        }
        try f.readback(marker)
    }
    func testCASRejectsAForeignSourceAndReplaysOnlyThePublishedTarget() throws {
        let f = try MaintenanceCloseFileFixture(); defer { try? f.close() }
        let first = try maintenanceCloseMarker(), next = try maintenanceCloseMarker(installation: 8)
        try f.publish(first)
        XCTAssertThrowsError(try f.publish(next, expected: maintenanceCloseMarker(installation: 9).encoded))
        try f.readback(first); try f.publish(next, expected: first.encoded); try f.readback(next)
        try f.publish(next, expected: first.encoded); try f.readback(next)
    }
    func testStagingAndPostPublicationErrorsNeverBecomeInventedSuccessfulReceipts() throws {
        for boundary in [AdministrativeSetupPublication.Stage.staged, .published] {
            let f = try MaintenanceCloseFileFixture(); defer { try? f.close() }
            let marker = try maintenanceCloseMarker()
            XCTAssertThrowsError(try AdministrativeSetupPublication.publish(marker.encoded, file: .maintenanceCloseMarker,
                directory: f.directory, owner: getuid(), didStage: { if $0 == boundary { throw Fault.injected } }))
            if boundary == .staged { XCTAssertThrowsError(try f.readback(marker)); XCTAssertFalse(FileManager.default.fileExists(atPath: f.path)) }
            else { try f.readback(marker) }
        }
    }
    func testCorruptUnsafeLinkedSymbolicAndReplacedParentsRefuseReadback() throws {
        for mutation in 0..<6 {
            let f = try MaintenanceCloseFileFixture(); defer { try? f.close() }
            let marker = try maintenanceCloseMarker(); try f.publish(marker)
            if mutation == 0 { try Data([1]).write(to: URL(fileURLWithPath: f.path)) }
            if mutation == 1 { XCTAssertEqual(chmod(f.path, 0o644), 0) }
            if mutation == 2 { XCTAssertEqual(link(f.path, f.path + ".alias"), 0) }
            if mutation == 3 { XCTAssertEqual(rename(f.path, f.path + ".old"), 0); XCTAssertEqual(symlink(f.path + ".old", f.path), 0) }
            if mutation == 4 { XCTAssertEqual(unlink(f.path), 0) }
            if mutation == 5 {
                XCTAssertEqual(rename(f.directory.path, f.directory.path + ".old"), 0)
                try FileManager.default.createDirectory(atPath: f.directory.path, withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o755])
            }
            XCTAssertThrowsError(try f.readback(marker))
        }
    }
}
