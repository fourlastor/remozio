import Darwin
import Foundation
@testable import RemozioCore

func maintenanceCloseBytes(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
func maintenanceCloseMarker(binding: AuthorityMaintenanceBinding? = nil, installation: UInt8 = 7) throws -> AuthorityMaintenanceCloseMarker {
    let binding = try binding ?? .init(accountID: maintenanceCloseBytes(1), attemptID: maintenanceCloseBytes(2),
        revision: maintenanceCloseBytes(3), incarnation: maintenanceCloseBytes(4), connectionID: maintenanceCloseBytes(5))
    return try .init(binding: binding, macID: maintenanceCloseBytes(6), installationID: maintenanceCloseBytes(installation),
        releaseDigest: maintenanceCloseBytes(8, 32), codeHash: maintenanceCloseBytes(9, 20), directoryID: maintenanceCloseBytes(10),
        ownerUID: getuid(), gate: .init(device: 1, inode: 2))
}
final class MaintenanceCloseFileFixture: @unchecked Sendable {
    let root: URL
    let directory: ProtectedSetupDirectory
    var path: String { directory.path + "/" + AuthorityMaintenanceCloseMarker.fileName }
    init() throws {
        guard getuid() > 0, getuid() == geteuid() else { throw JournalLeaseError.unsafeMetadata }
        root = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remozio-close-marker-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
        directory = try .init(anchor: root.path, relativePath: "Shared", owner: getuid(), visibility: .sharedMetadata)
    }
    func publish(_ marker: AuthorityMaintenanceCloseMarker, expected: Data? = nil) throws {
        try AdministrativeSetupPublication.replaceMaintenanceCloseMarker(marker.encoded, expected: expected,
            directory: directory, owner: getuid(), verify: {})
    }
    func readback(_ expected: AuthorityMaintenanceCloseMarker) throws {
        try AuthorityMaintenanceCloseMarker.readback(expected, directory: directory, owner: getuid())
    }
    func close() throws { directory.close(); try FileManager.default.removeItem(at: root) }
}
