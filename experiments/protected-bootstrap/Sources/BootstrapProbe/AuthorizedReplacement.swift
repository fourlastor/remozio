import AppKit
import Darwin
import Foundation

private enum ProbeFailure: Error { case unsafeScope }

/// Only disposable directories and literal test data. This experiment never launches Root code or registers a service.
@MainActor
enum AuthorizedReplacement {
    private static let parentPath = "/Library/Application Support"
    private static let names = ["", "nested", "payload", "nested/payload"]
    private static let payload = Data("Remozio bootstrap fixture\0".utf8)

    private static func status(_ url: URL, directory: Bool, owner: uid_t? = nil) throws -> stat {
        var value = stat()
        guard lstat(url.path, &value) == 0, value.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG),
              directory || value.st_nlink == 1, owner == nil || value.st_uid == owner else { throw ProbeFailure.unsafeScope }
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (directory ? O_DIRECTORY : 0))
        guard fd >= 0 else { throw ProbeFailure.unsafeScope }
        defer { Darwin.close(fd) }
        var held = stat(), volume = statfs()
        guard fstat(fd, &held) == 0, held.st_dev == value.st_dev, held.st_ino == value.st_ino,
              fstatfs(fd, &volume) == 0, volume.f_flags & UInt32(MNT_LOCAL) != 0 else { throw ProbeFailure.unsafeScope }
        guard let security = filesec_init() else { throw ProbeFailure.unsafeScope }
        defer { filesec_free(security) }
        var checked = stat(), present: Int32 = 0
        guard fstatx_np(fd, &checked, security) == 0, checked.st_dev == held.st_dev, checked.st_ino == held.st_ino,
              filesec_query_property(security, FILESEC_ACL, &present) == 0 else { throw ProbeFailure.unsafeScope }
        if present != 0 {
            var value: acl_t?
            guard filesec_get_property(security, FILESEC_ACL, &value) == 0, let acl = value, acl_valid(acl) == 0 else {
                throw ProbeFailure.unsafeScope
            }
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            var entry: acl_entry_t?, selector = ACL_FIRST_ENTRY, count = 0
            while true {
                errno = 0
                let result = acl_get_entry(acl, selector.rawValue, &entry)
                if result != 0 { guard errno == EINVAL else { throw ProbeFailure.unsafeScope }; break }
                guard let entry, count < 256 else { throw ProbeFailure.unsafeScope }
                count += 1; selector = ACL_NEXT_ENTRY
                var tag = ACL_UNDEFINED_TAG
                guard acl_get_tag_type(entry, &tag) == 0, tag == ACL_EXTENDED_DENY else { throw ProbeFailure.unsafeScope }
            }
        }
        return held
    }
    private static func parent() throws -> URL {
        for path in ["/", "/Library", parentPath] {
            let value = try status(URL(fileURLWithPath: path), directory: true, owner: 0)
            guard value.st_mode & 0o022 == 0 else { throw ProbeFailure.unsafeScope }
        }
        return URL(fileURLWithPath: parentPath)
    }
    private static func validateShape(_ root: URL) throws {
        guard Set(try FileManager.default.contentsOfDirectory(atPath: root.path)) == ["nested", "payload"],
              Set(try FileManager.default.contentsOfDirectory(atPath: root.appendingPathComponent("nested").path)) == ["payload"] else {
            throw ProbeFailure.unsafeScope
        }
        for name in names {
            let node = root.appendingPathComponent(name)
            _ = try status(node, directory: !name.contains("payload"))
            if name.contains("payload") {
                let fd = open(node.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
                guard fd >= 0 else { throw ProbeFailure.unsafeScope }
                defer { Darwin.close(fd) }
                var bytes = Data(count: payload.count + 1), offset = 0
                while offset < bytes.count {
                    let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
                    if count < 0, errno == EINTR { continue }
                    guard count >= 0 else { throw ProbeFailure.unsafeScope }
                    if count == 0 { break }; offset += count
                }
                guard offset == payload.count, bytes.prefix(offset) == payload else { throw ProbeFailure.unsafeScope }
            }
        }
    }
    private static func same(_ left: stat, _ right: stat) throws {
        guard left.st_dev == right.st_dev, left.st_ino == right.st_ino else { throw ProbeFailure.unsafeScope }
    }
    private static func attributes(_ root: URL, manager: FileManager) throws {
        // Protect each parent before changing its children.
        for name in names {
            _ = try parent()
            let node = root.appendingPathComponent(name), directory = !name.contains("payload")
            let before = try status(node, directory: directory)
            if !name.isEmpty {
                let container = try status(node.deletingLastPathComponent(), directory: true, owner: 0)
                guard container.st_mode & 0o022 == 0 else { throw ProbeFailure.unsafeScope }
            }
            let mode = directory ? 0o755 : 0o644
            try manager.setAttributes([.ownerAccountID: NSNumber(value: 0), .groupOwnerAccountID: NSNumber(value: 0),
                                       .posixPermissions: NSNumber(value: mode)], ofItemAtPath: node.path)
            let after = try status(node, directory: directory, owner: 0)
            try same(before, after)
            guard after.st_gid == 0, after.st_mode & 0o7777 == mode else { throw ProbeFailure.unsafeScope }
        }
    }
    static func preflight() -> [String: Any] {
        do { _ = try parent(); return ["schemaVersion": 1, "protectedParentAccepted": true, "authorizationRequested": false] }
        catch { return ["schemaVersion": 1, "protectedParentAccepted": false, "authorizationRequested": false] }
    }
    static func run() async -> [String: Any] {
        let id = UUID().uuidString, uid = getuid(), fm = FileManager.default
        let source = URL(fileURLWithPath: "/private/tmp/remozio-bootstrap-stage-" + id)
        var destination: URL?
        var replacement: FileManager?, attributeManager: FileManager?
        var requests: [String] = []
        var report: [String: Any] = ["schemaVersion": 1, "experiment": "authorized-disposable-bootstrap-files",
            "os": ProcessInfo.processInfo.operatingSystemVersionString, "productionInstallation": false,
            "remozioRootCodeExecuted": false, "servicesRegistered": false]
        do {
            let protectedParent = try parent(), originalParent = try status(protectedParent, directory: true, owner: 0)
            let target = protectedParent.appendingPathComponent("RemozioBootstrapProbe-" + id)
            destination = target
            var absent = stat()
            guard lstat(target.path, &absent) != 0, errno == ENOENT else { throw ProbeFailure.unsafeScope }
            try fm.createDirectory(at: source, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try fm.createDirectory(at: source.appendingPathComponent("nested"), withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700])
            for path in ["payload", "nested/payload"] { try payload.write(to: source.appendingPathComponent(path)) }
            try validateShape(source)
            let originalSource = try status(source, directory: true, owner: uid)
            let scope: [String: Any] = ["schemaVersion": 1, "event": "disposable-scope",
                "disposableSource": source.path, "disposableDestination": target.path]
            if let bytes = try? JSONSerialization.data(withJSONObject: scope, options: [.sortedKeys]) {
                FileHandle.standardError.write(bytes); FileHandle.standardError.write(Data([10]))
            }
            requests.append("replaceFile")
            replacement = FileManager(authorization: try await NSWorkspace.shared.requestAuthorization(to: .replaceFile))
            _ = try parent(); try same(originalParent, status(protectedParent, directory: true, owner: 0))
            guard lstat(target.path, &absent) != 0, errno == ENOENT else { throw ProbeFailure.unsafeScope }
            try validateShape(source)
            try same(originalSource, status(source, directory: true, owner: uid))
            _ = try replacement!.replaceItemAt(target, withItemAt: source)
            report["directoryPromotionReturnedSuccess"] = true
            var observed = stat()
            if lstat(target.path, &observed) == 0 { report["promotedOwnerUID"] = observed.st_uid; report["promotedMode"] = Int(observed.st_mode & 0o7777) }
            try validateShape(target)
            let promotedSource = try status(target, directory: true, owner: uid)
            report["promotionPreservedInode"] = promotedSource.st_dev == originalSource.st_dev && promotedSource.st_ino == originalSource.st_ino
            requests.append("setAttributes")
            attributeManager = FileManager(authorization: try await NSWorkspace.shared.requestAuthorization(to: .setAttributes))
            try attributes(target, manager: attributeManager!)
            try validateShape(target)
            guard getuid() == uid, geteuid() == uid else { throw ProbeFailure.unsafeScope }
            errno = 0
            let writeFD = open(target.appendingPathComponent("payload").path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC)
            let denied = writeFD < 0 && errno == EACCES
            if writeFD >= 0 { Darwin.close(writeFD) }
            report["ordinaryWriteRefused"] = denied
            guard denied else { throw ProbeFailure.unsafeScope }
            report["rootOwnedPrivateWriteBoundaryVerified"] = true
            report["allRequestedOperationsVerified"] = true
        } catch {
            let error = error as NSError
            report["errorDomain"] = error.domain; report["errorCode"] = error.code
            report["allRequestedOperationsVerified"] = false
        }
        // Leave any protected fixture for operator inspection. Never use privileged cleanup on an unprotected destination.
        do {
            if fm.fileExists(atPath: source.path) { try fm.removeItem(at: source) }
            var value = stat()
            let sourceAbsent = lstat(source.path, &value) != 0 && errno == ENOENT
            var destinationAbsent = true
            if let destination { destinationAbsent = lstat(destination.path, &value) != 0 && errno == ENOENT }
            report["cleanupComplete"] = sourceAbsent && destinationAbsent
        } catch { report["cleanupComplete"] = false }
        report["authorizationRequests"] = requests
        report["actualPromptCount"] = NSNull()
        if report["cleanupComplete"] as? Bool != true {
            report["disposableSource"] = source.path
            if let destination { report["disposableDestination"] = destination.path }
        }
        return report
    }
}
