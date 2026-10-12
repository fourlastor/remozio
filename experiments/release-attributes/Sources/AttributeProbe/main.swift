import Darwin
import Foundation
@testable import AttributeInspection

do {
    guard CommandLine.arguments.count == 2, getuid() != 0, getuid() == geteuid() else { exit(64) }
    let app = URL(fileURLWithPath: CommandLine.arguments[1]).standardizedFileURL
    let root = app.deletingLastPathComponent().deletingLastPathComponent()
    var info = stat()
    guard app.lastPathComponent == "Fixture.app", app.deletingLastPathComponent().lastPathComponent == "Host",
          root.lastPathComponent.hasPrefix("remozio-release-attributes-"), app.path == app.resolvingSymlinksInPath().path,
          lstat(root.path, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFDIR,
          info.st_mode & 0o077 == 0 else { exit(64) }
    var count = 0, links = 0, attributes: [String: Int] = [:]
    func inspect(parent: Int32? = nil, name: String, depth: Int) throws {
        guard depth <= 16 else { throw AttributeError.limit }
        var before = stat()
        let code = parent.map { fstatat($0, name, &before, AT_SYMLINK_NOFOLLOW) } ?? lstat(name, &before)
        guard code == 0 else { throw AttributeError.system(errno) }
        let type = before.st_mode & S_IFMT
        guard type == S_IFDIR || type == S_IFREG || type == S_IFLNK else { throw AttributeError.malformed }
        let flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK | (type == S_IFLNK ? O_SYMLINK : O_NOFOLLOW)
            | (type == S_IFDIR ? O_DIRECTORY : 0)
        let fd = parent.map { openat($0, name, flags) } ?? open(name, flags)
        guard fd >= 0 else { throw AttributeError.system(errno) }
        defer { close(fd) }
        var held = stat()
        guard fstat(fd, &held) == 0, held.st_uid == getuid(), held.st_dev == before.st_dev,
              held.st_ino == before.st_ino, held.st_mode & S_IFMT == type else { throw AttributeError.malformed }
        for attribute in try AttributeInspection.names(fd: fd) { attributes[attribute, default: 0] += 1 }
        if type == S_IFLNK { links += 1 }
        if type != S_IFDIR { return }
        let duplicate = dup(fd)
        guard duplicate >= 0 else { throw AttributeError.system(errno) }
        guard let stream = fdopendir(duplicate) else {
            close(duplicate); throw AttributeError.system(errno)
        }
        defer { closedir(stream) }
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw AttributeError.system(errno) }
                break
            }
            let child = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(validatingCString: $0) }
            }
            guard let child, !child.isEmpty else { throw AttributeError.malformed }
            if child == "." || child == ".." { continue }
            count += 1; guard count <= 8192 else { throw AttributeError.limit }
            try inspect(parent: fd, name: child, depth: depth + 1)
        }
    }
    try inspect(name: app.path, depth: 0)
    let record: [String: Any] = ["entries": count, "inspectedLinks": links, "skippedLinks": 0, "attributeNameCounts": attributes,
        "attributeValuesRead": false, "RootExecuted": false]
    FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]) + Data([10]))
} catch { fputs("attribute inventory failed: \(error)\n", stderr); exit(65) }
