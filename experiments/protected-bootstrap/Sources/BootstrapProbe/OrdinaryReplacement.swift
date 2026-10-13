import Darwin
import Foundation

enum OrdinaryReplacement {
    static func metadata(_ url: URL) -> [String: Any]? {
        var value = stat()
        guard lstat(url.path, &value) == 0 else { return nil }
        return ["ownerUID": value.st_uid, "mode": Int(value.st_mode & 0o7777), "inode": value.st_ino,
                "directory": value.st_mode & S_IFMT == S_IFDIR]
    }
    static func run() throws -> [String: Any] {
        guard getuid() != 0, getuid() == geteuid(), CommandLine.arguments == [CommandLine.arguments[0], "--ordinary"] else { exit(EX_NOPERM) }
        let fm = FileManager.default
        let root = URL(fileURLWithPath: "/private/tmp/remozio-filemanager-probe-" + UUID().uuidString)
        try fm.createDirectory(at: root, withIntermediateDirectories: false)
        guard chmod(root.path, 0o700) == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        defer { try? fm.removeItem(at: root) }
        var results: [[String: Any]] = []
        for (name, directory, existing, parentExists) in [
            ("replace-existing-file", false, true, true), ("replace-missing-file", false, false, true),
            ("replace-existing-directory", true, true, true), ("replace-missing-directory", true, false, true),
            ("replace-under-missing-parent", false, false, false)] {
            let fixture = root.appendingPathComponent(name)
            try fm.createDirectory(at: fixture, withIntermediateDirectories: false)
            let source = fixture.appendingPathComponent("source")
            let parent = fixture.appendingPathComponent("parent")
            if parentExists { try fm.createDirectory(at: parent, withIntermediateDirectories: false) }
            let destination = parent.appendingPathComponent("target")
            if directory {
                try fm.createDirectory(at: source, withIntermediateDirectories: false)
                try Data("replacement".utf8).write(to: source.appendingPathComponent("payload"))
                if existing {
                    try fm.createDirectory(at: destination, withIntermediateDirectories: false)
                    try Data("original".utf8).write(to: destination.appendingPathComponent("payload"))
                }
            } else {
                try Data("replacement".utf8).write(to: source)
                if existing { try Data("original".utf8).write(to: destination) }
            }
            guard chmod(source.path, directory ? 0o750 : 0o640) == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
            if existing { guard chmod(destination.path, directory ? 0o700 : 0o600) == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) } }
            let before = metadata(destination)
            var row: [String: Any] = ["case": name, "before": before as Any? ?? NSNull()]
            do {
                let resulting = try fm.replaceItemAt(destination, withItemAt: source)
                row["operationReturnedSuccess"] = true
                row["returnedDestination"] = resulting == destination
            } catch {
                let error = error as NSError
                row["operationReturnedSuccess"] = false; row["errorDomain"] = error.domain; row["errorCode"] = error.code
                if let underlying = error.userInfo[NSUnderlyingErrorKey] as? NSError {
                    row["underlyingErrorDomain"] = underlying.domain; row["underlyingErrorCode"] = underlying.code
                }
            }
            row["after"] = metadata(destination) as Any? ?? NSNull()
            row["sourceRemains"] = fm.fileExists(atPath: source.path)
            let payload = directory ? destination.appendingPathComponent("payload") : destination
            row["replacementBytesPresent"] = (try? Data(contentsOf: payload)) == Data("replacement".utf8)
            results.append(row)
        }
        var report: [String: Any] = ["schemaVersion": 1, "experiment": "ordinary-filemanager-replacement", "os": ProcessInfo.processInfo.operatingSystemVersionString,
            "administratorAuthorizationRequested": false, "privilegedFileManagerTested": false,
            "productionProtectedInstallationTested": false, "results": results]
        try fm.removeItem(at: root)
        report["fixtureRootRemoved"] = !fm.fileExists(atPath: root.path)
        return report
    }
}
