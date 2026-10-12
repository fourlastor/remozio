import Darwin
import Foundation
import Security

// This standalone experiment reuses Core's protected metadata validator.
enum JournalLeaseError: Error { case system(Int32), unsafeMetadata }
enum ServiceProbeError: Error { case arguments, account, placement, signature, manifest, notarization }

enum ServiceProbeContract {
    static let appID = "dev.remozio.experiments.lifecycle"
    static let teamID = "PVDFPZ5D64"
    enum Role: String, CaseIterable {
        case session, authority
        var label: String { "dev.remozio.experiments.lifecycle.\(rawValue)" }
        var executable: String { self == .session ? "RemozioLifecycleSession" : "RemozioLifecycleAuthority" }
        var folder: String { self == .session ? "LaunchAgents" : "LaunchDaemons" }
        var manifest: [String: Any] {
            var result: [String: Any] = ["Label": label, "BundleProgram": "Contents/Helpers/\(executable)",
                "ProgramArguments": [executable, "--service-probe"], "RunAtLoad": true]
            if self == .session { result["LimitLoadToSessionType"] = "Aqua" }
            else { result["UserName"] = "root" }
            return result
        }
    }
    static func validateManifests(_ app: URL) throws {
        for role in Role.allCases {
            let url = app.appendingPathComponent("Contents/Library/\(role.folder)/\(role.label).plist")
            let data = try Data(contentsOf: url, options: .mappedIfSafe)
            guard data.count <= 4096,
                  let values = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  NSDictionary(dictionary: values).isEqual(to: role.manifest) else { throw ServiceProbeError.manifest }
        }
    }
    static func signing(_ url: URL, identifier: String, notarized: Bool) throws {
        var code: SecStaticCode?, requirement: SecRequirement?, information: CFDictionary?
        let expression = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
            + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(teamID)\" and identifier \"\(identifier)\""
            + (notarized ? " and notarized" : "")
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess, let requirement else {
            throw ServiceProbeError.signature
        }
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode)
        guard SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any], let bits = values[kSecCodeInfoFlags as String] as? NSNumber,
              bits.uint32Value & 0x10000 != 0 else { throw notarized ? ServiceProbeError.notarization : .signature }
        let entitlements = values[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        guard entitlements.isEmpty else { throw ServiceProbeError.signature }
    }
    static func validateSigning(_ app: URL, notarized: Bool) throws {
        try signing(app, identifier: appID, notarized: notarized)
        for role in Role.allCases {
            try signing(app.appendingPathComponent("Contents/Helpers/\(role.executable)"), identifier: role.label, notarized: false)
        }
    }
}

/// Retains each named object until the service operation returns. No Root object is created here.
final class ServiceProbePlacement {
    private struct Node { let fd: Int32; let parent: Int32?; let name: String; let device: dev_t; let inode: ino_t; let directory: Bool }
    private var nodes: [Node] = []
    init(app: URL) throws {
        guard app.isFileURL, app.path.hasPrefix("/"), app.path.utf8.count < Int(PATH_MAX) else { throw ServiceProbeError.placement }
        let parts = app.path.dropFirst().split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !parts.isEmpty, parts.count <= 32, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) }) else {
            throw ServiceProbeError.placement
        }
        do {
            var parent = try retain(open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), parent: nil, name: "/", directory: true)
            for part in parts {
                parent = try retain(openat(parent, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), parent: parent, name: part, directory: true)
            }
            try inspect(app, parent: parent, depth: 0)
            try validate()
        } catch { close(); throw error }
    }
    deinit { close() }
    func close() { for node in nodes.reversed() { _ = Darwin.close(node.fd) }; nodes.removeAll() }
    private func retain(_ fd: Int32, parent: Int32?, name: String, directory: Bool) throws -> Int32 {
        guard fd >= 0, nodes.count < 128 else { if fd >= 0 { _ = Darwin.close(fd) }; throw ServiceProbeError.placement }
        do {
            var info = stat()
            guard fstat(fd, &info) == 0 else { throw ServiceProbeError.placement }
            try ProtectedStorageMetadata.validate(fd, info, directory: directory, privateObject: false, owner: 0, ancestorOwner: 0)
            nodes.append(Node(fd: fd, parent: parent, name: name, device: info.st_dev, inode: info.st_ino, directory: directory))
            return fd
        } catch { _ = Darwin.close(fd); throw error }
    }
    private func inspect(_ directory: URL, parent: Int32, depth: Int) throws {
        guard depth <= 16 else { throw ServiceProbeError.placement }
        for name in try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted() {
            guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.utf8.contains(0) else { throw ServiceProbeError.placement }
            var info = stat()
            guard fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else { throw ServiceProbeError.placement }
            let isDirectory = info.st_mode & S_IFMT == S_IFDIR
            guard isDirectory || info.st_mode & S_IFMT == S_IFREG else { throw ServiceProbeError.placement }
            let fd = try retain(openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (isDirectory ? O_DIRECTORY : 0)),
                parent: parent, name: name, directory: isDirectory)
            if isDirectory { try inspect(directory.appendingPathComponent(name), parent: fd, depth: depth + 1) }
        }
    }
    func validate() throws {
        guard !nodes.isEmpty else { throw ServiceProbeError.placement }
        for node in nodes {
            var held = stat(), named = stat()
            guard fstat(node.fd, &held) == 0,
                  (node.parent.map { fstatat($0, node.name, &named, AT_SYMLINK_NOFOLLOW) } ?? lstat(node.name, &named)) == 0,
                  held.st_dev == node.device, held.st_ino == node.inode, named.st_dev == node.device, named.st_ino == node.inode else {
                throw ServiceProbeError.placement
            }
            try ProtectedStorageMetadata.validate(node.fd, held, directory: node.directory, privateObject: false, owner: 0, ancestorOwner: 0)
        }
    }
}
