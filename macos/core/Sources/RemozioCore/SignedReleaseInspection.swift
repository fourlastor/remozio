import Darwin
import Foundation
import Security

/// Signature evidence for a candidate bundle. Revalidate protected copies before installation or execution.
public struct SignedReleaseEvidence: Sendable {
    public let manifest: ReleaseManifest
    public let codeDirectoryHashes: [AuthorityCodeRole: Data]
    public let dependencyCodeDirectoryHashes: [String: Data]

    init(manifest: ReleaseManifest, codeDirectoryHashes: [AuthorityCodeRole: Data],
         dependencyCodeDirectoryHashes: [String: Data] = [:]) {
        self.manifest = manifest; self.codeDirectoryHashes = codeDirectoryHashes
        self.dependencyCodeDirectoryHashes = dependencyCodeDirectoryHashes
    }
}


public enum SignedReleaseInspection {
    /// The expected identity must come from trusted setup or update policy, never from the candidate manifest.
    /// This check does not establish notarization, installed placement, generation floors, or quiescent activation.
    public static func inspect(_ bundle: URL, teamID: String, appIdentifier: String) throws -> SignedReleaseEvidence {
        guard teamID.utf8.count == 10, teamID.utf8.allSatisfy({ (65...90).contains($0) || (48...57).contains($0) }),
              ReleaseManifest.validToken(appIdentifier) else { throw ReleaseManifestError.invalidDeclaration }
        return try inspect(bundle, expectedAppIdentifier: appIdentifier, expectedTeamID: teamID) { identifier, hash in
            try XPCPeerPolicy(teamID: teamID, componentIdentifier: identifier,
                approvedCodeDirectoryHashes: [hash], expectedUserID: 0).requirement
        }
    }

    /// Internal fixture seam. Production has no caller-supplied signature requirement.
    static func inspect(_ bundle: URL, expectedAppIdentifier: String, expectedTeamID: String?,
                        requirement: (String, Data) throws -> String) throws -> SignedReleaseEvidence {
        let input = bundle.standardizedFileURL
        try noSymlink(input)
        let root = try canonicalURL(input)
        let app = try signedMetadata(root, identifier: expectedAppIdentifier, expectedTeamID: expectedTeamID, requirement: requirement)
        guard let declaration = app.plist[ReleaseManifest.infoKey] as? Data,
              declaration.count <= ReleaseManifest.maximumBytes else { throw ReleaseManifestError.missingMetadata }
        let manifest = try ReleaseManifest.decode(declaration)
        guard let appComponent = manifest.components.first(where: { $0.role == .app }),
              let executable = app.plist["CFBundleExecutable"] as? String,
              appComponent.identifier == expectedAppIdentifier, appComponent.relativePath == "Contents/MacOS/" + executable,
              app.plist["CFBundleVersion"] as? String == manifest.build,
              app.plist["CFBundleShortVersionString"] as? String == manifest.release,
              app.plist["LSMinimumSystemVersion"] as? String == "26.0" else { throw ReleaseManifestError.identityMismatch }
        let expectedPaths = Set(manifest.components.map(\.relativePath) + manifest.dependencies.flatMap {
            [$0.executablePath] + $0.executableAliases.sorted()
        })
        let actualPaths = try executableInventory(root, maximumExecutables: manifest.schemaVersion == 1 ? AuthorityCodeRole.allCases.count : 256)
        guard actualPaths == expectedPaths else {
            throw ReleaseManifestError.identityMismatch
        }
        var hashes: [AuthorityCodeRole: Data] = [:]
        for component in manifest.components {
            var path = root
            for segment in component.relativePath.split(separator: "/") {
                path.appendPathComponent(String(segment)); try noSymlink(path)
            }
            try thinArm64(path)
            let metadata = component.role == .app ? app : try signedMetadata(path, identifier: component.identifier, expectedTeamID: expectedTeamID, requirement: requirement)
            guard metadata.identifier == component.identifier, metadata.teamID == expectedTeamID,
                  component.teamID == metadata.teamID, metadata.plist["CFBundleVersion"] as? String == component.build,
                  metadata.plist["CFBundleIdentifier"] as? String == component.identifier,
                  metadata.plist["RemozioSecurityGeneration"] as? String == String(component.generation),
                  component.role == .app ? component.build == manifest.build : component.codeDirectoryHash == metadata.hash else {
                throw ReleaseManifestError.identityMismatch
            }
            hashes[component.role] = metadata.hash
        }
        var dependencyHashes: [String: Data] = [:]
        for dependency in manifest.dependencies {
            func exactPath(_ relative: String) throws -> URL {
                var path = root
                for part in relative.split(separator: "/") {
                    path.appendPathComponent(String(part)); try noSymlink(path)
                }
                return path
            }
            let signatureURL = try exactPath(dependency.signaturePath)
            let executableURL = try exactPath(dependency.executablePath)
            try thinArm64(executableURL)
            let header = try readHeader(executableURL, byteCount: 16).bytes
            guard header.count == 16 else { throw ReleaseManifestError.identityMismatch }
            let type = header.withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(fromByteOffset: 12, as: UInt32.self)) }
            guard type == (dependency.kind == .framework ? 6 : 2) else { throw ReleaseManifestError.identityMismatch }
            let metadata = try signedMetadata(signatureURL, identifier: dependency.identifier, expectedTeamID: expectedTeamID,
                                              requirement: requirement, allowMissingPlist: dependency.kind == .tool)
            guard metadata.hash == dependency.codeDirectoryHash, dependency.teamID == metadata.teamID else {
                throw ReleaseManifestError.identityMismatch
            }
            if let build = metadata.plist["CFBundleVersion"] {
                guard let build = build as? String, build == dependency.build else { throw ReleaseManifestError.identityMismatch }
            } else if dependency.build != nil { throw ReleaseManifestError.identityMismatch }
            if dependency.kind != .tool {
                let kind = dependency.kind == .framework ? "FMWK" : dependency.kind == .application ? "APPL" : "XPC!"
                guard metadata.plist["CFBundlePackageType"] as? String == kind,
                      metadata.plist["CFBundleIdentifier"] as? String == dependency.identifier,
                      let name = metadata.plist["CFBundleExecutable"] as? String, ReleaseManifest.validToken(name) else {
                    throw ReleaseManifestError.identityMismatch
                }
                let mainURL = dependency.kind == .framework ? signatureURL.appendingPathComponent(name)
                    : signatureURL.appendingPathComponent("Contents/MacOS/" + name)
                guard try canonicalURL(mainURL) == executableURL else { throw ReleaseManifestError.identityMismatch }
            } else if let identifier = metadata.plist["CFBundleIdentifier"] {
                guard let identifier = identifier as? String, identifier == dependency.identifier else {
                    throw ReleaseManifestError.identityMismatch
                }
            }
            let binary = try signedMetadata(executableURL, identifier: dependency.identifier, expectedTeamID: expectedTeamID,
                                           requirement: requirement, allowMissingPlist: true)
            guard binary.hash == metadata.hash else { throw ReleaseManifestError.identityMismatch }
            for alias in dependency.executableAliases {
                let target = try canonicalURL(root.appendingPathComponent(alias))
                guard target == executableURL else { throw ReleaseManifestError.unsafePath }
            }
            dependencyHashes[dependency.executablePath] = metadata.hash
        }
        // Check the enclosing seal again after inspecting all nested code. This remains a candidate snapshot.
        let final = try signedMetadata(root, identifier: expectedAppIdentifier, expectedTeamID: expectedTeamID, requirement: requirement)
        guard final.hash == app.hash, final.plist[ReleaseManifest.infoKey] as? Data == declaration else {
            throw ReleaseManifestError.identityMismatch
        }
        return SignedReleaseEvidence(manifest: manifest, codeDirectoryHashes: hashes, dependencyCodeDirectoryHashes: dependencyHashes)
    }

    private struct Metadata {
        let identifier: String
        let hash: Data
        let teamID: String?
        let plist: [String: Any]
    }
    private static func signedMetadata(_ url: URL, identifier: String, expectedTeamID: String?,
                                       requirement: (String, Data) throws -> String, allowMissingPlist: Bool = false) throws -> Metadata {
        var code: SecStaticCode?
        try checked(SecStaticCodeCreateWithPath(url as CFURL, [], &code))
        guard let code else { throw ReleaseManifestError.missingMetadata }
        func information() throws -> [String: Any] {
            var information: CFDictionary?
            try checked(SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information))
            guard let values = information as? [String: Any] else { throw ReleaseManifestError.missingMetadata }; return values
        }
        // The initial hash only selects a requirement. No metadata is trusted before strict validation.
        guard let candidateHash = try information()[kSecCodeInfoUnique as String] as? Data, candidateHash.count == 20 else {
            throw ReleaseManifestError.missingMetadata
        }
        var compiled: SecRequirement?
        try checked(SecRequirementCreateWithString(try requirement(identifier, candidateHash) as CFString, [], &compiled))
        guard let compiled else { throw ReleaseManifestError.missingMetadata }
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode)
        try checked(SecStaticCodeCheckValidity(code, flags, compiled))
        let values = try information()
        guard let actualIdentifier = values[kSecCodeInfoIdentifier as String] as? String, actualIdentifier == identifier,
              let hash = values[kSecCodeInfoUnique as String] as? Data, hash == candidateHash,
              let codeFlags = values[kSecCodeInfoFlags as String] as? NSNumber, codeFlags.uint32Value & 0x10000 != 0 else {
            throw ReleaseManifestError.identityMismatch
        }
        let rawPlist = values[kSecCodeInfoPList as String]
        let maybePlist = rawPlist as? [String: Any]
        guard rawPlist == nil || maybePlist != nil else { throw ReleaseManifestError.missingMetadata }
        guard allowMissingPlist || maybePlist != nil else { throw ReleaseManifestError.missingMetadata }
        let plist = maybePlist ?? [:]
        let entitlements = values[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        let teamID = values[kSecCodeInfoTeamIdentifier as String] as? String
        guard teamID == expectedTeamID, validEntitlements(entitlements, identifier: identifier, teamID: expectedTeamID) else {
            throw ReleaseManifestError.identityMismatch
        }
        return Metadata(identifier: actualIdentifier, hash: hash, teamID: teamID, plist: plist)
    }
    /// Only identity declarations are allowed. The caller supplies the Team ID from trusted policy.
    static func validEntitlements(_ values: [String: Any], identifier: String, teamID: String?) -> Bool {
        let applicationKey = "com.apple.application-identifier"
        let teamKey = "com.apple.developer.team-identifier"
        guard Set(values.keys).isSubset(of: [applicationKey, teamKey]) else { return false }
        if let value = values[applicationKey] {
            let expected = teamID.map { $0 + "." + identifier } ?? identifier
            guard value as? String == expected else { return false }
        }
        if let value = values[teamKey] {
            guard let teamID, value as? String == teamID else { return false }
        }
        return true
    }
    /// Inventories canonical executable files and in-bundle aliases. Directory names confer no authority.
    static func executableInventory(_ bundle: URL, maximumEntries: Int = 8192, maximumExecutables: Int = AuthorityCodeRole.allCases.count) throws -> Set<String> {
        guard (1...8192).contains(maximumEntries), (1...256).contains(maximumExecutables) else { throw ReleaseManifestError.invalidDeclaration }
        let root = try canonicalURL(bundle)
        let prefix = root.path + "/"
        let keys: Set<URLResourceKey> = [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey]
        var failed = false
        guard let entries = FileManager.default.enumerator(at: root, includingPropertiesForKeys: Array(keys),
            errorHandler: { _, _ in failed = true; return false }) else { throw ReleaseManifestError.unsafePath }
        var paths = Set<String>(), count = 0
        var aliases: [(path: String, target: String)] = []
        for case let url as URL in entries {
            count += 1
            guard count <= maximumEntries, url.path.hasPrefix(prefix) else { throw ReleaseManifestError.unsafePath }
            let relative = String(url.path.dropFirst(prefix.count))
            guard relative.utf8.count <= 1024, relative.split(separator: "/").count <= 16 else {
                throw ReleaseManifestError.unsafePath
            }
            let values = try url.resourceValues(forKeys: keys)
            if values.isSymbolicLink == true {
                let target = try canonicalURL(url)
                guard target.path == root.path || target.path.hasPrefix(prefix) else {
                    throw ReleaseManifestError.unsafePath
                }
                aliases.append((relative, target.path == root.path ? "" : String(target.path.dropFirst(prefix.count))))
                if values.isDirectory == true { entries.skipDescendants() }
                continue
            }
            if values.isDirectory == true { continue }
            guard values.isRegularFile == true else { throw ReleaseManifestError.unsafePath }
            if try containsExecutableCode(url) { paths.insert(relative) }
            guard paths.count <= maximumExecutables else { throw ReleaseManifestError.identityMismatch }
        }
        guard !failed else { throw ReleaseManifestError.unsafePath }
        let canonicalPaths = paths
        for alias in aliases {
            for code in canonicalPaths {
                if code == alias.target { paths.insert(alias.path) }
                else if alias.target.isEmpty || code.hasPrefix(alias.target + "/") {
                    let suffix = alias.target.isEmpty ? code : String(code.dropFirst(alias.target.count + 1))
                    paths.insert(alias.path + "/" + suffix)
                }
            }
            guard paths.count <= maximumExecutables else { throw ReleaseManifestError.identityMismatch }
        }
        return paths
    }
    private static func canonicalURL(_ url: URL) throws -> URL {
        guard let path = realpath(url.path, nil) else { throw ReleaseManifestError.unsafePath }
        defer { free(path) }
        return URL(fileURLWithPath: String(cString: path))
    }
    private static func readHeader(_ url: URL, byteCount: Int = 8) throws -> (mode: mode_t, bytes: Data) {
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { throw ReleaseManifestError.unsafePath }
        defer { close(descriptor) }
        var status = stat()
        guard fstat(descriptor, &status) == 0, status.st_mode & S_IFMT == S_IFREG else {
            throw ReleaseManifestError.unsafePath
        }
        var bytes = [UInt8](repeating: 0, count: byteCount), offset = 0
        while offset < bytes.count {
            let received = bytes.withUnsafeMutableBytes { read(descriptor, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if received < 0, errno == EINTR { continue }
            guard received >= 0 else { throw ReleaseManifestError.unsafePath }
            if received == 0 { break }
            offset += received
        }
        return (status.st_mode, Data(bytes.prefix(offset)))
    }
    private static func containsExecutableCode(_ url: URL) throws -> Bool {
        let header = try readHeader(url)
        let magic = Data(header.bytes.prefix(4))
        let codeMagic: Set<Data> = [Data([0xce, 0xfa, 0xed, 0xfe]), Data([0xcf, 0xfa, 0xed, 0xfe]),
            Data([0xfe, 0xed, 0xfa, 0xce]), Data([0xfe, 0xed, 0xfa, 0xcf]),
            Data([0xca, 0xfe, 0xba, 0xbe]), Data([0xbe, 0xba, 0xfe, 0xca]),
            Data([0xca, 0xfe, 0xba, 0xbf]), Data([0xbf, 0xba, 0xfe, 0xca])]
        return header.mode & 0o111 != 0 || codeMagic.contains(magic)
    }
    private static func thinArm64(_ url: URL) throws {
        guard try readHeader(url).bytes == Data([0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 1]) else {
            throw ReleaseManifestError.identityMismatch
        }
    }
    private static func noSymlink(_ url: URL) throws {
        guard try url.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink == false else { throw ReleaseManifestError.unsafePath }
    }
    private static func checked(_ status: OSStatus) throws {
        guard status == errSecSuccess else { throw ReleaseManifestError.security(status) }
    }
}
