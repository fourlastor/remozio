import Darwin
import Foundation
import Security
import RemozioCore

func ownedFixture(_ path: String) throws -> URL {
    guard getuid() != 0, getuid() == geteuid() else { throw ReleaseManifestError.unsafePath }
    let app = URL(fileURLWithPath: path).standardizedFileURL
    let root = app.deletingLastPathComponent().deletingLastPathComponent()
    guard app.path == app.resolvingSymlinksInPath().path,
          root.lastPathComponent.hasPrefix("remozio-sparkle-boundary-"),
          app.lastPathComponent == "Fixture.app", app.deletingLastPathComponent().lastPathComponent == "Host" else {
        throw ReleaseManifestError.unsafePath
    }
    var info = stat()
    guard lstat(root.path, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFDIR,
          info.st_mode & 0o077 == 0 else { throw ReleaseManifestError.unsafePath }
    return app
}


// Fixture-only metadata collection. The production reader validates every declaration after signing.
func fixtureMetadata(_ url: URL) throws -> (Data, String?, [String: Any]) {
    var code: SecStaticCode?, info: CFDictionary?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
          SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let values = info as? [String: Any], let hash = values[kSecCodeInfoUnique as String] as? Data else {
        throw ReleaseManifestError.missingMetadata
    }
    return (hash, values[kSecCodeInfoTeamIdentifier as String] as? String,
            values[kSecCodeInfoPList as String] as? [String: Any] ?? [:])
}
func fixtureCanonical(_ url: URL) throws -> String {
    guard let value = realpath(url.path, nil) else { throw ReleaseManifestError.unsafePath }
    defer { free(value) }
    return String(cString: value)
}
func experimentManifest(_ root: URL, teamID: String, appIdentifier: String) throws -> ReleaseManifest {
    let (_, _, app) = try fixtureMetadata(root)
    guard let build = app["CFBundleVersion"] as? String,
          let release = app["CFBundleShortVersionString"] as? String,
          let executable = app["CFBundleExecutable"] as? String else { throw ReleaseManifestError.missingMetadata }
    let framework = "Contents/Frameworks/Sparkle.framework", base = framework + "/Versions/B"
    let declarations: [(String, String, String, ReleaseDependencyKind)] = [
        (framework, base + "/Sparkle", "org.sparkle-project.Sparkle", .framework),
        (base + "/Autoupdate", base + "/Autoupdate", "org.sparkle-project.Sparkle.Autoupdate", .tool),
        (base + "/Updater.app", base + "/Updater.app/Contents/MacOS/Updater", "org.sparkle-project.Sparkle.Updater", .application),
        (base + "/XPCServices/Downloader.xpc", base + "/XPCServices/Downloader.xpc/Contents/MacOS/Downloader", "org.sparkle-project.DownloaderService", .xpcService),
        (base + "/XPCServices/Installer.xpc", base + "/XPCServices/Installer.xpc/Contents/MacOS/Installer", "org.sparkle-project.InstallerLauncher", .xpcService)
    ]
    let enumerationRoot = root.standardizedFileURL
    guard let entries = FileManager.default.enumerator(at: enumerationRoot, includingPropertiesForKeys: [.isSymbolicLinkKey]) else {
        throw ReleaseManifestError.unsafePath
    }
    var aliases: [(String, String)] = [], count = 0
    let canonicalRoot = try fixtureCanonical(root), prefix = canonicalRoot + "/"
    for case let url as URL in entries {
        count += 1; guard count <= 8192 else { throw ReleaseManifestError.invalidDeclaration }
        let values = try url.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey])
        if values.isSymbolicLink == true {
            let target = try fixtureCanonical(url)
            guard target.hasPrefix(prefix) else { throw ReleaseManifestError.unsafePath }
            aliases.append((String(url.standardizedFileURL.path.dropFirst(enumerationRoot.path.count + 1)), String(target.dropFirst(prefix.count))))
            if values.isDirectory == true { entries.skipDescendants() }
        }
    }
    let dependencies = try declarations.map { signaturePath, codePath, identifier, kind in
        let (hash, team, info) = try fixtureMetadata(root.appendingPathComponent(signaturePath))
        var codeAliases = Set<String>()
        for (alias, target) in aliases {
            if target == codePath { codeAliases.insert(alias) }
            else if codePath.hasPrefix(target + "/") { codeAliases.insert(alias + "/" + codePath.dropFirst(target.count + 1)) }
        }
        return try ReleaseDependency(owner: .app, kind: kind, signaturePath: signaturePath, executablePath: codePath,
            identifier: identifier, codeDirectoryHash: hash, teamID: team, build: info["CFBundleVersion"] as? String,
            executableAliases: codeAliases)
    }
    let component = try ReleaseComponent(role: .app, identifier: appIdentifier, generation: 1,
        relativePath: "Contents/MacOS/" + executable, codeDirectoryHash: nil, build: build, teamID: teamID, formats: [])
    return try .init(release: release, build: build, components: [component], dependencies: dependencies)
}

do {
    let args = CommandLine.arguments
    guard args.count == 5, ["prepare", "inspect", "bad-hash", "bad-alias", "bad-kind", "bad-build", "bad-identifier", "bad-team"].contains(args[1]),
          args[4].hasPrefix("dev.remozio.experiment.sparkleboundary.") else { throw ReleaseManifestError.invalidDeclaration }
    let root = try ownedFixture(args[2])
    if args[1] == "prepare" {
        let value = try experimentManifest(root, teamID: args[3], appIdentifier: args[4])
        let infoURL = root.appendingPathComponent("Contents/Info.plist")
        var info = try PropertyListSerialization.propertyList(from: Data(contentsOf: infoURL), format: nil) as! [String: Any]
        info[ReleaseManifest.infoKey] = try value.canonicalBytes
        info["RemozioSecurityGeneration"] = "1"
        info["LSMinimumSystemVersion"] = "26.0"
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: infoURL)
        print("prepared schema2 dependency declaration")
    } else if args[1].hasPrefix("bad-") {
        let infoURL = root.appendingPathComponent("Contents/Info.plist")
        var info = try PropertyListSerialization.propertyList(from: Data(contentsOf: infoURL), format: nil) as! [String: Any]
        guard let bytes = info[ReleaseManifest.infoKey] as? Data else { throw ReleaseManifestError.missingMetadata }
        let value = try ReleaseManifest.decode(bytes)
        var dependencies = value.dependencies
        if args[1] == "bad-hash" {
            let old = dependencies[0]
            dependencies[0] = try ReleaseDependency(owner: old.owner, kind: old.kind, signaturePath: old.signaturePath,
                executablePath: old.executablePath, identifier: old.identifier, codeDirectoryHash: Data(repeating: 0xa5, count: 20),
                teamID: old.teamID, build: old.build, executableAliases: old.executableAliases)
        } else if args[1] != "bad-alias" {
            guard let index = dependencies.firstIndex(where: { $0.kind == .framework }) else {
                throw ReleaseManifestError.invalidDeclaration
            }
            let old = dependencies[index], operation = args[1]
            dependencies[index] = try ReleaseDependency(owner: old.owner,
                kind: operation == "bad-kind" ? .tool : old.kind,
                signaturePath: operation == "bad-kind" ? old.executablePath : old.signaturePath,
                executablePath: old.executablePath, identifier: operation == "bad-identifier" ? "org.wrong.Framework" : old.identifier,
                codeDirectoryHash: old.codeDirectoryHash, teamID: operation == "bad-team" ? "ZZZZZZZZZZ" : old.teamID,
                build: operation == "bad-build" ? "9999" : old.build, executableAliases: old.executableAliases)
        } else {
            guard let toolIndex = dependencies.firstIndex(where: { $0.kind == .tool }),
                  let frameworkIndex = dependencies.firstIndex(where: { $0.kind == .framework }) else {
                throw ReleaseManifestError.invalidDeclaration
            }
            let tool = dependencies[toolIndex], framework = dependencies[frameworkIndex]
            dependencies[toolIndex] = try ReleaseDependency(owner: tool.owner, kind: tool.kind, signaturePath: tool.signaturePath,
                executablePath: tool.executablePath, identifier: tool.identifier, codeDirectoryHash: tool.codeDirectoryHash,
                teamID: tool.teamID, build: tool.build, executableAliases: framework.executableAliases)
            dependencies[frameworkIndex] = try ReleaseDependency(owner: framework.owner, kind: framework.kind, signaturePath: framework.signaturePath,
                executablePath: framework.executablePath, identifier: framework.identifier, codeDirectoryHash: framework.codeDirectoryHash,
                teamID: framework.teamID, build: framework.build, executableAliases: tool.executableAliases)
        }
        info[ReleaseManifest.infoKey] = try ReleaseManifest(release: value.release, build: value.build,
            components: value.components, dependencies: dependencies).canonicalBytes
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: infoURL)
        print("prepared negative declaration control")
    } else {
        let value = try SignedReleaseInspection.inspect(root, teamID: args[3], appIdentifier: args[4])
        let policy = try AuthorityCodePolicy(entries: value.manifest.components.map { component in
            guard let team = component.teamID, let hash = value.codeDirectoryHashes[component.role] else {
                throw ReleaseManifestError.identityMismatch
            }
            return try .init(role: component.role, teamID: team, identifier: component.identifier,
                installedGeneration: component.generation, minimumGeneration: component.generation,
                codeDirectoryHash: hash, active: true)
        })
        try ReleaseGenerationPreflight.validate(value, against: policy)
        let record: [String: Any] = ["schema": value.manifest.schemaVersion, "roles": value.manifest.components.count,
            "dependencies": value.manifest.dependencies.count, "dependencyHashes": value.dependencyCodeDirectoryHashes.count,
            "aliases": value.manifest.dependencies.reduce(0) { $0 + $1.executableAliases.count }, "preflight": true, "activation": false]
        let bytes = try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys])
        FileHandle.standardOutput.write(bytes + Data([10]))
    }
} catch {
    fputs("fixture inspection failed: \(error)\n", stderr)
    exit(65)
}
