import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class SignedReleaseInspectionTests: XCTestCase {
    private func inspect(_ url: URL, identifier: String) throws -> SignedReleaseEvidence {
        try SignedReleaseInspection.inspect(url, expectedAppIdentifier: identifier, expectedTeamID: nil) { identifier, _ in
            "identifier \"\(identifier)\""
        }
    }
    private var repository: URL {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { root.deleteLastPathComponent() }
        return root
    }
    func testBuiltDebugAndReleaseDeclarationsMatchSignedComponentsAndCompiledContracts() throws {
        for configuration in ["Debug", "Release"] {
            let app = repository.appendingPathComponent(".build/macos-app/DerivedData/Build/Products/\(configuration)/Remozio.app")
            guard FileManager.default.fileExists(atPath: app.path) else {
                throw XCTSkip("Build the app first; scripts/check.sh checks both real bundles before these tests.")
            }
            let identifier = "dev.remozio.mac" + (configuration == "Debug" ? ".debug" : "")
            let evidence = try inspect(app, identifier: identifier)
            XCTAssertEqual(evidence.manifest.components.count, 8)
            XCTAssertEqual(evidence.codeDirectoryHashes.count, 8)
            XCTAssertFalse(evidence.manifest.absentRoles.contains(.setupController))
            let setup = try XCTUnwrap(evidence.manifest.components.first { $0.role == .setupController })
            XCTAssertEqual(setup.relativePath, AdministrativeSetupConfiguration.executablePath)
            XCTAssertEqual(setup.codeDirectoryHash, evidence.codeDirectoryHashes[.setupController])
            XCTAssertEqual(setup.formats.first { $0.name == "setup.service-config" }?.readers, [1])
            for role: AuthorityCodeRole in [.app, .setupController] {
                let component = try XCTUnwrap(evidence.manifest.components.first { $0.role == role })
                let local = try XCTUnwrap(component.formats.first { $0.name == "setup.local-ipc" })
                XCTAssertEqual(local.readers, AdministrativeSetupInterface.supportedVersions)
                XCTAssertEqual(local.writers, AdministrativeSetupInterface.supportedVersions)
            }
            let authority = try XCTUnwrap(evidence.manifest.components.first { $0.role == .authority })
            func formats(_ name: String) throws -> ReleaseFormat { try XCTUnwrap(authority.formats.first { $0.name == name }) }
            for role: AuthorityCodeRole in [.authority, .setupController] {
                let component = try XCTUnwrap(evidence.manifest.components.first { $0.role == role })
                let preparation = try XCTUnwrap(component.formats.first { $0.name == "authority.installation-preparation" })
                let versions = Set(PreparationIntentStore.supportedSchemaVersions.map(UInt64.init))
                XCTAssertEqual(preparation.readers, versions)
                XCTAssertEqual(preparation.writers, versions)
            }
            XCTAssertEqual(try formats("authority.command-host-config").readers, InstalledAuthorityCommandConfiguration.supportedVersions)
            XCTAssertEqual(try formats("authority.command-config").readers, AuthorityCommandStartupConfiguration.supportedVersions)
            XCTAssertEqual(try formats("authority.command-execution-config").readers, AuthorityCommandExecutionConfiguration.supportedVersions)
            XCTAssertEqual(try formats("command.capture").readers, CommandCapture.supportedSchemaVersions)
            XCTAssertEqual(Set(authority.requests.map(\.schemaVersion)), CommandCapture.supportedSchemaVersions)
            for contract in authority.requests {
                XCTAssertEqual(contract.kind, 0); XCTAssertEqual(contract.wireVersion, 1); XCTAssertEqual(contract.actions, [0, 2])
                XCTAssertEqual(contract.purposes, [.issuedRequest, .cancellation, .biometricAuthorization, .status])
            }
            XCTAssertThrowsError(try SignedReleaseInspection.inspect(app, teamID: "ABCDEFGHIJ", appIdentifier: identifier))
        }
    }
    func testSignedMetadataAndHelperTamperingAreRejected() throws {
        let original = repository.appendingPathComponent(".build/macos-app/DerivedData/Build/Products/Debug/Remozio.app")
        guard FileManager.default.fileExists(atPath: original.path) else { throw XCTSkip("Build the app before artifact tamper checks.") }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        for path in ["Contents/Info.plist", "Contents/Helpers/RemozioCommandChild", AdministrativeSetupConfiguration.executablePath,
                     "Contents/Library/LaunchDaemons/" + AdministrativeSetupConfiguration.plistName] {
            let copy = root.appendingPathComponent(UUID().uuidString + ".app")
            try FileManager.default.copyItem(at: original, to: copy)
            XCTAssertNoThrow(try inspect(copy, identifier: "dev.remozio.mac.debug"))
            let changed = copy.appendingPathComponent(path)
            let file = try FileHandle(forWritingTo: changed); try file.seekToEnd(); try file.write(contentsOf: Data([0x41])); try file.close()
            XCTAssertThrowsError(try inspect(copy, identifier: "dev.remozio.mac.debug"))
        }
    }
    func testReSigningChangedHelperCannotBypassTheAppManifestHash() throws {
        let original = repository.appendingPathComponent(".build/macos-app/DerivedData/Build/Products/Debug/Remozio.app")
        guard FileManager.default.fileExists(atPath: original.path) else { throw XCTSkip("Build the app before artifact identity checks.") }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let copy = root.appendingPathComponent("Remozio.app")
        try FileManager.default.copyItem(at: original, to: copy)
        let child = copy.appendingPathComponent("Contents/Helpers/RemozioCommandChild")
        for (path, identifier) in [(child, "dev.remozio.command-child.debug"), (copy, "dev.remozio.mac.debug")] {
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
            // A different code requirement changes the helper CDHash while preserving its identifier and generation.
            process.arguments = ["--force", "--sign", "-", "--options", "runtime", "--identifier", identifier,
                                 "-r", "=designated => identifier \"\(identifier)\" and info[RemozioSecurityGeneration] = \"1\"", path.path]
            process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            try process.run(); process.waitUntilExit(); XCTAssertEqual(process.terminationStatus, 0)
        }
        XCTAssertThrowsError(try inspect(copy, identifier: "dev.remozio.mac.debug")) {
            XCTAssertEqual($0 as? ReleaseManifestError, .identityMismatch)
        }
    }
    func testUndeclaredExecutableCannotBecomeCompleteReleaseEvidence() throws {
        let original = repository.appendingPathComponent(".build/macos-app/DerivedData/Build/Products/Debug/Remozio.app")
        guard FileManager.default.fileExists(atPath: original.path) else { throw XCTSkip("Build the app before inventory checks.") }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        for relativePath in ["Contents/Helpers/UnlistedHelper", "Contents/Resources/UnlistedHelper", "Contents/Resources/UnlistedScript", "Contents/Helpers/UnlistedAlias", "Contents/Resources/UnlistedDirectoryAlias", "Contents/Resources/UnlistedTree"] {
            let copy = root.appendingPathComponent(UUID().uuidString + ".app")
            try FileManager.default.copyItem(at: original, to: copy)
            let extra = copy.appendingPathComponent(relativePath)
            if relativePath.hasSuffix("Tree") {
                let version = extra.appendingPathComponent("Versions/B")
                try FileManager.default.createDirectory(at: version.appendingPathComponent("PrivateHeaders"), withIntermediateDirectories: true)
                try FileManager.default.createDirectory(at: version.appendingPathComponent("Resources"), withIntermediateDirectories: false)
                try FileManager.default.copyItem(at: copy.appendingPathComponent("Contents/Helpers/RemozioCommandChild"),
                    to: version.appendingPathComponent("UnlistedHelper"))
                for (name, target) in [("PrivateHeaders", "Versions/Current/PrivateHeaders"),
                                       ("Resources", "Versions/Current/Resources"),
                                       ("Versions/Current", "B"), ("UnlistedHelper", "Versions/Current/UnlistedHelper")] {
                    try FileManager.default.createSymbolicLink(atPath: extra.appendingPathComponent(name).path, withDestinationPath: target)
                }
            } else if relativePath.hasSuffix("DirectoryAlias") {
                try FileManager.default.createSymbolicLink(atPath: extra.path, withDestinationPath: "../Helpers")
            } else if relativePath.hasSuffix("Alias") {
                try FileManager.default.createSymbolicLink(atPath: extra.path, withDestinationPath: "RemozioCommandChild")
            } else if relativePath.hasSuffix("Script") {
                try Data("#!/bin/sh\nexit 0\n".utf8).write(to: extra)
                try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: extra.path)
            } else {
                try FileManager.default.copyItem(at: copy.appendingPathComponent("Contents/Helpers/RemozioCommandChild"), to: extra)
            }
            let sign = Process(); sign.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
            sign.arguments = ["--force", "--sign", "-", "--options", "runtime", "--identifier", "dev.remozio.mac.debug", copy.path]
            sign.standardOutput = FileHandle.nullDevice; sign.standardError = FileHandle.nullDevice
            try sign.run(); sign.waitUntilExit(); XCTAssertEqual(sign.terminationStatus, 0)
            let verify = Process(); verify.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
            verify.arguments = ["--verify", "--deep", "--strict", copy.path]
            verify.standardOutput = FileHandle.nullDevice; verify.standardError = FileHandle.nullDevice
            try verify.run(); verify.waitUntilExit(); XCTAssertEqual(verify.terminationStatus, 0)
            XCTAssertThrowsError(try inspect(copy, identifier: "dev.remozio.mac.debug"), relativePath) {
                XCTAssertEqual($0 as? ReleaseManifestError, .identityMismatch)
            }
        }
    }
    func testInventoryBoundsAndInternalAliasesDoNotHideCode() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let contents = root.appendingPathComponent("Contents")
        try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: false)
        let code = contents.appendingPathComponent("code")
        // Even a non-executable Mach-O file belongs to the code inventory.
        try Data([0xcf, 0xfa, 0xed, 0xfe]).write(to: code)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: code.path)
        try FileManager.default.createSymbolicLink(at: contents.appendingPathComponent("alias"), withDestinationURL: code)
        XCTAssertEqual(try SignedReleaseInspection.executableInventory(root), ["Contents/code", "Contents/alias"])
        let data = contents.appendingPathComponent("data")
        try Data("plain resource".utf8).write(to: data)
        try FileManager.default.createSymbolicLink(at: contents.appendingPathComponent("data-alias"), withDestinationURL: data)
        XCTAssertEqual(try SignedReleaseInspection.executableInventory(root), ["Contents/code", "Contents/alias"])
        XCTAssertThrowsError(try SignedReleaseInspection.executableInventory(root, maximumEntries: 1))
        try FileManager.default.createSymbolicLink(at: contents.appendingPathComponent("external"), withDestinationURL: repository)
        XCTAssertThrowsError(try SignedReleaseInspection.executableInventory(root)) {
            XCTAssertEqual($0 as? ReleaseManifestError, .unsafePath)
        }
    }
    func testFrameworkLinksDoNotSkipCanonicalVersionCode() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let framework = root.appendingPathComponent("Contents/Frameworks/Vendor.framework")
        let version = framework.appendingPathComponent("Versions/B")
        try FileManager.default.createDirectory(at: version.appendingPathComponent("PrivateHeaders"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: version.appendingPathComponent("Resources"), withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        try Data([0xcf, 0xfa, 0xed, 0xfe]).write(to: version.appendingPathComponent("Vendor"))
        for (name, target) in [("PrivateHeaders", "Versions/Current/PrivateHeaders"),
                               ("Resources", "Versions/Current/Resources"),
                               ("Versions/Current", "B"), ("Vendor", "Versions/Current/Vendor")] {
            try FileManager.default.createSymbolicLink(atPath: framework.appendingPathComponent(name).path, withDestinationPath: target)
        }
        XCTAssertEqual(try SignedReleaseInspection.executableInventory(root), [
            "Contents/Frameworks/Vendor.framework/Versions/B/Vendor",
            "Contents/Frameworks/Vendor.framework/Versions/Current/Vendor",
            "Contents/Frameworks/Vendor.framework/Vendor"
        ])
    }

    func testSymlinkBundleCannotBecomeInspectionEvidence() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let link = root.appendingPathComponent("candidate.app")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: repository)
        XCTAssertThrowsError(try inspect(link, identifier: "dev.remozio.mac.debug")) {
            XCTAssertEqual($0 as? ReleaseManifestError, .unsafePath)
        }
    }
    func testReleaseEntitlementsBindToTrustedTeamAndComponent() {
        let identifier = "dev.remozio.mac", team = "ABCDEFGHIJ"
        let applicationKey = "com.apple.application-identifier", teamKey = "com.apple.developer.team-identifier"
        for values: [String: Any] in [[:], [applicationKey: team + "." + identifier], [teamKey: team],
                                      [applicationKey: team + "." + identifier, teamKey: team]] {
            XCTAssertTrue(SignedReleaseInspection.validEntitlements(values, identifier: identifier, teamID: team))
        }
        for values: [String: Any] in [[applicationKey: identifier], [applicationKey: "OTHERTEAM1." + identifier],
                                      [applicationKey: team + ".dev.remozio.other"], [applicationKey: 1],
                                      [teamKey: "OTHERTEAM1"], [teamKey: true], [teamKey: NSNull()],
                                      ["com.apple.security.get-task-allow": false],
                                      ["com.apple.security.cs.disable-library-validation": true],
                                      ["keychain-access-groups": [team + ".shared"]]] {
            XCTAssertFalse(SignedReleaseInspection.validEntitlements(values, identifier: identifier, teamID: team))
        }
    }
    func testAdHocFixtureEntitlementsCannotClaimATeam() {
        let identifier = "dev.remozio.mac"
        XCTAssertTrue(SignedReleaseInspection.validEntitlements([:], identifier: identifier, teamID: nil))
        XCTAssertTrue(SignedReleaseInspection.validEntitlements(["com.apple.application-identifier": identifier], identifier: identifier, teamID: nil))
        for values: [String: Any] in [["com.apple.application-identifier": "ABCDEFGHIJ." + identifier],
                                      ["com.apple.developer.team-identifier": "ABCDEFGHIJ"],
                                      ["com.apple.developer.team-identifier": NSNull()]] {
            XCTAssertFalse(SignedReleaseInspection.validEntitlements(values, identifier: identifier, teamID: nil))
        }
    }
    func testProductionIdentityInputsCannotInjectARequirement() throws {
        for team in ["", "abcdef1234", "ABCDEFGHIJ\" or true"] {
            XCTAssertThrowsError(try SignedReleaseInspection.inspect(repository, teamID: team, appIdentifier: "dev.remozio.mac")) {
                XCTAssertEqual($0 as? ReleaseManifestError, .invalidDeclaration)
            }
        }
    }
}
