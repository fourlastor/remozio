import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class InstallationServiceManifestTests: XCTestCase {
    private func fixture() throws -> (InstallationServiceManifest, InstallationInventory, SignedReleaseEvidence, [String: Any]) {
        let app = try ReleaseComponent(role: .app, identifier: "dev.remozio.mac", generation: 1,
            relativePath: "Contents/MacOS/Remozio", codeDirectoryHash: nil, build: "1", teamID: nil, formats: [])
        let authority = try ReleaseComponent(role: .authority, identifier: "dev.remozio.authority", generation: 1,
            relativePath: "Contents/Helpers/Authority", codeDirectoryHash: Data(repeating: 2, count: 20), build: "1", teamID: nil, formats: [])
        let release = SignedReleaseEvidence(manifest: try .init(release: "1", build: "1", components: [app, authority]),
            codeDirectoryHashes: [.app: Data(repeating: 1, count: 20), .authority: Data(repeating: 2, count: 20)])
        let account = try InstallationAccount(accountID: Data(repeating: 3, count: 16), ownerUID: 501)
        let service = try InstallationService(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
            label: "dev.remozio.authority", plistName: "dev.remozio.authority.plist", accountID: account.accountID)
        let path = "/Library/Remozio/authority.cbor"
        let arguments = [authority.relativePath, "--configuration", path]
        let expected = try InstallationServiceManifest(declaration: service, component: authority, configurationPath: path,
            userName: "root", arguments: arguments, machServices: [service.label], runAtLoad: true, keepAlive: true)
        let inventory = try InstallationInventory(macID: Data(repeating: 1, count: 16), installationID: Data(repeating: 2, count: 16),
            revision: Data(repeating: 4, count: 16), bundlePath: "/Library/Remozio/Remozio.app",
            releaseDigest: InstallationInventory.digest(release), accounts: [account], services: [service])
        return (expected, inventory, release, ["Label": service.label, "BundleProgram": authority.relativePath,
            "ProgramArguments": arguments, "UserName": "root", "MachServices": [service.label: true], "RunAtLoad": true, "KeepAlive": true])
    }
    private func encode(_ value: Any) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: value, format: .xml, options: 0)
    }
    func testMatchingSignedJobMetadata() throws {
        let (expected, inventory, release, plist) = try fixture()
        XCTAssertNoThrow(try expected.validate(encode(plist), inventory: inventory, release: release))
    }
    func testChangedLaunchTargetArgumentsAccountAndEndpointsAreRejected() throws {
        let (expected, inventory, release, plist) = try fixture()
        let changes: [(String, Any)] = [("Label", "dev.remozio.other"), ("BundleProgram", "Contents/Helpers/Other"),
            ("ProgramArguments", ["other"]), ("UserName", "nobody"), ("MachServices", ["dev.remozio.other": true]),
            ("KeepAlive", false), ("Program", "/tmp/other"), ("EnvironmentVariables", ["DYLD_INSERT_LIBRARIES": "/tmp/other"])]
        for (key, value) in changes {
            var changed = plist; changed[key] = value
            XCTAssertThrowsError(try expected.validate(encode(changed), inventory: inventory, release: release), key)
        }
    }
    func testMissingMalformedAndOversizedPlistsAreRejected() throws {
        let (expected, inventory, release, plist) = try fixture()
        for key in plist.keys {
            var changed = plist; changed.removeValue(forKey: key)
            XCTAssertThrowsError(try expected.validate(encode(changed), inventory: inventory, release: release))
        }
        for data in [Data(), Data("invalid".utf8), Data(repeating: 0, count: 65537)] {
            XCTAssertThrowsError(try expected.validate(data, inventory: inventory, release: release))
        }
    }
    func testExpectationCannotSelectAnUndeclaredComponent() throws {
        let (_, inventory, release, _) = try fixture()
        let other = try ReleaseComponent(role: .authority, identifier: "dev.remozio.other", generation: 1,
            relativePath: "Contents/Helpers/Other", codeDirectoryHash: Data(repeating: 2, count: 20), build: "1", teamID: nil, formats: [])
        let expected = try InstallationServiceManifest(declaration: inventory.services[0], component: other,
            configurationPath: "/Library/Remozio/authority.cbor", userName: "root",
            arguments: [other.relativePath, "--configuration", "/Library/Remozio/authority.cbor"],
            machServices: [], runAtLoad: true, keepAlive: false)
        let plist: [String: Any] = ["Label": "dev.remozio.authority", "BundleProgram": other.relativePath,
            "ProgramArguments": [other.relativePath, "--configuration", "/Library/Remozio/authority.cbor"],
            "UserName": "root", "RunAtLoad": true, "KeepAlive": false]
        XCTAssertThrowsError(try expected.validate(encode(plist), inventory: inventory, release: release))
    }
    func testUserAgentBindsAquaSessionAndRejectsExplicitUserName() throws {
        let (_, base, original, _) = try fixture()
        let component = try ReleaseComponent(role: .guiAgent, identifier: "dev.remozio.gui", generation: 1,
            relativePath: "Contents/Helpers/Gui", codeDirectoryHash: Data(repeating: 3, count: 20), build: "1", teamID: nil, formats: [])
        var hashes = original.codeDirectoryHashes; hashes[.guiAgent] = Data(repeating: 3, count: 20)
        let release = SignedReleaseEvidence(manifest: try .init(release: "1", build: "1", components: original.manifest.components + [component]),
            codeDirectoryHashes: hashes)
        let service = try InstallationService(role: .guiAgent, kind: .agent, domainUID: 501, executionUID: 501,
            label: "dev.remozio.gui", plistName: "dev.remozio.gui.plist", accountID: base.accounts[0].accountID)
        let inventory = try InstallationInventory(macID: base.macID, installationID: base.installationID, revision: base.revision,
            bundlePath: base.bundlePath, releaseDigest: InstallationInventory.digest(release),
            accounts: base.accounts, services: base.services + [service])
        let path = "/Library/Remozio/gui.cbor", arguments = [component.relativePath, "--configuration", path]
        let expected = try InstallationServiceManifest(declaration: service, component: component, configurationPath: path,
            userName: nil, arguments: arguments, machServices: [], runAtLoad: true, keepAlive: false)
        var plist: [String: Any] = ["Label": service.label, "BundleProgram": component.relativePath,
            "ProgramArguments": arguments, "RunAtLoad": true, "KeepAlive": false, "LimitLoadToSessionType": "Aqua"]
        XCTAssertNoThrow(try expected.validate(encode(plist), inventory: inventory, release: release))
        plist["LimitLoadToSessionType"] = "Background"
        XCTAssertThrowsError(try expected.validate(encode(plist), inventory: inventory, release: release))
        XCTAssertThrowsError(try InstallationServiceManifest(declaration: service, component: component, configurationPath: path,
            userName: "root", arguments: arguments, machServices: [], runAtLoad: true, keepAlive: false))
    }
    func testRootExpectationRejectsMissingAccountUnsafePathsAndMismatchedInvocation() throws {
        let (_, inventory, release, _) = try fixture()
        let service = inventory.services[0], component = try XCTUnwrap(release.manifest.components.first { $0.role == .authority })
        func expected(_ path: String, user: String?, arguments: [String]) throws -> InstallationServiceManifest {
            try .init(declaration: service, component: component, configurationPath: path, userName: user,
                arguments: arguments, machServices: [], runAtLoad: true, keepAlive: false)
        }
        let path = "/Library/Remozio/authority.cbor", arguments = [component.relativePath, "--configuration", "/Library/Remozio/authority.cbor"]
        XCTAssertThrowsError(try expected(path, user: nil, arguments: arguments))
        XCTAssertThrowsError(try expected(path, user: "nobody", arguments: arguments))
        XCTAssertThrowsError(try expected("/", user: "root", arguments: [component.relativePath, "/"]))
        XCTAssertThrowsError(try expected("/Library/../other", user: "root", arguments: [component.relativePath, "/Library/../other"]))
        XCTAssertThrowsError(try expected(path, user: "root", arguments: ["other", path]))
        XCTAssertThrowsError(try expected(path, user: "root", arguments: [component.relativePath, "--configuration", "/other"]))
    }

    func testInvocationRequiresSupportedModeAndActualConfigurationSlot() throws {
        let (_, inventory, release, _) = try fixture()
        let service = inventory.services[0], component = try XCTUnwrap(release.manifest.components.first { $0.role == .authority })
        let path = "/Library/Remozio/authority.cbor"
        let malformed = [[component.relativePath, path], [component.relativePath, path, "--configuration"],
            [component.relativePath, "--configuration", "/other", path],
            [component.relativePath, "--unsupported", path], [component.relativePath, "--command-configuration", path]]
        for arguments in malformed {
            XCTAssertThrowsError(try InstallationServiceManifest(declaration: service, component: component,
                configurationPath: path, userName: "root", arguments: arguments, machServices: [], runAtLoad: true, keepAlive: true))
        }
        for mode in ["--configuration", "--presence-configuration"] {
            XCTAssertNoThrow(try InstallationServiceManifest(declaration: service, component: component,
                configurationPath: path, userName: "root", arguments: [component.relativePath, mode, path],
                machServices: [], runAtLoad: true, keepAlive: true))
        }
    }
    func testTransportAndGatewayModeSetsMatchCurrentEntryPoints() throws {
        let path = "/Library/Remozio/service.cbor", account = Data(repeating: 3, count: 16)
        for role in [AuthorityCodeRole.transport, .notificationGateway] {
            let component = try ReleaseComponent(role: role, identifier: "dev.remozio.service", generation: 1,
                relativePath: "Contents/Helpers/Service", codeDirectoryHash: Data(repeating: 3, count: 20), build: "1", teamID: nil, formats: [])
            let service = try InstallationService(role: role, kind: .daemon, domainUID: nil, executionUID: 600,
                label: "dev.remozio.service", plistName: "dev.remozio.service.plist", accountID: account)
            for mode in ["--configuration", "--wake-configuration", "--remote-configuration"] {
                let build = { try InstallationServiceManifest(declaration: service, component: component,
                    configurationPath: path, userName: "_remozio_service", arguments: [component.relativePath, mode, path],
                    machServices: [], runAtLoad: true, keepAlive: true) }
                if role == .transport || mode == "--configuration" { XCTAssertNoThrow(try build()) }
                else { XCTAssertThrowsError(try build()) }
            }
            XCTAssertThrowsError(try InstallationServiceManifest(declaration: service, component: component,
                configurationPath: path, userName: "_remozio_service", arguments: [component.relativePath, "--presence-configuration", path],
                machServices: [], runAtLoad: true, keepAlive: true))
        }
    }

    func testConfigurationPathMatchesProtectedReaderByteLimits() throws {
        let (_, inventory, release, _) = try fixture()
        let service = inventory.services[0], component = try XCTUnwrap(release.manifest.components.first { $0.role == .authority })
        func expected(_ path: String) throws -> InstallationServiceManifest {
            try .init(declaration: service, component: component, configurationPath: path, userName: "root",
                arguments: [component.relativePath, "--configuration", path], machServices: [], runAtLoad: true, keepAlive: false)
        }
        func path(bytes: Int) -> String {
            var remaining = bytes - 1, parts: [String] = []
            while remaining > 255 { parts.append(String(repeating: "a", count: 255)); remaining -= 256 }
            parts.append(String(repeating: "b", count: remaining))
            return "/" + parts.joined(separator: "/")
        }
        let accepted = path(bytes: Int(PATH_MAX) - 2), rejected = path(bytes: Int(PATH_MAX) - 1)
        XCTAssertEqual(accepted.utf8.count, Int(PATH_MAX) - 2)
        XCTAssertEqual(rejected.utf8.count, Int(PATH_MAX) - 1)
        XCTAssertNoThrow(try expected(accepted))
        XCTAssertThrowsError(try expected(rejected))
        XCTAssertNoThrow(try expected("/" + String(repeating: "a", count: 255)))
        XCTAssertThrowsError(try expected("/" + String(repeating: "a", count: 256)))
        XCTAssertNoThrow(try expected("/" + String(repeating: "é", count: 127)))
        XCTAssertThrowsError(try expected("/" + String(repeating: "é", count: 128)))
    }

}
