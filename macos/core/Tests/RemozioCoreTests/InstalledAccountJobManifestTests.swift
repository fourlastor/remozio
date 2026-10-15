import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class InstalledAccountJobManifestTests: XCTestCase {
    private let account = Data(repeating: 1, count: 16)
    private let bundle = MachineBootstrap.bundlePath
    private func job(_ role: AuthorityCodeRole = .authority, account: Data? = nil, bundlePath: String? = nil) throws -> InstalledAccountJobManifest {
        let account = account ?? self.account
        return try .init(accountID: account, role: role, executionUID: role == .authority ? 0 : 20000,
            userName: role == .authority ? "root" : ServiceAccountClaim.recordName(accountID: account, role: .transport),
            bundlePath: bundlePath ?? bundle)
    }
    // Logical signed-release metadata only. No native signing, installation or launchd admission is claimed.
    private func release(bundlePath: String? = nil) throws -> SignedReleaseEvidence {
        let roles: [AuthorityCodeRole] = [.app, .authority, .transport]
        let components = try roles.map { role -> ReleaseComponent in
            let path: String
            switch role {
            case .app: path = "Contents/MacOS/Remozio"
            case .authority: path = InstalledAuthorityCommandConfiguration.executablePath
            default: path = "Contents/Library/LaunchServices/RemozioTransport"
            }
            return try .init(role: role, identifier: "dev.remozio.role-\(role.rawValue)", generation: 1, relativePath: path,
                codeDirectoryHash: role == .app ? nil : Data(repeating: UInt8(role.rawValue), count: 20), build: "1", teamID: "ABCDEFGHIJ", formats: [])
        }
        return try .init(manifest: .init(release: "1", build: "1", components: components),
            codeDirectoryHashes: Dictionary(uniqueKeysWithValues: roles.map { ($0, Data(repeating: UInt8($0.rawValue), count: 20)) }))
    }
    private func inventory(account: Data? = nil, bundlePath: String? = nil) throws -> InstallationInventory {
        let account = account ?? self.account, bundlePath = bundlePath ?? bundle
        return try .init(macID: Data(repeating: 2, count: 16), installationID: Data(repeating: 3, count: 16),
            revision: Data(repeating: 4, count: 16), bundlePath: bundlePath, releaseDigest: InstallationInventory.digest(release()),
            accounts: [.init(accountID: account, ownerUID: 501)],
            services: [job(.authority, account: account, bundlePath: bundlePath).declaration,
                       job(.transport, account: account, bundlePath: bundlePath).declaration])
    }
    private func dictionary(_ bytes: Data) throws -> [String: Any] {
        try XCTUnwrap(PropertyListSerialization.propertyList(from: bytes, options: [], format: nil) as? [String: Any])
    }
    func testAuthorityJobBindsTheRootHostAndAllAccountEndpoints() throws {
        let value = try job(), paths = try RuntimePreparationPaths(accountID: account), fields = try dictionary(value.bytes)
        XCTAssertEqual(value.path, "/Library/LaunchDaemons/" + paths.namespace + ".authority.plist")
        XCTAssertEqual(value.declaration.accountID, account); XCTAssertEqual(value.declaration.executionUID, 0)
        XCTAssertEqual(fields["UserName"] as? String, "root"); XCTAssertEqual(fields["GroupName"] as? String, "wheel")
        XCTAssertNil(fields["BundleProgram"])
        XCTAssertEqual(fields["Program"] as? String, bundle + "/" + InstalledAuthorityCommandConfiguration.executablePath)
        XCTAssertEqual(fields["ProgramArguments"] as? [String], [value.executablePath, "--command-configuration", paths.privateDirectory + "/command-host.cbor"])
        XCTAssertEqual(Set(try XCTUnwrap(fields["MachServices"] as? [String: Bool]).keys),
            [paths.authorityService, paths.commandService, paths.presenceService])
        XCTAssertNoThrow(try value.validate(value.bytes, inventory: inventory(), release: release()))
    }
    func testTransportJobUsesOnlyTheReservedIdentityAndPairingConfiguration() throws {
        let value = try job(.transport), paths = try RuntimePreparationPaths(accountID: account), fields = try dictionary(value.bytes)
        let name = ServiceAccountClaim.recordName(accountID: account, role: .transport)
        XCTAssertEqual(value.declaration.executionUID, 20000)
        XCTAssertEqual(fields["UserName"] as? String, name); XCTAssertEqual(fields["GroupName"] as? String, name)
        XCTAssertEqual(fields["ProgramArguments"] as? [String], [value.executablePath, "--pairing-configuration", paths.transportConfiguration])
        XCTAssertEqual(Set(try XCTUnwrap(fields["MachServices"] as? [String: Bool]).keys), [paths.pairingService])
        XCTAssertNoThrow(try value.validate(value.bytes, inventory: inventory(), release: release()))
    }
    func testChangedProgramIdentityArgumentsEndpointsOrExtraKeysCannotPass() throws {
        let value = try job(), original = try dictionary(value.bytes)
        let changes: [(String, Any)] = [("Program", "/usr/bin/true"), ("UserName", "nobody"), ("GroupName", "staff"),
            ("ProgramArguments", [value.executablePath, "--configuration", value.configurationPath]),
            ("MachServices", ["dev.remozio.injected": true]), ("KeepAlive", false),
            ("EnvironmentVariables", ["DYLD_INSERT_LIBRARIES": "/private/other"]),
            ("BundleProgram", InstalledAuthorityCommandConfiguration.executablePath)]
        for (key, replacement) in changes {
            var changed = original; changed[key] = replacement
            let bytes = try PropertyListSerialization.data(fromPropertyList: changed, format: .binary, options: 0)
            XCTAssertThrowsError(try value.validate(bytes, inventory: inventory(), release: release()))
        }
        XCTAssertThrowsError(try value.validate(value.bytes, inventory: inventory(account: Data(repeating: 8, count: 16)), release: release()))
        XCTAssertThrowsError(try value.validate(value.bytes, inventory: inventory(bundlePath: "/Library/Other.app"), release: release()))
    }
    func testReconstructionKeepsBytesAndAccountNamespacesIndependent() throws {
        for role: AuthorityCodeRole in [.authority, .transport] {
            let first = try job(role), again = try job(role), other = try job(role, account: Data(repeating: 8, count: 16))
            XCTAssertEqual(first.bytes, again.bytes); XCTAssertEqual(first.path, again.path)
            XCTAssertNotEqual(first.path, other.path); XCTAssertNotEqual(first.configurationPath, other.configurationPath)
            XCTAssertTrue(first.machServices.isDisjoint(with: other.machServices))
        }
    }
    func testXMLPreservesSpecialPathCharactersWithoutAddingPlistKeys() throws {
        let path = "/Library/R&m's <fixture>\r\n\t/Remozio.app", value = try job(bundlePath: path)
        let fields = try dictionary(value.bytes)
        XCTAssertEqual(fields["Program"] as? String, value.executablePath)
        XCTAssertEqual(fields["ProgramArguments"] as? [String], value.arguments)
        XCTAssertEqual(Set(fields.keys), ["Label", "Program", "UserName", "GroupName", "ProgramArguments", "RunAtLoad", "KeepAlive", "MachServices"])
    }
    func testUnsupportedRolesIdentitiesAndInvalidPathsAreRejectedBeforePublication() throws {
        for (role, uid, name): (AuthorityCodeRole, UInt32, String) in [(.authority, 501, "root"), (.authority, 0, "nobody"),
            (.transport, 0, "root"), (.transport, 20000, "other"), (.notificationGateway, 20001, "gateway")] {
            XCTAssertThrowsError(try InstalledAccountJobManifest(accountID: account, role: role, executionUID: uid, userName: name, bundlePath: bundle))
        }
        for path in ["relative.app", "/Library/../Other.app", "/Library//Other.app", "/Library/\u{1}/Other.app", "/Library/\u{fffe}/Other.app"] {
            XCTAssertThrowsError(try job(bundlePath: path))
        }
    }
}
