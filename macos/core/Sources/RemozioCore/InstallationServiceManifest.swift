import Darwin
import Foundation

public enum InstallationServiceManifestError: Error, Equatable {
    case invalidExpectation, invalidPlist, declarationMismatch
}

/// Expected signed job bytes. Validation grants no registration, process or activation authority.
public struct InstallationServiceManifest {
    public let declaration: InstallationService
    public let configurationPath: String
    public let userName: String?
    private let values: [String: Any]
    private let component: ReleaseComponent

    /// The installer must resolve userName to the declaration UID through trusted directory lookup.
    /// Arguments and endpoints come from its protected configuration, not network claims.
    public init(declaration: InstallationService, component: ReleaseComponent, configurationPath: String,
                userName: String?, arguments: [String], machServices: Set<String>, runAtLoad: Bool, keepAlive: Bool) throws {
        let parts = configurationPath.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        guard declaration.kind != .mainApp, declaration.role == component.role,
              configurationPath.hasPrefix("/"), configurationPath.utf8.count + 1 < Int(PATH_MAX),
              !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }),
              arguments.count == 3,
              arguments[0] == component.relativePath,
              Self.modes(for: component.role).contains(arguments[1]),
              arguments[2] == configurationPath,
              arguments.allSatisfy({ !$0.utf8.contains(0) && $0.utf8.count < 4096 }),
              machServices.count <= 32,
              machServices.allSatisfy({ ReleaseManifest.validToken($0) && $0.hasPrefix("dev.remozio.") }) else {
            throw InstallationServiceManifestError.invalidExpectation
        }
        if declaration.kind == .agent {
            guard userName == nil else { throw InstallationServiceManifestError.invalidExpectation }
        } else {
            guard let userName, !userName.isEmpty, userName.utf8.count <= 255,
                  userName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) ||
                      (97...122).contains($0) || $0 == 95 || $0 == 45 }),
                  declaration.executionUID == 0 ? userName == "root" : userName != "root" else {
                throw InstallationServiceManifestError.invalidExpectation
            }
        }
        var values: [String: Any] = ["Label": declaration.label, "BundleProgram": component.relativePath,
            "ProgramArguments": arguments, "RunAtLoad": runAtLoad, "KeepAlive": keepAlive]
        if let userName { values["UserName"] = userName }
        if declaration.kind == .agent { values["LimitLoadToSessionType"] = "Aqua" }
        if !machServices.isEmpty { values["MachServices"] = Dictionary(uniqueKeysWithValues: machServices.map { ($0, true) }) }
        self.declaration = declaration; self.configurationPath = configurationPath; self.userName = userName
        self.values = values; self.component = component
    }

    private static func modes(for role: AuthorityCodeRole) -> Set<String> {
        switch role {
        case .authority: ["--configuration", "--presence-configuration"]
        case .transport: ["--configuration", "--wake-configuration", "--remote-configuration"]
        default: ["--configuration"]
        }
    }

    /// Compare only bytes already obtained from the freshly verified, protected bundle.
    /// Expected dictionary-account names still need independent UID validation by the installer.
    public func validate(_ bytes: Data, inventory: InstallationInventory, release: SignedReleaseEvidence) throws {
        try inventory.compareRelease(release)
        guard release.manifest.components.contains(component), inventory.services.contains(declaration), !bytes.isEmpty, bytes.count <= 65536 else {
            throw InstallationServiceManifestError.declarationMismatch
        }
        let decoded: Any
        do { decoded = try PropertyListSerialization.propertyList(from: bytes, options: [], format: nil) }
        catch { throw InstallationServiceManifestError.invalidPlist }
        guard let actual = decoded as? [String: Any], NSDictionary(dictionary: values).isEqual(to: actual) else {
            throw InstallationServiceManifestError.declarationMismatch
        }
    }
}
