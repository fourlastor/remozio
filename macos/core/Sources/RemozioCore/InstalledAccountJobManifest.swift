import Foundation
import RemozioProtocol

/// A fixed per-account system job. Its unsigned plist derives authority from protected setup state and signed code.
struct InstalledAccountJobManifest {
    static let directory = "/Library/LaunchDaemons"
    let declaration: InstallationService
    let bundlePath: String
    let configurationPath: String
    let executablePath: String
    let arguments: [String]
    let userName: String
    let groupName: String
    let machServices: Set<String>
    var path: String { Self.directory + "/" + declaration.plistName! }

    init(accountID: Data, role: AuthorityCodeRole, executionUID: UInt32, userName: String,
         bundlePath: String) throws {
        let paths = try RuntimePreparationPaths(accountID: accountID)
        guard role == .authority || role == .transport,
              role == .authority ? (executionUID == 0 && userName == "root") :
                (executionUID > 0 && executionUID < UInt32.max && userName == ServiceAccountClaim.recordName(accountID: accountID, role: .transport)),
              bundlePath.hasPrefix("/"), bundlePath.hasSuffix(".app"), bundlePath.utf8.count < 4096, Self.validXML(bundlePath),
              bundlePath.dropFirst().split(separator: "/", omittingEmptySubsequences: false).allSatisfy({
                  !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255
              }) else { throw InstallationServiceManifestError.invalidExpectation }
        let label = paths.namespace + (role == .authority ? ".authority" : ".transport")
        declaration = try .init(role: role, kind: .daemon, domainUID: nil, executionUID: executionUID,
            label: label, plistName: label + ".plist", accountID: accountID)
        self.bundlePath = bundlePath; self.userName = userName
        groupName = role == .authority ? "wheel" : userName
        let relative = role == .authority ? InstalledAuthorityCommandConfiguration.executablePath : "Contents/Library/LaunchServices/RemozioTransport"
        executablePath = bundlePath + "/" + relative
        configurationPath = role == .authority ? paths.privateDirectory + "/command-host.cbor" : paths.transportConfiguration
        arguments = [executablePath, role == .authority ? "--command-configuration" : "--pairing-configuration", configurationPath]
        machServices = role == .authority ? [paths.authorityService, paths.commandService, paths.presenceService] : [paths.pairingService]
    }
    // Stable XML avoids dictionary-order differences across fresh-process recovery.
    var bytes: Data {
        let strings: [(String, String)] = [("Label", declaration.label), ("Program", executablePath),
            ("UserName", userName), ("GroupName", groupName)]
        let prefix = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n"
        var xml = prefix
        for (key, value) in strings { xml += "<key>\(key)</key><string>\(Self.escape(value))</string>\n" }
        xml += "<key>ProgramArguments</key><array>" + arguments.map { "<string>\(Self.escape($0))</string>" }.joined() + "</array>\n"
        xml += "<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n<key>MachServices</key><dict>"
        for name in machServices.sorted() { xml += "<key>\(Self.escape(name))</key><true/>" }
        xml += "</dict>\n</dict></plist>\n"
        return Data(xml.utf8)
    }
    func validate(_ bytes: Data, inventory: InstallationInventory, release: SignedReleaseEvidence) throws {
        guard bytes.count <= 65536, !bytes.isEmpty, inventory.bundlePath == bundlePath,
              inventory.services.contains(declaration),
              let component = release.manifest.components.first(where: { $0.role == declaration.role }),
              executablePath == bundlePath + "/" + component.relativePath else { throw InstallationServiceManifestError.declarationMismatch }
        try inventory.compareRelease(release)
        guard bytes == self.bytes else { throw InstallationServiceManifestError.declarationMismatch }
    }
    private static func validXML(_ value: String) -> Bool {
        value.unicodeScalars.allSatisfy { scalar in
            let n = scalar.value
            return n == 9 || n == 10 || n == 13 || (0x20...0xd7ff).contains(n)
                || (0xe000...0xfffd).contains(n) || (0x10000...0x10ffff).contains(n)
        }
    }
    private static func escape(_ value: String) -> String {
        value.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\r", with: "&#13;").replacingOccurrences(of: "\t", with: "&#9;").replacingOccurrences(of: "\n", with: "&#10;")
            .replacingOccurrences(of: "\"", with: "&quot;").replacingOccurrences(of: "'", with: "&apos;")
    }
}
