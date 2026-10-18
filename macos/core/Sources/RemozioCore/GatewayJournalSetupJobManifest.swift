import Foundation

/// A dormant temporary setup job. Demand starts only its authenticated setup listener, never journal initialization by itself.
struct GatewayJournalSetupJobManifest {
    let configuration: GatewayJournalSetupServiceConfiguration
    let label: String
    let userName: String
    let arguments: [String]
    var path: String { InstalledAccountJobManifest.directory + "/" + label + ".plist" }
    var executablePath: String { configuration.executablePath }
    var machServices: Set<String> { [label] }
    init(configuration: GatewayJournalSetupServiceConfiguration) throws {
        self.configuration = configuration
        guard let claim = configuration.intent.material.runtime.services.claims.first(where: { $0.role == .gateway }),
              claim.number == configuration.intent.configuration.serviceUID else { throw GatewayPreparationError.invalidRecord }
        label = try configuration.serviceName; userName = ServiceAccountClaim.recordName(accountID: configuration.intent.accountID, role: .gateway)
        arguments = [configuration.executablePath, "--journal-setup", try configuration.configurationPath]
    }
    var bytes: Data {
        var xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n"
        for (key, value) in [("Label", label), ("Program", executablePath), ("UserName", userName), ("GroupName", userName)] {
            xml += "<key>\(key)</key><string>\(Self.escape(value))</string>\n"
        }
        xml += "<key>ProgramArguments</key><array>" + arguments.map { "<string>\(Self.escape($0))</string>" }.joined() + "</array>\n"
        xml += "<key>RunAtLoad</key><false/><key>KeepAlive</key><false/>\n<key>MachServices</key><dict><key>\(Self.escape(label))</key><true/></dict>\n</dict></plist>\n"
        return Data(xml.utf8)
    }
    func validateBytes(_ bytes: Data) throws {
        guard bytes == self.bytes else { throw GatewayPreparationError.changedScope }
    }
    private static func escape(_ value: String) -> String {
        value.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }
}

extension LaunchdJobObservation {
    /// Operational fields only. Native loaded settings and system-domain admission require separate evidence.
    func matches(_ job: GatewayJournalSetupJobManifest) -> Bool {
        kind == "LaunchDaemon" && path == job.path && program == job.executablePath && arguments == job.arguments
            && userName == job.userName && groupName == job.userName && endpoints == job.machServices
            && !properties.contains("runatload") && !properties.contains("keepalive")
    }
}
