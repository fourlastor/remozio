import Darwin
import Foundation

/// Retains the selected metadata path for the entire invocation, including fresh-handshake pin reloads.
struct CommandFrontendConfigurationSelection {
    let configuration: CommandFrontendConfiguration
    let path: String
    static func accountPath(ownerUID: uid_t) throws -> String {
        guard ownerUID > 0, ownerUID < UInt32.max else { throw CommandFrontendConfigurationError.invalidConfiguration }
        return "/Library/Application Support/Remozio/frontend-\(ownerUID).cbor"
    }
    static func load(ownerUID: uid_t,
                     readPublic: (String) throws -> Data = ProtectedServiceConfiguration.readPublic) throws -> Self {
        do {
            let scoped = try accountPath(ownerUID: ownerUID)
            let bytes: Data, path: String
            do { bytes = try readPublic(scoped); path = scoped }
            catch JournalLeaseError.system(let number) where number == ENOENT {
                path = CommandFrontendMain.configurationPath
                bytes = try readPublic(path)
            }
            return try .init(configuration: .decode(bytes), path: path)
        } catch { throw CommandFrontendConfigurationError.invalidConfiguration }
    }
}
