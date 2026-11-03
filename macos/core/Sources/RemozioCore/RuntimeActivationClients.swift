import Darwin
import Foundation

/// Actual protected client values. Decoding does not prove their account or release scope.
struct RuntimeActivationClients: CustomStringConvertible {
    let presence: AuthorityPresenceClientConfiguration
    let pairing: TransportPairingControlConfiguration
    let frontend: CommandFrontendConfiguration
    var description: String { "RuntimeActivationClients(redacted)" }

    static func load(directory: ProtectedSetupDirectory, owner: uid_t, ownerUID: uid_t,
                     verifyCurrent: () throws -> Void) throws -> Self {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        func read(_ file: AdministrativeSetupPublication.File) throws -> Data {
            try file.validate(); try verifyCurrent(); try directory.validate()
            let bytes = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name,
                owner: owner, privateFile: false)
            try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory,
                owner: owner, verify: verifyCurrent)
            return bytes
        }
        let presence = try AuthorityPresenceClientConfiguration.decode(read(.presenceClient(ownerUID: ownerUID)))
        let pairing = try TransportPairingControlConfiguration.decode(read(.pairingClient(ownerUID: ownerUID)))
        let frontend = try CommandFrontendConfiguration.decode(read(.frontendClient(ownerUID: ownerUID)))
        let value = Self(presence: presence, pairing: pairing, frontend: frontend)
        try value.validateRetained(directory: directory, owner: owner, ownerUID: ownerUID, verifyCurrent: verifyCurrent)
        return value
    }

    func validateRetained(directory: ProtectedSetupDirectory, owner: uid_t, ownerUID: uid_t,
                          verifyCurrent: () throws -> Void) throws {
        for (bytes, file) in [(presence.canonicalBytes, AdministrativeSetupPublication.File.presenceClient(ownerUID: ownerUID)),
                              (pairing.canonicalBytes, .pairingClient(ownerUID: ownerUID)),
                              (frontend.canonicalBytes, .frontendClient(ownerUID: ownerUID))] {
            try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory,
                owner: owner, verify: verifyCurrent)
        }
    }
}
