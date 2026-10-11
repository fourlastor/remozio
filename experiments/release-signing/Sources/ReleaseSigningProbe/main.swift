import Darwin
import Foundation
import RemozioCore
let args = CommandLine.arguments
guard args.count == 4, args[1].hasPrefix("/") else { exit(64) }
do {
    let evidence = try SignedReleaseInspection.inspect(URL(fileURLWithPath: args[1]), teamID: args[2], appIdentifier: args[3])
    let result: [String: Any] = ["result": "accepted", "components": evidence.manifest.components.count, "hashes": evidence.codeDirectoryHashes.count, "release": evidence.manifest.release, "build": evidence.manifest.build, "absentRoles": evidence.manifest.absentRoles.map(\.rawValue).sorted()]
    let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
    print(String(decoding: data, as: UTF8.self))
} catch {
    print("rejected")
    exit(1)
}
