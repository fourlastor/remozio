import Foundation
import RemozioProtocol

/// Local public choices only. The imported bundle supplies no port, tunnel identity or destination hostname.
struct SharedSetupImportRelayPlan: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "setup.shared-import-relay-plan"
    static let supportedVersions: Set<UInt64> = [1]
    static let maximumBytes = 2048
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 32)
    let port: UInt16
    let hostname: String
    let tunnelName: String
    let bytes: Data
    var accessApplicationName: String { tunnelName + "-approval" }
    var description: String { "SharedSetupImportRelayPlan(redacted)" }
    var debugDescription: String { description }
    init(expected: SharedSetupImportIntent, port: UInt16) throws {
        guard port >= 1024, let cloud = expected.recipe.cloudflare else { throw SharedSetupImportError.invalidRecord }
        let suffix = expected.operationID.map { String(format: "%02x", $0) }.joined()
        hostname = "m-" + suffix + "." + cloud.dnsSuffix
        try SetupCloudflareConfiguration.validateScope(accountID: cloud.accountID, zoneID: cloud.zoneID, dnsSuffix: hostname)
        tunnelName = "remozio-" + suffix; self.port = port
        let scope = expected.scope
        bytes = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .text("remozio-local-import-relay"), 2: .bytes(scope.macID), 3: .bytes(scope.installationID),
            4: .bytes(scope.releaseDigest), 5: .bytes(scope.accountID), 6: .unsigned(UInt64(scope.ownerUID)),
            7: .bytes(scope.accountBinding), 8: .bytes(expected.operationID), 9: .bytes(expected.proposalDigest),
            10: .unsigned(UInt64(port)), 11: .text(cloud.accountID), 12: .text(cloud.zoneID), 13: .text(cloud.dnsSuffix)
        ]), limits: Self.limits)
    }
    func validate(expected: SharedSetupImportIntent) throws {
        guard try Self(expected: expected, port: port).bytes == bytes else { throw SharedSetupImportError.wrongScope }
    }
    static func decode(_ bytes: Data, expected: SharedSetupImportIntent) throws -> Self {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...13), case let .unsigned(value) = fields[10],
              let port = UInt16(exactly: value) else { throw SharedSetupImportError.invalidRecord }
        let result = try Self(expected: expected, port: port)
        guard result.bytes == bytes else { throw SharedSetupImportError.wrongScope }; return result
    }
}
