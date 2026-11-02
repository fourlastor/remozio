import Foundation
import RemozioProtocol

/// Changes audit admission without rebuilding the retained command settings from defaults.
enum RuntimeAuditUpgradeConfiguration {
    static func command(_ source: AuthorityCommandStartupConfiguration) throws -> AuthorityCommandStartupConfiguration {
        let presence = source.presence, wake = presence.wake, request = wake.request, service = request.service
        guard service.auditVersions.isEmpty else { throw RuntimeActivationError.changedScope }
        var fields = try map(service.canonicalBytes)
        fields[11] = .array([.unsigned(PhoneAuditReleaseContract.version)])
        let nextService = try AuthorityServiceConfiguration.decode(DeterministicCBOR.encode(.map(fields), limits: limits))
        let nextRequest = try AuthorityRequestStartupConfiguration.decode(replacingChild(request.canonicalBytes,
            expected: service.canonicalBytes, with: nextService.canonicalBytes))
        let nextWake = try AuthorityWakeStartupConfiguration.decode(replacingChild(wake.canonicalBytes,
            expected: request.canonicalBytes, with: nextRequest.canonicalBytes))
        let nextPresence = try AuthorityPresenceStartupConfiguration.decode(replacingChild(presence.canonicalBytes,
            expected: wake.canonicalBytes, with: nextWake.canonicalBytes))
        return try AuthorityCommandStartupConfiguration.decode(replacingChild(source.canonicalBytes,
            expected: presence.canonicalBytes, with: nextPresence.canonicalBytes))
    }
    private static func replacingChild(_ bytes: Data, expected: Data, with child: Data) throws -> Data {
        var fields = try map(bytes)
        guard fields[1] == .bytes(expected) else { throw RuntimeActivationError.changedScope }
        fields[1] = .bytes(child)
        return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    private static func map(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits) else {
            throw RuntimeActivationError.invalidPlan
        }
        return fields
    }
    private static let limits = try! CBORLimits(maxBytes: 65_536, maxDepth: 3, maxItems: 512)
}
