import Foundation
import RemozioProtocol

/// Compiled codec requirements only. This comparison does not prove current service readiness.
enum PhoneRoutingReleaseContract {
    static let version: UInt64 = 1
    static let names: Set<String> = ["authority.routing-ipc", "phone.routing-frame", "routing.away-challenge",
                                     "routing.away-control", "routing.status-response"]

    static var requirements: [RetainedReleaseFormat] { get throws {
        let codecs = try [AuthorityCodeRole.authority, .transport].flatMap { role in
            try names.sorted().map { name in
                let writes = name == "authority.routing-ipc" || name == "phone.routing-frame" ||
                    (role == .authority && name != "routing.away-control")
                return try RetainedReleaseFormat(role: role, name: name, readVersions: [version],
                    writeVersions: writes ? [version] : [])
            }
        }
        return try codecs + [
            RetainedReleaseFormat(role: .authority, name: RuntimeActivationPlan.formatName, readVersions: [3]),
            RetainedReleaseFormat(role: .setupController, name: RuntimeActivationPlan.formatName, readVersions: [3], writeVersions: [3])
        ]
    } }

    static func hasDeclarations(in release: SignedReleaseEvidence) -> Bool {
        release.manifest.components.contains { component in component.formats.contains { names.contains($0.name) } }
    }

    static func selectedVersion(in release: SignedReleaseEvidence, policy: AuthorityCodePolicy,
                                nativeHosts: Bool, maximumPayloadBytes: Int) throws -> UInt64? {
        guard nativeHosts, maximumPayloadBytes >= PhoneRoutingFrame.maximumBytes, hasDeclarations(in: release) else { return nil }
        try validate(release, policy: policy)
        return version
    }

    static func validate(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy) throws {
        try ReleaseCompatibilityPreflight.validate(release, policy: policy,
            requirements: .init(formats: requirements, requests: []))
        for (role, path): (AuthorityCodeRole, String) in [(.authority, InstalledAuthorityCommandConfiguration.executablePath),
                                                        (.transport, "Contents/Library/LaunchServices/RemozioTransport")] {
            guard release.manifest.components.first(where: { $0.role == role })?.relativePath == path else {
                throw RuntimeActivationError.changedScope
            }
        }
    }
}
