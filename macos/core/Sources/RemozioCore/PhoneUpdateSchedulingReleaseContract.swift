import Foundation
import RemozioProtocol

/// Select compiled codecs only. Current candidate ownership and activation admission remain separate checks.
enum PhoneUpdateSchedulingReleaseContract {
    static let version: UInt64 = 1
    static let names: Set<String> = ["authority.update-scheduling-ipc", "phone.update-scheduling-frame",
        "update.scheduling-control", "update.scheduling-challenge", "update.scheduling-status-response"]
    static var requirements: [RetainedReleaseFormat] { get throws {
        let codecs = try [AuthorityCodeRole.authority, .transport].flatMap { role in
            try names.sorted().map { name in
                let writes = role == .authority || name == "authority.update-scheduling-ipc" || name == "phone.update-scheduling-frame"
                return try RetainedReleaseFormat(role: role, name: name, readVersions: [version], writeVersions: writes ? [version] : [])
            }
        }
        return try codecs + UpdateSchedulingCandidateRecord.requirements + [
            RetainedReleaseFormat(role: .authority, name: "authority.journal", readVersions: [17], writeVersions: [17]),
            RetainedReleaseFormat(role: .setupController, name: "authority.journal", readVersions: [17], writeVersions: [17]),
            RetainedReleaseFormat(role: .authority, name: RuntimeActivationPlan.formatName, readVersions: [5]),
            RetainedReleaseFormat(role: .setupController, name: RuntimeActivationPlan.formatName, readVersions: [5], writeVersions: [5])
        ]
    } }
    static func hasDeclarations(in release: SignedReleaseEvidence) -> Bool {
        release.manifest.components.contains { $0.formats.contains { names.contains($0.name) } }
    }
    static func selectedVersion(in release: SignedReleaseEvidence, policy: AuthorityCodePolicy,
        nativeHosts: Bool, maximumPayloadBytes: Int) throws -> UInt64? {
        guard nativeHosts, maximumPayloadBytes >= PhoneUpdateSchedulingFrame.maximumBytes, hasDeclarations(in: release) else { return nil }
        try validate(release, policy: policy)
        return version
    }
    static func validate(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy) throws {
        try ReleaseCompatibilityPreflight.validate(release, policy: policy, requirements: .init(formats: requirements, requests: []))
        for (role, path): (AuthorityCodeRole, String) in [(.authority, InstalledAuthorityCommandConfiguration.executablePath),
            (.transport, "Contents/Library/LaunchServices/RemozioTransport")] {
            guard release.manifest.components.first(where: { $0.role == role })?.relativePath == path else { throw RuntimeActivationError.changedScope }
        }
    }
}
