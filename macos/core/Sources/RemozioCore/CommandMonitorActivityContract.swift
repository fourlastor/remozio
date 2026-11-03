import Foundation
import RemozioProtocol

/// Signed helper support for retaining Root activity during command cleanup.
enum CommandMonitorActivityContract {
    static let formatName = "command.monitor-activity"
    static var requirements: [RetainedReleaseFormat] { get throws {
        try [.init(role: .authority, name: formatName, readVersions: [1], writeVersions: [1]),
             .init(role: .commandMonitor, name: formatName, readVersions: [1], writeVersions: [])]
    } }
    static func validate(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy) throws {
        try ReleaseCompatibilityPreflight.validate(release, policy: policy,
            requirements: .init(formats: requirements, requests: []))
    }
}
