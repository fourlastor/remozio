import Foundation

/// Readers and emitters for retained Gateway records, independent of native host selection.
enum GatewayRuntimeRecordFormats {
    static func requirements(commitVersions: Set<UInt64>, settingsRetained: Bool) throws -> [RetainedReleaseFormat] {
        guard !commitVersions.isEmpty, commitVersions.isSubset(of: GatewayRuntimeCommit.supportedVersions) else {
            throw GatewayPreparationError.invalidRecord
        }
        var formats: [RetainedReleaseFormat] = []
        for role in [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController] {
            formats.append(try .init(role: role, name: GatewayRuntimeExtension.formatName,
                readVersions: GatewayRuntimeExtension.supportedVersions,
                writeVersions: role == .setupController ? GatewayRuntimeExtension.supportedVersions : []))
            // Root emits the selected commit and revision inside a recovery fence, without replacing their files.
            let commitWrites: Set<UInt64> = role == .setupController ? commitVersions :
                role == .authority && commitVersions.contains(2) ? [2] : []
            formats.append(try .init(role: role, name: GatewayRuntimeCommit.formatName,
                readVersions: commitVersions, writeVersions: commitWrites))
            if settingsRetained {
                formats.append(try .init(role: role, name: GatewayRuntimeSettingsRevision.formatName,
                    readVersions: GatewayRuntimeSettingsRevision.supportedVersions,
                    writeVersions: role == .authority || role == .setupController ? GatewayRuntimeSettingsRevision.supportedVersions : []))
            }
        }
        for role in [AuthorityCodeRole.authority, .setupController] {
            for (name, versions) in [(GatewayRuntimeExtensions.formatName, GatewayRuntimeExtensions.supportedVersions),
                                     (GatewayRuntimeActivationPlan.formatName, GatewayRuntimeActivationPlan.supportedVersions)] {
                formats.append(try .init(role: role, name: name, readVersions: versions,
                    writeVersions: role == .setupController ? versions : []))
            }
        }
        return formats
    }
}
