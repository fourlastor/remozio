import Darwin
import Foundation

/// Factories keep fake rights and platform adapters out of a Root endpoint.
struct SetupAuditUpgradeEndpointOperations {
    let requireRelease: () throws -> Void
    let importAuthorization: (Data) throws -> SetupAuditUpgradeAuthorization
    typealias OpenInvocation = (SetupAuditUpgradeProgress, SetupAuditUpgradeAuthorization,
                                SetupAccountOwner.ExecutorAdmission) throws -> SetupAuditUpgradeInvocation
    let openInvocation: OpenInvocation
    private init(requireRelease: @escaping () throws -> Void,
                 importAuthorization: @escaping (Data) throws -> SetupAuditUpgradeAuthorization,
                 openInvocation: @escaping OpenInvocation) {
        self.requireRelease = requireRelease; self.importAuthorization = importAuthorization; self.openInvocation = openInvocation
    }
    static func native(owner: SetupAccountOwner, invocation: XPCInvocationGuard) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return .init(requireRelease: owner.requireAuditUpgradeSupport,
            importAuthorization: { try SetupAuditUpgradeAuthorization.open(externalForm: $0, invocation: invocation) },
            openInvocation: { try SetupAuditUpgradeInvocation.open(owner: owner, expected: $0, authorization: $1, admission: $2) })
    }
    static func owned(requireRelease: @escaping () throws -> Void = {},
                      importAuthorization: @escaping (Data) throws -> SetupAuditUpgradeAuthorization,
                      openInvocation: @escaping OpenInvocation) throws -> Self {
        guard getuid() > 0, getuid() == geteuid() else { throw JournalLeaseError.unsafeMetadata }
        return .init(requireRelease: requireRelease, importAuthorization: importAuthorization, openInvocation: openInvocation)
    }
}
