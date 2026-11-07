import Foundation
import RemozioProtocol

/// A retained selection, not proof of a candidate, service health or update admission.
struct AuthorityUpdateSchedulingStartupSelection: Equatable, Sendable {
    private let planBytes: Data
    private let releaseDigest: Data

    static func capture(plan: RuntimeActivationPlan?, configuration: InstalledAuthorityCommandConfiguration,
        release: SignedReleaseEvidence, bundlePath: String) throws -> Self? {
        guard let plan, plan.phoneUpdateSchedulingVersion != nil else { return nil }
        guard plan.phoneUpdateSchedulingVersion == PhoneUpdateSchedulingReleaseContract.version,
              plan.reference.serviceActivity != nil, plan.accountID == configuration.command.accountID,
              plan.reference.services.macID == configuration.command.macID,
              plan.host.canonicalBytes == configuration.canonicalBytes, plan.bundlePath == bundlePath,
              configuration.command.presence.wake.request.service.maximumPayloadBytes >= PhoneUpdateSchedulingFrame.maximumBytes else {
            throw RuntimeActivationError.changedScope
        }
        try configuration.validateRelease(release, bundlePath: bundlePath)
        try PhoneUpdateSchedulingReleaseContract.validate(release, policy: configuration.codePolicy)
        return try Self(planBytes: plan.encoded, releaseDigest: InstallationInventory.digest(release))
    }

    func requireCurrent(plan: RuntimeActivationPlan?, configuration: InstalledAuthorityCommandConfiguration,
        release: SignedReleaseEvidence, bundlePath: String) throws {
        guard try Self.capture(plan: plan, configuration: configuration, release: release, bundlePath: bundlePath) == self else {
            throw RuntimeActivationError.changedScope
        }
    }
}

/// Unreadable optional state does not claim absence or disable ordinary command startup.
enum AuthorityUpdateSchedulingStartupSnapshot: Equatable, Sendable {
    case unsupported, unavailable, selected(AuthorityUpdateSchedulingStartupSelection)
    init(capture: () throws -> AuthorityUpdateSchedulingStartupSelection?) {
        do { self = try capture().map(Self.selected) ?? .unsupported }
        catch { self = .unavailable }
    }
}

struct AuthorityUpdateSchedulingStartup: Sendable {
    let provider: AuthorityPhoneUpdateSchedulingProvider
    let offers: AuthorityUpdateSchedulingOfferOwner
}

typealias AuthorityUpdateSchedulingStartupFactory = @Sendable (
    AuthorityJournal, EnclaveAuthorityRequestSigner, AuthorityClock
) throws -> AuthorityUpdateSchedulingStartup
