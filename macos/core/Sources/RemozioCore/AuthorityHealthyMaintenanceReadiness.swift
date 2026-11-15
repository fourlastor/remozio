import CryptoKit
import Foundation

/// The facts that a healthy maintenance open and reopen require from the running Authority.
/// They come only from protected installed state that is read again for each check. A request never supplies them.
struct AuthorityHealthyMaintenanceReadiness: Equatable, Sendable {
    /// The exact phone push state that the running Authority would have installed.
    enum PhonePush: Equatable, Sendable {
        /// No phone push source exists. The capability must hold no installed and no retained commit.
        case absent
        /// The capability must hold this commit, both installed and retained.
        case installed(commitDigest: Data)
    }
    /// The maintenance account. Composition always gives the service a gateway settings binding for its registration account,
    /// also when gateway settings control is disabled, so the binding must exist and name this account in both cases.
    let accountID: Data
    let phonePush: PhonePush

    /// The host configuration declares phone push. Startup installs it with this digest, and the installed runner
    /// starts no gateway extension monitor, so a published gateway runtime cannot replace it.
    init(accountID: Data, phonePush: AuthorityPhonePushStartupConfiguration) throws {
        try self.init(accountID: accountID, commitDigest: Data(SHA256.hash(data: phonePush.canonicalBytes)))
    }
    /// The host configuration declares no phone push. The gateway extension monitor installs the published runtime
    /// with its commit observation digest. No published runtime means no phone push.
    init(accountID: Data, gatewayRuntimeCommit: Data?) throws {
        try self.init(accountID: accountID, commitDigest: gatewayRuntimeCommit)
    }
    private init(accountID: Data, commitDigest: Data?) throws {
        guard accountID.count == 16, commitDigest == nil || commitDigest?.count == 32 else { throw RuntimePreparationError.changedScope }
        self.accountID = accountID
        phonePush = commitDigest.map { .installed(commitDigest: $0) } ?? .absent
    }
    /// The same precedence as the installed runner. The loader returns nil only when no runtime commit is published;
    /// an unreadable or invalid runtime throws, and the check refuses.
    static func current(accountID: Data, configuredPhonePush: AuthorityPhonePushStartupConfiguration?,
        loadGatewayRuntime: () throws -> GatewayRuntimeLoader.Loaded?) throws -> Self {
        if let configuredPhonePush { return try .init(accountID: accountID, phonePush: configuredPhonePush) }
        return try .init(accountID: accountID, gatewayRuntimeCommit: loadGatewayRuntime()?.commit.observationDigest)
    }
}
