import Darwin
import Foundation

/// Holds real runtime resources after bounded job removal. A ready value does not start services or grant command authority.
final class RuntimeAuditUpgradeNativeDrain: RuntimeAuditCutoverQuiescence {
    private let graph: RuntimeAuditUpgradeGraphRecord
    private let rootActivity: ReleaseActivityToken
    private let verifyOwner: () throws -> Void
    private let verifyStartup: (RuntimeAuditUpgradeCutoverRecord) throws -> Void
    private let verifyPlatform: () throws -> Void
    private let makeSessions: (RuntimeAuditUpgradeCutoverRecord) throws -> [RuntimeJobStopSession]
    private let stopTemporary: () throws -> Bool
    private let requireTemporaryAbsent: () throws -> Void
    private let openRole: (ServiceAccountRole) throws -> ServiceReleaseActivityToken
    private let openAuthority: () throws -> AuthorityJournalCutoverInspection
    private let openGateway: () throws -> GatewayJournalCutoverLease
    private let processID = getpid()
    private var sessions: [RuntimeJobStopSession]?
    private var roles: [ServiceAccountRole: ServiceReleaseActivityToken] = [:]
    private var authority: AuthorityJournalCutoverInspection?
    private var gateway: GatewayJournalCutoverLease?
    private var ready = false
    private var active = false
    private var retired = false
    private var closed = false

    static func open(graph: RuntimeAuditUpgradeGraph, record: RuntimeAuditUpgradeGraphRecord,
                     rootActivity: ReleaseActivityToken, verifyOwner: @escaping @Sendable () throws -> Void) throws -> RuntimeAuditUpgradeNativeDrain {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try graph.requireOwner(0); try record.validate(graph); try rootActivity.validateExclusive(); try verifyOwner()
        let plan = graph.snapshot.plan, source = plan.preparation.source, target = plan.preparation.target
        let services = source.reference.services, policy = source.host.codePolicy
        guard plan.sourceInitialization.complete, let activity = plan.preparation.intent.target.serviceActivity else {
            throw RuntimePreparationError.incomplete
        }
        func verify() throws { try rootActivity.validateExclusive(); try verifyOwner() }
        func jobs(_ foreground: RuntimeActivationPlan, _ activation: GatewayRuntimeActivationPlan?) throws -> [InstalledAccountJobManifest] {
            let gateway: InstalledAccountJobManifest
            if let activation { gateway = try activation.gatewayJob }
            else if let hosts = foreground.consumerHosts { gateway = try hosts.job(.gateway) }
            else {
                guard let claim = services.claims.first(where: { $0.role == .gateway }) else { throw RuntimePreparationError.incomplete }
                gateway = try .init(accountID: services.accountID, role: .notificationGateway, executionUID: claim.number,
                    userName: claim.name, bundlePath: foreground.bundlePath)
            }
            return [foreground.authorityJob, foreground.transportJob, gateway]
        }
        let before = try jobs(source, plan.sourceGateway.activation.plan), after = try jobs(target, plan.gateway.activation.plan)
        let temporary: GatewayJournalSetupJobManifest?
        if let service = plan.sourceGateway.service { temporary = try .init(configuration: service) }
        else {
            temporary = try plan.sourceGateway.journal.intent.map { intent in
                try GatewayJournalSetupJobManifest(configuration: .init(intent: intent, bundlePath: source.bundlePath, codePolicy: policy))
            }
        }
        return .init(graph: record, rootActivity: rootActivity, verifyOwner: verifyOwner, verifyStartup: { current in
            try verify()
            let expected = try RuntimeAuditUpgradeStartupFence(current).encoded
            let actual = try ProtectedServiceConfiguration.readOptionalAuditFence(accountID: services.accountID)
            guard actual == expected || (current.phase == .metadataCommitted && actual == nil) else {
                throw RuntimeAuditUpgradeStartupError.recoveryRequired
            }
            try verify()
        }, verifyPlatform: {
            try LocalAccountDirectory.validateOwnership(LocalAccountDirectory.lookup(uid: plan.sourceAccount.ownerUID),
                uid: plan.sourceAccount.ownerUID, directoryID: plan.sourceAccount.directoryID)
            let directory = try NativeServiceAccountDirectory(accountID: services.accountID, ownerUID: services.ownerUID)
            for claim in services.claims { try directory.validateGroup(claim); try directory.validateUser(claim, ownerUID: services.ownerUID) }
        }, makeSessions: { current in
            try (current.phase == .metadataCommitted ? after : before).map { job in
                try RuntimeJobStopSession.open(job: job, policy: policy, rootActivity: rootActivity, verifyOwnerAndFence: verify)
            }
        }, stopTemporary: {
            guard let temporary else { return true }
            return try GatewayJournalSetupJobRegistration.cleanupStopped(temporary, verifyCurrent: verify)
        }, requireTemporaryAbsent: {
            guard let temporary else { return }
            try verify()
            guard try GatewayJournalSetupJobRegistration.isAbsent(temporary) else { throw RuntimeActivationError.unavailable }
            try verify()
        }, openRole: { role in
            let barrier = try ServiceReleaseActivityBarrier.openForUpdate(services: services, role: role,
                expected: activity.identity(for: role), verifyCurrent: { try rootActivity.validateExclusive(); try verifyOwner() })
            return try barrier.acquireExclusive()
        }, openAuthority: {
            // Held Root, role and journal locks continue to exclude admission after the coordinator removes its fence.
            try AuthorityJournalCutoverInspection.openInitialized(initialization: plan.sourceInitialization, policy: policy,
                rootActivity: rootActivity, verifyOwnerAndFence: verify)
        }, openGateway: { try GatewayJournalCutoverLease.open(graph: graph, rootActivity: rootActivity, verifyOwner: verify) })
    }
    // This seam can only use the ordinary process owner. It cannot grant native Root admission.
    static func openOwned(graph: RuntimeAuditUpgradeGraphRecord, rootActivity: ReleaseActivityToken,
                          verifyOwner: @escaping () throws -> Void = {},
                          verifyStartup: @escaping (RuntimeAuditUpgradeCutoverRecord) throws -> Void = { _ in },
                          verifyPlatform: @escaping () throws -> Void = {},
                          makeSessions: @escaping (RuntimeAuditUpgradeCutoverRecord) throws -> [RuntimeJobStopSession],
                          stopTemporary: @escaping () throws -> Bool, requireTemporaryAbsent: @escaping () throws -> Void,
                          openRole: @escaping (ServiceAccountRole) throws -> ServiceReleaseActivityToken,
                          openAuthority: @escaping () throws -> AuthorityJournalCutoverInspection,
                          openGateway: @escaping () throws -> GatewayJournalCutoverLease) throws -> RuntimeAuditUpgradeNativeDrain {
        guard getuid() > 0, getuid() == geteuid() else { throw JournalLeaseError.unsafeMetadata }
        return .init(graph: graph, rootActivity: rootActivity, verifyOwner: verifyOwner, verifyStartup: verifyStartup,
            verifyPlatform: verifyPlatform, makeSessions: makeSessions, stopTemporary: stopTemporary,
            requireTemporaryAbsent: requireTemporaryAbsent, openRole: openRole, openAuthority: openAuthority, openGateway: openGateway)
    }
    private init(graph: RuntimeAuditUpgradeGraphRecord, rootActivity: ReleaseActivityToken, verifyOwner: @escaping () throws -> Void,
                 verifyStartup: @escaping (RuntimeAuditUpgradeCutoverRecord) throws -> Void, verifyPlatform: @escaping () throws -> Void,
                 makeSessions: @escaping (RuntimeAuditUpgradeCutoverRecord) throws -> [RuntimeJobStopSession],
                 stopTemporary: @escaping () throws -> Bool, requireTemporaryAbsent: @escaping () throws -> Void,
                 openRole: @escaping (ServiceAccountRole) throws -> ServiceReleaseActivityToken,
                 openAuthority: @escaping () throws -> AuthorityJournalCutoverInspection,
                 openGateway: @escaping () throws -> GatewayJournalCutoverLease) {
        self.graph = graph; self.rootActivity = rootActivity; self.verifyOwner = verifyOwner; self.verifyStartup = verifyStartup
        self.verifyPlatform = verifyPlatform; self.makeSessions = makeSessions; self.stopTemporary = stopTemporary
        self.requireTemporaryAbsent = requireTemporaryAbsent; self.openRole = openRole; self.openAuthority = openAuthority; self.openGateway = openGateway
    }
    private func verify() throws {
        guard !closed, !retired, getpid() == processID else { throw RuntimeActivationError.unavailable }
        try rootActivity.validateExclusive(); try verifyOwner()
    }
    func acquire(_ current: RuntimeAuditUpgradeCutoverRecord) throws -> (any RuntimeAuditCutoverQuiescence)? {
        guard !active else { throw RuntimeActivationError.unavailable }
        active = true; defer { active = false }
        do {
            try verify(); guard current.graph == graph else { throw PreparationStoreError.staleRevision }
            if ready { try complete(); return self }
            try verifyStartup(current); try verifyPlatform()
            if sessions == nil { sessions = try makeSessions(current) }
            var stopped = true
            for session in sessions! { if try session.poll() != .registrationRemoved { stopped = false } }
            if try !stopTemporary() { stopped = false }
            guard stopped else { try verify(); return nil }
            for role in ServiceAccountPlan.roles where roles[role] == nil {
                do { roles[role] = try openRole(role) } catch ReleaseActivityError.busy { try verify(); return nil }
            }
            if authority == nil {
                do { authority = try openAuthority() } catch JournalLeaseError.busy { try verify(); return nil }
            }
            if gateway == nil {
                do { gateway = try openGateway() } catch JournalLeaseError.busy { try verify(); return nil }
            }
            try verifyStartup(current); try complete(); ready = true; return self
        } catch { retired = true; throw error }
    }
    private func lifetime() throws {
        try verify()
        guard Set(roles.keys) == Set(ServiceAccountPlan.roles), let authority, let gateway else { throw RuntimeActivationError.incomplete }
        for role in ServiceAccountPlan.roles { try roles[role]!.validateExclusive() }
        try authority.validateLifetime(); try gateway.validate(); try verify()
    }
    private func complete() throws {
        try lifetime(); try verifyPlatform()
        guard let sessions else { throw RuntimeActivationError.incomplete }
        for session in sessions { try session.requireRemoved() }
        try requireTemporaryAbsent(); try authority!.validate(); try lifetime()
    }
    func validateLifetime() throws {
        guard ready, !active else { throw RuntimeActivationError.unavailable }
        active = true; defer { active = false }
        do { try lifetime() } catch { retired = true; throw error }
    }
    func validateComplete() throws {
        guard ready, !active else { throw RuntimeActivationError.unavailable }
        active = true; defer { active = false }
        do { try complete() } catch { retired = true; throw error }
    }
    func close() throws {
        guard !active else { throw JournalDatabaseError.transactionActive }
        guard !closed else { return }
        gateway?.close(); gateway = nil
        try authority?.close(); authority = nil
        for role in ServiceAccountPlan.roles { roles[role]?.close() }; roles.removeAll()
        closed = true
    }
    deinit { gateway?.close(); try? authority?.close(); for token in roles.values { token.close() } }
}

extension RuntimeAuditUpgradeCutoverCoordinator {
    static func openWithNativeDrain(machine: PreparationIntentStore, graph: RuntimeAuditUpgradeGraph,
                                    record: RuntimeAuditUpgradeGraphRecord, installedRelease: SignedReleaseEvidence,
                                    currentPolicy: AuthorityCodePolicy, rootActivity: ReleaseActivityToken,
                                    rootActivityOwnership: RootActivityOwnership = .owned,
                                    verifyOwner: @escaping @Sendable () throws -> Void) throws -> RuntimeAuditUpgradeCutoverCoordinator {
        let drain = try RuntimeAuditUpgradeNativeDrain.open(graph: graph, record: record, rootActivity: rootActivity, verifyOwner: verifyOwner)
        do {
            return try open(machine: machine, graph: graph, record: record, installedRelease: installedRelease,
                currentPolicy: currentPolicy, rootActivity: rootActivity, rootActivityOwnership: rootActivityOwnership, verifyOwner: verifyOwner,
                acquireQuiescence: drain.acquire, closePendingQuiescence: drain.close)
        } catch { try? drain.close(); throw error }
    }
}
