import Darwin
import Foundation
import RemozioProtocol

/// Holds current code approval separately from the target's recorded startup policy. Authenticated callers remain separate.
enum MachineUpdateRetainedSetupRuntimeNativeAuthority {
    typealias Native = MachineUpdateRetainedSetupRuntimeNativeContext
    typealias Entry = Native.Entry
    typealias Frame = Native.Frame
    typealias Verify = Native.Verify
    typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    typealias PolicyEntry = MachineUpdateRetainedSetupPolicyNativeEntry
    typealias Support = MachineUpdateRetainedSetupPromotionNativeSupport
    final class HeldScope {
        private let processID = getpid(), thread = pthread_self()
        private let policy: AuthorityCodePolicy, candidate: SignedReleaseEvidence
        fileprivate let targetAccountID: Data
        private var current: Verify?
        private var checking = false
        fileprivate init(policy: AuthorityCodePolicy, expected: Frame, candidate: SignedReleaseEvidence, current: @escaping Verify) {
            self.policy = policy; self.candidate = candidate; targetAccountID = expected.entry.runtime.preparation.accountID; self.current = current
        }
        func requireActive() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            guard !checking, let current else { expire(); throw JournalLeaseError.invalidated }
            checking = true; defer { checking = false }
            do { try current(); guard self.current != nil else { throw JournalLeaseError.invalidated } }
            catch { expire(); throw error }
        }
        func verifyRelease(_ actual: Entry, candidate: SignedReleaseEvidence) throws {
            try requireActive()
            do {
                guard actual.runtime.preparation.accountID == targetAccountID,
                      try InstallationInventory.digest(candidate) == InstallationInventory.digest(self.candidate),
                      let app = policy.entries.first(where: { $0.role == .app && $0.active }) else { throw RuntimeActivationError.changedScope }
                let bundle = URL(fileURLWithPath: actual.runtime.setup.source.actual.inventory.bundlePath)
                let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
                try MachineUpdateRetainedSetupPolicyNativeContext.requireRelease(release, approvedRuntime: actual.runtime,
                    candidate: candidate, currentCodePolicy: policy)
                try RuntimeRetainedSetupReleaseBinding.requireFormats(release); try requireActive()
            } catch { expire(); throw error }
        }
        func verifyCode() throws {
            try requireActive()
            do {
                guard let setup = policy.entries.first(where: { $0.role == .setupController && $0.active }) else { throw RuntimeActivationError.changedScope }
                let local = try XPCPeerPolicy(teamID: setup.teamID, componentIdentifier: setup.identifier,
                    approvedCodeDirectoryHashes: [setup.codeDirectoryHash], expectedUserID: 0)
                try DynamicCodeValidation.validateSelf(requirement: local.requirement)
                guard try DynamicCodeValidation.selfPath() == MachineBootstrap.bundlePath + "/" + AdministrativeSetupConfiguration.executablePath else {
                    throw RuntimeActivationError.changedScope
                }
                try requireActive()
            } catch { expire(); throw error }
        }
        func withCurrentCodePolicy<Value>(_ body: (AuthorityCodePolicy) throws -> Value) throws -> Value {
            try requireActive()
            do { let result = try body(policy); try requireActive(); return result }
            catch { expire(); throw error }
        }
        fileprivate func expire() { current = nil }
    }
    static func withNativeScope<Value>(expected: Frame, candidate: SignedReleaseEvidence, currentAuthorityAccountID: Data,
        perform: (HeldScope, Native.NativeCustody) throws -> Value) throws -> Value {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try Native.withNativeCustody(machineDirectory: MachineBootstrap.machineDirectory, expected: expected, candidate: candidate) { custody in
            let (initial, host) = try PolicyEntry.publishedAuthority(runtime: expected.entry.runtime, accountID: currentAuthorityAccountID)
            let paths = try Support.Paths(accountID: initial.accountID, journalPath: initial.journalPath, continuityPath: initial.continuityPath)
            let hostPath = try RuntimePreparationPaths(accountID: initial.accountID).privateDirectory + "/" + AdministrativeSetupPublication.File.commandHost.name
            func published() throws {
                try custody.requireActive()
                guard try ProtectedServiceConfiguration.read(path: hostPath) == host.canonicalBytes else { throw RuntimeActivationError.changedScope }
                try custody.requireActive()
            }
            return try withAuthorityPair(initial: initial, verifyCurrent: published, openStorage: {
                try Support.openExistingStorage(initial: initial,
                    openJournalLease: { try ProtectedJournalLease.acquire(directoryPath: paths.journalDirectory) },
                    openContinuityLease: { try ProtectedContinuityLease.acquire(directoryPath: paths.continuityDirectory, excludingDirectory: $0) })
            }) { policy, current in
                let scope = HeldScope(policy: policy, expected: expected, candidate: candidate, current: current)
                defer { scope.expire() }
                try scope.verifyRelease(expected.entry, candidate: candidate); try scope.verifyCode()
                let result = try perform(scope, custody)
                try scope.verifyRelease(expected.entry, candidate: candidate); try scope.verifyCode(); return result
            }
        }
    }
    /// The stop owner lends its original pair. Recapture and native approval never reopen the current Authority stores.
    static func withMaintenanceScope<Value>(stop: RuntimeMaintenanceAuthorityStop, capture: RuntimeMaintenanceStopCapture,
        owner: SetupRetainedInvocation, expected: SetupAccountOwner.RetainedMaintenanceCapture,
        transitions: [PreparationIntentStore.RuntimeMaintenanceTransition], candidate: SignedReleaseEvidence,
        perform: (HeldScope, Native.NativeCustody, Frame) throws -> Value) throws -> Value {
        try RuntimeMaintenanceCommitments.requireProfile(capture.window.purpose)
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let (initial, host) = try PolicyEntry.publishedAuthority(runtime: expected.binding.entry.runtime,
            accountID: expected.binding.authorityAccountID)
        return try stop.withNativeBody(purpose: capture.window.purpose, initialization: initial, policy: host.codePolicy,
            capture: capture) { pair in
            let actual = try owner.recaptureMaintenance(expected: expected, transitions: transitions,
                capture: capture, pair: pair, candidate: candidate)
            return try Native.withNativeCustody(machineDirectory: MachineBootstrap.machineDirectory, expected: actual.frame,
                candidate: candidate) { custody in
                try PolicyEntry.withCurrentPolicy(initial: initial, read: {
                    try pair.validate(); try custody.requireActive()
                    return try pair.maintenancePolicyBoundary(initialization: initial)
                }) { policy, current in
                    let scope = HeldScope(policy: policy, expected: actual.frame, candidate: candidate, current: current)
                    defer { scope.expire() }
                    try scope.verifyRelease(actual.binding.entry, candidate: candidate); try scope.verifyCode()
                    let value = try perform(scope, custody, actual.frame)
                    try scope.verifyRelease(actual.binding.entry, candidate: candidate); try scope.verifyCode(); return value
                }
            }
        }
    }
    /// Owned pairs prove equality and expiry only. This helper cannot construct HeldScope or a native approval.
    static func withAuthorityPair<Value>(initial: AuthorityInitializationIntent, verifyCurrent: Verify,
        openStorage: () throws -> sending AuthorityStorage, perform: (AuthorityCodePolicy, @escaping Verify) throws -> Value) throws -> Value {
        try Support.withReadOnlyPair(initial: initial, verifyCurrent: verifyCurrent, openStorage: openStorage) { journal, current in
            try PolicyEntry.withCurrentPolicy(initial: initial, read: {
                try current(); let pair = try journal.captureRetainedSetupPolicyBoundary(expected: initial); try current(); return pair
            }, perform: perform)
        }
    }
    /// Call only after P04 closes its writer. The target pair stays read-only and cannot initialize or repair storage.
    static func withTargetPair<Value>(scope: HeldScope, expected: Entry,
        perform: (@escaping () throws -> Boundary) throws -> Value) throws -> Value {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try scope.requireActive()
        guard expected.runtime.preparation.accountID == scope.targetAccountID, let record = expected.intent, record.phase == .recorded,
              let initial = expected.runtime.setup.account?.initialization else { throw RuntimePreparationError.incomplete }
        let paths = try Support.Paths(accountID: initial.accountID, journalPath: initial.journalPath, continuityPath: initial.continuityPath)
        return try Support.withReadOnlyPair(initial: initial, verifyCurrent: scope.requireActive, openStorage: {
            try Support.openExistingStorage(initial: initial,
                openJournalLease: { try ProtectedJournalLease.acquire(directoryPath: paths.journalDirectory) },
                openContinuityLease: { try ProtectedContinuityLease.acquire(directoryPath: paths.continuityDirectory, excludingDirectory: $0) })
        }) { journal, current in
            func read() throws -> Boundary {
                try current(); let pair = try journal.captureRetainedSetupPolicyBoundary(expected: initial)
                try record.requireRecorded(pair); try current(); return pair
            }
            _ = try read(); let result = try perform(read); _ = try read(); return result
        }
    }
}
