import Darwin
import Foundation

/// One machine lease across the asynchronous exchange. Every callback checks active ownership before accessing SQLite.
/// The native factory owns the store and release token. Owned fixtures retain their store separately for assertions.
final class GatewayJournalSetupRootScope: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let machine: PreparationIntentStore
    private let account: AccountPreparationIntent
    private let foreground: RuntimeActivationPlan
    private let inventory: InstallationInventory
    let configuration: GatewayJournalSetupServiceConfiguration
    private let verifyHost: (InstallationInventory) throws -> Void
    private let releaseToken: ReleaseActivityToken?
    private let ownsMachine: Bool
    private let expectedImport: SharedSetupImportIntent?
    private let processID = getpid()
    private var expected: GatewayJournalPreparationState
    private var active = true

    static func openNative(machineDirectory: String, macID: Data, ownerUID: UInt32, expectedIntentDigest: Data, expectedImport: SharedSetupImportIntent? = nil,
                           verifyHost: @escaping (InstallationInventory) throws -> Void) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard ownerUID > 0, ownerUID < UInt32.max, expectedIntentDigest.count == 32 else { throw GatewayPreparationError.invalidRecord }
        let activity = try ReleaseActivityBarrier.open(machineDirectory: machineDirectory), token = try activity.acquireShared()
        var machine: PreparationIntentStore?
        do {
            let store = try PreparationIntentStore.open(directoryPath: machineDirectory, macID: macID); machine = store
            guard let account = try store.accountPreparation(ownerUID: ownerUID), let inventory = try store.loadInventory() else {
                throw GatewayPreparationError.incomplete
            }
            let activation = try store.runtimeActivation(accountID: account.accountID)
            guard activation.jobsRegistered, let foreground = activation.plan else { throw GatewayPreparationError.incomplete }
            let state = try store.gatewayJournalPreparation(accountID: account.accountID)
            guard let intent = state.intent, try intent.digest == expectedIntentDigest else { throw GatewayPreparationError.changedScope }
            let configuration = try GatewayJournalSetupServiceConfiguration(intent: intent, bundlePath: inventory.bundlePath, codePolicy: foreground.host.codePolicy)
            return try Self(machine: store, account: account, foreground: foreground, inventory: inventory,
                configuration: configuration, expected: state, ownsMachine: true, releaseToken: token, expectedImport: expectedImport, verifyHost: { inventory in
                    guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
                    try verifyHost(inventory)
                    try LocalAccountDirectory.validateOwnership(LocalAccountDirectory.lookup(uid: ownerUID), uid: ownerUID, directoryID: account.directoryID)
                })
        } catch { try? machine?.close(); token.close(); throw error }
    }
    init(machine: PreparationIntentStore, account: AccountPreparationIntent, foreground: RuntimeActivationPlan,
         inventory: InstallationInventory, configuration: GatewayJournalSetupServiceConfiguration,
         expected: GatewayJournalPreparationState, ownsMachine: Bool = false, releaseToken: ReleaseActivityToken? = nil,
         expectedImport: SharedSetupImportIntent? = nil, verifyHost: @escaping (InstallationInventory) throws -> Void = { _ in }) throws {
        guard expected.intent == configuration.intent else { throw GatewayPreparationError.changedScope }
        self.machine = machine; self.account = account; self.foreground = foreground; self.inventory = inventory
        self.configuration = configuration; self.expected = expected; self.ownsMachine = ownsMachine
        self.releaseToken = releaseToken; self.verifyHost = verifyHost; self.expectedImport = expectedImport
        try verifyCurrent()
    }
    func verifyCurrent() throws {
        try lock.withLock {
            guard active, getpid() == processID else { throw GatewayPreparationError.incomplete }
            try releaseToken?.validate(); try verifyHost(inventory)
            try machine.validateAccountPreparation(account)
            try SharedSetupImportGatewayRuntimeScope.validate(machine: machine, account: account, expected: expectedImport)
            let activation = try machine.runtimeActivation(accountID: account.accountID)
            guard try machine.inventory() == inventory, activation.jobsRegistered,
                  try activation.plan?.encoded == foreground.encoded,
                  try machine.gatewayJournalPreparation(accountID: account.accountID) == expected else {
                throw GatewayPreparationError.changedScope
            }
            try configuration.validate(foreground: foreground, inventory: inventory)
        }
    }
    func withCurrent<Value>(_ body: () throws -> Value) throws -> Value {
        try lock.withLock { try verifyCurrent(); let result = try body(); try verifyCurrent(); return result }
    }
    func verifyPending() throws {
        try lock.withLock { try verifyCurrent(); guard !expected.initialized else { throw GatewayPreparationError.changedScope } }
    }
    func state() throws -> GatewayJournalPreparationState { try withCurrent { expected } }
    func complete(_ report: GatewayJournalSetupReport) throws {
        try lock.withLock {
            try verifyPending(); try report.validate(intent: configuration.intent)
            // Version 1 reports the empty head checked by the authenticated gateway initializer.
            expected = try machine.completeGatewayJournalInitialization(configuration.intent,
                head: .init(registration: configuration.intent.configuration.registration, revision: 0, receipt: nil))
            try verifyCurrent(); guard expected.initialized else { throw GatewayPreparationError.incomplete }
        }
    }
    private func release() throws -> SignedReleaseEvidence {
        try verifyCurrent()
        guard let app = configuration.codePolicy.entries.first(where: { $0.role == .app && $0.active }) else { throw GatewayPreparationError.invalidRecord }
        let value = try SignedReleaseInspection.inspect(URL(fileURLWithPath: inventory.bundlePath), teamID: app.teamID, appIdentifier: app.identifier)
        try configuration.validate(foreground: foreground, inventory: inventory, release: value); return value
    }
    func inspectNativeFiles() throws {
        try withCurrent {
            try verifyPending()
            _ = try GatewayJournalFileProvisioning.prepare(account: account, services: configuration.intent.material.runtime.services,
                mode: .requireExisting, expected: configuration.intent.files, verifyCurrent: { try self.verifyPending() })
        }
    }
    func publishNativeArtifacts(retainedOnly: Bool) throws {
        try withCurrent {
            try verifyPending()
            _ = try GatewayJournalSetupJobArtifacts.prepare(configuration: configuration, account: account, machine: machine,
                foreground: foreground, inventory: inventory, release: release(), mode: retainedOnly ? .validateRetained : .preparePending,
                verifyCurrent: { try self.verifyPending() })
        }
    }
    func registerNativeJob() throws {
        try withCurrent {
            let job = try GatewayJournalSetupJobManifest(configuration: configuration)
            try GatewayJournalSetupJobRegistration.ensure(job, verifyCurrent: { try self.publishNativeArtifacts(retainedOnly: true) })
        }
    }
    func exchangeNative() async throws -> GatewayJournalSetupReport {
        let channel = try withCurrent {
            try publishNativeArtifacts(retainedOnly: true)
            return try GatewayJournalSetupChannel(intent: configuration.intent, gatewayCode: configuration.gatewayCode,
                timeoutMilliseconds: configuration.intent.configuration.settings.handshakeTimeoutMillis,
                verifyPending: { try self.verifyPending() })
        }
        return try await channel.prepare()
    }
    func cleanupNativeJob() throws -> Bool {
        try withCurrent {
            let job = try GatewayJournalSetupJobManifest(configuration: configuration)
            if try GatewayJournalSetupJobRegistration.isAbsent(job) { return true }
            return try GatewayJournalSetupJobRegistration.cleanupStopped(job, verifyCurrent: {
                try self.verifyCurrent()
                try GatewayJournalSetupJobArtifacts.validateRetainedJob(job, verifyCurrent: { try self.verifyCurrent() })
            })
        }
    }
    func removeNativeJobFile() throws {
        try withCurrent {
            _ = try GatewayJournalSetupJobArtifacts.removeAfterJobAbsent(configuration: configuration, machine: machine,
                verifyCurrent: { try self.verifyCurrent() })
        }
    }
    func close() throws {
        try lock.withLock {
            guard active else { return }; active = false
            defer { releaseToken?.close() }
            if ownsMachine { try machine.close() }
        }
    }
    deinit { try? close() }
}
