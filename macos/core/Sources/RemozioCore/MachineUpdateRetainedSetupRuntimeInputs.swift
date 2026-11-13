import Darwin
import Foundation

/// Exact public import choices. This value grants no writer, publication, credential or native startup authority.
struct MachineUpdateRetainedSetupRuntimeInputs: Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    typealias Runtime = MachineUpdateStableRuntimePreparationSnapshot
    typealias RelaySelection = MachineUpdateStableRuntimeImportPreparation.RelaySelection
    let scope: SharedSetupImportIntent.Scope
    let journalPresent: Bool
    let intent: SharedSetupImportIntent?
    let relay: RelaySelection?
    var description: String { "MachineUpdateRetainedSetupRuntimeInputs(redacted)" }
    var debugDescription: String { description }

    private init(scope: SharedSetupImportIntent.Scope, journalPresent: Bool, intent: SharedSetupImportIntent?, relay: RelaySelection?) throws {
        guard journalPresent || intent == nil && relay == nil,
              (intent == nil) == (relay == nil), intent == nil || intent?.scope == scope else {
            throw SharedSetupImportError.wrongScope
        }
        if let intent {
            guard (intent.recipe.cloudflare != nil) == (relay?.plan != nil) else { throw RuntimePreparationError.incomplete }
            try relay?.plan?.validate(expected: intent)
        }
        self.scope = scope; self.journalPresent = journalPresent; self.intent = intent; self.relay = relay
    }

    static func captureNative(expected: Runtime, verifyCurrent: () throws -> Void) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let inventory = expected.setup.source.actual.inventory
        guard inventory.bundlePath == MachineBootstrap.bundlePath else { throw MachineUpdateActivationError.wrongBoundary }
        let relativeMachine = String(MachineBootstrap.machineDirectory.dropFirst())
        try verifyCurrent()
        let value = try SharedSetupImportJournal.withExisting(anchor: "/", relativeMachineDirectory: relativeMachine, owner: 0,
            macID: inventory.macID, installationID: inventory.installationID) { journal in
                guard let journal else {
                    return try capture(expected: expected, journal: nil, verifyCurrent: verifyCurrent,
                        readRelay: { _ in throw SharedSetupImportError.wrongScope })
                }
                let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: relativeMachine + "/SharedSetupImport",
                    owner: 0, createIfMissing: false)
                defer { directory.close() }
                try journal.requireDirectory(directory)
                return try capture(expected: expected, journal: journal, verifyCurrent: verifyCurrent,
                    readRelay: { try .read($0, directory: directory, owner: 0) })
            }
        try verifyCurrent(); return value
    }

    /// Owned controls supply real journals and files. Verification must not query an active machine transaction.
    static func capture(expected: Runtime, journal: SharedSetupImportJournal?, verifyCurrent: () throws -> Void,
        readRelay: (SharedSetupImportIntent) throws -> RelaySelection) throws -> Self {
        let scope = try sourceScope(expected)
        try verifyCurrent()
        try journal?.requireDestination(macID: scope.macID, installationID: scope.installationID)
        let intent = try journal?.current(scope: scope)
        if let intent, intent.phase != .retained {
            guard expected.state.configurationPublished, intent.phase == .runtimePublished else { throw RuntimePreparationError.incomplete }
        }
        let relay = try intent.map(readRelay)
        let value = try Self(scope: scope, journalPresent: journal != nil, intent: intent, relay: relay)
        try verifyCurrent()
        guard try journal?.current(scope: scope) == intent else { throw SharedSetupImportError.wrongScope }
        if let intent { guard try readRelay(intent) == relay else { throw SharedSetupImportError.conflict } }
        try verifyCurrent(); try value.requireSource(expected); return value
    }
    func requireSource(_ expected: Runtime) throws {
        guard try Self.sourceScope(expected) == scope else { throw SharedSetupImportError.wrongScope }
    }
    func requireSame(as other: Self) throws {
        guard self == other else { throw SharedSetupImportError.conflict }
    }
    func requireCurrentNative(expected: Runtime, verifyCurrent: () throws -> Void) throws {
        try requireSource(expected)
        try Self.captureNative(expected: expected, verifyCurrent: verifyCurrent).requireSame(as: self)
    }
    /// Checks one acknowledgement after actual runtime publication. The writer must separately pin every other protected row.
    func requirePublicationAcknowledgement(from before: Self) throws {
        guard journalPresent == before.journalPresent, journalPresent, scope == before.scope, relay == before.relay,
              let previous = before.intent, let intent, previous.phase == .retained, intent.phase == .runtimePublished,
              intent.scope == previous.scope, intent.operationID == previous.operationID,
              intent.proposalDigest == previous.proposalDigest, intent.recipe == previous.recipe,
              intent.originalPortableVersion == previous.originalPortableVersion, intent.revision != previous.revision else {
            throw SharedSetupImportError.conflict
        }
    }
    private static func sourceScope(_ expected: Runtime) throws -> SharedSetupImportIntent.Scope {
        let account = expected.preparation
        let inventory = try expected.setup.source.provisioningInventory(accountID: account.accountID,
            ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
        return try .init(account: account, inventory: inventory)
    }
}
