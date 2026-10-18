import Foundation
import RemozioProtocol

/// One-shot setup under the gateway UID. It starts no listener and accesses no provider or signing credential.
/// The Root host must retain file identities and authorize initialization through its protected pending intent.
enum GatewayJournalInitialization {
    enum Stage { case opened, closed }
    struct Result {
        let head: GatewayHeadEvidence
        let initialized: Bool
    }

    static func resume(configuration: GatewayServiceConfiguration, expected: GatewayJournalFileIdentity,
                       mayInitializeEmpty: Bool) throws -> Result {
        try configuration.requireNativeProcess()
        let clock = try AuthorityClock()
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 8, maxItems: 256)
        let settings = configuration.settings
        return try resume(registration: configuration.registration, mayInitializeEmpty: mayInitializeEmpty,
            verifyCurrent: { try configuration.requireNativeProcess() },
            openJournal: { initialize in
                let lease = try ProtectedGatewayLease.acquire(directoryPath: configuration.directoryPath, serviceUID: configuration.serviceUID)
                do {
                    guard try lease.fileIdentity() == expected else { throw JournalLeaseError.identityChanged }
                    return try GatewayDatabase(lease: lease, identity: configuration.registration,
                        payloadLimits: limits, signingLimits: limits, maximumOperations: settings.maximumStoredControls,
                        maximumPendingPerEnrollment: settings.maximumPendingPerEnrollment,
                        maximumLifetimeMillis: settings.maximumCandidateLifetimeMillis, clockEpoch: clock.epoch,
                        busyMilliseconds: settings.databaseBusyMillis, initialize: initialize, migrateLegacyStore: false, probePolicy: settings.probe)
                } catch { lease.close(); throw error }
            })
    }

    // Owned SQLite fixtures prove retry and retention, not native service launch or the Root caller's authorization.
    static func resume(registration: GatewayRegistrationIdentity, mayInitializeEmpty: Bool,
                       verifyCurrent: () throws -> Void, openJournal: (Bool) throws -> GatewayDatabase,
                       didStage: (Stage) throws -> Void = { _ in }) throws -> Result {
        try verifyCurrent()
        var initialized = false
        let database: GatewayDatabase
        do { database = try openJournal(false) }
        catch GatewayDatabaseError.incompatibleStore {
            guard mayInitializeEmpty else { throw GatewayDatabaseError.incompatibleStore }
            try verifyCurrent()
            // The database constructor independently requires an empty schema. An incompatible live store is never reset.
            database = try openJournal(true); initialized = true
        }
        do {
            try didStage(.opened); try verifyCurrent()
            let head = try database.headEvidence()
            guard head.registration == registration, !initialized || (head.revision == 0 && head.receipt == nil) else {
                throw GatewayDatabaseError.wrongScope
            }
            try verifyCurrent(); try database.close()
            try didStage(.closed); try verifyCurrent()
            return Result(head: head, initialized: initialized)
        } catch { try? database.close(); throw error }
    }
}
