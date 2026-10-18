import Foundation

struct GatewayJournalSetupRootOutcome {
    let state: GatewayJournalPreparationState
    let cleanupComplete: Bool
}
struct GatewayJournalSetupRootOperations: Sendable {
    let inspectFiles: @Sendable () throws -> Void
    let publish: @Sendable () throws -> Void
    let verifyPublished: @Sendable () throws -> Void
    let register: @Sendable () throws -> Void
    let exchange: @Sendable () async throws -> GatewayJournalSetupReport
    let cleanup: @Sendable () throws -> Bool
    let remove: @Sendable () throws -> Void
    static func native(_ scope: GatewayJournalSetupRootScope) -> Self {
        .init(inspectFiles: { try scope.inspectNativeFiles() }, publish: { try scope.publishNativeArtifacts(retainedOnly: false) },
            verifyPublished: { try scope.publishNativeArtifacts(retainedOnly: true) }, register: { try scope.registerNativeJob() },
            exchange: { try await scope.exchangeNative() }, cleanup: { try scope.cleanupNativeJob() }, remove: { try scope.removeNativeJobFile() })
    }
}

/// Root owns one machine lease until the exchange settles. No SQLite or caller verification callback survives scope closure.
/// The administrator endpoint must authenticate its caller before opening this operation outside its existing machine-store callback.
enum GatewayJournalSetupRootOperation {
    enum Stage { case verified, filesInspected, artifactsPublished, jobRegistered, reportReceived, completionRetained, cleaned }
    static func resumeNative(machineDirectory: String, macID: Data, ownerUID: UInt32, expectedIntentDigest: Data,
                             verifyHost: @escaping (InstallationInventory) throws -> Void) async throws -> GatewayJournalSetupRootOutcome {
        let scope = try GatewayJournalSetupRootScope.openNative(machineDirectory: machineDirectory, macID: macID,
            ownerUID: ownerUID, expectedIntentDigest: expectedIntentDigest, verifyHost: verifyHost)
        return try await resume(scope: scope, operations: .native(scope))
    }
    // Owned fixtures use real protected state and files with injected job control. They do not prove native UID or signed peer admission.
    static func resume(scope: GatewayJournalSetupRootScope, operations: GatewayJournalSetupRootOperations,
                       didStage: @Sendable (Stage) throws -> Void = { _ in }) async throws -> GatewayJournalSetupRootOutcome {
        do {
            try Task.checkCancellation(); try scope.verifyCurrent(); try didStage(.verified)
            if !(try scope.state().initialized) {
                try scope.verifyPending(); try operations.inspectFiles(); try didStage(.filesInspected)
                try scope.verifyPending(); try operations.publish(); try operations.verifyPublished(); try didStage(.artifactsPublished)
                try scope.verifyPending(); try operations.register(); try operations.verifyPublished(); try didStage(.jobRegistered)
                try Task.checkCancellation()
                let report = try await operations.exchange()
                try Task.checkCancellation(); try scope.verifyPending(); try didStage(.reportReceived)
                try operations.inspectFiles(); try scope.complete(report); try didStage(.completionRetained)
            }
            try scope.verifyCurrent()
            let cleaned = try operations.cleanup()
            if cleaned { try operations.remove(); try scope.verifyCurrent(); try didStage(.cleaned) }
            let result = GatewayJournalSetupRootOutcome(state: try scope.state(), cleanupComplete: cleaned)
            try scope.close(); return result
        } catch {
            let failure = error
            // Lost replies can leave a live initializer. Cleanup refuses an active or uncertain job and never replaces it.
            do { try scope.verifyCurrent(); if try operations.cleanup() { try operations.remove() } } catch { }
            try? scope.close(); throw failure
        }
    }
}
