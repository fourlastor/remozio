import Foundation

/// Logical setup composition. The native Root host must authenticate its caller and launch the signed initializer under the gateway UID.
/// No production launcher is connected here. Owned fixtures exercise the same transaction and retry sequence.
enum GatewayJournalPreparationController {
    enum Stage { case verified, journalReady, completionRetained, completed }

    static func resume(machine: PreparationIntentStore, expected: GatewayJournalPreparationState,
                       verifyCurrent: () throws -> Void,
                       inspectFiles: (GatewayJournalSetupIntent) throws -> Void,
                       initialize: (GatewayJournalSetupIntent, Bool) throws -> GatewayJournalInitialization.Result,
                       didStage: (Stage) throws -> Void = { _ in }) throws -> GatewayJournalPreparationState {
        guard let intent = expected.intent else { throw GatewayPreparationError.incomplete }
        var retained = expected
        func verify() throws {
            try verifyCurrent()
            guard try machine.gatewayJournalPreparation(accountID: intent.accountID) == retained else { throw GatewayPreparationError.changedScope }
        }
        try verify()
        // Completion is historical. Do not acquire an active service's writer lock or reopen creation permission on a setup retry.
        if expected.initialized { return expected }
        try inspectFiles(intent); try verify(); try didStage(.verified); try verify()
        let result = try initialize(intent, true)
        try didStage(.journalReady); try verify()
        try inspectFiles(intent); try verify()
        retained = try machine.completeGatewayJournalInitialization(intent, head: result.head)
        try didStage(.completionRetained); try verify()
        guard retained.initialized else { throw GatewayPreparationError.incomplete }
        try didStage(.completed); try verify()
        return retained
    }
}
