import Foundation

/// Protected setup inputs only. A retained reference does not assert connector health or import completion.
struct RelayRunCredentialSetupContext: Sendable {
    let account: AccountPreparationIntent
    let inventory: InstallationInventory
    let expected: SharedSetupImportIntent
    let plan: SharedSetupImportRelayPlan
    let created: SharedSetupRelayProvisioningRecord
    let runtime: RuntimeMaterialReference
    let reference: RelayRunCredentialReference?
}

enum RelayRunCredentialSetupError: Error { case credentialRequired }

/// Network reads happen outside these synchronous machine and import leases.
struct RelayRunCredentialSetupOperations: Sendable {
    let prepare: @Sendable (RelayRunCredentialSetupContext, CloudflareTunnelRunCredential?, Bool,
                            () throws -> Void) throws -> RelayRunCredentialReference
    let publish: @Sendable (RelayRunCredentialSetupContext, RelayRunCredentialReference,
                            () throws -> Void) throws -> Void
    static let native = Self(prepare: { context, credential, custodyAccepted, verify in
        try RelayRunCredentialPreparation.prepareNative(account: context.account, inventory: context.inventory,
            expected: context.expected, plan: context.plan, created: context.created, runtime: context.runtime,
            reference: context.reference, fileCustodyAccepted: custodyAccepted, verifyCurrent: verify,
            makeCredential: {
                guard let credential else { throw RelayRunCredentialSetupError.credentialRequired }
                return credential
            }).reference
    }, publish: { context, reference, verify in
        let mode: RelayRunCredentialPublication.Mode = [.runtimePublished, .gatewayPrepared].contains(context.expected.phase)
            ? .prepareUnactivated : .validateRetained
        _ = try RelayRunCredentialPublication.publishNative(account: context.account, inventory: context.inventory,
            expected: context.expected, plan: context.plan, created: context.created, runtime: context.runtime,
            reference: reference, mode: mode, verifyCurrent: verify)
    })
}
