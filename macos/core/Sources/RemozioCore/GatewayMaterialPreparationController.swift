import Darwin
import Foundation

/// Retains optional material only. The administrator endpoint must authenticate the caller and current signed release.
enum GatewayMaterialPreparationController {
    enum Stage { case materialRestored, referenceRetained, completed }

    static func prepare(machine: PreparationIntentStore, account: AccountPreparationIntent,
                        expected: GatewayPreparationState, provider: SetupFCMConfiguration, senderID: String,
                        packageName: String, fileWakeCustodyAccepted: Bool,
                        verifyCurrent: () throws -> Void) throws -> GatewayPreparationState {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard fileWakeCustodyAccepted || expected.reference != nil else { throw GatewayPreparationError.custodyNotAccepted }
        return try withoutActuallyEscaping(verifyCurrent) { verify in
            try prepare(machine: machine, account: account, expected: expected, verifyCurrent: verify,
                verifyServices: { services in
                    let directory = try NativeServiceAccountDirectory(accountID: account.accountID, ownerUID: account.ownerUID)
                    for claim in services.claims {
                        try directory.validateGroup(claim); try directory.validateUser(claim, ownerUID: account.ownerUID)
                    }
                }, restoreMaterial: { runtime, reference, verify in
                    try GatewayMaterialPreparation.prepare(account: account, runtime: runtime, expected: reference,
                        provider: provider, senderID: senderID, packageName: packageName,
                        fileWakeCustodyAccepted: fileWakeCustodyAccepted || reference != nil, verifyCurrent: verify)
                })
        }
    }

    // Logical controller fixtures exercise owned storage. They do not authenticate an administrator or prove native UID isolation.
    static func prepare(machine: PreparationIntentStore, account: AccountPreparationIntent,
                        expected: GatewayPreparationState, verifyCurrent: @escaping () throws -> Void,
                        verifyServices: @escaping (ServiceAccountPlan) throws -> Void,
                        restoreMaterial: (RuntimeMaterialReference, GatewayMaterialReference?, () throws -> Void) throws -> GatewayPreparationMaterial,
                        didStage: (Stage) throws -> Void = { _ in }) throws -> GatewayPreparationState {
        try verifyCurrent(); try machine.validateAccountPreparation(account)
        let runtime = try machine.runtimePreparation(accountID: account.accountID)
        let activation = try machine.runtimeActivation(accountID: account.accountID)
        guard runtime.configurationPublished, let reference = runtime.reference,
              activation.jobsRegistered, let plan = activation.plan, plan.reference == reference,
              let inventory = try machine.inventory(), try plan.enrolledInventory(inventory) == inventory else {
            throw GatewayPreparationError.incomplete
        }
        guard try machine.gatewayPreparation(accountID: account.accountID) == expected else { throw GatewayPreparationError.changedScope }
        let planBytes = try plan.encoded
        var retained = expected.reference
        func verify() throws {
            try verifyCurrent(); try machine.validateAccountPreparation(account)
            let currentActivation = try machine.runtimeActivation(accountID: account.accountID)
            guard try machine.inventory() == inventory,
                  try machine.runtimePreparation(accountID: account.accountID) == runtime,
                  currentActivation.jobsRegistered, try currentActivation.plan?.encoded == planBytes,
                  try machine.gatewayPreparation(accountID: account.accountID).reference == retained else {
                throw GatewayPreparationError.changedScope
            }
            try verifyServices(reference.services)
        }
        try verify()
        let material = try restoreMaterial(reference, retained, verify)
        try didStage(.materialRestored); try verify()
        let next = try material.reference
        guard next.runtime == reference else { throw GatewayPreparationError.changedScope }
        if let retained { guard retained == next else { throw GatewayPreparationError.conflictingMaterial } }
        try machine.retainGatewayMaterial(next); retained = next
        try didStage(.referenceRetained); try verify()
        let confirmed = try restoreMaterial(reference, next, verify)
        guard try confirmed.reference == next else { throw GatewayPreparationError.conflictingMaterial }
        try didStage(.completed); try verify()
        return try machine.gatewayPreparation(accountID: account.accountID)
    }
}
