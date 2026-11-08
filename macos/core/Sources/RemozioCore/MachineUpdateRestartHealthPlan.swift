import Foundation
import RemozioProtocol

/// Selected health inputs only. Native owners must verify code, closed admission, keys and journals before use.
struct MachineUpdateRestartHealthPlan: CustomStringConvertible, CustomDebugStringConvertible {
    struct Requirement: Equatable, Sendable {
        let binding: RuntimeReleaseBinding
        let configurationEpoch: UUID
        let configurationRevision: UUID
        let backendEpoch: UUID
        let backendRevision: UUID
        let role: AuthorityCodeRole
        let executionUID: UInt32
        let code: AuthorityCodeEntry
        let publicKey: Data
    }
    struct Account {
        let configuration: RuntimeReleaseConfigurationPlan
        let backend: RuntimeReleaseBackendPlan?
        let requirements: [Requirement]
        var accountID: Data { configuration.binding.accountID }
    }
    let accounts: [Account]
    let preservedAccounts: [Data]
    var requirements: [Requirement] { accounts.flatMap(\.requirements) }
    var description: String { "MachineUpdateRestartHealthPlan(redacted)" }
    var debugDescription: String { description }

    init(snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence) throws {
        let source = snapshot.source, context = source.replacement
        let configuration = snapshot.configuration, backend = snapshot.backend
        try configuration.validate(); try backend.validate(epoch: configuration)
        try MachineUpdateBackendEpoch.requirePublicationFormats(candidate, epoch: configuration)
        guard context.activation.phase == .restartChecking,
              context.replacement?.phase == .observed,
              configuration.record.publication?.complete == true,
              backend.record.publication?.complete == true,
              configuration.record.activationAttempt == context.activation.attemptID,
              configuration.record.updateID == context.activation.updateID,
              configuration.record.macID == context.inventory.macID,
              configuration.record.installationID == context.inventory.installationID,
              configuration.record.inventoryDigest == context.activation.inventoryDigest,
              configuration.record.admissionDigest == context.activation.admissionDigest,
              try configuration.artifact(5) == context.inventory.canonicalBytes,
              try configuration.artifact(6) == context.candidate.encoded,
              try configuration.artifact(7) == context.admission.encoded,
              Set(configuration.record.accounts.map(\.accountID)) == Set(source.accounts.map(\.accountID)),
              Set(source.accounts.map(\.accountID)).count == source.accounts.count,
              Set(context.runtime.runtimes.map { $0.reference.services.accountID }).count == context.runtime.runtimes.count,
              Set(context.runtime.gateways.map(\.accountID)).count == context.runtime.gateways.count else {
            throw RuntimePreparationError.changedScope
        }
        var selected: [Account] = [], preserved: [Data] = []
        for account in source.accounts.sorted(by: { $0.accountID.lexicographicallyPrecedes($1.accountID) }) {
            guard let row = configuration.record.accounts.first(where: { $0.accountID == account.accountID }),
                  row.ownerUID == account.ownerUID,
                  try row.sourceDigest == source.accountDigest(accountID: account.accountID) else {
                throw RuntimePreparationError.changedScope
            }
            let runtime = context.runtime.runtimes.first { $0.reference.services.accountID == account.accountID }
            let gateway = context.runtime.gateways.first { $0.accountID == account.accountID }
            let foregroundRegistered = runtime?.jobsRegistered == true
            let gatewayRegistered = gateway?.jobRegistered == true
            guard foregroundRegistered || gatewayRegistered else { preserved.append(account.accountID); continue }
            guard let runtime, runtime.configurationPublished, runtime.reference.serviceActivity != nil,
                  account.servicesComplete, account.initialization?.complete == true,
                  let activation = runtime.activationRecord,
                  try RuntimeActivationPlan.decode(activation).reference == runtime.reference,
                  let plans = try configuration.configuration(accountID: account.accountID),
                  let policy = try configuration.policy(accountID: account.accountID) else {
                throw RuntimePreparationError.incomplete
            }
            try plans.requireSource(source, policy: policy, candidate: candidate)
            let capture = try backend.capture(accountID: account.accountID)
            let startup = capture?.startup
            if let startup {
                guard let original = capture?.source else { throw RuntimePreparationError.incomplete }
                try startup.requireSourceForPublication(configuration: plans.startup, source: original,
                    sourceConfiguration: plans.source, machine: source, currentPolicy: policy, candidate: candidate)
            }
            var required: [Requirement] = []
            func add(_ role: AuthorityCodeRole, uid: UInt32, publicKey: Data) throws {
                guard let code = plans.startup.host.codePolicy.entries.first(where: { $0.role == role && $0.active }) else {
                    throw RuntimePreparationError.changedScope
                }
                required.append(.init(binding: plans.startup.binding,
                    configurationEpoch: configuration.record.id, configurationRevision: configuration.record.revision,
                    backendEpoch: backend.record.id, backendRevision: backend.record.revision,
                    role: role, executionUID: uid, code: code, publicKey: publicKey))
            }
            if foregroundRegistered {
                guard let transport = runtime.reference.services.claims.first(where: { $0.role == .transport }) else {
                    throw RuntimePreparationError.incomplete
                }
                try add(.authority, uid: 0, publicKey: runtime.reference.services.authorityPublicKey)
                try add(.transport, uid: transport.number, publicKey: runtime.reference.transportPublicKeyX963)
            }
            if gatewayRegistered {
                guard gateway?.configurationPublished == true, let startup,
                      let claim = runtime.reference.services.claims.first(where: { $0.role == .gateway }),
                      startup.gateway.serviceUID == claim.number else { throw RuntimePreparationError.incomplete }
                try add(.notificationGateway, uid: claim.number, publicKey: startup.gateway.receiptPublicKey)
            }
            selected.append(.init(configuration: plans.startup, backend: startup, requirements: required))
        }
        guard context.runtime.runtimes.allSatisfy({ runtime in source.accounts.contains { $0.accountID == runtime.reference.services.accountID } }),
              context.runtime.gateways.allSatisfy({ gateway in source.accounts.contains { $0.accountID == gateway.accountID } }) else {
            throw RuntimePreparationError.changedScope
        }
        accounts = selected; preservedAccounts = preserved
    }

    func select(accountID: Data, role: AuthorityCodeRole) throws -> (Account, Requirement) {
        guard let account = accounts.first(where: { $0.accountID == accountID }),
              let requirement = account.requirements.first(where: { $0.role == role }) else {
            throw RuntimePreparationError.changedScope
        }
        return (account, requirement)
    }
}
