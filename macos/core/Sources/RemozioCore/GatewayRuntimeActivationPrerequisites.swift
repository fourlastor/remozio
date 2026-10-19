import Darwin
import Foundation

/// Read-only native inspection. The setup owner holds its release scope, but closes the machine writer before this call.
enum GatewayRuntimeActivationPrerequisites {
    static func requireNativeInitializerAbsent(_ context: GatewayRuntimeActivationContext,
                                              verifyCurrent: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verifyCurrent()
        _ = try context.plan.proposal(journal: context.journal, foreground: context.foreground, inventory: context.inventory)
        guard let intent = context.journal.intent else { throw GatewayPreparationError.incomplete }
        let configuration = try GatewayJournalSetupServiceConfiguration(intent: intent, bundlePath: context.plan.bundlePath,
            codePolicy: context.foreground.host.codePolicy)
        try configuration.validate(foreground: context.foreground, inventory: context.inventory)
        let job = try GatewayJournalSetupJobManifest(configuration: configuration)
        guard try GatewayJournalSetupJobRegistration.isAbsent(job) else { throw GatewayPreparationError.incomplete }
        try verifyCurrent()
    }
}
