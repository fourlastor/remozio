import Darwin
import Foundation

protocol MacGatewaySetupDriver: Sendable {
    func initialSelection(_ expected: SetupGatewayProgress) async throws -> GatewayRuntimeSettingsSelection?
    func settingsProgress() async throws -> SetupGatewaySettingsProgress?
    func applySettings(_ expected: SetupGatewaySettingsProgress, selection: GatewayRuntimeSettingsSelection) async throws -> SetupGatewaySettingsProgress
    func progress() async throws -> SetupGatewayActivationProgress?
    func prepare(_ expected: SetupGatewayProgress, choices: GatewaySetupPreparationChoices) async throws -> SetupGatewayProgress
    func initializeJournal(_ expected: SetupGatewayProgress) async throws -> SetupGatewayJournalResult
    func activate(_ expected: SetupGatewayActivationProgress, settings: GatewayRuntimeActivationSettings) async throws -> SetupGatewayActivationProgress
}

extension MacGatewaySetupDriver {
    func initialSelection(_ expected: SetupGatewayProgress) async throws -> GatewayRuntimeSettingsSelection? { nil }
}

/// Explicit app setup only. Refresh never imports administrator rights or retries an uncertain operation.
actor NativeMacGatewaySetupDriver: MacGatewaySetupDriver {
    private let operationTimeout: UInt64
    init(operationTimeoutMilliseconds: UInt64 = 60_000) throws {
        guard (1...300_000).contains(operationTimeoutMilliseconds) else { throw AdministrativeSetupChannelError.invalidConfiguration }
        operationTimeout = operationTimeoutMilliseconds
    }
    private func open(settingsCapability: Bool = false) async throws -> AdministrativeSetupChannel {
        try await MacAccountSetupConnection.open(gatewayActivation: true, gatewaySettings: settingsCapability, gatewayOperationTimeoutMilliseconds: operationTimeout)
    }
    func progress() async throws -> SetupGatewayActivationProgress? {
        let channel = try await open()
        do {
            try await channel.start(); let result = try await channel.gatewayActivationProgress()
            await channel.close(); return result
        } catch { await channel.close(); throw error }
    }
    func settingsProgress() async throws -> SetupGatewaySettingsProgress? {
        let channel = try await open(settingsCapability: true)
        do {
            try await channel.start(); let result = try await channel.gatewaySettingsProgress()
            await channel.close(); return result
        } catch { await channel.close(); throw error }
    }
    func applySettings(_ expected: SetupGatewaySettingsProgress, selection: GatewayRuntimeSettingsSelection) async throws -> SetupGatewaySettingsProgress {
        try requireOwner(expected.activation.setup.ownerUID)
        guard expected.supportsSettingsChanges else { throw AdministrativeSetupChannelError.unsupportedVersion }
        if let pending = try expected.pendingSelection {
            guard try pending.bytes == selection.bytes else { throw GatewayPreparationError.conflictingMaterial }
        }
        let channel = try await open(settingsCapability: true)
        do {
            try await channel.start()
            guard try await channel.gatewaySettingsProgress() == expected else { throw AdministrativeSetupError.staleProgress }
            try Task.checkCancellation()
            let session = try SetupAdministratorSession(); defer { session.close() }
            try session.authorize(); try Task.checkCancellation()
            let retained: SetupGatewaySettingsProgress
            if try expected.pendingDigest == nil {
                retained = try await channel.retainGatewaySettings(expected, selection: selection, authorization: session.externalForm())
            } else { retained = expected }
            try Task.checkCancellation()
            let result = try await channel.resumeGatewaySettings(retained, authorization: session.externalForm())
            await channel.close(); return result
        } catch { await channel.close(); throw error }
    }
    private func requireOwner(_ owner: UInt32) throws {
        guard getuid() > 0, getuid() == geteuid(), owner == getuid() else { throw AdministrativeSetupError.wrongAccount }
    }
    func prepare(_ expected: SetupGatewayProgress, choices: GatewaySetupPreparationChoices) async throws -> SetupGatewayProgress {
        try requireOwner(expected.ownerUID)
        guard !expected.journalInitialized else { throw GatewayPreparationError.incomplete }
        guard choices.fileWakeCustodyAccepted else { throw GatewayPreparationError.custodyNotAccepted }
        let channel = try await open()
        do {
            try await channel.start()
            guard try await channel.gatewayProgress() == expected else { throw AdministrativeSetupError.staleProgress }
            try Task.checkCancellation()
            let session = try SetupAdministratorSession(); defer { session.close() }
            try session.authorize(); try Task.checkCancellation()
            let result = try await channel.prepareGateway(expected, choices: choices, authorization: session.externalForm())
            await channel.close(); return result
        } catch { await channel.close(); throw error }
    }
    func initializeJournal(_ expected: SetupGatewayProgress) async throws -> SetupGatewayJournalResult {
        try requireOwner(expected.ownerUID)
        guard expected.journalIntentDigest != nil else { throw GatewayPreparationError.incomplete }
        let channel = try await open()
        do {
            try await channel.start()
            guard try await channel.gatewayProgress() == expected else { throw AdministrativeSetupError.staleProgress }
            try Task.checkCancellation()
            let session = try SetupAdministratorSession(); defer { session.close() }
            try session.authorize(); try Task.checkCancellation()
            let result = try await channel.resumeGatewayJournal(expected, authorization: session.externalForm())
            await channel.close(); return result
        } catch { await channel.close(); throw error }
    }
    func activate(_ expected: SetupGatewayActivationProgress, settings: GatewayRuntimeActivationSettings) async throws -> SetupGatewayActivationProgress {
        try requireOwner(expected.setup.ownerUID)
        guard expected.setup.journalInitialized else { throw GatewayPreparationError.incomplete }
        guard expected.settings == nil || expected.settings == settings else { throw GatewayPreparationError.conflictingMaterial }
        let channel = try await open()
        do {
            try await channel.start()
            guard try await channel.gatewayActivationProgress() == expected else { throw AdministrativeSetupError.staleProgress }
            try Task.checkCancellation()
            let session = try SetupAdministratorSession(); defer { session.close() }
            try session.authorize(); try Task.checkCancellation()
            let result = try await channel.activateGateway(expected, settings: settings, authorization: session.externalForm())
            await channel.close(); return result
        } catch { await channel.close(); throw error }
    }
}
