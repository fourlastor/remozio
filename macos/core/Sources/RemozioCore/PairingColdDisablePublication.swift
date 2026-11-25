import Darwin
import Foundation

/// Fixed, private file operations owned by the Setup cold-disable transaction.
enum PairingColdDisablePublication {
    enum Stage { case intent, runtime, host, activation, complete }

    static func apply(expectedHost: InstalledAuthorityCommandConfiguration, directory: ProtectedSetupDirectory, owner: uid_t,
        verifyStopped: () throws -> Void, retainTarget: (InstalledAuthorityCommandConfiguration) throws -> Void,
        didPublish: (Stage) throws -> Void = { _ in }) throws -> PairingColdDisableIntent {
        try verifyStopped()
        let actualHost = try InstalledAuthorityCommandConfiguration.decode(read(.commandHost, directory: directory, owner: owner))
        let actualCommand = try read(.commandConfiguration, directory: directory, owner: owner)
        let pending: PairingColdDisableIntent
        let target: InstalledAuthorityCommandConfiguration
        if let recorded = try readIntent(directory: directory, owner: owner) {
            pending = recorded
            try pending.requireScope(expectedHost)
            let expectedDigest = PairingColdDisableIntent.digest(expectedHost.canonicalBytes)
            guard expectedDigest == pending.sourceHost || expectedDigest == pending.targetHost else {
                throw PairingColdDisableError.changedConfiguration
            }
            try pending.requireScope(actualHost)
            if PairingColdDisableIntent.digest(actualHost.canonicalBytes) == pending.sourceHost {
                guard !pending.completed else { throw PairingColdDisableError.changedConfiguration }
                target = try PairingColdDisableConfiguration(source: actualHost).target
            } else {
                target = actualHost
            }
            try pending.requireTarget(target)
            let currentCommandDigest = PairingColdDisableIntent.digest(actualCommand)
            guard currentCommandDigest == pending.targetCommand || (!pending.completed && currentCommandDigest == pending.sourceCommand) else {
                throw PairingColdDisableError.changedConfiguration
            }
        } else {
            guard actualHost.canonicalBytes == expectedHost.canonicalBytes,
                  actualCommand == expectedHost.command.canonicalBytes else { throw PairingColdDisableError.changedConfiguration }
            let configuration = try PairingColdDisableConfiguration(source: expectedHost)
            pending = try .init(configuration)
            target = configuration.target
            _ = try AdministrativeSetupPublication.publish(pending.encoded, file: .pairingColdDisableIntent,
                directory: directory, owner: owner, verify: verifyStopped)
            try didPublish(.intent)
        }

        if pending.completed {
            try requireTargets(pending, directory: directory, owner: owner, verify: verifyStopped)
            try retainTarget(target)
            return pending
        }
        func verifyPending() throws {
            try verifyStopped()
            guard try readIntent(directory: directory, owner: owner) == pending else { throw PairingColdDisableError.changedConfiguration }
        }
        try AdministrativeSetupPublication.replacePairingColdDisable(target.command.canonicalBytes,
            expected: actualCommand, file: .commandConfiguration, directory: directory, owner: owner, verify: verifyPending)
        try didPublish(.runtime)
        try AdministrativeSetupPublication.replacePairingColdDisable(target.canonicalBytes,
            expected: actualHost.canonicalBytes, file: .commandHost, directory: directory, owner: owner, verify: verifyPending)
        try didPublish(.host)
        try requireTargets(pending, directory: directory, owner: owner, verify: verifyPending)
        try retainTarget(target)
        try didPublish(.activation)
        try requireTargets(pending, directory: directory, owner: owner, verify: verifyPending)
        let complete = try pending.completion()
        // The writer revalidates after exchanging the marker, so accept only these two states during its CAS.
        func verifyCompletion() throws {
            try verifyStopped()
            let actual = try readIntent(directory: directory, owner: owner)
            guard actual == pending || actual == complete else { throw PairingColdDisableError.changedConfiguration }
        }
        try AdministrativeSetupPublication.replacePairingColdDisable(complete.encoded, expected: pending.encoded,
            file: .pairingColdDisableIntent, directory: directory, owner: owner, verify: verifyCompletion)
        guard try readIntent(directory: directory, owner: owner) == complete else { throw PairingColdDisableError.changedConfiguration }
        try didPublish(.complete)
        return complete
    }

    static func requireConfiguration(_ host: InstalledAuthorityCommandConfiguration, directory: ProtectedSetupDirectory,
        owner: uid_t, verify: () throws -> Void) throws {
        try AdministrativeSetupPublication.validateRetained(host.canonicalBytes, file: .commandHost,
            directory: directory, owner: owner, verify: verify)
        try AdministrativeSetupPublication.validateRetained(host.command.canonicalBytes, file: .commandConfiguration,
            directory: directory, owner: owner, verify: verify)
    }

    static func canRestoreOriginal(_ source: RuntimeActivationPlan, directory: ProtectedSetupDirectory, owner: uid_t,
        loadActivation: () throws -> RuntimeActivationState, verify: () throws -> Void) throws -> Bool {
        try verify()
        guard try readIntent(directory: directory, owner: owner) == nil else { return false }
        try requireConfiguration(source.host, directory: directory, owner: owner, verify: verify)
        let current = try loadActivation()
        guard current.jobsRegistered, let retained = current.plan, try retained.encoded == source.encoded else {
            throw PairingColdDisableError.changedConfiguration
        }
        try verify()
        return try readIntent(directory: directory, owner: owner) == nil
    }

    static func retire(_ record: PairingColdDisableIntent, retainedHost: InstalledAuthorityCommandConfiguration,
        directory: ProtectedSetupDirectory, owner: uid_t, verify: () throws -> Void, didRemove: () throws -> Void = {}) throws {
        try record.requireAccountScope(retainedHost)
        try GatewaySettingsFenceRemoval.removeCompletedPairingDisable(record, directory: directory, owner: owner, verifyCurrent: {
            try requireConfiguration(retainedHost, directory: directory, owner: owner, verify: verify)
        }, didRemove: didRemove)
    }

    static func requireTargets(_ record: PairingColdDisableIntent, directory: ProtectedSetupDirectory,
        owner: uid_t, verify: () throws -> Void) throws {
        let host = try InstalledAuthorityCommandConfiguration.decode(read(.commandHost, directory: directory, owner: owner))
        try record.requireTarget(host)
        try requireConfiguration(host, directory: directory, owner: owner, verify: verify)
    }

    static func readIntent(directory: ProtectedSetupDirectory, owner: uid_t) throws -> PairingColdDisableIntent? {
        try directory.validate()
        let bytes = try ProtectedServiceConfiguration.readOptionalPrivate(anchor: directory.path,
            relativePath: PairingColdDisableIntent.fileName, owner: owner)
        try directory.validate()
        return try bytes.map(PairingColdDisableIntent.decode)
    }

    private static func read(_ file: AdministrativeSetupPublication.File, directory: ProtectedSetupDirectory, owner: uid_t) throws -> Data {
        try directory.validate()
        let bytes = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name, owner: owner)
        try directory.validate()
        return bytes
    }
}
