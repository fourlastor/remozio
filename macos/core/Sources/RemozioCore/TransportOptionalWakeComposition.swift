import Foundation

extension TransportWakeRunner {
    /// Restore an optional companion from fixed protected metadata. Direct approvals retain their existing owner and identity.
    public init(pairingConfigurationPath: String, initialRetryMilliseconds: UInt64 = 1000,
                maximumRetryMilliseconds: UInt64 = 30_000, report: @escaping @Sendable (Status) -> Void) throws {
        let base = try TransportPairingStartupConfiguration.load(path: pairingConfigurationPath)
        let paths = try RuntimePreparationPaths(accountID: base.transport.accountID)
        guard base.wake == nil, pairingConfigurationPath == paths.transportConfiguration else {
            throw ApprovalTransportStartupError.invalidConfiguration
        }
        let requirement = base.control.transportPolicy.requirement
        let verify: @Sendable () throws -> Void = {
            guard try TransportPairingStartupConfiguration.load(path: pairingConfigurationPath).canonicalBytes == base.canonicalBytes else {
                throw GatewayPreparationError.changedScope
            }
            try DynamicCodeValidation.validateSelf(requirement: requirement)
        }
        try verify()
        try self.init(optionalConfiguration: {
            guard let loaded = try GatewayRuntimeLoader.load(transport: base, verifyCurrent: verify) else {
                throw GatewayWakeSignerError.unavailable
            }
            return loaded
        }, initialRetryMilliseconds: initialRetryMilliseconds, maximumRetryMilliseconds: maximumRetryMilliseconds,
            makeRuntime: { configuration in
                let runtime = try configuration.makeRuntime()
                return TransportWakeAttempt(start: { try await runtime.start() }, poll: { try await runtime.poll() }, close: { await runtime.close() })
            }, report: report)
    }

    // Owned fixtures inject channels, not acceptance. The native loader fixes code/UID policies and protected file paths.
    init(optionalConfiguration: @escaping @Sendable () throws -> GatewayRuntimeLoader.Loaded,
         initialRetryMilliseconds: UInt64 = 1000, maximumRetryMilliseconds: UInt64 = 30_000,
         makeRuntime: @escaping @Sendable (TransportWakeStartupConfiguration) throws -> TransportWakeAttempt,
         report: @escaping @Sendable (Status) -> Void) throws {
        try self.init(initialRetryMilliseconds: initialRetryMilliseconds, maximumRetryMilliseconds: maximumRetryMilliseconds,
            makeAttempt: {
                do {
                    try Task.checkCancellation()
                    let initial = try optionalConfiguration()
                    guard initial.configuration.target == .transport, let wake = initial.configuration.wake else {
                        throw GatewayPreparationError.invalidRecord
                    }
                    try initial.commit.validate(initial.configuration)
                    let expectedBytes = try initial.configuration.encoded
                    let validate: @Sendable () throws -> Void = {
                        try Task.checkCancellation()
                        let current = try optionalConfiguration()
                        guard current.commit.pairDigest == initial.commit.pairDigest,
                              try current.configuration.encoded == expectedBytes else { throw GatewayPreparationError.changedScope }
                        try current.commit.validate(current.configuration)
                    }
                    let runtime = try makeRuntime(wake)
                    return TransportWakeAttempt(start: {
                        do { try validate(); try await runtime.start(); try validate() }
                        catch is CancellationError { throw CancellationError() }
                        catch { throw GatewayWakeSignerError.unavailable }
                    }, poll: {
                        do { try validate(); try await runtime.poll(); try validate() }
                        catch is CancellationError { throw CancellationError() }
                        catch { throw GatewayWakeSignerError.unavailable }
                    }, close: { await runtime.close() }, intervalMilliseconds: wake.pollMilliseconds)
                } catch is CancellationError { throw CancellationError() }
                catch { throw GatewayWakeSignerError.unavailable }
            }, report: report)
    }
}
