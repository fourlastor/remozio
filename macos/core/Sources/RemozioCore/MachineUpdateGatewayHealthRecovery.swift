import Foundation

/// Routes an authenticated hot-journal failure to the ordinary recovery owner under the original drain.
enum MachineUpdateGatewayHealthRecovery {
    static func check<Proof: Sendable>(health: @Sendable () async throws -> Proof,
        verifyRecovery: @Sendable () throws -> Void, recoverOrdinary: @Sendable () async throws -> Void) async throws -> Proof {
        do { return try await health() }
        catch MachineUpdateConsumerHealthChannelError.gatewayRecoveryRequired {
            try Task.checkCancellation(); try verifyRecovery()
            try await recoverOrdinary()
            try verifyRecovery(); try Task.checkCancellation()
            // Recovery is not health evidence. A new authenticated exchange is required.
            throw MachineUpdateConsumerHealthChannelError.gatewayRecoveryRequired
        }
    }
}
