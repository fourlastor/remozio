import Foundation

/// Retain host placement until admitted setup work settles and the owner closes its machine scope.
/// The owner serializes placement checks. This lock serializes the final close after those checks have stopped.
final class AdministrativeSetupShutdown: @unchecked Sendable {
    private let lock = NSLock()
    private let owner: SetupAccountOwner
    private let placement: ReleaseDestinationLease
    private var closed = false
    init(owner: SetupAccountOwner, placement: ReleaseDestinationLease) { self.owner = owner; self.placement = placement }
    func close() async throws {
        try await owner.closeWhenIdle()
        lock.withLock { if !closed { placement.close(); closed = true } }
    }
}
