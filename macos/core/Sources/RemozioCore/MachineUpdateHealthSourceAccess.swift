import Foundation

/// Borrows an exact synchronous machine read. This object grants no writer, health receipt or floor authority.
final class MachineUpdateHealthSourceAccess: @unchecked Sendable {
    private let lock = NSLock()
    private var borrowed: PreparationIntentStore.HealthSnapshotScope?

    func withScope<Value>(_ scope: PreparationIntentStore.HealthSnapshotScope,
                          expected: MachineUpdateRestartSnapshot, _ body: () throws -> Value) throws -> Value {
        try scope.read().requireSame(as: expected)
        try lock.withLock {
            guard borrowed == nil else { throw MachineUpdateHealthCoordinatorError.busy }
            borrowed = scope
        }
        defer { lock.withLock { if borrowed === scope { borrowed = nil } } }
        let value = try body()
        try scope.read().requireSame(as: expected)
        return value
    }

    func requireCurrent(_ expected: MachineUpdateRestartSnapshot,
                        read: () throws -> MachineUpdateRestartSnapshot) throws {
        let scope = lock.withLock { borrowed }
        let actual = try scope.map { try $0.read() } ?? read()
        try actual.requireSame(as: expected)
    }
}
