import Foundation

/// Owns one completed reply packet. Closing it leaves the ordinary runtime and its retained credentials in place.
final class MachineUpdateInstalledReadinessReply: MachineUpdateConsumerHealthAnswering, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let request: MachineUpdateConsumerHealthRequest
    private var packet: Data?
    init(request: MachineUpdateConsumerHealthRequest, packet: Data) throws {
        try request.validate(); _ = try MachineUpdateConsumerHealthPacket.decode(packet)
        self.request = request; self.packet = packet
    }
    func answer(_ bytes: Data) throws -> Data {
        try lock.withLock {
            guard let packet else { throw MachineUpdateRoleChallengeError.unavailable }
            self.packet = nil
            try request.validate()
            guard bytes == request.bytes else { throw MachineUpdateRoleChallengeError.changedScope }
            return packet
        }
    }
    func close() { lock.withLock { packet = nil } }
}
