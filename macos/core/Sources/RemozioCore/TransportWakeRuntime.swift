import Foundation

public enum TransportWakeRuntimeError: Error, Equatable { case invalidConfiguration, closed, busy }

/// Owns the optional hint and gateway connections. Ordinary phone transport has its own connection and lifetime.
/// Only the provisioned signer can turn an opaque Root grant into a challenged wake submission.
public actor TransportWakeRuntime {
    private enum State { case new, opening, open, closed }
    private let hints: AuthorityWakeHintChannel
    private let gateway: GatewayWakeChannel
    private let signer: GatewayWakeSigner
    private let verifyCurrent: @Sendable () throws -> Void
    private var state = State.new
    private var polling = false
    private var loopRunning = false
    private var accepted: Set<UUID> = []
    public init(hints: AuthorityWakeHintChannel, gateway: GatewayWakeChannel, signer: GatewayWakeSigner) throws {
        try self.init(hints: hints, gateway: gateway, signer: signer, verifyCurrent: {})
    }
    init(hints: AuthorityWakeHintChannel, gateway: GatewayWakeChannel, signer: GatewayWakeSigner,
         verifyCurrent: @escaping @Sendable () throws -> Void) throws {
        guard hints.binding == signer.binding else { throw TransportWakeRuntimeError.invalidConfiguration }
        self.hints = hints; self.gateway = gateway; self.signer = signer; self.verifyCurrent = verifyCurrent
    }
    public func start() async throws {
        try verifyCurrent(); try Task.checkCancellation()
        guard state == .new else { throw TransportWakeRuntimeError.closed }
        state = .opening
        do {
            try await hints.start()
            try verifyCurrent(); try Task.checkCancellation()
            guard state == .opening else { throw TransportWakeRuntimeError.closed }
            try await gateway.start()
            try verifyCurrent(); try Task.checkCancellation()
            guard state == .opening else { throw TransportWakeRuntimeError.closed }
            state = .open
        } catch { await close(); throw error }
    }
    /// Retry rejection with a fresh challenge. Acceptance transfers provider retry ownership to the gateway.
    public func poll() async throws {
        try requireOpen()
        guard !polling else { throw TransportWakeRuntimeError.busy }
        polling = true
        defer { polling = false }
        do {
            let current = try await hints.current()
            try requireOpen()
            accepted.formIntersection(current.deliveryIDs)
            for delivery in current.deliveryIDs where !accepted.contains(delivery) {
                try requireOpen()
                do { try await gateway.wake(deliveryID: delivery, signer: signer) }
                catch GatewayWakeChannelError.rejected { continue }
                try requireOpen()
                accepted.insert(delivery)
            }
        } catch { await close(); throw error }
    }
    /// The service retains this task and cancels it before releasing its configuration or signer.
    public func run(intervalMilliseconds: UInt64) async throws {
        guard (100...60_000).contains(intervalMilliseconds), !loopRunning else { throw TransportWakeRuntimeError.invalidConfiguration }
        loopRunning = true
        defer { loopRunning = false }
        do {
            try await start()
            while true {
                try Task.checkCancellation()
                try await poll()
                try await Task.sleep(for: .milliseconds(intervalMilliseconds))
            }
        } catch { await close(); throw error }
    }
    public func close() async {
        guard state != .closed else { return }
        state = .closed; accepted.removeAll()
        await hints.close(); await gateway.close()
    }
    private func requireOpen() throws {
        try verifyCurrent(); try Task.checkCancellation()
        guard state == .open else { throw TransportWakeRuntimeError.closed }
    }
}
