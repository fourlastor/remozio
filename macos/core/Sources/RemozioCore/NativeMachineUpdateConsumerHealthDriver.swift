import Foundation

@objc protocol MachineUpdateConsumerHealthXPCProtocol {
    func healthHello(reply: @escaping @Sendable (UInt64, Data?) -> Void)
    func checkUpdateHealth(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void)
}

/// Pins the consumer before activation and binds every reply to the same kernel peer credentials.
final class NativeMachineUpdateConsumerHealthDriver: MachineUpdateConsumerHealthDriver, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let connection: NSXPCConnection
    private let inspectPeer: () throws -> XPCPeerCredentials
    private var peer: XPCPeerCredentials?
    private var closed = false
    convenience init(serviceName: String, policy: XPCPeerPolicy) {
        let connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
        policy.configure(connection)
        self.init(connection: connection, inspectPeer: { try policy.verifyCredentials(connection) })
    }
    /// Anonymous test connections cannot prove native code or service account admission.
    init(connection: NSXPCConnection, inspectPeer: @escaping () throws -> XPCPeerCredentials) {
        self.connection = connection; self.inspectPeer = inspectPeer
        connection.remoteObjectInterface = NSXPCInterface(with: MachineUpdateConsumerHealthXPCProtocol.self)
    }
    func start(closed onClose: @escaping @Sendable () -> Void) {
        lock.withLock {
            guard !closed else { onClose(); return }
            connection.interruptionHandler = onClose; connection.invalidationHandler = onClose
            connection.activate()
        }
    }
    func invoke(_ call: MachineUpdateConsumerHealthCall, reply: @escaping @Sendable (MachineUpdateConsumerHealthReply) -> Void) {
        lock.withLock {
            guard !closed,
                  let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any MachineUpdateConsumerHealthXPCProtocol else {
                reply(.failed); return
            }
            switch call {
            case .hello: proxy.healthHello { [weak self] version, bytes in
                self?.checked(.greeting(version, bytes), reply: reply) ?? reply(.failed)
            }
            case .check(let bytes): proxy.checkUpdateHealth(bytes) { [weak self] bytes in
                self?.checked(.response(bytes), reply: reply) ?? reply(.failed)
            }
            }
        }
    }
    private func checked(_ value: MachineUpdateConsumerHealthReply, reply: @Sendable (MachineUpdateConsumerHealthReply) -> Void) {
        do {
            try lock.withLock {
                guard !closed else { throw MachineUpdateConsumerHealthChannelError.closed }
                let current = try inspectPeer()
                if let peer { guard peer == current else { throw XPCPeerPolicyError.wrongPeer } }
                else { peer = current }
            }
            reply(value)
        } catch { reply(.failed) }
    }
    func requirePeer() throws {
        try lock.withLock {
            guard !closed, let peer, try inspectPeer() == peer else { throw XPCPeerPolicyError.wrongPeer }
        }
    }
    func close() {
        lock.withLock { guard !closed else { return }; closed = true; connection.invalidate() }
    }
    deinit { close() }
}
