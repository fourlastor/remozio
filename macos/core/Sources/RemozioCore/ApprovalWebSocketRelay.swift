import Foundation
import Network
import Synchronization

public enum ApprovalRelayError: Error { case invalidConfiguration, stopped, busy }

protocol OwnedApprovalRelay: Sendable {
    func start() throws
    func closeAndWait() async
}

private final class WebSocketByteConnection: ByteConnectionDriver, @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "dev.remozio.relay-channel")
    private let closed = Mutex(false)

    init(_ connection: NWConnection) { self.connection = connection }
    func start(_ event: @escaping @Sendable (ByteConnectionEvent) -> Void) {
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: event(.ready)
            case .failed: event(.failed)
            case .cancelled: event(.cancelled)
            default: break
            }
        }
        connection.start(queue: queue)
    }
    func receive(_ result: @escaping @Sendable (Data?, Bool, Bool) -> Void) {
        guard !closed.withLock({ $0 }) else { result(nil, false, true); return }
        connection.receiveMessage { [weak self] data, context, complete, error in
            guard let self, !self.closed.withLock({ $0 }), error == nil else {
                result(nil, false, true); return
            }
            let metadata = context?.protocolMetadata(definition: NWProtocolWebSocket.definition) as? NWProtocolWebSocket.Metadata
            switch metadata?.opcode {
            case .ping?, .pong?: self.receive(result)
            case .close?: result(nil, true, false)
            case .binary?:
                guard complete else { result(nil, false, true); return }
                if data?.isEmpty ?? true { self.receive(result) } else { result(data, false, false) }
            default: result(nil, false, true)
            }
        }
    }
    func send(_ data: Data, result: @escaping @Sendable (Bool) -> Void) {
        guard !closed.withLock({ $0 }) else { result(true); return }
        let context = NWConnection.ContentContext(identifier: "ciphertext",
            metadata: [NWProtocolWebSocket.Metadata(opcode: .binary)])
        connection.send(content: data, contentContext: context, isComplete: true,
            completion: .contentProcessed { result($0 != nil) })
    }
    func cancel() {
        let first = closed.withLock { value in let first = !value; value = true; return first }
        if first { connection.stateUpdateHandler = nil; connection.cancel() }
    }
}

/// Carries opaque TLS bytes from a loopback WebSocket to one fixed loopback approval listener.
/// The existing listener authenticates the phone. This carrier owns no TLS or approval keys.
public final class ApprovalWebSocketRelay: OwnedApprovalRelay, @unchecked Sendable {
    public static let subprotocol = "remozio.ciphertext.v1"
    private final class Slot: @unchecked Sendable {
        let websocket: NetworkByteChannel
        let tcp: NetworkByteChannel
        var task: Task<Void, Never>?
        init(_ websocket: NWConnection, targetPort: UInt16) {
            self.websocket = NetworkByteChannel(driver: WebSocketByteConnection(websocket))
            tcp = NetworkByteChannel(connection: NWConnection(host: .ipv4(.loopback),
                port: NWEndpoint.Port(rawValue: targetPort)!, using: .tcp), admission: { _ in true })
        }
        func abort() { websocket.abort(); tcp.abort(); task?.cancel() }
    }
    private let listener: NWListener
    private let queue = DispatchQueue(label: "dev.remozio.approval-relay")
    private let lock = NSLock()
    private let targetPort: UInt16
    private let maximumConnections: Int
    private let timeoutMilliseconds: UInt64
    private let event: @Sendable (DirectListenerEvent) -> Void
    private var slots: [UUID: Slot] = [:]
    private var started = false
    private var ready = false
    private var closed = false

    /// A zero listening port is for disposable experiments. Protected startup requires a fixed nonzero port.
    /// The destination is the current approval listener port, never a peer-supplied host or route.
    public init(listenPort: UInt16, targetPort: UInt16, maximumConnections: Int = 8,
                timeoutMilliseconds: UInt64 = 15_000,
                event: @escaping @Sendable (DirectListenerEvent) -> Void) throws {
        guard targetPort > 0, (1...64).contains(maximumConnections),
              (1...60_000).contains(timeoutMilliseconds), listenPort == 0 || listenPort != targetPort else {
            throw ApprovalRelayError.invalidConfiguration
        }
        self.targetPort = targetPort; self.maximumConnections = maximumConnections
        self.timeoutMilliseconds = timeoutMilliseconds; self.event = event
        let websocket = NWProtocolWebSocket.Options()
        websocket.skipHandshake = false
        websocket.maximumMessageSize = NetworkByteChannel.maximumChunkBytes
        websocket.autoReplyPing = true
        websocket.setClientRequestHandler(queue) { protocols, _ in
            let accepted = protocols.contains {
                $0.trimmingCharacters(in: CharacterSet(charactersIn: " \t")) == Self.subprotocol
            }
            return .init(status: accepted ? .accept : .reject, subprotocol: accepted ? Self.subprotocol : nil)
        }
        let parameters = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
        parameters.defaultProtocolStack.applicationProtocols.insert(websocket, at: 0)
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback),
            port: NWEndpoint.Port(rawValue: listenPort)!)
        listener = try NWListener(using: parameters)
        listener.stateUpdateHandler = { [weak self] state in self?.changed(state) }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { connection.cancel(); return }
            self.accept(connection)
        }
    }

    public func start() throws {
        try lock.withLock {
            guard !started, !closed else { throw ApprovalRelayError.stopped }
            started = true
            listener.start(queue: queue)
        }
        queue.asyncAfter(deadline: .now() + .milliseconds(Int(timeoutMilliseconds))) { [weak self] in
            guard let self else { return }
            if self.lock.withLock({ !self.ready && !self.closed }) { self.finish(.failed) }
        }
    }
    public func close() { finish(.stopped) }
    public func closeAndWait() async {
        close()
        let tasks = lock.withLock { slots.values.compactMap { $0.task } }
        for task in tasks { await task.value }
    }
    deinit { close() }

    private func changed(_ state: NWListener.State) {
        switch state {
        case .ready:
            guard let port = listener.port else { finish(.failed); return }
            let first = lock.withLock { () -> Bool in
                guard !ready, !closed else { return false }
                ready = true; return true
            }
            if first { event(.ready(port: port.rawValue)) }
        case .failed: finish(.failed)
        case .cancelled: finish(.stopped)
        default: break
        }
    }
    private func accept(_ connection: NWConnection) {
        let accepted = lock.withLock { () -> Bool in
            guard started, !closed, slots.count < maximumConnections else { return false }
            let id = UUID(), slot = Slot(connection, targetPort: targetPort)
            slots[id] = slot
            let timeout = timeoutMilliseconds
            slot.task = Task { [weak self] in
                await withTaskCancellationHandler {
                    do {
                        try await slot.websocket.start(timeoutMilliseconds: timeout)
                        try Task.checkCancellation()
                        let initial = try await Self.firstCiphertext(slot.websocket, timeoutMilliseconds: timeout)
                        try await slot.tcp.start(timeoutMilliseconds: timeout)
                        try await slot.tcp.send(initial)
                        try await Self.forward(slot.websocket, slot.tcp)
                    } catch { }
                    await slot.websocket.close(); await slot.tcp.close()
                    self?.release(id)
                } onCancel: { slot.websocket.abort(); slot.tcp.abort() }
            }
            return true
        }
        if !accepted { connection.cancel() }
    }
    private func release(_ id: UUID) { _ = lock.withLock { slots.removeValue(forKey: id) } }
    private func finish(_ result: DirectListenerEvent) {
        let owned = lock.withLock { () -> [Slot]? in
            guard !closed else { return nil }
            closed = true
            return Array(slots.values)
        }
        guard let owned else { return }
        listener.cancel()
        for slot in owned { slot.abort() }
        queue.async { [event] in event(result) }
    }

    private static func firstCiphertext(_ channel: NetworkByteChannel, timeoutMilliseconds: UInt64) async throws -> Data {
        try await withThrowingTaskGroup(of: Data?.self) { group in
            group.addTask { try await channel.receive() }
            group.addTask {
                try await Task.sleep(for: .milliseconds(Int64(timeoutMilliseconds)))
                channel.abort()
                throw NetworkChannelError.timedOut
            }
            defer { group.cancelAll() }
            guard let bytes = try await group.next() ?? nil else { throw NetworkChannelError.closed }
            return bytes
        }
    }

    /// Each direction waits for the preceding write. EOF, failure, and cancellation abort both directions.
    static func forward(_ first: NetworkByteChannel, _ second: NetworkByteChannel) async throws {
        try await withTaskCancellationHandler {
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask { while let bytes = try await first.receive() { try await second.send(bytes) } }
                group.addTask { while let bytes = try await second.receive() { try await first.send(bytes) } }
                do { _ = try await group.next() }
                catch {
                    first.abort(); second.abort(); group.cancelAll()
                    throw error
                }
                first.abort(); second.abort(); group.cancelAll()
                while !group.isEmpty { _ = try? await group.next() }
            }
        } onCancel: { first.abort(); second.abort() }
    }
}
