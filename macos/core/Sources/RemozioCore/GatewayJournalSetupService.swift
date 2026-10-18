import Darwin
import Foundation
import Synchronization

/// The capacity is always one, so successful acquisition after admission closes proves that prior work has drained.
final class GatewayJournalSetupWork: Sendable {
    let budget: AuthorityXPCWorkBudget
    init() throws { budget = try .init(maximum: 1) }
    func waitForIdle(timeoutMilliseconds: UInt64) async throws {
        guard (1...120000).contains(timeoutMilliseconds) else { throw GatewayPreparationError.invalidRecord }
        let (deadline, overflow) = DispatchTime.now().uptimeNanoseconds.addingReportingOverflow(timeoutMilliseconds * 1000000)
        guard !overflow else { throw GatewayPreparationError.invalidRecord }
        while true {
            try Task.checkCancellation()
            if budget.acquire() { budget.release(); return }
            guard DispatchTime.now().uptimeNanoseconds < deadline else { throw GatewayServiceError.unavailable }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
}

private final class GatewayJournalSetupRetirement: Sendable { let value = Mutex(false) }
private final class GatewayJournalSetupOwnedConnection: OwnedAuthorityConnection, @unchecked Sendable {
    let connection: NSXPCConnection
    let endpoint: GatewayJournalSetupXPCEndpoint
    init(_ connection: NSXPCConnection, _ endpoint: GatewayJournalSetupXPCEndpoint) { self.connection = connection; self.endpoint = endpoint }
    func activate() { connection.activate() }
    func close() { endpoint.close(); connection.invalidate() }
    deinit { connection.invalidate() }
}

private final class GatewayJournalSetupXPCListener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let listener: NSXPCListener
    private let configuration: GatewayJournalSetupServiceConfiguration
    private let registry: AuthorityConnectionRegistry
    private let work: GatewayJournalSetupWork
    private let retired: GatewayJournalSetupRetirement
    private var running = false
    private var closed = false
    init(configuration: GatewayJournalSetupServiceConfiguration, work: GatewayJournalSetupWork, retired: GatewayJournalSetupRetirement) throws {
        self.configuration = configuration; self.work = work; self.retired = retired
        registry = try .init(maximum: 1, timeoutMilliseconds: configuration.intent.configuration.settings.handshakeTimeoutMillis)
        listener = NSXPCListener(machServiceName: try configuration.serviceName)
        super.init()
        let code = configuration.setupCode
        let policy = try XPCPeerPolicy(teamID: code.teamID, componentIdentifier: code.identifier,
            approvedCodeDirectoryHashes: [code.codeDirectoryHash], expectedUserID: 0)
        policy.configure(listener); listener.delegate = self
    }
    func start() throws {
        try lock.withLock {
            try configuration.requireNativeProcess()
            guard !closed, !running else { throw GatewayServiceError.unavailable }
            try registry.start(); running = true; listener.activate()
        }
    }
    func close() {
        lock.withLock { closed = true; running = false; listener.invalidate(); listener.delegate = nil }
        registry.close()
    }
    deinit { listener.invalidate(); registry.close() }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        lock.withLock {
            guard listener === self.listener, running, !closed, let id = registry.reserve() else { connection.invalidate(); return false }
            do {
                try configuration.requireNativeProcess()
                let endpoint = try GatewayJournalSetupXPCEndpoint(connection: connection, setupCode: configuration.setupCode,
                    intent: configuration.intent, budget: work.budget, onHandshake: { [registry] in registry.handshake(id) },
                    onClose: { [weak self, registry, retired] in
                        retired.value.withLock { $0 = true }; self?.close(); registry.remove(id)
                    })
                return registry.install(GatewayJournalSetupOwnedConnection(connection, endpoint), id: id)
            } catch { registry.remove(id); connection.invalidate(); return false }
        }
    }
}

/// Owns only the temporary authenticated setup listener. Opening and starting it never initialize SQLite.
/// The executable owner must await close before reporting drained work. A timeout or cancellation is not a drain proof.
public final class GatewayJournalSetupService: @unchecked Sendable {
    private let lock = NSLock()
    private let configuration: GatewayJournalSetupServiceConfiguration
    private let listener: GatewayJournalSetupXPCListener
    private let work: GatewayJournalSetupWork
    private let retired: GatewayJournalSetupRetirement
    private var timeoutTask: Task<Void, Never>?
    private var started = false
    private var closed = false
    private init(configuration: GatewayJournalSetupServiceConfiguration) throws {
        self.configuration = configuration
        let work = try GatewayJournalSetupWork(), retired = GatewayJournalSetupRetirement()
        self.work = work; self.retired = retired
        listener = try .init(configuration: configuration, work: work, retired: retired)
    }
    public static func open(path: String) throws -> GatewayJournalSetupService {
        try .init(configuration: GatewayJournalSetupServiceConfiguration.load(path: path))
    }
    public var isRetired: Bool { retired.value.withLock { $0 } }
    public func start() throws {
        try lock.withLock {
            guard !started, !closed else { throw GatewayServiceError.unavailable }
            try listener.start(); started = true
            let lifetime = configuration.maximumLifetimeMilliseconds
            timeoutTask = Task { [weak self] in
                do { try await Task.sleep(for: .milliseconds(lifetime)) } catch { return }
                self?.retire()
            }
        }
    }
    private func retire() {
        let timer = lock.withLock { () -> Task<Void, Never>? in
            closed = true; let previous = timeoutTask; timeoutTask = nil; return previous
        }
        timer?.cancel(); retired.value.withLock { $0 = true }; listener.close()
    }
    public func close() async throws {
        retire()
        let timeout = max(UInt64(configuration.intent.configuration.settings.databaseBusyMillis) + 1000, 5000)
        try await work.waitForIdle(timeoutMilliseconds: timeout)
    }
    deinit { timeoutTask?.cancel(); retired.value.withLock { $0 = true }; listener.close() }
}
