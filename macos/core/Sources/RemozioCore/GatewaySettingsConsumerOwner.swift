import CryptoKit
import Darwin
import Foundation
import Synchronization

/// An exact selected role file. Construction does not authenticate its protected storage.
struct GatewaySettingsConsumerSelection: Sendable {
    let binding: GatewaySettingsConsumerBinding
    let fenceDigest: Data
    let fence: GatewayRuntimeSettingsFence
    let configuration: Data
    let commit: GatewayRuntimeCommit

    private init(binding: GatewaySettingsConsumerBinding, fence: GatewayRuntimeSettingsFence,
                 configuration: Data, commit: GatewayRuntimeCommit) throws {
        guard binding.macID == fence.macID, binding.accountID == fence.accountID,
              try commit.encoded == fence.selected.encoded else { throw GatewayPreparationError.changedScope }
        self.fence = fence
        self.binding = binding; self.fenceDigest = Data(SHA256.hash(data: try fence.encoded))
        self.configuration = configuration; self.commit = commit
    }
    static func gateway(binding: GatewaySettingsConsumerBinding, fence: GatewayRuntimeSettingsFence,
                        configuration: GatewayServiceConfiguration, commit: GatewayRuntimeCommit) throws -> Self {
        guard binding.role == .gateway else { throw GatewayPreparationError.changedScope }
        try fence.validate(gateway: configuration, commit: commit)
        return try .init(binding: binding, fence: fence, configuration: configuration.canonicalBytes, commit: commit)
    }
    static func transport(binding: GatewaySettingsConsumerBinding, fence: GatewayRuntimeSettingsFence,
                          configuration: GatewayRuntimeExtension, commit: GatewayRuntimeCommit) throws -> Self {
        guard binding.role == .transport, configuration.target == .transport else { throw GatewayPreparationError.changedScope }
        try fence.validate(services: configuration.material.runtime.services); try commit.validate(configuration)
        return try .init(binding: binding, fence: fence, configuration: configuration.encoded, commit: commit)
    }
    /// Exact committed files can outlive the temporary fence. A different fence always stops this selection.
    func verifyPublished(readFence: () throws -> GatewayRuntimeSettingsFence?,
                         readSelected: () throws -> (configuration: Data, commit: GatewayRuntimeCommit),
                         verifyCurrent: () throws -> Void) throws {
        try verifyCurrent()
        let before = try readFence()?.encoded
        if let before, before != (try fence.encoded) { throw GatewayPreparationError.changedScope }
        func selected() throws {
            let value = try readSelected()
            guard value.configuration == configuration, try value.commit.encoded == commit.encoded else {
                throw GatewayPreparationError.changedScope
            }
        }
        try selected(); try verifyCurrent()
        guard try readFence()?.encoded == before else { throw GatewayPreparationError.changedScope }
        try selected(); try verifyCurrent()
        guard try readFence()?.encoded == before else { throw GatewayPreparationError.changedScope }
    }
    func validate(binding: GatewaySettingsConsumerBinding, fence: GatewayRuntimeSettingsFence) throws {
        guard self.binding == binding, fenceDigest == Data(SHA256.hash(data: try fence.encoded)),
              try commit.encoded == fence.selected.encoded else { throw GatewayPreparationError.changedScope }
    }
}

/// Only the owner can create this process-local permit. No message or persisted receipt can restore it.
final class GatewaySettingsConsumerPermit: Sendable {
    private let active = Mutex(true)
    private let processID: pid_t
    private let binding: GatewaySettingsConsumerBinding
    private let fenceDigest: Data
    private let configurationDigest: Data
    private let commitBytes: Data
    private let verifyScope: @Sendable () throws -> Void

    fileprivate init(selection: GatewaySettingsConsumerSelection, verifyScope: @escaping @Sendable () throws -> Void) throws {
        processID = getpid(); binding = selection.binding; fenceDigest = selection.fenceDigest
        configurationDigest = Data(SHA256.hash(data: selection.configuration)); commitBytes = try selection.commit.encoded
        self.verifyScope = verifyScope
    }
    fileprivate func revoke() { active.withLock { $0 = false } }
    func requireValid(binding: GatewaySettingsConsumerBinding, fence: GatewayRuntimeSettingsFence,
                      configuration: Data, commit: GatewayRuntimeCommit) throws {
        try verifyScope()
        guard getpid() == processID, self.binding == binding,
              fenceDigest == Data(SHA256.hash(data: try fence.encoded)),
              configurationDigest == Data(SHA256.hash(data: configuration)),
              try commit.encoded == commitBytes, commitBytes == (try fence.selected.encoded),
              active.withLock({ $0 }) else { throw GatewayPreparationError.changedScope }
        try verifyScope()
        guard active.withLock({ $0 }) else { throw GatewayPreparationError.changedScope }
    }
}


/// Construction opens no backend. A failed close remains retryable and must retain all unsettled work.
protocol OwnedGatewaySettingsConsumerRuntime: AnyObject, Sendable {
    /// Stops admission immediately. Existing work still needs closeAndWait.
    func retire()
    func start() async throws
    func closeAndWait() async throws
}

/// Owns paused control independently from the optional backend. Native peer admission belongs to the endpoint.
actor GatewaySettingsConsumerOwner {
    struct InitialRuntime: Sendable {
        let runtime: any OwnedGatewaySettingsConsumerRuntime
        let verifyCurrent: @Sendable () throws -> Void
    }
    struct Operations: Sendable {
        let verifyScope: @Sendable () throws -> Void
        let readFence: @Sendable () throws -> GatewayRuntimeSettingsFence
        let loadSelected: @Sendable (GatewaySettingsConsumerBinding, GatewayRuntimeSettingsFence) throws -> GatewaySettingsConsumerSelection
        let makeRuntime: @Sendable (GatewaySettingsConsumerSelection, GatewaySettingsConsumerPermit) throws -> any OwnedGatewaySettingsConsumerRuntime
        let verifyAccepted: (@Sendable (GatewaySettingsConsumerSelection) throws -> Void)?
        let makeInitialRuntime: (@Sendable (GatewaySettingsConsumerBinding) throws -> InitialRuntime?)?
        init(verifyScope: @escaping @Sendable () throws -> Void,
             readFence: @escaping @Sendable () throws -> GatewayRuntimeSettingsFence,
             loadSelected: @escaping @Sendable (GatewaySettingsConsumerBinding, GatewayRuntimeSettingsFence) throws -> GatewaySettingsConsumerSelection,
             makeRuntime: @escaping @Sendable (GatewaySettingsConsumerSelection, GatewaySettingsConsumerPermit) throws -> any OwnedGatewaySettingsConsumerRuntime,
             verifyAccepted: (@Sendable (GatewaySettingsConsumerSelection) throws -> Void)? = nil,
             makeInitialRuntime: (@Sendable (GatewaySettingsConsumerBinding) throws -> InitialRuntime?)? = nil) {
            self.verifyScope = verifyScope; self.readFence = readFence; self.loadSelected = loadSelected
            self.makeRuntime = makeRuntime; self.verifyAccepted = verifyAccepted; self.makeInitialRuntime = makeInitialRuntime
        }
    }
    nonisolated let binding: GatewaySettingsConsumerBinding
    private let operations: Operations
    private var runtime: (any OwnedGatewaySettingsConsumerRuntime)?
    private var starting: Task<Void, Error>?
    private var drain: (id: UUID, task: Task<Void, Error>)?
    private var quiescedFence: Data?
    private var accepted: (selection: GatewaySettingsConsumerSelection, permit: GatewaySettingsConsumerPermit)?
    private var cleanupRequired = false
    private var runtimeStarted = false
    private var initialAllowed = true
    private var closed = false

    init(role: GatewaySettingsConsumerRole, macID: Data, accountID: Data, operations: Operations,
         initialRuntime: (any OwnedGatewaySettingsConsumerRuntime)? = nil) throws {
        binding = try .init(role: role, macID: macID, accountID: accountID)
        self.operations = operations; runtime = initialRuntime
    }
    deinit {
        accepted?.permit.revoke()
        let pending = drain?.task, starting = starting, runtime = runtime
        runtime?.retire()
        Task {
            if let pending { if (try? await pending.value) != nil { return } }
            else { _ = try? await starting?.value }
            guard let runtime else { return }
            // A failed close must not abandon an owned backend when its controller disappears.
            while true {
                do { try await runtime.closeAndWait(); return }
                catch { try? await Task.sleep(for: .milliseconds(100)) }
            }
        }
    }
    private func validate(_ request: GatewaySettingsConsumerRequest) throws -> GatewayRuntimeSettingsFence {
        guard !closed else { throw GatewayPreparationError.changedScope }
        try operations.verifyScope()
        let fence = try operations.readFence(); try request.validate(binding: binding, fence: fence)
        try operations.verifyScope(); return fence
    }
    private func current(_ fence: GatewayRuntimeSettingsFence) throws {
        guard !closed else { throw GatewayPreparationError.changedScope }
        try operations.verifyScope()
        guard try operations.readFence().encoded == fence.encoded else { throw GatewayPreparationError.changedScope }
        try operations.verifyScope()
    }
    private func observation(for fence: GatewayRuntimeSettingsFence) throws -> GatewaySettingsConsumerObservation {
        if cleanupRequired || drain != nil { return .quiescing }
        if let accepted, accepted.selection.fenceDigest == Data(SHA256.hash(data: try fence.encoded)) {
            return runtimeStarted ? .runtimeStarted : .accepted
        }
        return quiescedFence == Data(SHA256.hash(data: try fence.encoded)) ? .paused : .unknown
    }
    /// The endpoint supplies a fresh caller check for every action. Cleanup does not depend on client cancellation.
    func performAuthenticated(_ request: GatewaySettingsConsumerRequest,
                              verifyCaller: @Sendable () throws -> Void) async throws -> GatewaySettingsConsumerResponse {
        try verifyCaller(); let fence = try validate(request)
        switch request.action {
        case .observe:
            try verifyCaller()
            return try .init(request: request, observation: observation(for: fence))
        case .quiesce:
            initialAllowed = false
            accepted?.permit.revoke(); accepted = nil; runtimeStarted = false; quiescedFence = nil
            try await settle()
            try current(fence)
            guard accepted == nil, runtime == nil, starting == nil, drain == nil else { throw GatewayPreparationError.changedScope }
            quiescedFence = Data(SHA256.hash(data: try fence.encoded))
            try verifyCaller()
            return try .init(request: request, observation: .paused)
        case .accept:
            guard !cleanupRequired, drain == nil, quiescedFence == Data(SHA256.hash(data: try fence.encoded)) else {
                throw GatewayPreparationError.incomplete
            }
            let selection = try operations.loadSelected(binding, fence)
            try selection.validate(binding: binding, fence: fence); try current(fence); try verifyCaller()
            if let accepted {
                guard accepted.selection.configuration == selection.configuration else { throw GatewayPreparationError.changedScope }
                try accepted.permit.requireValid(binding: binding, fence: fence, configuration: selection.configuration, commit: selection.commit)
            } else {
                guard runtime == nil, starting == nil else { throw GatewayPreparationError.incomplete }
                let operations = operations, bytes = try fence.encoded
                let permit = try GatewaySettingsConsumerPermit(selection: selection, verifyScope: {
                    try operations.verifyScope()
                    if let verify = operations.verifyAccepted { try verify(selection) }
                    else if try operations.readFence().encoded != bytes { throw GatewayPreparationError.changedScope }
                    try operations.verifyScope()
                })
                accepted = (selection, permit)
            }
            return try .init(request: request, observation: observation(for: fence))
        }
    }
    /// Initial startup is separate from settings acceptance and cannot return after authenticated quiescence.
    func startConfiguredRuntimeIfNeeded() async throws -> Bool {
        guard !closed else { throw GatewayPreparationError.changedScope }
        if cleanupRequired { try await settle() }
        guard !closed else { throw GatewayPreparationError.changedScope }
        if accepted != nil { return try await startAcceptedRuntimeIfNeeded() }
        guard initialAllowed, !cleanupRequired, drain == nil, starting == nil, runtime == nil,
              let makeInitialRuntime = operations.makeInitialRuntime else { return false }
        try operations.verifyScope()
        guard let initial = try makeInitialRuntime(binding) else { return false }
        let instance = initial.runtime, verify = initial.verifyCurrent, operations = operations
        runtime = instance
        let start = Task { try operations.verifyScope(); try verify(); try await instance.start() }
        starting = start
        do {
            try await start.value
            guard !closed, initialAllowed, accepted == nil, drain == nil, runtime === instance else {
                throw GatewayPreparationError.changedScope
            }
            try operations.verifyScope(); try verify()
            starting = nil; runtimeStarted = true; return true
        } catch {
            let failure = error
            if runtime === instance { try await settle() }
            throw failure
        }
    }
    /// The minimal native host can poll without rebuilding or replacing an active backend.
    func startAcceptedRuntimeIfNeeded() async throws -> Bool {
        guard !closed else { throw GatewayPreparationError.changedScope }
        guard accepted != nil else { return false }
        if cleanupRequired { try await settle() }
        guard !closed else { throw GatewayPreparationError.changedScope }
        guard accepted != nil, !cleanupRequired, drain == nil, starting == nil, runtime == nil else { return false }
        try await startAcceptedRuntime(); return true
    }
    /// Starts only the accepted selection. The backend is retained before its asynchronous start can suspend.
    func startAcceptedRuntime() async throws {
        guard !closed, !cleanupRequired, drain == nil, starting == nil, runtime == nil, let accepted else { throw GatewayPreparationError.incomplete }
        let fence = accepted.selection.fence
        try operations.verifyScope()
        let selected = try operations.loadSelected(binding, fence)
        try selected.validate(binding: binding, fence: fence)
        try accepted.permit.requireValid(binding: binding, fence: fence, configuration: selected.configuration, commit: selected.commit)
        let instance = try operations.makeRuntime(selected, accepted.permit)
        runtime = instance
        let start = Task { try await instance.start() }; starting = start
        do {
            try await start.value
            guard !closed, drain == nil, self.accepted?.permit === accepted.permit, runtime === instance else {
                throw GatewayPreparationError.changedScope
            }
            try operations.verifyScope()
            try accepted.permit.requireValid(binding: binding, fence: fence, configuration: selected.configuration, commit: selected.commit)
            starting = nil; runtimeStarted = true
        } catch {
            let failure = error
            if runtime === instance { try await settle() }
            if self.accepted?.permit === accepted.permit {
                do { try accepted.permit.requireValid(binding: binding, fence: fence,
                    configuration: selected.configuration, commit: selected.commit) }
                catch { accepted.permit.revoke(); self.accepted = nil; quiescedFence = nil }
            }
            throw failure
        }
    }
    /// Every waiter joins one owned drain. A close error retains the runtime and prevents a paused receipt.
    private func settle() async throws {
        let pending: (id: UUID, task: Task<Void, Error>)
        if let drain { pending = drain }
        else {
            let runtime = runtime, starting = starting
            runtime?.retire()
            cleanupRequired = true
            pending = (UUID(), Task { _ = try? await starting?.value; try await runtime?.closeAndWait() })
            drain = pending
        }
        do {
            try await pending.task.value
            if drain?.id == pending.id {
                runtime = nil; starting = nil; runtimeStarted = false; cleanupRequired = false; drain = nil
            }
        } catch {
            if drain?.id == pending.id { drain = nil }
            throw error
        }
    }
    /// Stops admission before the enclosing host waits for disconnected control work.
    func retire() {
        closed = true; initialAllowed = false; accepted?.permit.revoke(); accepted = nil; quiescedFence = nil; runtimeStarted = false
        runtime?.retire()
    }
    func close() async throws {
        retire()
        try await settle()
    }
}
