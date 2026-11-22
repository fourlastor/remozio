import Foundation
import Observation

/// Own this controller at app scope so dismissing a view does not drop the recovery connection.
@MainActor @Observable
public final class MacSetupRecoveryControls {
    typealias Status = SetupRetainedStatusWire.Observation
    typealias Wire = SetupOrphanRecoveryWire
    struct Authorization {
        let prepare: @MainActor () async throws -> Void
        let readForm: @Sendable () throws -> Data
        let close: @Sendable () -> Void
    }

    public struct Selection: Equatable, Sendable, CustomReflectable {
        public var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
        fileprivate let observationID: UUID
        fileprivate let identity: SetupRetainedInvocationStatus.Identity
        let action: Wire.Action
    }

    enum ObservationState: Equatable { case unread, loading, unavailable, observed(Status) }
    enum Health: Equatable { case unconfirmed }
    enum SelectionInvalidation: Error, Equatable { case observationChanged, reservationChanged, incarnationChanged }
    enum AttemptState: Equatable {
        case idle, authorizing, submitting, pending, notSubmitted, unconfirmed, finished(Wire.Code)
    }

    public enum StatusSummary: Equatable, Sendable {
        case unread, reading, unavailable, noSavedWork, busy, applicabilityUnavailable, noAction, restoreAvailable
    }

    public enum AttemptSummary: Equatable, Sendable {
        case idle, authorizing, submitting, pending, notSubmitted, unconfirmed, restored, refused, repairRequired, failed
    }

    private(set) var status: ObservationState = .unread
    private(set) var attempt: AttemptState = .idle
    private(set) var selectionInvalidation: SelectionInvalidation?
    var health: Health { .unconfirmed }

    @ObservationIgnored private let read: @MainActor () async throws -> Status
    @ObservationIgnored private let eligible: @MainActor (Status) -> Wire.Action?
    @ObservationIgnored private let openRecovery: @MainActor () async throws -> MacSetupRecoveryChannel
    @ObservationIgnored private let makeAuthorization: @MainActor () throws -> Authorization
    @ObservationIgnored private var observationID = UUID()
    @ObservationIgnored private var attemptID: UUID?
    private var channel: MacSetupRecoveryChannel?
    @ObservationIgnored private var authorization: Authorization?
    private var authorizationCleanup: Task<Void, Never>?
    @ObservationIgnored private var acknowledgement = false
    private var operation: Task<Void, Never>?
    @ObservationIgnored private var closed = false

    public convenience init() {
        self.init(read: {
            let channel = try await MacAccountSetupConnection.openRecoveryClient(lane: .status)
            return try await channel.readStatus()
        }, openRecovery: {
            try await MacAccountSetupConnection.openRecoveryClient(lane: .recovery)
        }, makeAuthorization: {
            let session = try SetupAdministratorSession()
            return Authorization(prepare: {
                try await Task.detached { try session.authorize() }.value
            }, readForm: { try session.externalForm() }, close: { session.close() })
        })
    }

    init(read: @escaping @MainActor () async throws -> Status,
         eligible: (@MainActor (Status) -> Wire.Action?)? = nil,
         openRecovery: @escaping @MainActor () async throws -> MacSetupRecoveryChannel,
         makeAuthorization: @escaping @MainActor () throws -> Authorization) {
        self.read = read
        self.eligible = eligible ?? Self.restoreAction
        self.openRecovery = openRecovery
        self.makeAuthorization = makeAuthorization
    }

    private static func restoreAction(_ observation: Status) -> Wire.Action? {
        guard observation.applicability == .restore, observation.reservation == .orphan, observation.identity != nil,
              observation.window != nil, observation.worker == .idle, observation.cleanup == .joined else { return nil }
        return .restore
    }

    public var statusSummary: StatusSummary {
        switch status {
        case .unread: return .unread
        case .loading: return .reading
        case .unavailable: return .unavailable
        case .observed(let observation):
            switch observation.reservation {
            case .none: return .unavailable
            case .absent, .settled: return .noSavedWork
            case .recovering, .attached, .reserved: return .busy
            case .orphan:
                if observation.worker == .running || observation.worker == .registered || observation.cleanup == .joining {
                    return .busy
                }
                if observation.applicability == .noAction { return .noAction }
                return Self.restoreAction(observation) == .restore ? .restoreAvailable : .applicabilityUnavailable
            }
        }
    }

    public var attemptSummary: AttemptSummary {
        switch attempt {
        case .idle: .idle
        case .authorizing: .authorizing
        case .submitting: .submitting
        case .pending: .pending
        case .notSubmitted: .notSubmitted
        case .unconfirmed: .unconfirmed
        case .finished(.restored): .restored
        case .finished(.refusedUnavailable), .finished(.notApplicable): .refused
        case .finished(.repairRequired): .repairRequired
        case .finished: .failed
        }
    }

    public var canCheckProgress: Bool {
        channel != nil && operation == nil && (attempt == .pending || attempt == .unconfirmed)
    }

    public var canStopTracking: Bool {
        channel != nil && operation == nil && attempt == .unconfirmed
    }

    public var selection: Selection? {
        guard !closed, attemptID == nil, operation == nil, authorizationCleanup == nil else { return nil }
        return currentSelection
    }

    private var currentSelection: Selection? {
        guard case .observed(let observation) = status, let identity = observation.identity,
              let action = eligible(observation) else { return nil }
        return Selection(observationID: observationID, identity: identity, action: action)
    }

    public func refresh() async {
        guard !closed, attempt != .submitting else { return }
        let id = UUID()
        observationID = id
        status = .loading
        do {
            let value = try await read()
            guard !closed, observationID == id else { return }
            status = Task.isCancelled ? .unavailable : .observed(value)
        } catch {
            guard !closed, observationID == id else { return }
            status = .unavailable
        }
    }

    public func begin(_ selected: Selection) async {
        guard selection == selected else { return }
        let id = UUID()
        attemptID = id
        acknowledgement = false
        selectionInvalidation = nil
        attempt = .authorizing
        await runOperation { await self.submit(selected, id: id) }
    }

    private func submit(_ selected: Selection, id: UUID) async {
        do {
            let connection = try await openRecovery()
            guard !closed, attemptID == id else { await connection.close(); return }
            channel = connection
            try await connection.open(onClose: { [weak self] in
                Task { await self?.connectionClosed(attemptID: id) }
            })
            try checkSelection(selected, attemptID: id)
            let grant = try makeAuthorization()
            authorization = grant
            try await grant.prepare()
            try checkSelection(selected, attemptID: id)
            let request = try Wire.Request(requestID: AccountPreparationIntent.randomID(), action: selected.action,
                identity: selected.identity)
            attempt = .submitting
            let result = try await connection.start(request, readAuthorization: grant.readForm)
            guard !closed, attemptID == id else { return }
            if result == .requestRecorded {
                acknowledgement = true
                attempt = .pending
            } else {
                await finish(.finished(result))
            }
        } catch {
            guard !closed, attemptID == id else { return }
            let dispatched = await channel?.didDispatchStart == true
            guard !closed, attemptID == id else { return }
            if dispatched, await channel?.isOpen == true {
                guard !closed, attemptID == id else { return }
                attempt = .unconfirmed
                return
            }
            guard !closed, attemptID == id else { return }
            selectionInvalidation = error as? SelectionInvalidation
            await finish(dispatched ? .unconfirmed : .notSubmitted)
        }
    }

    private func connectionClosed(attemptID id: UUID) async {
        guard !closed, attemptID == id else { return }
        let dispatched = await channel?.didDispatchStart == true
        guard !closed, attemptID == id else { return }
        await finish(dispatched ? .unconfirmed : .notSubmitted)
    }

    public func readProgress() async {
        guard !closed, canCheckProgress, let id = attemptID, let channel else { return }
        await runOperation { await self.readProgress(on: channel, id: id) }
    }

    private func readProgress(on channel: MacSetupRecoveryChannel, id: UUID) async {
        do {
            let result = try await channel.readProgress()
            guard !closed, attemptID == id else { return }
            switch result {
            case .pending:
                acknowledgement = true
                attempt = .pending
            case .refusedUnavailable where !acknowledgement: attempt = .unconfirmed
            default: await finish(.finished(result))
            }
        } catch {
            let stillOpen = await channel.isOpen
            guard !closed, attemptID == id else { return }
            if stillOpen { attempt = .unconfirmed }
            else { await finish(.unconfirmed) }
        }
    }

    /// An explicit local reset only releases the connection. Require a fresh status read afterward.
    public func endTracking() async {
        guard !closed, canStopTracking else { return }
        await finish(.unconfirmed)
    }

    public func close() async {
        guard !closed else { return }
        closed = true
        operation?.cancel()
        let outcome: AttemptState = switch attempt {
        case .authorizing: .notSubmitted
        case .submitting, .pending, .unconfirmed: .unconfirmed
        default: attempt
        }
        await finish(outcome)
    }

    private func runOperation(_ body: @escaping @MainActor @Sendable () async -> Void) async {
        // A view can stop awaiting this operation without cancelling the connection it owns.
        let task = Task { await body() }
        operation = task
        await task.value
        operation = nil
    }

    private func checkSelection(_ selected: Selection, attemptID id: UUID) throws {
        try Task.checkCancellation()
        guard !closed, attemptID == id, let current = currentSelection else {
            throw SelectionInvalidation.observationChanged
        }
        guard current.identity.reservationID == selected.identity.reservationID else {
            throw SelectionInvalidation.reservationChanged
        }
        guard current.identity.incarnation == selected.identity.incarnation else {
            throw SelectionInvalidation.incarnationChanged
        }
        guard current == selected else { throw SelectionInvalidation.observationChanged }
    }

    private func finish(_ outcome: AttemptState) async {
        let previous = channel
        channel = nil
        attemptID = nil
        observationID = UUID()
        status = .unread
        attempt = outcome
        if let grant = authorization {
            authorization = nil
            let cleanup = Task.detached { [close = grant.close] in close() }
            authorizationCleanup = cleanup
            await previous?.close()
            await cleanup.value
            authorizationCleanup = nil
        } else {
            await previous?.close()
            await authorizationCleanup?.value
        }
    }
}
