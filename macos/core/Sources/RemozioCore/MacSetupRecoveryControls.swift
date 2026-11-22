import Foundation
import Observation

/// Own this controller at app scope so dismissing a view does not drop the recovery connection.
@MainActor @Observable
final class MacSetupRecoveryControls {
    typealias Status = SetupRetainedStatusWire.Observation
    typealias Wire = SetupOrphanRecoveryWire
    typealias Authorization = @Sendable () throws -> Data

    struct Selection: Equatable, Sendable {
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

    private(set) var status: ObservationState = .unread
    private(set) var attempt: AttemptState = .idle
    private(set) var selectionInvalidation: SelectionInvalidation?
    var health: Health { .unconfirmed }

    @ObservationIgnored private let read: @MainActor () async throws -> Status
    @ObservationIgnored private let eligible: @MainActor (Status) -> Wire.Action?
    @ObservationIgnored private let openRecovery: @MainActor () async throws -> MacSetupRecoveryChannel
    @ObservationIgnored private let authorize: @MainActor () async throws -> Authorization
    @ObservationIgnored private var observationID = UUID()
    @ObservationIgnored private var attemptID: UUID?
    @ObservationIgnored private var channel: MacSetupRecoveryChannel?
    @ObservationIgnored private var acknowledgement = false
    @ObservationIgnored private var operation: Task<Void, Never>?
    @ObservationIgnored private var closed = false

    convenience init() {
        self.init(read: {
            let channel = try await MacAccountSetupConnection.openRecoveryClient(lane: .status)
            return try await channel.readStatus()
        }, eligible: { _ in nil }, openRecovery: {
            try await MacAccountSetupConnection.openRecoveryClient(lane: .recovery)
        }, authorize: { throw AdministrativeSetupChannelError.unsupportedVersion })
    }

    /// The injected applicability and authorization paths are only used in deterministic client tests.
    init(read: @escaping @MainActor () async throws -> Status,
         eligible: @escaping @MainActor (Status) -> Wire.Action? = { _ in nil },
         openRecovery: @escaping @MainActor () async throws -> MacSetupRecoveryChannel,
         authorize: @escaping @MainActor () async throws -> Authorization) {
        self.read = read
        self.eligible = eligible
        self.openRecovery = openRecovery
        self.authorize = authorize
    }

    var selection: Selection? {
        guard !closed, attemptID == nil, operation == nil else { return nil }
        return currentSelection
    }

    private var currentSelection: Selection? {
        guard case .observed(let observation) = status, let identity = observation.identity,
              let action = eligible(observation) else { return nil }
        return Selection(observationID: observationID, identity: identity, action: action)
    }

    func refresh() async {
        guard !closed else { return }
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

    func begin(_ selected: Selection) async {
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
            try await connection.open()
            try checkSelection(selected, attemptID: id)
            let form = try await authorize()
            try checkSelection(selected, attemptID: id)
            let request = try Wire.Request(requestID: AccountPreparationIntent.randomID(), action: selected.action,
                identity: selected.identity)
            attempt = .submitting
            let result = try await connection.start(request, readAuthorization: form)
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
            if dispatched {
                attempt = .unconfirmed
            } else {
                selectionInvalidation = error as? SelectionInvalidation
                await finish(.notSubmitted)
            }
        }
    }

    func readProgress() async {
        guard !closed, operation == nil, let id = attemptID, let channel,
              attempt == .pending || attempt == .unconfirmed else { return }
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
            guard !closed, attemptID == id else { return }
            attempt = .unconfirmed
        }
    }

    /// An explicit local reset only releases the connection. Require a fresh status read afterward.
    func endTracking() async {
        guard !closed, attempt != .authorizing, attempt != .submitting else { return }
        let outcome: AttemptState = attemptID == nil ? attempt : .unconfirmed
        await finish(outcome)
    }

    func close() async {
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
        await previous?.close()
    }
}
