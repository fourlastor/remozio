import Foundation
import Observation

@MainActor @Observable
public final class MacExpiredRePairControls {
    public enum Notice: Equatable {
        case discarded, authorizationCancelled, notSubmitted, noLongerListed, unconfirmed
    }

    public enum Availability: Equatable, Sendable {
        case unread, available, updateRequired, unavailable
    }

    /// An empty array means the authority reports no expired stages.
    public private(set) var records: [ExpiredRePairRecord]?
    public private(set) var availability: Availability = .unread
    public private(set) var notice: Notice?

    @ObservationIgnored private let load: @MainActor () async throws -> [ExpiredRePairRecord]
    @ObservationIgnored private let discard: @MainActor (ExpiredRePairRecord) async throws -> Void
    @ObservationIgnored private var operation: Task<Void, Never>?
    @ObservationIgnored private var operationID: UUID?

    public convenience init(openChannel: @escaping @MainActor () throws -> AuthorityPairingChannel) {
        self.init(load: {
            for _ in 0..<2 {
                try Task.checkCancellation()
                let channel = try openChannel()
                defer { channel.abort() }
                do {
                    _ = try await channel.start()
                    try await channel.negotiateExpiredRePairList()
                } catch {
                    continue
                }
                return try await channel.expiredRePairs()
            }

            // A legacy service can close the connection on the unknown selector.
            try Task.checkCancellation()
            let legacy = try openChannel()
            defer { legacy.abort() }
            _ = try await legacy.start()
            try await legacy.requirePhoneManagement()
            throw ExpiredRePairListError.updateRequired
        }, discard: { record in
            let channel = try openChannel()
            defer { channel.abort() }
            _ = try await channel.start()
            try await channel.discardExpiredRePair(record)
        })
    }

    init(load: @escaping @MainActor () async throws -> [ExpiredRePairRecord],
         discard: @escaping @MainActor (ExpiredRePairRecord) async throws -> Void) {
        self.load = load
        self.discard = discard
    }

    public func refresh() async {
        await run {
            self.notice = nil
            _ = await self.read()
        }
    }

    public func discardConfirmed(_ record: ExpiredRePairRecord) async {
        guard operation == nil, !Task.isCancelled else { return }
        guard records?.contains(record) == true else {
            notice = records == nil ? .notSubmitted : .noLongerListed
            return
        }
        await run {
            self.notice = nil
            do {
                try await self.discard(record)
                guard !Task.isCancelled else { return }
                self.notice = .discarded
                self.records?.removeAll { $0 == record }
                _ = await self.read()
            } catch SetupAdministratorAuthorizationError.cancelled {
                guard !Task.isCancelled else { return }
                self.notice = .authorizationCancelled
            } catch ExpiredRePairDiscardError.replyUnconfirmed {
                // A lost reply cannot tell us whether this request removed the record.
                guard !Task.isCancelled else { return }
                let current = await self.read()
                guard !Task.isCancelled else { return }
                self.notice = current?.contains(record) == false ? .noLongerListed : .unconfirmed
            } catch {
                guard !Task.isCancelled else { return }
                self.notice = .notSubmitted
            }
        }
    }

    public func cancel() {
        operation?.cancel()
        operation = nil
        operationID = nil
    }

    private func read() async -> [ExpiredRePairRecord]? {
        do {
            let current = try await load()
            guard !Task.isCancelled else { return nil }
            records = current
            availability = .available
        } catch {
            guard !Task.isCancelled else { return nil }
            records = nil
            switch error {
            case ExpiredRePairListError.updateRequired: availability = .updateRequired
            default: availability = .unavailable
            }
        }
        return records
    }

    private func run(_ work: @escaping @MainActor () async -> Void) async {
        guard operation == nil, !Task.isCancelled else { return }
        let id = UUID()
        let task = Task {
            guard !Task.isCancelled else { return }
            await work()
        }
        operation = task
        operationID = id
        await withTaskCancellationHandler {
            await task.value
        } onCancel: {
            task.cancel()
        }
        if operationID == id {
            operation = nil
            operationID = nil
        }
    }
}
