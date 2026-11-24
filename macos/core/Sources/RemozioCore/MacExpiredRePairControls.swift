import Foundation
import Observation

@MainActor @Observable
public final class MacExpiredRePairControls {
    public enum Notice: Equatable {
        case discarded, authorizationCancelled, noLongerListed, unconfirmed
    }

    /// An empty array means the authority reports no expired stages.
    public private(set) var records: [ExpiredRePairRecord]?
    public private(set) var unavailable = false
    public private(set) var notice: Notice?

    @ObservationIgnored private let load: @MainActor () async throws -> [ExpiredRePairRecord]
    @ObservationIgnored private let discard: @MainActor (ExpiredRePairRecord) async throws -> Void
    @ObservationIgnored private var operation: Task<Void, Never>?
    @ObservationIgnored private var operationID: UUID?

    public convenience init(openChannel: @escaping @MainActor () throws -> AuthorityPairingChannel) {
        self.init(load: {
            let channel = try openChannel()
            defer { channel.abort() }
            _ = try await channel.start()
            return try await channel.expiredRePairs()
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
            _ = await self.read()
        }
    }

    public func discardConfirmed(_ record: ExpiredRePairRecord) async {
        guard records?.contains(record) == true else { return }
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
            } catch {
                // A lost reply cannot tell us whether this request removed the record.
                guard !Task.isCancelled else { return }
                let current = await self.read()
                guard !Task.isCancelled else { return }
                self.notice = current?.contains(record) == false ? .noLongerListed : .unconfirmed
            }
        }
    }

    public func cancel() {
        operation?.cancel()
        operation = nil
        operationID = nil
    }

    private func read() async -> [ExpiredRePairRecord]? {
        let current = try? await load()
        guard !Task.isCancelled else { return nil }
        records = current
        unavailable = current == nil
        return current
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
