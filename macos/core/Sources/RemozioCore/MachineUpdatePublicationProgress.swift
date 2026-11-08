import Foundation

/// Durable file intent only. These values grant no file writer, service health or floor authority.
struct MachineUpdatePublicationProgress: Codable, Equatable, Sendable {
    enum File: Int, Codable, CaseIterable, Sendable { case host, transport, gateway, presence, pairing, frontend }
    enum State: Int, Codable, Sendable { case pending, writing, published }
    struct Entry: Codable, Equatable, Sendable {
        let accountID: Data
        let file: File
        let state: State
    }
    let entries: [Entry]
    init(accountIDs: [Data]) {
        entries = accountIDs.flatMap { account in
            File.allCases.map { .init(accountID: account, file: $0, state: .pending) }
        }
    }
    private init(entries: [Entry]) { self.entries = entries }
    func validate(accountIDs: [Data]) throws {
        guard accountIDs.count <= 128, accountIDs.allSatisfy({ $0.count == 16 }),
              Set(accountIDs).count == accountIDs.count,
              accountIDs == accountIDs.sorted(by: { $0.lexicographicallyPrecedes($1) }) else {
            throw PreparationStoreError.corruptRecord
        }
        let expected = Self(accountIDs: accountIDs).entries
        guard entries.count <= 768, entries.count == expected.count,
              zip(entries, expected).allSatisfy({ $0.accountID == $1.accountID && $0.file == $1.file }) else {
            throw PreparationStoreError.corruptRecord
        }
    }
    func state(accountID: Data, file: File) throws -> State {
        guard let entry = entries.first(where: { $0.accountID == accountID && $0.file == file }) else {
            throw PreparationStoreError.notFound
        }
        return entry.state
    }
    func advancing(accountID: Data, file: File, to next: State) throws -> Self {
        let current = try state(accountID: accountID, file: file)
        guard current == .pending && next == .writing || current == .writing && next == .published else {
            throw PreparationStoreError.invalidTransition
        }
        return Self(entries: entries.map { entry in
            entry.accountID == accountID && entry.file == file ? .init(accountID: accountID, file: file, state: next) : entry
        })
    }
    var complete: Bool { entries.allSatisfy { $0.state == .published } }
}

enum MachineUpdatePublicationOperation {
    case begin
    case prepare(Data, MachineUpdatePublicationProgress.File)
    case complete(Data, MachineUpdatePublicationProgress.File)
}

extension MachineUpdateConfigurationEpoch.Configuration {
    func bytes(_ file: MachineUpdatePublicationProgress.File, target: Bool) throws -> Data {
        switch file {
        case .host: return target ? startup.host.canonicalBytes : source.host.canonicalBytes
        case .transport: return target ? startup.transport.canonicalBytes : source.transport.canonicalBytes
        case .gateway: return try target ? startup.gateway.encoded : source.gateway.encoded
        case .presence: return target ? startup.clients.presence.canonicalBytes : source.clients.presence.canonicalBytes
        case .pairing: return target ? startup.clients.pairing.canonicalBytes : source.clients.pairing.canonicalBytes
        case .frontend: return target ? startup.clients.frontend.canonicalBytes : source.clients.frontend.canonicalBytes
        }
    }
    func requireActual(_ actual: RuntimeReleaseConfigurationSource, progress: MachineUpdatePublicationProgress?) throws {
        let actuals = try [actual.host.canonicalBytes, actual.transport.canonicalBytes, actual.gateway.encoded,
            actual.clients.presence.canonicalBytes, actual.clients.pairing.canonicalBytes, actual.clients.frontend.canonicalBytes]
        for file in MachineUpdatePublicationProgress.File.allCases {
            let state = try progress?.state(accountID: startup.binding.accountID, file: file) ?? .pending
            let source = try bytes(file, target: false), target = try bytes(file, target: true), value = actuals[file.rawValue]
            guard state == .pending && value == source || state == .writing && (value == source || value == target) ||
                  state == .published && value == target else { throw InstalledAuthorityCommandError.changedConfiguration }
        }
    }
}
