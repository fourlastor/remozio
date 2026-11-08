import Foundation

/// Durable backend intent only. It grants no file writer, native startup, health or floor authority.
struct MachineUpdateBackendPublicationProgress: Codable, Equatable, Sendable {
    enum File: Int, Codable, CaseIterable, Sendable {
        case authority, transport, gateway, commit
        var artifact: AdministrativeSetupPublication.File {
            switch self {
            case .authority: .authorityGatewayRuntime
            case .transport: .transportGatewayRuntime
            case .gateway: .gatewayConfiguration
            case .commit: .gatewayRuntimeCommit
            }
        }
    }
    enum State: Int, Codable, Sendable { case pending, writing, published }
    struct Entry: Codable, Equatable, Sendable {
        let accountID: Data
        let file: File
        let state: State
    }
    let entries: [Entry]
    init(record: MachineUpdateBackendEpochRecord) {
        entries = (record.accounts ?? []).filter { $0.sourceDigest != nil }.flatMap { account in
            File.allCases.map { .init(accountID: account.accountID, file: $0, state: .pending) }
        }
    }
    private init(entries: [Entry]) { self.entries = entries }
    func validate(record: MachineUpdateBackendEpochRecord) throws {
        let expected = Self(record: record).entries
        guard entries.count <= 512, entries.count == expected.count,
              zip(entries, expected).allSatisfy({ $0.accountID == $1.accountID && $0.file == $1.file }) else {
            throw PreparationStoreError.corruptRecord
        }
        for entry in entries where entry.file == .commit && entry.state != .pending {
            guard entries.filter({ $0.accountID == entry.accountID && $0.file != .commit }).allSatisfy({ $0.state == .published }) else {
                throw PreparationStoreError.corruptRecord
            }
        }
    }
    func state(accountID: Data, file: File) throws -> State {
        guard let entry = entries.first(where: { $0.accountID == accountID && $0.file == file }) else { throw PreparationStoreError.notFound }
        return entry.state
    }
    func advancing(accountID: Data, file: File, to next: State) throws -> Self {
        let current = try state(accountID: accountID, file: file)
        guard current == .pending && next == .writing || current == .writing && next == .published else {
            throw PreparationStoreError.invalidTransition
        }
        if file == .commit {
            guard entries.filter({ $0.accountID == accountID && $0.file != .commit }).allSatisfy({ $0.state == .published }) else {
                throw PreparationStoreError.invalidTransition
            }
        }
        return Self(entries: entries.map { entry in
            entry.accountID == accountID && entry.file == file ? .init(accountID: accountID, file: file, state: next) : entry
        })
    }
    var complete: Bool { entries.allSatisfy { $0.state == .published } }
}

enum MachineUpdateBackendPublicationOperation {
    case begin
    case prepare(Data, MachineUpdateBackendPublicationProgress.File)
    case complete(Data, MachineUpdateBackendPublicationProgress.File)
}

extension MachineUpdateBackendEpoch.Capture {
    func bytes(_ file: MachineUpdateBackendPublicationProgress.File, target: Bool) throws -> Data {
        guard let source, let startup else { throw PreparationStoreError.invalidTransition }
        if !target {
            switch file {
            case .authority: return try source.pair.authority.encoded
            case .transport: return try source.pair.transport.encoded
            case .gateway: return source.gateway.canonicalBytes
            case .commit: return try source.commit.encoded
            }
        }
        let pair = try GatewayRuntimeExtensions(release: startup)
        switch file {
        case .authority: return try pair.authority.encoded
        case .transport: return try pair.transport.encoded
        case .gateway: return startup.gateway.canonicalBytes
        case .commit: return try GatewayRuntimeCommit(release: startup, pair: pair).encoded
        }
    }
    func requireActual(_ bytes: Data, file: MachineUpdateBackendPublicationProgress.File,
                       progress: MachineUpdateBackendPublicationProgress?) throws {
        let state = try progress?.state(accountID: accountID, file: file) ?? .pending
        let source = try self.bytes(file, target: false), target = try self.bytes(file, target: true)
        guard state == .pending && bytes == source || state == .writing && (bytes == source || bytes == target) ||
              state == .published && bytes == target else { throw GatewayPreparationError.changedScope }
    }
}
