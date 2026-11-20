import CryptoKit
import Foundation
import RemozioProtocol

/// Correlation metadata only. A decoded descriptor grants no writer, join or admission authority.
struct RuntimeMaintenanceUnboundRelease: Equatable, Sendable {
    enum Origin: UInt64, Sendable { case authorized = 1, retainedAuthorizedRecovery = 2 }
    let intentID: Data, authorizedRevision: Data, authorizedDigest: Data
    let predecessorRevision: Data, predecessorDigest: Data, pendingRevision: Data
    let origin: Origin

    init(authorized: RuntimeMaintenanceWindowRecord, previous: RuntimeMaintenanceWindowRecord,
        pendingRevision: Data, intentID: Data = AccountPreparationIntent.randomID()) throws {
        guard authorized.phase == .authorized, authorized.purpose == .retainedRuntime,
              authorized.operation == .notStarted, authorized.service == .notStopped,
              authorized.shutdownBinding == nil, authorized.unboundRelease == nil, authorized.failure == nil, authorized.gate == nil,
              previous.shutdownBinding == nil, previous.unboundRelease == nil, previous.gate == nil,
              previous.operation == .notStarted, previous.service == .notStopped,
              previous == authorized || previous.phase == .needsOwnerRecovery else {
            throw PreparationStoreError.invalidTransition
        }
        try previous.requireSameScope(as: authorized)
        try self.init(intentID: intentID, authorizedRevision: authorized.revision,
            authorizedDigest: Self.digest(authorized), predecessorRevision: previous.revision,
            predecessorDigest: Self.digest(previous), pendingRevision: pendingRevision,
            origin: previous == authorized ? .authorized : .retainedAuthorizedRecovery)
    }
    private init(intentID: Data, authorizedRevision: Data, authorizedDigest: Data,
        predecessorRevision: Data, predecessorDigest: Data, pendingRevision: Data, origin: Origin) throws {
        guard [intentID, authorizedRevision, predecessorRevision, pendingRevision].allSatisfy({ $0.count == 16 }),
              authorizedDigest.count == 32, predecessorDigest.count == 32,
              pendingRevision != predecessorRevision, pendingRevision != authorizedRevision,
              (origin == .authorized) == (predecessorRevision == authorizedRevision && predecessorDigest == authorizedDigest)
              else { throw RuntimePreparationError.invalidRecord }
        self.intentID = intentID; self.authorizedRevision = authorizedRevision; self.authorizedDigest = authorizedDigest
        self.predecessorRevision = predecessorRevision; self.predecessorDigest = predecessorDigest
        self.pendingRevision = pendingRevision; self.origin = origin
    }
    func requireOrigin(_ authorized: RuntimeMaintenanceWindowRecord, previous: RuntimeMaintenanceWindowRecord) throws {
        guard self == (try Self(authorized: authorized, previous: previous,
            pendingRevision: pendingRevision, intentID: intentID)) else { throw PreparationStoreError.staleRevision }
    }
    static func digest(_ row: RuntimeMaintenanceWindowRecord) throws -> Data {
        var bytes = Data("remozio.runtime-maintenance.unbound-origin.v1\0".utf8)
        bytes.append(try row.encoded)
        return Data(SHA256.hash(data: bytes))
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(intentID),
            2: .bytes(authorizedRevision), 3: .bytes(authorizedDigest), 4: .bytes(predecessorRevision),
            5: .bytes(predecessorDigest), 6: .bytes(pendingRevision), 7: .unsigned(origin.rawValue)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...7), fields[0] == .unsigned(1),
              case .unsigned(let raw) = fields[7], let origin = Origin(rawValue: raw) else {
            throw RuntimePreparationError.invalidRecord
        }
        func data(_ key: UInt64) throws -> Data {
            guard case .bytes(let value) = fields[key] else { throw RuntimePreparationError.invalidRecord }
            return value
        }
        let result = try Self(intentID: data(1), authorizedRevision: data(2), authorizedDigest: data(3),
            predecessorRevision: data(4), predecessorDigest: data(5), pendingRevision: data(6), origin: origin)
        guard try result.encoded == bytes else { throw RuntimePreparationError.invalidRecord }
        return result
    }
    private static let limits = try! CBORLimits(maxBytes: 512, maxDepth: 1, maxItems: 17)
}
