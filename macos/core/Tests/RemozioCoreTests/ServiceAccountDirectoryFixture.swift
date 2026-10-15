import Foundation
@testable import RemozioCore

enum ServiceAccountDirectoryFixtureError: Error { case interrupted }
final class ServiceAccountDirectoryFixture: ServiceAccountDirectoryAccess {
    var users: [ServiceDirectoryRecord] = [], groups: [ServiceDirectoryRecord] = []
    var writes: [String] = []
    var lostWrite: String?
    var invalidUser: ServiceAccountRole?
    func lookup(kind: ServiceDirectoryKind, index: ServiceDirectoryIndex) throws -> [ServiceDirectoryRecord] {
        let rows = kind == .user ? users : groups
        switch index {
        case .name(let value): return rows.filter { $0.names.contains(value) }
        case .number(let value): return rows.filter { $0.number == value }
        case .id(let value): return rows.filter { $0.id == value }
        }
    }
    func createGroup(_ claim: ServiceAccountClaim) throws {
        let operation = "group-\(claim.role.rawValue)"; writes.append(operation)
        groups.append(.init(number: claim.number, id: claim.groupID, names: [claim.name]))
        if lostWrite == operation { lostWrite = nil; throw ServiceAccountDirectoryFixtureError.interrupted }
    }
    func createUser(_ claim: ServiceAccountClaim) throws {
        let operation = "user-\(claim.role.rawValue)"; writes.append(operation)
        users.append(.init(number: claim.number, id: claim.userID, names: [claim.name]))
        if lostWrite == operation { lostWrite = nil; throw ServiceAccountDirectoryFixtureError.interrupted }
    }
    func validateGroup(_ claim: ServiceAccountClaim) throws {
        guard groups.filter({ $0.matches(claim, kind: .group) }).count == 1 else { throw ServiceAccountProvisioningError.conflictingRecord }
    }
    func validateUser(_ claim: ServiceAccountClaim, ownerUID: UInt32) throws {
        guard ownerUID != claim.number, invalidUser != claim.role,
              users.filter({ $0.matches(claim, kind: .user) }).count == 1 else { throw ServiceAccountProvisioningError.conflictingRecord }
    }
}
