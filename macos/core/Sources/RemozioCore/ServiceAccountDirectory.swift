import Foundation
import OpenDirectory

enum ServiceDirectoryKind: Sendable { case user, group }
enum ServiceDirectoryIndex: Sendable { case name(String), number(UInt32), id(UUID) }
struct ServiceDirectoryRecord: Equatable, Sendable, CustomStringConvertible {
    let number: UInt32
    let id: UUID
    let names: [String]
    var description: String { "ServiceDirectoryRecord(redacted)" }
    static func decode(numbers: [String], ids: [String], names: [String]) throws -> Self {
        guard numbers.count == 1, let number = UInt32(numbers[0]), number < UInt32.max,
              numbers[0] == String(number), ids.count == 1, ids[0].utf8.count == 36, let id = UUID(uuidString: ids[0]),
              !names.isEmpty, names.count <= 32, Set(names).count == names.count,
              names.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 255 && !$0.utf8.contains(0) }) else {
            throw ServiceAccountProvisioningError.conflictingRecord
        }
        return .init(number: number, id: id, names: names)
    }
    func matches(_ claim: ServiceAccountClaim, kind: ServiceDirectoryKind) -> Bool {
        number == claim.number && names == [claim.name] && id == (kind == .user ? claim.userID : claim.groupID)
    }
}
enum ServiceDirectoryState: Equatable { case absent, retained }

// Every index must agree. Partial matches, aliases and duplicate records cannot authorize adoption or creation.
enum ServiceDirectoryPreflight {
    static func evaluate(claim: ServiceAccountClaim, kind: ServiceDirectoryKind, byName: [ServiceDirectoryRecord],
                         byNumber: [ServiceDirectoryRecord], byID: [ServiceDirectoryRecord]) throws -> ServiceDirectoryState {
        let lists = [byName, byNumber, byID]
        if lists.allSatisfy(\.isEmpty) { return .absent }
        guard lists.allSatisfy({ $0.count == 1 && $0[0].matches(claim, kind: kind) }),
              byName == byNumber, byName == byID else { throw ServiceAccountProvisioningError.conflictingRecord }
        return .retained
    }
}

/// Public identity queries only. This reader never requests credential or membership attributes and cannot create records.
final class ServiceAccountDirectoryReader {
    private let node: ODNode
    init() throws { node = try ODNode(session: ODSession.default(), name: "/Local/Default") }
    func lookup(kind: ServiceDirectoryKind, index: ServiceDirectoryIndex) throws -> [ServiceDirectoryRecord] {
        let numeric = kind == .user ? kODAttributeTypeUniqueID : kODAttributeTypePrimaryGroupID
        let attribute: String, value: String
        switch index {
        case .name(let name):
            guard !name.isEmpty, name.utf8.count <= 255, !name.utf8.contains(0) else { throw ServiceAccountProvisioningError.invalidPlan }
            attribute = kODAttributeTypeRecordName; value = name
        case .number(let number):
            guard number < UInt32.max else { throw ServiceAccountProvisioningError.invalidPlan }
            attribute = numeric; value = String(number)
        case .id(let id): attribute = kODAttributeTypeGUID; value = id.uuidString
        }
        do {
            let query = try ODQuery(node: node, forRecordTypes: kind == .user ? kODRecordTypeUsers : kODRecordTypeGroups,
                attribute: attribute, matchType: ODMatchType(kODMatchEqualTo), queryValues: value,
                returnAttributes: [numeric, kODAttributeTypeGUID, kODAttributeTypeRecordName], maximumResults: 2)
            guard let records = try query.resultsAllowingPartial(false) as? [ODRecord] else { throw ServiceAccountProvisioningError.unavailable }
            return try records.map { record in
                func values(_ key: String) throws -> [String] {
                    guard let result = try record.values(forAttribute: key) as? [String] else { throw ServiceAccountProvisioningError.conflictingRecord }
                    return result
                }
                return try .decode(numbers: values(numeric), ids: values(kODAttributeTypeGUID), names: values(kODAttributeTypeRecordName))
            }
        } catch let error as ServiceAccountProvisioningError { throw error }
        catch { throw ServiceAccountProvisioningError.unavailable }
    }
    func state(claim: ServiceAccountClaim, kind: ServiceDirectoryKind) throws -> ServiceDirectoryState {
        try ServiceDirectoryPreflight.evaluate(claim: claim, kind: kind,
            byName: lookup(kind: kind, index: .name(claim.name)), byNumber: lookup(kind: kind, index: .number(claim.number)),
            byID: lookup(kind: kind, index: .id(kind == .user ? claim.userID : claim.groupID)))
    }
}
