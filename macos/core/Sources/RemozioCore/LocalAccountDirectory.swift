import Darwin
import Foundation
import OpenDirectory

struct LocalAccountIdentity: Equatable, Sendable, CustomStringConvertible {
    let uid: UInt32
    let primaryGroupID: UInt32
    let directoryID: UUID
    var description: String { "LocalAccountIdentity(redacted)" }
}
enum LocalAccountLookupError: Error, Equatable {
    case invalidScope, missing, ambiguous, malformed, unavailable, ownershipChanged
}
struct LocalAccountFields {
    let uids: [String]
    let groups: [String]
    let ids: [String]
}

// This returns public identity metadata. It grants no enrollment or command authority.
// A privileged caller must obtain the UID from its authenticated invocation.
enum LocalAccountDirectory {
    static func decode(uid: UInt32, records: [LocalAccountFields]) throws -> LocalAccountIdentity {
        guard uid > 0, uid < UInt32.max else { throw LocalAccountLookupError.invalidScope }
        guard !records.isEmpty else { throw LocalAccountLookupError.missing }
        guard records.count == 1 else { throw LocalAccountLookupError.ambiguous }
        let record = records[0]
        func number(_ values: [String]) throws -> UInt32 {
            guard values.count == 1, (1...10).contains(values[0].utf8.count),
                  values[0].utf8.allSatisfy({ (48...57).contains($0) }),
                  let value = UInt32(values[0]), value < UInt32.max else { throw LocalAccountLookupError.malformed }
            return value
        }
        guard try number(record.uids) == uid, record.ids.count == 1,
              record.ids[0].utf8.count == 36, let id = UUID(uuidString: record.ids[0]) else {
            throw LocalAccountLookupError.malformed
        }
        return try LocalAccountIdentity(uid: uid, primaryGroupID: number(record.groups), directoryID: id)
    }
    // The expected UUID must come from protected enrollment state, never a new caller claim.
    static func validateOwnership(_ current: LocalAccountIdentity, uid: UInt32, directoryID: UUID) throws {
        guard current.uid == uid, current.directoryID == directoryID else { throw LocalAccountLookupError.ownershipChanged }
    }
    static func lookup(uid: UInt32) throws -> LocalAccountIdentity {
        guard uid > 0, uid < UInt32.max else { throw LocalAccountLookupError.invalidScope }
        let fields: [LocalAccountFields]
        do {
            let node = try ODNode(session: ODSession.default(), name: "/Local/Default")
            let attributes = [kODAttributeTypeUniqueID, kODAttributeTypePrimaryGroupID, kODAttributeTypeGUID]
            let query = try ODQuery(node: node, forRecordTypes: kODRecordTypeUsers,
                attribute: kODAttributeTypeUniqueID, matchType: ODMatchType(kODMatchEqualTo),
                queryValues: String(uid), returnAttributes: attributes, maximumResults: 2)
            guard let records = try query.resultsAllowingPartial(false) as? [ODRecord] else { throw LocalAccountLookupError.unavailable }
            fields = try records.map { record in
                func strings(_ key: String) throws -> [String] {
                    guard let value = try record.values(forAttribute: key) as? [String] else { throw LocalAccountLookupError.malformed }
                    return value
                }
                return try LocalAccountFields(uids: strings(kODAttributeTypeUniqueID), groups: strings(kODAttributeTypePrimaryGroupID),
                    ids: strings(kODAttributeTypeGUID))
            }
        } catch let error as LocalAccountLookupError { throw error }
        catch { throw LocalAccountLookupError.unavailable }
        return try decode(uid: uid, records: fields)
    }
}
