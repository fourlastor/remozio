import Darwin
import Foundation
import OpenDirectory

/// Root setup only. Construction grants no administrator consent or retained account scope.
final class NativeServiceAccountDirectory: ServiceAccountDirectoryAccess {
    private let processID = getpid()
    private let ownerUID: UInt32
    private let accountID: Data
    private let node: ODNode
    private let reader: ServiceAccountDirectoryReader
    private static let hidden = "dsAttrTypeNative:IsHidden"
    init(accountID: Data, ownerUID: UInt32) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard accountID.count == 16, ownerUID > 0, ownerUID < UInt32.max else { throw ServiceAccountProvisioningError.invalidPlan }
        self.ownerUID = ownerUID; self.accountID = accountID
        node = try ODNode(session: ODSession.default(), name: "/Local/Default")
        reader = try ServiceAccountDirectoryReader()
    }
    private func requireRoot() throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard getpid() == processID else { throw ServiceAccountProvisioningError.unavailable }
    }
    private func requireClaim(_ claim: ServiceAccountClaim) throws {
        try requireRoot()
        guard claim.accountID == accountID, claim.number != ownerUID, ServiceAccountPlan.roles.contains(claim.role) else {
            throw ServiceAccountProvisioningError.changedScope
        }
    }
    func lookup(kind: ServiceDirectoryKind, index: ServiceDirectoryIndex) throws -> [ServiceDirectoryRecord] {
        try requireRoot(); return try reader.lookup(kind: kind, index: index)
    }
    func available(_ claim: ServiceAccountClaim) throws -> Bool {
        try requireClaim(claim)
        for kind in [ServiceDirectoryKind.user, .group] {
            for index in [ServiceDirectoryIndex.name(claim.name), .number(claim.number), .id(claim.userID), .id(claim.groupID)] {
                if try !reader.lookup(kind: kind, index: index).isEmpty { return false }
            }
        }
        return try user(.number(claim.number)) == nil && user(.name(claim.name)) == nil &&
            group(.number(claim.number)) == nil && group(.name(claim.name)) == nil
    }
    func createGroup(_ claim: ServiceAccountClaim) throws {
        try requireClaim(claim)
        guard claim.number != ownerUID, try reader.state(claim: claim, kind: .group) == .absent,
              try reader.state(claim: claim, kind: .user) == .absent,
              try user(.number(claim.number)) == nil, try user(.name(claim.name)) == nil,
              try group(.number(claim.number)) == nil, try group(.name(claim.name)) == nil else {
            throw ServiceAccountProvisioningError.conflictingRecord
        }
        do {
            _ = try node.createRecord(withRecordType: kODRecordTypeGroups, name: claim.name, attributes: [
                kODAttributeTypeGUID: [claim.groupID.uuidString], kODAttributeTypePrimaryGroupID: [String(claim.number)],
                kODAttributeTypePassword: ["*"]])
        } catch { throw ServiceAccountProvisioningError.unavailable }
        try validateGroup(claim)
    }
    func createUser(_ claim: ServiceAccountClaim) throws {
        try requireClaim(claim); try validateGroup(claim)
        guard claim.number != ownerUID, try reader.state(claim: claim, kind: .user) == .absent,
              try user(.number(claim.number)) == nil, try user(.name(claim.name)) == nil else {
            throw ServiceAccountProvisioningError.conflictingRecord
        }
        do {
            // Submit the disabled authentication policy, shell and UUID in the creation call, before the record can be used.
            _ = try node.createRecord(withRecordType: kODRecordTypeUsers, name: claim.name, attributes: [
                kODAttributeTypeGUID: [claim.userID.uuidString], kODAttributeTypeUniqueID: [String(claim.number)],
                kODAttributeTypePrimaryGroupID: [String(claim.number)], kODAttributeTypeUserShell: ["/usr/bin/false"],
                kODAttributeTypeNFSHomeDirectory: ["/var/empty"], kODAttributeTypeAuthenticationAuthority: [";DisabledUser;"],
                kODAttributeTypePassword: ["*"], Self.hidden: ["1"]])
        } catch { throw ServiceAccountProvisioningError.unavailable }
        try validateUser(claim, ownerUID: ownerUID)
    }
    func validateGroup(_ claim: ServiceAccountClaim) throws {
        try requireClaim(claim)
        let attributes = [kODAttributeTypePrimaryGroupID, kODAttributeTypeGUID, kODAttributeTypeRecordName,
            kODAttributeTypeGroupMembership, kODAttributeTypeGroupMembers, kODAttributeTypeNestedGroups]
        let values = try details(claim, kind: .group, attributes: attributes)
        guard (values[kODAttributeTypeGroupMembership] ?? []).isEmpty,
              (values[kODAttributeTypeGroupMembers] ?? []).isEmpty, (values[kODAttributeTypeNestedGroups] ?? []).isEmpty,
              let byNumber = try group(.number(claim.number)), let byName = try group(.name(claim.name)),
              byNumber == byName, byNumber.number == claim.number, byNumber.name == claim.name else {
            throw ServiceAccountProvisioningError.conflictingRecord
        }
    }
    func validateUser(_ claim: ServiceAccountClaim, ownerUID: UInt32) throws {
        try requireClaim(claim)
        guard ownerUID == self.ownerUID, claim.number != ownerUID else { throw ServiceAccountProvisioningError.changedScope }
        let attributes = [kODAttributeTypeUniqueID, kODAttributeTypePrimaryGroupID, kODAttributeTypeGUID, kODAttributeTypeRecordName,
            kODAttributeTypeUserShell, kODAttributeTypeNFSHomeDirectory, kODAttributeTypeAuthenticationAuthority, Self.hidden]
        let values = try details(claim, kind: .user, attributes: attributes)
        guard values[kODAttributeTypePrimaryGroupID] == [String(claim.number)], values[kODAttributeTypeUserShell] == ["/usr/bin/false"],
              values[kODAttributeTypeNFSHomeDirectory] == ["/var/empty"], values[Self.hidden] == ["1"],
              let authorities = values[kODAttributeTypeAuthenticationAuthority], authorities.count == 1,
              authorities[0].hasPrefix(";DisabledUser;"),
              let byNumber = try user(.number(claim.number)), let byName = try user(.name(claim.name)),
              byNumber == byName, byNumber.number == claim.number, byNumber.group == claim.number,
              byNumber.name == claim.name, byNumber.shell == "/usr/bin/false" else {
            throw ServiceAccountProvisioningError.conflictingRecord
        }
        let account = try DedicatedServiceAccount.resolve(uid: claim.number)
        try account.validate(ownerUID: ownerUID)
        guard account.gid == claim.number else { throw ServiceAccountProvisioningError.conflictingRecord }
        try DedicatedServiceAccount.rejectAdministrators(uid: claim.number)
        guard try reader.state(claim: claim, kind: .user) == .retained else { throw ServiceAccountProvisioningError.conflictingRecord }
    }
    private func details(_ claim: ServiceAccountClaim, kind: ServiceDirectoryKind, attributes: [String]) throws -> [String: [String]] {
        // Read authentication policy only after all public indexes match this retained record claim.
        guard try reader.state(claim: claim, kind: kind) == .retained else { throw ServiceAccountProvisioningError.conflictingRecord }
        let record: ODRecord
        let values: [String: [String]]
        do {
            record = try node.record(withRecordType: kind == .user ? kODRecordTypeUsers : kODRecordTypeGroups,
                name: claim.name, attributes: attributes)
            guard let result = try record.recordDetails(forAttributes: attributes) as? [String: [String]] else {
                throw ServiceAccountProvisioningError.conflictingRecord
            }
            values = result
        } catch let error as ServiceAccountProvisioningError { throw error }
        catch { throw ServiceAccountProvisioningError.unavailable }
        let numeric = kind == .user ? kODAttributeTypeUniqueID : kODAttributeTypePrimaryGroupID
        let observed = try ServiceDirectoryRecord.decode(numbers: values[numeric] ?? [], ids: values[kODAttributeTypeGUID] ?? [],
            names: values[kODAttributeTypeRecordName] ?? [])
        guard observed.matches(claim, kind: kind) else { throw ServiceAccountProvisioningError.conflictingRecord }
        return values
    }
    private enum Index { case name(String), number(UInt32) }
    private struct User: Equatable { let number: UInt32; let group: UInt32; let name: String; let shell: String }
    private struct Group: Equatable { let number: UInt32; let name: String }
    private func user(_ index: Index) throws -> User? {
        var value = passwd(), result: UnsafeMutablePointer<passwd>?
        var bytes = [CChar](repeating: 0, count: 65_536)
        return try bytes.withUnsafeMutableBufferPointer { buffer in
            let status: Int32
            switch index {
            case .number(let uid): status = getpwuid_r(uid, &value, buffer.baseAddress!, buffer.count, &result)
            case .name(let name): status = getpwnam_r(name, &value, buffer.baseAddress!, buffer.count, &result)
            }
            guard status == 0 else { throw ServiceAccountProvisioningError.unavailable }
            guard result != nil else { return nil }
            guard let name = value.pw_name.flatMap({ String(validatingCString: $0) }),
                  let shell = value.pw_shell.flatMap({ String(validatingCString: $0) }) else { throw ServiceAccountProvisioningError.conflictingRecord }
            return .init(number: value.pw_uid, group: value.pw_gid, name: name, shell: shell)
        }
    }
    private func group(_ index: Index) throws -> Group? {
        var value = Darwin.group(), result: UnsafeMutablePointer<Darwin.group>?
        var bytes = [CChar](repeating: 0, count: 65_536)
        return try bytes.withUnsafeMutableBufferPointer { buffer in
            let status: Int32
            switch index {
            case .number(let gid): status = getgrgid_r(gid, &value, buffer.baseAddress!, buffer.count, &result)
            case .name(let name): status = getgrnam_r(name, &value, buffer.baseAddress!, buffer.count, &result)
            }
            guard status == 0 else { throw ServiceAccountProvisioningError.unavailable }
            guard result != nil else { return nil }
            guard let name = value.gr_name.flatMap({ String(validatingCString: $0) }) else { throw ServiceAccountProvisioningError.conflictingRecord }
            return .init(number: value.gr_gid, name: name)
        }
    }
}
