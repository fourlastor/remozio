import Darwin
import Foundation
import RemozioMach

enum DedicatedServiceAccountError: Error { case unsafeAccount }

/// Reads account isolation before a native service opens credentials. It does not provision an account.
struct DedicatedServiceAccount: Equatable {
    let uid: uid_t
    let gid: gid_t
    let shell: String
    let groups: Set<gid_t>

    func validate(ownerUID: uid_t) throws {
        guard uid > 0, uid < UInt32.max, ownerUID > 0, ownerUID < UInt32.max, uid != ownerUID,
              gid > 0, gid < UInt32.max, ["/usr/bin/false", "/sbin/nologin"].contains(shell),
              !groups.isEmpty, groups.count <= 1024, groups.contains(gid),
              groups.isDisjoint(with: [0, 80, UInt32.max]) else { throw DedicatedServiceAccountError.unsafeAccount }
    }

    func validateProcess(realUID: uid_t, effectiveUID: uid_t, realGID: gid_t, effectiveGID: gid_t,
                         groups processGroups: Set<gid_t>) throws {
        guard realUID == uid, effectiveUID == uid, realGID == gid, effectiveGID == gid,
              processGroups.count <= 1024,
              processGroups.isSubset(of: groups), processGroups.isDisjoint(with: [0, 80, UInt32.max]) else {
            throw DedicatedServiceAccountError.unsafeAccount
        }
    }

    static func requireCurrent(serviceUID: uid_t, ownerUID: uid_t) throws {
        guard serviceUID > 0, serviceUID < UInt32.max, ownerUID > 0, ownerUID < UInt32.max, serviceUID != ownerUID,
              getuid() == serviceUID, geteuid() == serviceUID else { throw DedicatedServiceAccountError.unsafeAccount }
        let account = try resolve(uid: serviceUID)
        try account.validate(ownerUID: ownerUID)
        try rejectAdministrators(uid: serviceUID)
        let count = getgroups(0, nil)
        guard count >= 0, count <= 1024 else { throw DedicatedServiceAccountError.unsafeAccount }
        var groups = [gid_t](repeating: 0, count: Int(count))
        let observed = count == 0 ? 0 : getgroups(count, &groups)
        guard observed == count else { throw DedicatedServiceAccountError.unsafeAccount }
        try account.validateProcess(realUID: getuid(), effectiveUID: geteuid(), realGID: getgid(), effectiveGID: getegid(),
                                    groups: Set(groups))
    }

    static func resolve(uid: uid_t) throws -> Self {
        guard uid > 0, uid < UInt32.max else { throw DedicatedServiceAccountError.unsafeAccount }
        var storage = [CChar](repeating: 0, count: 65_536)
        var entry = passwd(), result: UnsafeMutablePointer<passwd>?
        return try storage.withUnsafeMutableBufferPointer { bytes in
            guard getpwuid_r(uid, &entry, bytes.baseAddress!, bytes.count, &result) == 0,
                  result != nil, entry.pw_uid == uid, let name = entry.pw_name,
                  let shell = entry.pw_shell, let shellValue = String(validatingCString: shell),
                  String(validatingCString: name)?.isEmpty == false, entry.pw_gid < UInt32.max else {
                throw DedicatedServiceAccountError.unsafeAccount
            }
            var groups = [Int32](repeating: 0, count: 1024), count: Int32 = 1024
            guard getgrouplist(name, Int32(bitPattern: entry.pw_gid), &groups, &count) >= 0,
                  count > 0, count <= 1024 else { throw DedicatedServiceAccountError.unsafeAccount }
            return Self(uid: uid, gid: entry.pw_gid, shell: shellValue,
                        groups: Set(groups.prefix(Int(count)).map { UInt32(bitPattern: $0) }))
        }
    }

    static func rejectAdministrators(uid: uid_t,
        membership: (uid_t, String) throws -> Bool = groupMembership) throws {
        for name in ["wheel", "admin"] {
            guard try !membership(uid, name) else { throw DedicatedServiceAccountError.unsafeAccount }
        }
    }

    static func groupMembership(uid: uid_t, name: String) throws -> Bool {
        guard ["wheel", "admin"].contains(name), uid > 0, uid < UInt32.max else {
            throw DedicatedServiceAccountError.unsafeAccount
        }
        var storage = [CChar](repeating: 0, count: 65_536)
        var entry = group(), result: UnsafeMutablePointer<group>?
        let gid: gid_t = try storage.withUnsafeMutableBufferPointer { bytes in
            guard getgrnam_r(name, &entry, bytes.baseAddress!, bytes.count, &result) == 0,
                  result != nil, let observedName = entry.gr_name, String(validatingCString: observedName) == name,
                  entry.gr_gid != UInt32.max else { throw DedicatedServiceAccountError.unsafeAccount }
            return entry.gr_gid
        }
        var userUUID = UUID().uuid, groupUUID = UUID().uuid, member: Int32 = -1
        guard mbr_uid_to_uuid(uid, &userUUID) == 0, mbr_gid_to_uuid(gid, &groupUUID) == 0,
              mbr_check_membership(&userUUID, &groupUUID, &member) == 0,
              member == 0 || member == 1 else { throw DedicatedServiceAccountError.unsafeAccount }
        return member == 1
    }
}
