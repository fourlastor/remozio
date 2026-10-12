import Darwin
import Foundation

struct ServiceProbeTransportAccount: Equatable {
    static let name = "_remozio_lifecycle_transport"
    let uid: uid_t
    let gid: gid_t
    let groups: [gid_t]

    static func resolve(invokingUID: uid_t? = nil) throws -> Self {
        var storage = [CChar](repeating: 0, count: 65_536)
        var entry = passwd(), result: UnsafeMutablePointer<passwd>?
        return try storage.withUnsafeMutableBufferPointer { bytes in
            guard getpwnam_r(name, &entry, bytes.baseAddress!, bytes.count, &result) == 0,
                  result != nil, let observedName = entry.pw_name, String(validatingCString: observedName) == name,
                  let shell = entry.pw_shell, String(validatingCString: shell) == "/usr/bin/false" else {
                throw ServiceProbeError.account
            }
            var groups = [Int32](repeating: 0, count: 1024), count: Int32 = 1024
            guard getgrouplist(observedName, Int32(bitPattern: entry.pw_gid), &groups, &count) >= 0,
                  count > 0, count <= 1024 else { throw ServiceProbeError.account }
            let account = Self(uid: entry.pw_uid, gid: entry.pw_gid,
                groups: Set(groups.prefix(Int(count)).map { UInt32(bitPattern: $0) }).sorted())
            try account.validate(invokingUID: invokingUID)
            try rejectAdministrators(uid: account.uid)
            return account
        }
    }
    func validate(invokingUID: uid_t? = nil) throws {
        guard uid != 0, uid != UInt32.max, gid != UInt32.max,
              invokingUID == nil || (invokingUID != 0 && invokingUID != UInt32.max && uid != invokingUID),
              !groups.isEmpty, groups.count <= 1024, groups == Array(Set(groups)).sorted(),
              groups.contains(gid), !groups.contains(UInt32.max), !groups.contains(0), !groups.contains(80) else {
            throw ServiceProbeError.account
        }
    }
    static func rejectAdministrators(uid: uid_t,
        membership: (uid_t, String) throws -> Bool = groupMembership) throws {
        for name in ["wheel", "admin"] {
            guard try !membership(uid, name) else { throw ServiceProbeError.account }
        }
    }
    static func groupMembership(uid: uid_t, name: String) throws -> Bool {
        guard ["wheel", "admin"].contains(name), uid != UInt32.max else { throw ServiceProbeError.account }
        var storage = [CChar](repeating: 0, count: 65_536)
        var entry = group(), result: UnsafeMutablePointer<group>?
        let gid: gid_t = try storage.withUnsafeMutableBufferPointer { bytes in
            guard getgrnam_r(name, &entry, bytes.baseAddress!, bytes.count, &result) == 0,
                  result != nil, let observedName = entry.gr_name, String(validatingCString: observedName) == name,
                  entry.gr_gid != UInt32.max else { throw ServiceProbeError.account }
            return entry.gr_gid
        }
        var userUUID = UUID().uuid, groupUUID = UUID().uuid, member: Int32 = -1
        guard mbr_uid_to_uuid(uid, &userUUID) == 0, mbr_gid_to_uuid(gid, &groupUUID) == 0,
              mbr_check_membership(&userUUID, &groupUUID, &member) == 0,
              member == 0 || member == 1 else { throw ServiceProbeError.account }
        return member == 1
    }
    func revalidate(invokingUID: uid_t? = nil) throws {
        guard try Self.resolve(invokingUID: invokingUID) == self else { throw ServiceProbeError.account }
    }
}
