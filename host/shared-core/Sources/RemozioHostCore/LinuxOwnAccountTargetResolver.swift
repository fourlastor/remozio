#if os(Linux)
import Foundation
import Glibc
import RemozioProtocol

public enum LinuxTargetResolutionError: Error, Equatable { case unavailable, invalidIdentity, unsupportedTarget }

/// NSS observations for an authenticated caller's own account only. No credential changes or execution authority.
public enum LinuxOwnAccountTargetResolver {
    public static func resolve(callerUID: UInt32, requestedTargetUID: UInt32) throws -> CommandTarget {
        try resolve(callerUID: callerUID, requestedTargetUID: requestedTargetUID, lookup: lookup)
    }

    // Internal seam for unavailable/malformed NSS results; production uses the OS functions below.
    static func resolve(callerUID: UInt32, requestedTargetUID: UInt32,
                        lookup: (UInt32) throws -> CommandTarget) throws -> CommandTarget {
        guard callerUID > 0, callerUID < UInt32.max, requestedTargetUID == callerUID else {
            throw LinuxTargetResolutionError.unsupportedTarget
        }
        let target = try lookup(callerUID)
        guard target.uid == callerUID, target.gid < UInt32.max,
              !target.supplementaryGroups.isEmpty, target.supplementaryGroups.count <= 1024,
              target.supplementaryGroups.contains(target.gid), !target.supplementaryGroups.contains(UInt32.max),
              zip(target.supplementaryGroups, target.supplementaryGroups.dropFirst()).allSatisfy({ $0.0 < $0.1 }),
              let name = target.observedName, !name.isEmpty, !name.utf8.contains(0) else {
            throw LinuxTargetResolutionError.invalidIdentity
        }
        return target
    }

    private static func lookup(_ uid: UInt32) throws -> CommandTarget {
        var buffer = [CChar](repeating: 0, count: 65_536)
        var entry = passwd(), result: UnsafeMutablePointer<passwd>?
        return try buffer.withUnsafeMutableBufferPointer { storage in
            guard getpwuid_r(uid, &entry, storage.baseAddress!, storage.count, &result) == 0, result != nil,
                  entry.pw_uid == uid, entry.pw_gid < UInt32.max, let nameBytes = entry.pw_name,
                  let name = String(validatingCString: nameBytes), !name.isEmpty else {
                throw LinuxTargetResolutionError.unavailable
            }
            var groups = [gid_t](repeating: 0, count: 1024), count: Int32 = 1024
            let status = groups.withUnsafeMutableBufferPointer {
                getgrouplist(nameBytes, entry.pw_gid, $0.baseAddress!, &count)
            }
            guard status >= 0, count > 0, count <= 1024 else { throw LinuxTargetResolutionError.unavailable }
            return CommandTarget(uid: uid, gid: entry.pw_gid,
                supplementaryGroups: Array(Set(groups.prefix(Int(count)))).sorted(), observedName: name)
        }
    }
}
#endif
