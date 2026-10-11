import Darwin
import Foundation
import RemozioProtocol

public enum CommandTargetResolutionError: Error, Equatable { case unavailable, invalidIdentity }

/// Resolves target credentials from the OS. It does not change process credentials or authorize execution.
public enum CommandTargetResolver {
    public static func resolve(uid: UInt32) throws -> CommandTarget {
        guard uid < UInt32.max else { throw CommandTargetResolutionError.invalidIdentity }
        var buffer = [CChar](repeating: 0, count: 65_536)
        var entry = passwd(), result: UnsafeMutablePointer<passwd>?
        return try buffer.withUnsafeMutableBufferPointer { storage in
            guard getpwuid_r(uid, &entry, storage.baseAddress!, storage.count, &result) == 0, result != nil,
                  entry.pw_uid == uid, entry.pw_gid < UInt32.max, let nameBytes = entry.pw_name,
                  let name = String(validatingCString: nameBytes), !name.isEmpty else {
                throw CommandTargetResolutionError.unavailable
            }
            var groups = [Int32](repeating: 0, count: 1024), count: Int32 = 1024
            let status = groups.withUnsafeMutableBufferPointer {
                getgrouplist(nameBytes, Int32(bitPattern: entry.pw_gid), $0.baseAddress!, &count)
            }
            guard status >= 0, count > 0, count <= 1024 else { throw CommandTargetResolutionError.unavailable }
            let resolved = Set(groups.prefix(Int(count)).map { UInt32(bitPattern: $0) }).sorted()
            guard resolved.contains(entry.pw_gid), !resolved.contains(UInt32.max) else {
                throw CommandTargetResolutionError.invalidIdentity
            }
            return CommandTarget(uid: uid, gid: entry.pw_gid, supplementaryGroups: resolved, observedName: name)
        }
    }
}
