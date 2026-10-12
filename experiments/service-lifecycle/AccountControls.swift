import Darwin
import Foundation

@main struct AccountControls {
    static func main() throws {
        let own = getuid()
        guard own != 0 else { throw ServiceProbeError.account }
        let other: uid_t = own == 601 ? 602 : 601
        let valid = ServiceProbeTransportAccount(uid: other, gid: 601, groups: [601])
        try valid.validate(invokingUID: own)
        try valid.validate()
        let invalid: [(uid_t, gid_t, [gid_t], uid_t)] = [
            (0, 601, [601], own), (own, 601, [601], own), (UInt32.max, 601, [601], own),
            (other, UInt32.max, [601], own), (other, 601, [], own), (other, 601, [602], own),
            (other, 601, [601, 601], own), (other, 601, [602, 601], own),
            (other, 601, [0, 601], own), (other, 601, [80, 601], own),
            (other, 601, [601, UInt32.max], own), (other, 601, [601], 0),
            (other, 601, [601], UInt32.max),
        ]
        for (uid, gid, groups, invoker) in invalid {
            do {
                try ServiceProbeTransportAccount(uid: uid, gid: gid, groups: groups).validate(invokingUID: invoker)
                fatalError("Invalid account accepted")
            } catch ServiceProbeError.account {}
        }
        var queried: [String] = []
        try ServiceProbeTransportAccount.rejectAdministrators(uid: other) { uid, name in
            precondition(uid == other); queried.append(name); return false
        }
        precondition(queried == ["wheel", "admin"])
        for rejectedGroup in ["wheel", "admin"] {
            do {
                try ServiceProbeTransportAccount.rejectAdministrators(uid: other) { _, name in name == rejectedGroup }
                fatalError("Nested administrative membership accepted")
            } catch ServiceProbeError.account {}
            do {
                try ServiceProbeTransportAccount.rejectAdministrators(uid: other) { _, name in
                    if name == rejectedGroup { throw ServiceProbeError.account }
                    return false
                }
                fatalError("Membership lookup failure accepted")
            } catch ServiceProbeError.account {}
        }
        for name in ["wheel", "admin"] {
            _ = try ServiceProbeTransportAccount.groupMembership(uid: own, name: name)
        }
        print("Account controls passed: synthetic records, nested membership, lookup errors and native current-account queries. No account or service changed.")
    }
}
