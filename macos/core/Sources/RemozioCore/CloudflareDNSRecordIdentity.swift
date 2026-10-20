import Foundation

struct CloudflareDNSRecordIdentity: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let zoneID: String
    let recordID: String
    let hostname: String
    let target: String
    var description: String { "CloudflareDNSRecordIdentity(redacted)" }
    var debugDescription: String { description }
}
