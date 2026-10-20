import Foundation

struct CloudflareAccessApplicationIdentity: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let accountID: String
    let applicationID: String
    let name: String
    let hostname: String
    let audience: String
    var description: String { "CloudflareAccessApplicationIdentity(redacted)" }
    var debugDescription: String { description }
}
