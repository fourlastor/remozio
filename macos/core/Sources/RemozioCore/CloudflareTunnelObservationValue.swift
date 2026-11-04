import Foundation

struct CloudflareTunnelObservation: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let accountID: String
    let tunnelID: String
    let name: String
    var description: String { "CloudflareTunnelObservation(redacted)" }
    var debugDescription: String { description }
}
