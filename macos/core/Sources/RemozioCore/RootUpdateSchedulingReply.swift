import Foundation

/// The Root signs one query response after its challenge reaches both durable stores.
struct RootUpdateSchedulingReply: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let canonicalChallenge: Data
    let signature: Data
    var description: String { "RootUpdateSchedulingReply(redacted)" }
    var debugDescription: String { description }
}
