import Foundation

/// Holds an authenticated proposal in memory and exposes its credential-free preview.
/// Closing releases this object's proposal and prevents new requests. Existing requests remain independent.
public final class ReviewedSetupFile: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let preview: SetupPreview
    private let lock = NSLock()
    private var proposal: PortableSetup?

    init(proposal: PortableSetup) {
        self.proposal = proposal
        preview = proposal.preview
    }

    public func operation(action: SetupPortableImportOperation.Action, expected: SetupPortableImportProgress,
                          fileCustodyAccepted: Bool = false) throws -> SetupPortableImportOperation {
        try lock.withLock {
            guard let proposal else { throw AdministrativeSetupChannelError.closed }
            return try SetupPortableImportOperation(action: action, expected: expected, proposal: proposal,
                fileCustodyAccepted: fileCustodyAccepted)
        }
    }

    public func close() { lock.withLock { proposal = nil } }
    public var description: String { "ReviewedSetupFile(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
}
