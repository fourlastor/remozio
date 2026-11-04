import Darwin
import Foundation
import RemozioProtocol
@testable import RemozioCore

/// Ordinary-owner paired journal and continuity stores for cutover inspection tests.
/// It mirrors the private CheckpointedJournalTests fixture and adds read-only cutover opening.
/// It does not prove Root placement or native service account isolation.
final class CutoverJournalFixture {
    private enum Fault: Error { case injected }
    let root: URL
    let maximumConsumptions: Int
    let epoch = Data(repeating: 3, count: 16)
    let limits = try! CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
    var journal: JournalDatabase!
    var store: ContinuityStore!
    var writer: AuditEpochWriter!
    init(authorityGeneration: UInt64? = 7, maximumConsumptions: Int = 10) throws {
        self.maximumConsumptions = maximumConsumptions
        guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Fault.injected }
        defer { free(canonical) }
        root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        for name in ["journal", "continuity"] {
            let directory = root.appendingPathComponent(name)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for file in ["writer.lock", "\(name).sqlite"] {
                let fd = Darwin.open(directory.appendingPathComponent(file).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw Fault.injected }
                Darwin.close(fd)
            }
        }
        journal = try openJournal(initialize: true)
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(Data(repeating: 1, count: 16)), 2: .bytes(Data(repeating: 2, count: 16)),
            3: .bytes(epoch), 4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
        writer = try journal.write { try $0.createEpoch(descriptor) }
        store = try openStore(initial: observed(generation: 1, authorityGeneration: authorityGeneration))
    }
    deinit { try? journal?.close(); store?.close(); try? FileManager.default.removeItem(at: root) }
    func openJournal(initialize: Bool = false, readOnlyForCutover: Bool = false) throws -> sending JournalDatabase {
        try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "journal", owner: geteuid()),
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            recordLimits: limits, descriptorLimits: limits, decisionLimits: limits, maximumConsumptions: maximumConsumptions,
            busyMilliseconds: 100, initialize: initialize, readOnlyForCutover: readOnlyForCutover)
    }
    func openStore(initial: ContinuityCheckpoint? = nil, readOnlyForCutover: Bool = false) throws -> sending ContinuityStore {
        try ContinuityStore(lease: ProtectedContinuityLease(anchor: root.path, relativeDirectory: "continuity", owner: geteuid(), excludingDirectory: nil),
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16), initialize: initial, readOnlyForCutover: readOnlyForCutover)
    }
    func observed(generation: UInt64, authorityGeneration: UInt64? = 7) throws -> ContinuityCheckpoint {
        try journal.read { try CheckpointedJournal.checkpoint(transaction: $0, epoch: epoch, generation: generation, authorityGeneration: authorityGeneration) }
    }
    func openTransferredStorage(readOnlyForCutover: Bool = false) throws -> sending AuthorityStorage {
        let anchor = root.path, limits = self.limits
        return try AuthorityStorage(openJournal: {
            try JournalDatabase(lease: ProtectedJournalLease(anchor: anchor, relativeDirectory: "journal", owner: geteuid()),
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 10, busyMilliseconds: 100, initialize: false, readOnlyForCutover: readOnlyForCutover)
        }, openContinuity: { journalDirectory in
            try ContinuityStore(lease: ProtectedContinuityLease(anchor: anchor, relativeDirectory: "continuity", owner: geteuid(),
                excludingDirectory: journalDirectory),
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16), initialize: nil, readOnlyForCutover: readOnlyForCutover)
        })
    }
}
