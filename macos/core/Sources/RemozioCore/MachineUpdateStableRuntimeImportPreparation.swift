import CryptoKit
import Darwin
import Foundation

/// Joins retained import inputs with stable publication. The publication owner verifies actual runtime storage and files.
enum MachineUpdateStableRuntimeImportPreparation {
    typealias Verify = () throws -> Void
    struct RelaySelection: Equatable {
        let plan: SharedSetupImportRelayPlan?
        let snapshot: SharedSetupImportRelayStorage.Snapshot?
        init(plan: SharedSetupImportRelayPlan?, snapshot: SharedSetupImportRelayStorage.Snapshot?) throws {
            guard (plan == nil) == (snapshot == nil) else { throw SharedSetupImportError.conflict }
            if let plan, let snapshot {
                guard snapshot.digest == Data(SHA256.hash(data: plan.bytes)) else { throw SharedSetupImportError.conflict }
            }
            self.plan = plan; self.snapshot = snapshot
        }
        static func read(_ expected: SharedSetupImportIntent, directory: ProtectedSetupDirectory, owner: uid_t) throws -> Self {
            try .init(plan: SharedSetupImportRelayStorage.read(expected: expected, directory: directory, owner: owner),
                snapshot: SharedSetupImportRelayStorage.snapshot(expected: expected, directory: directory, owner: owner))
        }
    }
}
