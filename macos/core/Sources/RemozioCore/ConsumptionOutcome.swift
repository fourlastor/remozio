import Foundation
import RemozioHostCore

public typealias ConsumptionOutcomeError = RemozioHostCore.ConsumptionOutcomeError
public typealias ConsumptionOutcome = RemozioHostCore.ConsumptionOutcome
public typealias ConsumptionOutcomePage = RemozioHostCore.ConsumptionOutcomePage

/// Recovery progress only. The host keeps admission closed until every batch and its checkpoint commit.
struct ConsumptionRecoveryBatch: Equatable, Sendable {
    let nextRequestID: Data?
    let changedCount: Int
    let journalHead: UInt64
}
