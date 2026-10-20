import Foundation
import RemozioProtocol

public enum ConsumptionOutcomeError: Error, Equatable {
    case missingConsumption, staleRevision, corruptData, pageTooSmall
}

/// Persisted observation, not a live authorization or dispatch permit. Revision zero is the initial receipt.
public struct ConsumptionOutcome: Equatable, Sendable {
    public let receipt: ConsumptionReceipt
    public let revision: UInt64
    public let phase: RequestPhase
    public let event: AuditEventMetadata

    init(receipt: ConsumptionReceipt) {
        self.receipt = receipt; revision = 0; event = receipt.event
        phase = receipt.event.outcome == .noDispatch ? .declined : .authorized
    }

    init(receipt: ConsumptionReceipt, revision: UInt64, event: AuditEventMetadata) throws {
        guard receipt.event.outcome == .accepted, (1...2).contains(revision),
              event.macID == receipt.decision.macID, event.accountID == receipt.decision.accountID,
              event.requestID == receipt.decision.requestID, event.decisionPhoneID == receipt.decision.phoneID,
              event.category == receipt.event.category, event.action == receipt.event.action,
              event.authentication == .system, event.peerDeviceID == nil else { throw ConsumptionOutcomeError.corruptData }
        let phase: RequestPhase
        switch (event.kind, event.outcome, event.reason) {
        case (.dispatched, .attempted, .none) where revision == 1: phase = .executing
        case (.verifiedResult, .verifiedSuccess, .none) where revision == 2: phase = .succeeded
        case (.verifiedResult, .verifiedFailure, .none) where revision == 2: phase = .failed
        case (.unknownOutcome, .unresolved, .outcomeUnavailable), (.unknownOutcome, .unresolved, .authorityRestarted): phase = .unknown
        case (.cancelled, .noDispatch, .none) where revision == 1: phase = .cancelled
        default: throw ConsumptionOutcomeError.corruptData
        }
        self.receipt = receipt; self.revision = revision; self.phase = phase; self.event = event
    }

    func next(_ transition: RequestEvent, eventID: Data, receiptTimeMs: UInt64?, epoch: Data, sequence: UInt64) throws -> ConsumptionOutcome {
        _ = try RequestLifecycle.transition(from: phase, event: transition)
        let kind: AuditEventKind, outcome: AuditOutcome, reason: AuditReason
        switch transition {
        case .beginDispatch: kind = .dispatched; outcome = .attempted; reason = .none
        case .verifySuccess: kind = .verifiedResult; outcome = .verifiedSuccess; reason = .none
        case .verifyFailure: kind = .verifiedResult; outcome = .verifiedFailure; reason = .none
        case .loseOutcome: kind = .unknownOutcome; outcome = .unresolved; reason = .outcomeUnavailable
        case .restartAuthority: kind = .unknownOutcome; outcome = .unresolved; reason = .authorityRestarted
        case .proveNoDispatch: kind = .cancelled; outcome = .noDispatch; reason = .none
        default: throw LifecycleError.invalidTransition
        }
        let event = try AuditEventMetadata(eventID: eventID, macID: receipt.decision.macID, accountID: receipt.decision.accountID,
            journalEpoch: epoch, sequence: sequence, requestID: receipt.decision.requestID, eventTimeMs: nil,
            authorityReceiptTimeMs: receiptTimeMs, kind: kind, category: receipt.event.category, action: receipt.event.action,
            decisionPhoneID: receipt.decision.phoneID, authentication: .system, outcome: outcome, reason: reason,
            droppedEventCount: nil, peerDeviceID: nil)
        return try ConsumptionOutcome(receipt: receipt, revision: revision + 1, event: event)
    }
}

/// A bounded page of historical observations. The cursor carries no authorization.
public struct ConsumptionOutcomePage: Equatable, Sendable {
    public let outcomes: [ConsumptionOutcome]
    public let nextRequestID: Data?
}
