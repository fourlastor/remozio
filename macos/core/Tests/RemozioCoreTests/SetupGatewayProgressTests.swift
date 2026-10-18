import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class SetupGatewayProgressTests: XCTestCase {
    private let limits = try! CBORLimits(maxBytes: 2048, maxDepth: 2, maxItems: 64)
    private func progress(_ f: GatewayJournalSetupExchangeTests.Fixture, unprepared: Bool = false) throws -> SetupGatewayProgress {
        try .init(account: f.runtime.account, runtime: f.runtime.machine.runtimePreparation(accountID: f.intent.accountID),
            activation: f.runtime.machine.runtimeActivation(accountID: f.intent.accountID),
            material: unprepared ? .init(reference: nil) : f.runtime.machine.gatewayPreparation(accountID: f.intent.accountID),
            journal: unprepared ? .init(intent: nil, initialized: false) : f.state())
    }
    private func changed(_ bytes: Data, _ edit: (inout [UInt64: CBORValue]) -> Void) throws -> Data {
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw GatewayPreparationError.invalidRecord }
        edit(&fields); return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    func testUnpreparedPendingAndCompletedProgressRoundTrip() throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture()
        let empty = try progress(f, unprepared: true), pending = try progress(f)
        XCTAssertNil(empty.gatewayMaterialID); XCTAssertNil(empty.journalIntentDigest); XCTAssertFalse(empty.journalInitialized)
        XCTAssertNotNil(pending.gatewayMaterialID); XCTAssertEqual(pending.journalIntentDigest, try f.intent.digest)
        XCTAssertFalse(pending.journalInitialized)
        try pending.validatePreparation(of: empty); try pending.validatePreparation(of: pending)
        XCTAssertThrowsError(try pending.validateJournalCompletion(of: pending))
        try f.retainCompletion(.decode(f.initialize()))
        let completed = try progress(f)
        try completed.validateJournalCompletion(of: pending)
        XCTAssertThrowsError(try pending.validatePreparation(of: completed))
        for value in [empty,pending,completed] { XCTAssertEqual(try SetupGatewayProgress.decode(value.bytes), value) }
    }
    func testMalformedVersionPurposeIdentifiersAndFieldSetsAreRejected() throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture(), bytes = try progress(f).bytes
        for key in [UInt64(2),3,4,5,7,8,9,10] {
            XCTAssertThrowsError(try SetupGatewayProgress.decode(changed(bytes) { $0[key] = .bytes(Data([1])) }))
        }
        for edit: (inout [UInt64: CBORValue]) -> Void in [
            { $0[0] = .unsigned(2) }, { $0[1] = .text("foreign-purpose") }, { $0[12] = .null }, { $0.removeValue(forKey: 8) },
            { $0[6] = .unsigned(0) }, { $0[6] = .unsigned(UInt64(UInt32.max)) }, { $0[11] = .unsigned(1) },
            { $0[9] = .null }, { $0[10] = .null; $0[11] = .boolean(true) }
        ] { XCTAssertThrowsError(try SetupGatewayProgress.decode(changed(bytes, edit))) }
        XCTAssertThrowsError(try SetupGatewayProgress.decode(bytes + Data([0])))
        XCTAssertThrowsError(try SetupGatewayProgress.decode(Data(repeating: 0, count: 641)))
    }
    func testChangedAccountForegroundMaterialOrIntentCannotMasqueradeAsACompletion() throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture(), pending = try progress(f)
        try f.retainCompletion(.decode(f.initialize())); let completed = try progress(f), bytes = try completed.bytes
        for key in [UInt64(2),3,4,5,7,8,9,10] {
            let count = [UInt64(8),10].contains(key) ? 32 : 16
            let other = try SetupGatewayProgress.decode(changed(bytes) { $0[key] = .bytes(Data(repeating: 99, count: count)) })
            XCTAssertThrowsError(try other.validateJournalCompletion(of: pending))
        }
        let otherOwner = try SetupGatewayProgress.decode(changed(bytes) { $0[6] = .unsigned(UInt64(pending.ownerUID) + 1) })
        XCTAssertThrowsError(try otherOwner.validateJournalCompletion(of: pending))
    }
    func testACompletionRequiresAPreviouslyPreparedIntentAndAnInitializedJournal() throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture(), empty = try progress(f, unprepared: true), pending = try progress(f)
        XCTAssertThrowsError(try SetupGatewayJournalResult(progress: pending, cleanupComplete: true))
        try f.retainCompletion(.decode(f.initialize())); let completed = try progress(f)
        XCTAssertThrowsError(try completed.validateJournalCompletion(of: empty))
        for cleaned in [false,true] {
            let result = try SetupGatewayJournalResult(progress: completed, cleanupComplete: cleaned)
            XCTAssertEqual(try SetupGatewayJournalResult.decode(result.bytes), result)
            XCTAssertThrowsError(try SetupGatewayProgress.decode(result.bytes))
            XCTAssertThrowsError(try SetupGatewayJournalResult.decode(completed.bytes))
        }
    }
    func testResultRejectsAlteredPurposeVersionAndAnUninitializedNestedRecord() throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture(), pending = try progress(f)
        try f.retainCompletion(.decode(f.initialize()))
        let result = try SetupGatewayJournalResult(progress: progress(f), cleanupComplete: false), bytes = try result.bytes
        for edit: (inout [UInt64: CBORValue]) -> Void in [
            { $0[0] = .unsigned(2) }, { $0[1] = .text("foreign-purpose") }, { $0[4] = .null }, { $0[3] = .unsigned(1) }
        ] { XCTAssertThrowsError(try SetupGatewayJournalResult.decode(changed(bytes, edit))) }
        let uninitialized = try pending.bytes
        XCTAssertThrowsError(try SetupGatewayJournalResult.decode(changed(bytes) { $0[2] = .bytes(uninitialized) }))
        XCTAssertThrowsError(try SetupGatewayJournalResult.decode(Data(repeating: 0, count: 769)))
    }
}
