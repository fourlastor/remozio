import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RootUpdateSchedulingRefreshTests: XCTestCase {
    private struct Failed: Error {}
    private func refresh(_ f: RootUpdateSchedulingFixture,
        verify: ((JournalTransaction) throws -> Void)? = nil) throws -> UpdateSchedulingIntent {
        try f.data.withCandidate { try f.owner.refreshUpdateSchedulingOffer(candidate: $0, verifyHost: verify ?? f.checkHost) }
    }
    func testStartupRefreshMigratesTheCommandSchemaWithoutOptionalPhonePush() throws {
        let f = try RootUpdateSchedulingFixture(startupOffer: false, gatewayEnabled: false)
        XCTAssertEqual(try f.data.db.read { try $0.storageSchemaVersion }, 15)
        let before = try f.data.store.read().committed
        let offer = try refresh(f)
        XCTAssertEqual(offer.snapshot.generation, 1); XCTAssertEqual(offer.snapshot.revision, 0)
        XCTAssertNil(offer.requestedAction)
        XCTAssertEqual(try f.data.db.read { try $0.storageSchemaVersion }, 17)
        XCTAssertEqual(try f.data.store.read().committed.ledgerDigest, before.ledgerDigest)
        XCTAssertEqual(try f.data.store.read().committed.journalHead, before.journalHead)
        XCTAssertNil(try f.data.store.read().pending)
        XCTAssertEqual(try f.status(), offer)
    }
    func testStatusBeforeStartupRefreshDoesNotMigrateOrOfferARelease() throws {
        let f = try RootUpdateSchedulingFixture(startupOffer: false, gatewayEnabled: false)
        let before = try f.data.store.read()
        XCTAssertThrowsError(try f.status())
        XCTAssertEqual(try f.data.db.read { try $0.storageSchemaVersion }, 15)
        XCTAssertEqual(try f.data.store.read(), before)
        XCTAssertFalse(f.owner.retired)
    }
    func testRepeatedRefreshPreservesAcceptedIntentAndDoesNotWriteAnotherCheckpoint() throws {
        let f = try RootUpdateSchedulingFixture()
        let control = try f.control(), accepted = try f.consume(control), before = try f.data.store.read()
        XCTAssertEqual(try refresh(f), accepted); XCTAssertEqual(try refresh(f), accepted)
        XCTAssertEqual(try f.data.store.read(), before)
        XCTAssertEqual(try f.status().requestedAction, .deferUpdate)
    }
    func testRefusedHostCannotMigrateOrPublishAnOffer() throws {
        let f = try RootUpdateSchedulingFixture(startupOffer: false, gatewayEnabled: false), before = try f.data.store.read()
        XCTAssertThrowsError(try refresh(f, verify: { _ in throw Failed() }))
        XCTAssertEqual(try f.data.store.read(), before)
        XCTAssertEqual(try f.data.db.read { try $0.storageSchemaVersion }, 15)
        XCTAssertFalse(f.owner.retired)
    }
    func testNewMachineGenerationPublishesOneOfferAndRejectsTheOldChallenge() throws {
        let f = try RootUpdateSchedulingFixture(), oldControl = try f.control()
        let first = try XCTUnwrap(f.data.machine.store.updateCandidate())
        let retired = try f.data.machine.store.retireUpdateCandidate(first)
        let second = try f.data.machine.select(first.preparation, replacing: retired)
        let offer = try refresh(f)
        XCTAssertEqual(offer.snapshot.generation, second.generation)
        XCTAssertEqual(offer.snapshot.generation, first.generation + 1)
        XCTAssertEqual(offer.snapshot.revision, 0); XCTAssertNil(offer.requestedAction)
        XCTAssertThrowsError(try f.consume(oldControl))
        let before = try f.data.store.read()
        XCTAssertEqual(try refresh(f), offer); XCTAssertEqual(try f.data.store.read(), before)
    }
}
