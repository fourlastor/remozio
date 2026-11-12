import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Uses decoded owned archives. These comparisons prove no current source, file publication, or writer authority.
final class RetainedSetupPromotionTransitionTests: XCTestCase {
    private typealias Record = MachineUpdateRetainedSetupPromotionIntentRecord
    private typealias Fixture = RetainedSetupPromotionArchiveTests.Fixture
    private let adjacent: [(Record.Phase, Record.Phase)] = [(.prepared, .publishing), (.publishing, .filesPublished)]

    private func record(_ fixture: Fixture, phase: Record.Phase, id: UUID? = nil,
        revision: UUID? = nil, publication: Data? = nil) throws -> Record {
        var fields = fixture.recordFields
        fields[4] = .unsigned(phase.rawValue)
        if let id { fields[2] = .bytes(Fixture.bytes(id)) }
        if let revision { fields[3] = .bytes(Fixture.bytes(revision)) }
        if let publication { fields[5] = .bytes(publication) }
        return try .decode(fixture.record(fields))
    }

    func testAcceptsBothAdjacentPhasesWithExactPublicationAndFreshRevision() throws {
        let fixture = try Fixture()
        for (from, to) in adjacent {
            let before = try record(fixture, phase: from)
            let after = try record(fixture, phase: to, revision: UUID())
            XCTAssertEqual(before.id, after.id)
            XCTAssertNotEqual(before.revision, after.revision)
            XCTAssertEqual(before.publicationBytes, after.publicationBytes)
            XCTAssertNoThrow(try before.publication()); XCTAssertNoThrow(try after.publication())
            XCTAssertNoThrow(try after.requireTransition(from: before))
        }
    }

    func testRejectsSkippedReversedRepeatedAndTerminalTransitions() throws {
        let fixture = try Fixture()
        let invalid: [(Record.Phase, Record.Phase)] = [
            (.prepared, .prepared), (.prepared, .filesPublished),
            (.publishing, .prepared), (.publishing, .publishing),
            (.filesPublished, .prepared), (.filesPublished, .publishing), (.filesPublished, .filesPublished),
        ]
        for (from, to) in invalid {
            let before = try record(fixture, phase: from)
            let after = try record(fixture, phase: to, revision: UUID())
            XCTAssertEqual(before.id, after.id)
            XCTAssertNotEqual(before.revision, after.revision)
            XCTAssertEqual(before.publicationBytes, after.publicationBytes)
            XCTAssertThrowsError(try after.requireTransition(from: before)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
        }
    }

    func testRejectsAChangedIDWithOtherwiseValidAdjacentPhases() throws {
        let fixture = try Fixture()
        for (from, to) in adjacent {
            let before = try record(fixture, phase: from), revision = UUID()
            let valid = try record(fixture, phase: to, revision: revision)
            XCTAssertNoThrow(try valid.requireTransition(from: before))
            let changed = try record(fixture, phase: to, id: UUID(), revision: revision)
            XCTAssertNotEqual(changed.id, before.id)
            XCTAssertEqual(changed.revision, valid.revision)
            XCTAssertEqual(changed.publicationBytes, valid.publicationBytes)
            XCTAssertThrowsError(try changed.requireTransition(from: before)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
        }
    }

    func testRejectsAnUnchangedRevisionWithOtherwiseValidAdjacentPhases() throws {
        let fixture = try Fixture()
        for (from, to) in adjacent {
            let before = try record(fixture, phase: from)
            let valid = try record(fixture, phase: to, revision: UUID())
            XCTAssertNoThrow(try valid.requireTransition(from: before))
            let unchanged = try record(fixture, phase: to, revision: before.revision)
            XCTAssertEqual(unchanged.id, before.id)
            XCTAssertEqual(unchanged.publicationBytes, before.publicationBytes)
            XCTAssertThrowsError(try unchanged.requireTransition(from: before)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
        }
    }

    func testRejectsAChangedValidPublicationWithOtherwiseValidAdjacentPhases() throws {
        let fixture = try Fixture(), foreign = try Fixture(changedPolicy: true)
        let publication = try foreign.envelope()
        XCTAssertNoThrow(try RuntimeRetainedSetupCompletionPublication.decode(publication))
        for (from, to) in adjacent {
            let before = try record(fixture, phase: from), revision = UUID()
            let valid = try record(fixture, phase: to, revision: revision)
            XCTAssertNoThrow(try valid.requireTransition(from: before))
            let changed = try record(fixture, phase: to, revision: revision, publication: publication)
            XCTAssertNoThrow(try changed.publication())
            XCTAssertEqual(changed.id, before.id)
            XCTAssertEqual(changed.revision, valid.revision)
            XCTAssertNotEqual(changed.publicationBytes, before.publicationBytes)
            XCTAssertThrowsError(try changed.requireTransition(from: before)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
        }
    }
}
