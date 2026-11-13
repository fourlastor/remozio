import CryptoKit
import Foundation
import XCTest
@testable import RemozioCore

final class RetainedSetupPromotionGateExclusionTests: XCTestCase {
    func testRetainedSQLEntryRefusesReservationAndStorageGatesWithoutNativeContext() throws {
        try MachineUpdateReplacementTests.withStableAccountReservationWriterFixture { f in
            XCTAssertTrue(try f.machine().withOwnedRetainedSetupPromotionSQLFixture { _ in true })
            var refusals = 0
            let verify: (PreparationIntentStore.CompletionIntentStorageStage, MachineUpdateStableAccountSetupSnapshot) throws -> Void = { _, _ in
                XCTAssertThrowsError(try f.machine().withOwnedRetainedSetupPromotionSQLFixture { _ -> Bool in
                    XCTFail("Another gate reached the retained SQL body"); return true
                }) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
                refusals += 1
            }
            _ = try f.machine().beginStableAccountPreparation(owner: f.owner, allowedTargetUIDs: [0], disclosureAccepted: true,
                expected: f.machine().stableAccountSetupSnapshot(owner: f.owner, candidate: f.candidate),
                candidate: f.candidate, directory: f.directory, admission: f.admission,
                makeInitial: f.initial, verifyScoped: verify)
            XCTAssertEqual(refusals, 4)
            let reserved = try f.machine().stableAccountSetupSnapshot(owner: f.owner, candidate: f.candidate)
            _ = try f.machine().pinStableAccountPreparation(publicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                expected: reserved, candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: verify)
            XCTAssertEqual(refusals, 8)
            XCTAssertTrue(try f.machine().withOwnedRetainedSetupPromotionSQLFixture { _ in true })
            try f.admission.validate()
        }
    }
}
