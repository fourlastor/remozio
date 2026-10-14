import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityPairingInvitationTests: XCTestCase {
    func testContextExportRetainsRootPinsAndScope() throws {
        let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
        let authority = P256.Signing.PrivateKey().publicKey.x963Representation
        let transport = P256.Signing.PrivateKey().publicKey.x963Representation
        let bytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account),
            3: .bytes(authority), 4: .bytes(transport), 5: .unsigned(1), 6: .unsigned(120000)]),
            limits: .init(maxBytes: 512, maxDepth: 1, maxItems: 15))
        let context = try AuthorityPairingContext.decode(bytes, macID: mac, accountID: account)
        let invitation = try PairingInvitation.importText(context.invitation(label: "Studio").exportText())
        XCTAssertEqual(invitation.macID, mac); XCTAssertEqual(invitation.accountID, account)
        XCTAssertEqual(invitation.authorityPublicKey, authority); XCTAssertEqual(invitation.transportPublicKey, transport)
        XCTAssertEqual(invitation.minimumEnvelopeVersion, 1)
        XCTAssertThrowsError(try context.invitation(label: "Studio\nMac"))
        XCTAssertThrowsError(try AuthorityPairingContext.decode(bytes, macID: Data(repeating: 3, count: 16), accountID: account))
    }
}
