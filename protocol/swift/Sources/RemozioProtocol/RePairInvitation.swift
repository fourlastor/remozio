import Foundation

/// An unsigned selection for an existing enrollment. Only the setup transcript authorizes pairing.
public struct RePairInvitation: Sendable, CustomStringConvertible {
    public let invitation: PairingInvitation
    public let predecessor: PairingReplacement
    public var description: String { "RePairInvitation(redacted)" }

    private static let prefix = "remozio-repair:v1:"
    private static let maximumBytes = 640
    private static var limits: CBORLimits {
        get throws { try .init(maxBytes: maximumBytes, maxDepth: 2, maxItems: 12) }
    }

    public init(invitation: PairingInvitation, predecessor: PairingReplacement) {
        self.invitation = invitation
        self.predecessor = predecessor
    }

    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.array([.unsigned(1), .bytes(invitation.encode()),
            .array([.bytes(invitation.macID), .bytes(invitation.accountID),
                .bytes(predecessor.phoneID), .bytes(predecessor.epoch)])]), limits: Self.limits)
    }

    public func exportText() throws -> String {
        Self.prefix + (try encode()).base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .array(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              fields.count == 3, fields[0] == .unsigned(1), case .bytes(let ordinary) = fields[1],
              case .array(let scope) = fields[2], scope.count == 4,
              case .bytes(let phoneID) = scope[2], case .bytes(let epoch) = scope[3] else {
            throw PairingInvitationError.invalidInvitation
        }
        let invitation = try PairingInvitation.decode(ordinary)
        guard scope[0] == .bytes(invitation.macID), scope[1] == .bytes(invitation.accountID) else {
            throw PairingInvitationError.invalidInvitation
        }
        let result = try Self(invitation: invitation, predecessor: PairingReplacement(phoneID: phoneID, epoch: epoch))
        guard try result.encode() == bytes else { throw PairingInvitationError.invalidInvitation }
        return result
    }

    public static func importText(_ text: String) throws -> Self {
        guard text.utf8.count <= prefix.count + (maximumBytes * 4 + 2) / 3, text.hasPrefix(prefix) else {
            throw PairingInvitationError.invalidInvitation
        }
        let payload = text.dropFirst(prefix.count)
        guard !payload.isEmpty, payload.count % 4 != 1, payload.utf8.allSatisfy({ byte in
            (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte) || byte == 45 || byte == 95
        }) else { throw PairingInvitationError.invalidInvitation }
        let base64 = payload.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let padded = base64 + String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let bytes = Data(base64Encoded: padded) else { throw PairingInvitationError.invalidInvitation }
        let result = try decode(bytes)
        guard try result.exportText() == text else { throw PairingInvitationError.invalidInvitation }
        return result
    }

    public func matches(_ proposal: PairingPhoneProposal) -> Bool {
        let scope = proposal.phone.scope
        return scope.macID == invitation.macID && scope.accountID == invitation.accountID
            && scope.phoneID == predecessor.phoneID && scope.enrollmentEpoch != predecessor.epoch
            && proposal.replacement == predecessor
    }
}
