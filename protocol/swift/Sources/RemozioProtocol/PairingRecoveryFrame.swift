import Foundation

public enum PairingRecoveryFrameError: Error { case invalidFrame }

/// The candidate names one retained attempt and proves possession of its transport key.
public struct PairingRecoveryQuery: Equatable, Sendable, CustomStringConvertible {
    public let setupID: Data
    public let transcriptDigest: Data
    public let scope: ChannelScope

    public init(setupID: Data, transcriptDigest: Data, scope: ChannelScope) throws {
        guard setupID.count == 16, transcriptDigest.count == 32 else {
            throw PairingRecoveryFrameError.invalidFrame
        }
        self.setupID = setupID
        self.transcriptDigest = transcriptDigest
        self.scope = scope
    }

    public var description: String { "PairingRecoveryQuery(redacted)" }

    public func signingInput(exporter: Data, challenge: Data) throws -> Data {
        guard exporter.count == 32, challenge.count == 32 else { throw PairingRecoveryFrameError.invalidFrame }
        let domain = Data("dev.remozio.pairing.recovery-lookup/1".utf8)
        return domain + Data([0]) + exporter + challenge + fixedBytes
    }

    fileprivate static let fixedLength = 112

    fileprivate var fixedBytes: Data {
        var bytes = setupID
        bytes.append(transcriptDigest)
        bytes.append(scope.macID)
        bytes.append(scope.accountID)
        bytes.append(scope.phoneID)
        bytes.append(scope.enrollmentEpoch)
        return bytes
    }

    fileprivate init(fixedBytes: Data) throws {
        guard fixedBytes.count == Self.fixedLength else { throw PairingRecoveryFrameError.invalidFrame }
        func field(_ offset: Int, _ length: Int) -> Data {
            Data(fixedBytes.dropFirst(offset).prefix(length))
        }
        let scope = try ChannelScope(macID: field(48, 16), accountID: field(64, 16),
            phoneID: field(80, 16), enrollmentEpoch: field(96, 16))
        try self.init(setupID: field(0, 16), transcriptDigest: field(16, 32), scope: scope)
    }
}

/// One query, one challenge, one proof, and one reply. The connection closes after the reply.
public enum PairingRecoveryFrame: Sendable, CustomStringConvertible {
    case lookup(PairingRecoveryQuery)
    case challenge(Data)
    case proof(Data)
    case refused
    case committed(signature: Data)
    case expired(PairingExpiryReceipt)

    public static let applicationProtocol = "remozio-pairing-recovery/1"
    public static let exporterLabel = "EXPORTER-dev.remozio.pairing.recovery-lookup/1"
    public static let maximumBytes = 1 + PairingExpiryReceipt.maximumBytes
    public var description: String { "PairingRecoveryFrame(redacted)" }

    public func encode() throws -> Data {
        switch self {
        case .lookup(let query):
            return Data([0]) + query.fixedBytes
        case .challenge(let challenge):
            guard challenge.count == 32 else { throw PairingRecoveryFrameError.invalidFrame }
            return Data([1]) + challenge
        case .proof(let signature):
            guard signature.count == 64 else { throw PairingRecoveryFrameError.invalidFrame }
            return Data([2]) + signature
        case .refused:
            return Data([3])
        case .committed(let signature):
            guard signature.count == 64 else { throw PairingRecoveryFrameError.invalidFrame }
            return Data([4]) + signature
        case .expired(let receipt):
            return try Data([5]) + receipt.encode()
        }
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard bytes.count <= maximumBytes, let tag = bytes.first else { throw PairingRecoveryFrameError.invalidFrame }
        let body = Data(bytes.dropFirst())
        switch tag {
        case 0:
            return try .lookup(PairingRecoveryQuery(fixedBytes: body))
        case 1 where body.count == 32:
            return .challenge(body)
        case 2 where body.count == 64:
            return .proof(body)
        case 3 where body.isEmpty:
            return .refused
        case 4 where body.count == 64:
            return .committed(signature: body)
        case 5:
            return try .expired(PairingExpiryReceipt.decode(body))
        default:
            throw PairingRecoveryFrameError.invalidFrame
        }
    }
}
