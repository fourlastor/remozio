import Foundation
import RemozioProtocol
import Security

public typealias AuthorityPairingLookupHandler = @Sendable (PairingRecoveryQuery, Data, Data) throws -> PairingRecoveryFrame
public typealias AuthorityPairingLookupProvider = @Sendable (
    ApprovalRequestCoordinator, PairingRecoveryQuery, Data, Data,
    @Sendable (JournalTransaction) throws -> Void
) throws -> PairingRecoveryFrame

enum PairingRecoveryIPC {
    case begin(PairingRecoveryQuery, exporter: Data, deadline: UInt64)
    case finish(Data)

    static func encodeBegin(_ query: PairingRecoveryQuery, exporter: Data, deadline: UInt64) throws -> Data {
        guard exporter.count == 32 else { throw PairingRecoveryFrameError.invalidFrame }
        let deadlineBytes = withUnsafeBytes(of: deadline.bigEndian) { Data($0) }
        return try PairingRecoveryFrame.lookup(query).encode() + exporter + deadlineBytes
    }

    static func decode(_ bytes: Data) throws -> Self {
        // A proof is a normal fixed-width wire frame. A lookup has two private TLS fields.
        if bytes.count == 65, case .proof(let signature) = try PairingRecoveryFrame.decode(bytes) {
            return .finish(signature)
        }
        guard bytes.count == 153,
              case .lookup(let query) = try PairingRecoveryFrame.decode(Data(bytes.prefix(113))) else {
            throw PairingRecoveryFrameError.invalidFrame
        }
        let exporter = Data(bytes.dropFirst(113).prefix(32))
        let deadline = bytes.suffix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        return .begin(query, exporter: exporter, deadline: deadline)
    }
}

/// Root owns this state for one admitted Transport XPC connection.
struct PairingRecoveryLookup {
    struct Attempt {
        let query: PairingRecoveryQuery
        let exporter: Data
        let challenge: Data
        let deadline: UInt64

        func signingInput() throws -> Data {
            try query.signingInput(exporter: exporter, challenge: challenge)
        }
    }

    private enum State { case waiting, challenged(Attempt), consumed }
    private var state = State.waiting

    mutating func begin(query: PairingRecoveryQuery, exporter: Data, deadline: UInt64,
                        now: UInt64 = DispatchTime.now().uptimeNanoseconds) throws -> Data {
        guard case .waiting = state, exporter.count == 32, deadline > now,
              deadline - now <= 60_000_000_000 else { throw PairingRecoveryFrameError.invalidFrame }
        state = .consumed
        var challenge = Data(count: 32)
        let status = challenge.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, bytes.count, bytes.baseAddress!)
        }
        guard status == errSecSuccess else { throw PairingRecoveryFrameError.invalidFrame }
        state = .challenged(Attempt(query: query, exporter: exporter, challenge: challenge, deadline: deadline))
        return challenge
    }

    mutating func consume(now: UInt64 = DispatchTime.now().uptimeNanoseconds) -> Attempt? {
        defer { state = .consumed }
        guard case .challenged(let attempt) = state, now < attempt.deadline else { return nil }
        return attempt
    }
}
