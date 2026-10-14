import Darwin
import Foundation
import RemozioProtocol

public enum TransportPairingControlError: Error, Equatable {
    case invalidConfiguration, wrongAccount, invalidMessage, closed, busy, timedOut, unsupportedVersion
}

/// Protected metadata for the app-to-transport setup channel. It grants no enrollment authority.
public struct TransportPairingControlConfiguration: Sendable, CustomStringConvertible {
    public let macID: Data
    public let accountID: Data
    public let ownerUID: UInt32
    public let transportUID: UInt32
    public let serviceName: String
    public let appPolicy: XPCPeerPolicy
    public let transportPolicy: XPCPeerPolicy
    public let timeoutMilliseconds: UInt64
    public let setupTimeoutMilliseconds: UInt64
    public let maximumCandidates: Int
    public let canonicalBytes: Data
    public var description: String { "TransportPairingControlConfiguration(redacted)" }
    public init(macID: Data, accountID: Data, ownerUID: UInt32, transportUID: UInt32, serviceName: String,
                teamID: String, appIdentifier: String, appHashes: Set<Data>, transportIdentifier: String,
                transportHashes: Set<Data>, timeoutMilliseconds: UInt64 = 5000,
                setupTimeoutMilliseconds: UInt64 = 300_000, maximumCandidates: Int = 2) throws {
        guard macID.count == 16, accountID.count == 16, ownerUID > 0, ownerUID < UInt32.max,
              transportUID > 0, transportUID < UInt32.max, ownerUID != transportUID,
              GatewayWakeEndpointConfiguration.validServiceName(serviceName), (1...60_000).contains(timeoutMilliseconds),
              (1...300_000).contains(setupTimeoutMilliseconds), (1...8).contains(maximumCandidates) else {
            throw TransportPairingControlError.invalidConfiguration
        }
        appPolicy = try .init(teamID: teamID, componentIdentifier: appIdentifier,
            approvedCodeDirectoryHashes: appHashes, expectedUserID: ownerUID)
        transportPolicy = try .init(teamID: teamID, componentIdentifier: transportIdentifier,
            approvedCodeDirectoryHashes: transportHashes, expectedUserID: transportUID)
        self.macID = macID; self.accountID = accountID; self.ownerUID = ownerUID; self.transportUID = transportUID
        self.serviceName = serviceName; self.timeoutMilliseconds = timeoutMilliseconds
        self.setupTimeoutMilliseconds = setupTimeoutMilliseconds; self.maximumCandidates = maximumCandidates
        canonicalBytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID),
            3: .unsigned(UInt64(ownerUID)), 4: .unsigned(UInt64(transportUID)), 5: .text(serviceName), 6: .text(teamID),
            7: .text(appIdentifier), 8: .array(appHashes.sorted { $0.lexicographicallyPrecedes($1) }.map(CBORValue.bytes)),
            9: .text(transportIdentifier), 10: .array(transportHashes.sorted { $0.lexicographicallyPrecedes($1) }.map(CBORValue.bytes)),
            11: .unsigned(timeoutMilliseconds), 12: .unsigned(setupTimeoutMilliseconds),
            13: .unsigned(UInt64(maximumCandidates))]), limits: Self.limits)
    }
    /// Public metadata still requires Root ownership and protected ancestors.
    public static func load(path: String) throws -> Self { try decode(ProtectedServiceConfiguration.readPublic(path: path)) }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...13),
              f[0] == .unsigned(1), case .bytes(let mac) = f[1], case .bytes(let account) = f[2],
              case .unsigned(let owner) = f[3], let ownerUID = UInt32(exactly: owner),
              case .unsigned(let transport) = f[4], let transportUID = UInt32(exactly: transport),
              case .text(let service) = f[5], case .text(let team) = f[6], case .text(let app) = f[7],
              case .array(let appHashes) = f[8], case .text(let identifier) = f[9], case .array(let transportHashes) = f[10],
              case .unsigned(let timeout) = f[11], case .unsigned(let setup) = f[12],
              case .unsigned(let count) = f[13], let maximum = Int(exactly: count) else {
            throw TransportPairingControlError.invalidConfiguration
        }
        func hashes(_ values: [CBORValue]) throws -> Set<Data> {
            guard (1...16).contains(values.count) else { throw TransportPairingControlError.invalidConfiguration }
            return try Set(values.map { value in
                guard case .bytes(let data) = value else { throw TransportPairingControlError.invalidConfiguration }; return data
            })
        }
        let value = try Self(macID: mac, accountID: account, ownerUID: ownerUID, transportUID: transportUID,
            serviceName: service, teamID: team, appIdentifier: app, appHashes: hashes(appHashes),
            transportIdentifier: identifier, transportHashes: hashes(transportHashes), timeoutMilliseconds: timeout,
            setupTimeoutMilliseconds: setup, maximumCandidates: maximum)
        guard value.canonicalBytes == bytes else { throw TransportPairingControlError.invalidConfiguration }; return value
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: 4096, maxDepth: 2, maxItems: 96) } }
}

/// Local transport progress only. None of these phases establishes a Root commit or phone activation.
public enum TransportPairingPhase: UInt64, Sendable {
    case proposed = 0, sendingTranscript = 1, awaitingProof = 2, proofReady = 3, sendingReceipt = 4, receiptSent = 5
}
public struct TransportPairingCandidate: Sendable, CustomStringConvertible {
    public let id: Data
    public let proposal: PairingPhoneProposal
    public let phase: TransportPairingPhase
    public let biometricProof: Data?
    public var description: String { "TransportPairingCandidate(redacted)" }
    init(id: Data, proposal: PairingPhoneProposal, phase: TransportPairingPhase, biometricProof: Data?) throws {
        guard id.count == 16, biometricProof.map({ $0.count == 64 }) ?? true,
              (phase.rawValue >= TransportPairingPhase.proofReady.rawValue) == (biometricProof != nil) else {
            throw TransportPairingControlError.invalidMessage
        }
        self.id = id; self.proposal = proposal; self.phase = phase; self.biometricProof = biometricProof
    }
}
public struct TransportPairingSnapshot: Sendable, CustomStringConvertible {
    public let port: UInt16
    public let candidates: [TransportPairingCandidate]
    public var description: String { "TransportPairingSnapshot(redacted)" }
    static let maximumBytes = 530_000
    init(port: UInt16, candidates: [TransportPairingCandidate]) throws {
        guard port > 0, candidates.count <= 8, Set(candidates.map(\.id)).count == candidates.count else {
            throw TransportPairingControlError.invalidMessage
        }
        self.port = port; self.candidates = candidates
    }
    func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .unsigned(UInt64(port)),
            2: .array(candidates.map { candidate in .array([.bytes(candidate.id), .bytes(try candidate.proposal.encode()),
                .unsigned(candidate.phase.rawValue), candidate.biometricProof.map(CBORValue.bytes) ?? .null]) })]), limits: Self.limits)
    }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...2),
              f[0] == .unsigned(1), case .unsigned(let number) = f[1], let port = UInt16(exactly: number),
              case .array(let rows) = f[2], rows.count <= 8 else { throw TransportPairingControlError.invalidMessage }
        let candidates = try rows.map { row -> TransportPairingCandidate in
            guard case .array(let r) = row, r.count == 4, case .bytes(let id) = r[0], case .bytes(let proposal) = r[1],
                  case .unsigned(let raw) = r[2], let phase = TransportPairingPhase(rawValue: raw) else {
                throw TransportPairingControlError.invalidMessage
            }
            let proof: Data?
            switch r[3] { case .null: proof = nil; case .bytes(let data): proof = data; default: throw TransportPairingControlError.invalidMessage }
            return try .init(id: id, proposal: .decode(proposal), phase: phase, biometricProof: proof)
        }
        let value = try Self(port: port, candidates: candidates)
        guard try value.encode() == bytes else { throw TransportPairingControlError.invalidMessage }; return value
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 3, maxItems: 96) } }
}
