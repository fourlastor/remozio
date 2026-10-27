import Crypto
import Foundation
import RemozioHostCore
import RemozioProtocol

public enum FixtureError: Error {
    case failed(String)
}

public func require(_ condition: Bool, _ reason: String) throws {
    guard condition else { throw FixtureError.failed(reason) }
}

public func randomBytes(_ count: Int) -> Data {
    var generator = SystemRandomNumberGenerator()
    return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
}

public func digest(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

public struct FixtureApprovalMaterial: Sendable {
    public let request: IssuedRequestPayload
    public let retained: RetainedApprovalRequest
    public let trust: ApprovalTrustSnapshot
    public let decisionBytes: Data
    public let signature: Data

    public init(request: IssuedRequestPayload, retained: RetainedApprovalRequest, trust: ApprovalTrustSnapshot,
         decisionBytes: Data, signature: Data) {
        self.request = request
        self.retained = retained
        self.trust = trust
        self.decisionBytes = decisionBytes
        self.signature = signature
    }

    public func verify(now: AuthorityMoment) throws -> VerifiedDecision {
        try require(request == retained.payload, "fixture request retention mismatch")
        return try DecisionVerifier.verify(canonicalDecision: decisionBytes, signature: signature, retained: retained,
            trust: trust, now: now, decisionLimits: FixtureProtocol.limits,
            requestLimits: FixtureProtocol.limits, signingLimits: FixtureProtocol.limits)
    }

    public func withDecision(_ bytes: Data, signature: Data? = nil) -> Self {
        Self(request: request, retained: retained, trust: trust, decisionBytes: bytes,
            signature: signature ?? self.signature)
    }
}

public enum FixtureProtocol {
    public static let limits = try! CBORLimits(maxBytes: 32768, maxDepth: 32, maxItems: 4096)
    public static let macID = Data(repeating: 1, count: 16)
    public static let accountID = Data(repeating: 2, count: 16)

    /// Synthetic software keys never leave this process. The fixture does not establish biometric or hardware custody.
    public static func make(capture: Data, clock: LinuxAuthorityClock, decline: Bool = false) throws -> FixtureApprovalMaterial {
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 4)
        let capabilities = ContractCapabilities(contracts: [contract: []])
        let execute = CapturedAction(choice: .execute, scope: .currentRequest)
        let declined = CapturedAction(choice: .decline, scope: .currentRequest)
        let admitted = try clock.now()
        let lifetime: UInt64 = 60_000
        let deadline = admitted.milliseconds.addingReportingOverflow(lifetime)
        try require(!deadline.overflow, "fixture deadline overflow")

        // Capture semantics are checked by the fixture's admission boundary, not this common-wrapper builder.
        // Keeping that boundary separate lets malformed canonical-map captures exercise its refusal path.
        let issued = try IssuedRequestPayload(contract: contract, macID: macID, accountID: accountID,
            requestID: randomBytes(16), challenge: randomBytes(32), requiredFeatures: [],
            createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1000 + lifetime,
            canonicalCapture: capture, permittedActions: [execute, declined], bodyLimits: limits, captureLimits: limits)
        let requestBytes = try issued.encode(limits: limits)
        let authorityKey = P256.Signing.PrivateKey()
        let requestSignature = try authorityKey.signature(for: SigningInput.make(wireVersion: 1, messageType: .request,
            purpose: .issuedRequest, canonicalPayload: requestBytes, payloadLimits: limits, inputLimits: limits)).rawRepresentation
        try require(ApprovalSignature.verify(signature: requestSignature, publicKey: authorityKey.publicKey.x963Representation,
            wireVersion: 1, messageType: .request, purpose: .issuedRequest, canonicalPayload: requestBytes,
            payloadLimits: limits, inputLimits: limits), "fixture request signature")
        let request = try IssuedRequestPayload.decode(requestBytes, bodyLimits: limits, captureLimits: limits,
            localCapabilities: capabilities)
        try require(request == issued, "fixture request round trip")

        let phoneID = Data(repeating: 5, count: 16)
        let biometricKeyID = Data(repeating: 6, count: 16), decisionKeyID = Data(repeating: 7, count: 16)
        let biometricKey = P256.Signing.PrivateKey(), decisionKey = P256.Signing.PrivateKey()
        let enrollment = try ApprovalEnrollment(phoneID: phoneID, active: true, capabilities: capabilities, keys: [
            EnrolledApprovalKey(id: biometricKeyID, keyClass: .biometric, publicKey: biometricKey.publicKey.x963Representation),
            EnrolledApprovalKey(id: decisionKeyID, keyClass: .decision, publicKey: decisionKey.publicKey.x963Representation),
        ])
        let trust = try ApprovalTrustSnapshot(macID: macID, accountID: accountID, revision: UUID(),
            authorityCapabilities: capabilities, allowedContracts: [contract], enrollments: [enrollment])
        let retained = try RetainedApprovalRequest(payload: request, phase: .presented, admittedAt: admitted,
            deadlineMilliseconds: deadline.partialValue)
        let decision = try DecisionPayload(macID: request.macID, accountID: request.accountID, requestID: request.requestID,
            requestDigest: request.requestDigest(bodyLimits: limits, signingLimits: limits), challenge: request.challenge,
            phoneID: phoneID, keyID: decline ? decisionKeyID : biometricKeyID, action: decline ? declined : execute)
        let decisionBytes = try decision.encode(limits: limits)
        let signingKey = decline ? decisionKey : biometricKey
        let signature = try signingKey.signature(for: SigningInput.make(wireVersion: 1, messageType: .decision,
            purpose: decline ? .cancellation : .biometricAuthorization, canonicalPayload: decisionBytes,
            payloadLimits: limits, inputLimits: limits)).rawRepresentation
        return FixtureApprovalMaterial(request: request, retained: retained, trust: trust,
            decisionBytes: decisionBytes, signature: signature)
    }
}
