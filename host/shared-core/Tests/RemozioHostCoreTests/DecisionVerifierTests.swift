#if os(Linux)
import Crypto
import Glibc
import Synchronization
#else
import CryptoKit
#endif
import Foundation
@testable import RemozioHostCore
import RemozioProtocol
import XCTest

final class DecisionVerifierTests: XCTestCase {
    private let epoch = UUID()
    private let revision = UUID()
    private let key = P256.Signing.PrivateKey()
    private func id(_ byte: UInt8, count: Int = 16) -> Data { Data(repeating: byte, count: count) }
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 4096, maxDepth: 12, maxItems: 256) } }
    private func contract(_ kind: RequestKind = .command) throws -> RequestContract {
        try RequestContract(requestKind: kind, wireVersion: 1, schemaVersion: 1)
    }
    private func request(_ kind: RequestKind = .command, action: CapturedAction = .init(choice: .execute, scope: .currentRequest)) throws -> IssuedRequestPayload {
        try IssuedRequestPayload(contract: contract(kind), macID: id(1), accountID: id(2), requestID: id(3), challenge: id(4, count: 32),
            requiredFeatures: [1], createdUnixMilliseconds: 10, expiresUnixMilliseconds: 20,
            canonicalCapture: Data([0xa0]), permittedActions: [action, .init(choice: .decline, scope: .currentRequest)],
            bodyLimits: limits, captureLimits: limits)
    }
    private func trust(_ request: IssuedRequestPayload, active: Bool = true, keyClass: ApprovalKeyClass = .biometric,
                       phone: UInt8 = 5, keyID: UInt8 = 6, mac: UInt8 = 1, account: UInt8 = 2,
                       allowed: Bool = true, localFeatures: Set<UInt64> = [1], peerFeatures: Set<UInt64> = [1],
                       peerSupported: Bool = true, localSupported: Bool = true, publicKey: Data? = nil) throws -> ApprovalTrustSnapshot {
        let enrolledKey = try EnrolledApprovalKey(id: id(keyID), keyClass: keyClass, publicKey: publicKey ?? key.publicKey.x963Representation)
        let enrollment = try ApprovalEnrollment(phoneID: id(phone), active: active,
            capabilities: ContractCapabilities(contracts: peerSupported ? [request.contract: peerFeatures] : [:]), keys: [enrolledKey])
        return try ApprovalTrustSnapshot(macID: id(mac), accountID: id(account), revision: revision,
            authorityCapabilities: ContractCapabilities(contracts: localSupported ? [request.contract: localFeatures] : [:]),
            allowedContracts: allowed ? [request.contract] : [], enrollments: [enrollment])
    }
    private func decision(_ request: IssuedRequestPayload, action: CapturedAction? = nil) throws -> Data {
        try DecisionPayload(macID: request.macID, accountID: request.accountID, requestID: request.requestID,
            requestDigest: request.requestDigest(bodyLimits: limits, signingLimits: limits), challenge: request.challenge,
            phoneID: id(5), keyID: id(6), action: action ?? request.permittedActions[0]).encode(limits: limits)
    }
    private func signature(_ bytes: Data, purpose: SigningPurpose = .biometricAuthorization) throws -> Data {
        try key.signature(for: SigningInput.make(wireVersion: 1, messageType: .decision, purpose: purpose,
            canonicalPayload: bytes, payloadLimits: limits, inputLimits: limits)).rawRepresentation
    }
    private func verify(_ request: IssuedRequestPayload, bytes: Data? = nil, signature suppliedSignature: Data? = nil,
                        trust suppliedTrust: ApprovalTrustSnapshot? = nil, phase: RequestPhase = .presented,
                        now: UInt64 = 150, clock: UUID? = nil, purpose: SigningPurpose = .biometricAuthorization) throws -> VerifiedDecision {
        let body = try bytes ?? decision(request)
        return try DecisionVerifier.verify(canonicalDecision: body, signature: suppliedSignature ?? signature(body, purpose: purpose),
            retained: RetainedApprovalRequest(payload: request, phase: phase,
                admittedAt: AuthorityMoment(epoch: epoch, milliseconds: 100), deadlineMilliseconds: 200),
            trust: suppliedTrust ?? trust(request), now: AuthorityMoment(epoch: clock ?? epoch, milliseconds: now),
            decisionLimits: limits, requestLimits: limits, signingLimits: limits)
    }
    private func expect(_ error: DecisionVerificationError, _ body: () throws -> VerifiedDecision,
                        file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) { XCTAssertEqual($0 as? DecisionVerificationError, error, file: file, line: line) }
    }

    func testAcceptedActionsDerivePurposeAndKeyClass() throws {
        let cases: [(RequestKind, CapturedAction, ApprovalKeyClass, SigningPurpose)] = [
            (.command, .init(choice: .execute, scope: .currentRequest), .biometric, .biometricAuthorization),
            (.onePasswordAccess, .init(choice: .approveAccess, scope: .currentRequest), .biometric, .biometricAuthorization),
            (.onePasswordUnlock, .init(choice: .unlockVault, scope: .currentRequest), .biometric, .biometricAuthorization),
            (.littleSnitch, .init(choice: .allowOnce, scope: .currentRequest), .decision, .oneTimeUI),
            (.littleSnitch, .init(choice: .denyOnce, scope: .currentRequest), .decision, .oneTimeUI),
            (.littleSnitch, .init(choice: .cancelTarget, scope: .currentRequest), .decision, .oneTimeUI),
            (.littleSnitch, .init(choice: .allowRule, scope: .forever), .biometric, .biometricAuthorization),
            (.littleSnitch, .init(choice: .denyRule, scope: .session), .biometric, .biometricAuthorization),
            (.littleSnitch, .init(choice: .removeRule, scope: .timed(seconds: 60)), .biometric, .biometricAuthorization),
        ]
        for (kind, action, keyClass, purpose) in cases {
            let request = try request(kind, action: action)
            let result = try verify(request, trust: trust(request, keyClass: keyClass), purpose: purpose)
            XCTAssertEqual(result.decision.action, action)
            XCTAssertEqual(result.requirement.keyClass, keyClass)
            XCTAssertEqual(result.trustRevision, revision)
            XCTAssertEqual(result.clockEpoch, epoch)
            XCTAssertEqual(result.deadlineMilliseconds, 200)
        }
        let request = try request()
        let result = try verify(request, bytes: decision(request, action: .init(choice: .decline, scope: .currentRequest)),
            trust: trust(request, keyClass: .decision), purpose: .cancellation)
        XCTAssertEqual(result.requirement.effect, .resolveRequest)
    }

    func testEveryRequestBindingIsCheckedEvenWithValidSignature() throws {
        let request = try request()
        guard case let .map(original) = try DeterministicCBOR.decode(decision(request), limits: limits) else { return XCTFail() }
        for field in UInt64(1)...5 {
            var fields = original
            fields[field] = .bytes(id(99, count: field == 4 || field == 5 ? 32 : 16))
            let bytes = try DeterministicCBOR.encode(.map(fields), limits: limits)
            expect(.wrongRequest) { try verify(request, bytes: bytes) }
        }
        expect(.wrongAccount) { try verify(request, trust: trust(request, mac: 9)) }
        expect(.wrongAccount) { try verify(request, trust: trust(request, account: 9)) }
    }

    func testCurrentEnrollmentAndKeyAreRequired() throws {
        let request = try request()
        expect(.unavailableEnrollment) { try verify(request, trust: trust(request, active: false)) }
        expect(.unavailableEnrollment) { try verify(request, trust: trust(request, phone: 9)) }
        expect(.wrongKey) { try verify(request, trust: trust(request, keyID: 9)) }
        expect(.wrongKeyClass) { try verify(request, trust: trust(request, keyClass: .decision)) }
        expect(.invalidSignature) { try verify(request, trust: trust(request, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)) }
        let declined = try decision(request, action: .init(choice: .decline, scope: .currentRequest))
        expect(.wrongKeyClass) { try verify(request, bytes: declined, purpose: .cancellation) }
    }

    func testExactActionAndSignatureContextAreRequired() throws {
        let request = try request(.littleSnitch, action: .init(choice: .allowRule, scope: .session))
        XCTAssertThrowsError(try verify(request, bytes: decision(request, action: .init(choice: .allowRule, scope: .forever)))) {
            XCTAssertEqual($0 as? ActionPolicyError, .notPermitted)
        }
        expect(.invalidSignature) { try verify(request, purpose: .oneTimeUI) }
        let original = try decision(request)
        var damaged = try signature(original)
        damaged[0] ^= 1
        expect(.invalidSignature) { try verify(request, signature: damaged) }
        expect(.invalidSignature) { try verify(request, signature: Data()) }
        let declined = try decision(request, action: .init(choice: .decline, scope: .currentRequest))
        expect(.invalidSignature) {
            try verify(request, bytes: declined, signature: signature(original), trust: trust(request, keyClass: .decision))
        }
    }

    func testCurrentCapabilitiesAndSecurityFloorAreRequired() throws {
        let request = try request()
        expect(.unsupportedContract) { try verify(request, trust: trust(request, allowed: false)) }
        expect(.unsupportedContract) { try verify(request, trust: trust(request, peerSupported: false)) }
        expect(.unsupportedContract) { try verify(request, trust: trust(request, localSupported: false)) }
        expect(.unsupportedFeatures) { try verify(request, trust: trust(request, localFeatures: [])) }
        expect(.unsupportedFeatures) { try verify(request, trust: trust(request, peerFeatures: [])) }
    }

    func testMonotonicDeadlineAndPendingPhaseAreRequired() throws {
        let request = try request()
        _ = try verify(request, phase: .queued, now: 100)
        _ = try verify(request, now: 199)
        expect(.expired) { try verify(request, now: 200) }
        expect(.expired) { try verify(request, now: UInt64.max) }
        expect(.invalidClock) { try verify(request, now: 99) }
        expect(.invalidClock) { try verify(request, clock: UUID()) }
        for phase in RequestPhase.allCases where phase != .queued && phase != .presented {
            expect(.unavailableRequest) { try verify(request, phase: phase) }
        }
    }

    #if os(Linux)
    func testReplacementLinuxAuthorityRejectsOldRequestWhileBoottimeContinuesForward() throws {
        let nanoseconds = Mutex(100_000_000)
        let sampler = try SleepInclusiveClock(readTime: { clockID, sample in
            XCTAssertEqual(clockID, CLOCK_BOOTTIME)
            sample.pointee = timespec(tv_sec: 0, tv_nsec: nanoseconds.withLock { $0 })
            return 0
        })
        let original = LinuxAuthorityClock(clock: sampler), request = try request()
        let retained = try RetainedApprovalRequest(payload: request, phase: .presented,
            admittedAt: original.now(), deadlineMilliseconds: 200)
        let body = try decision(request), signature = try signature(body), trust = try trust(request)
        nanoseconds.withLock { $0 = 150_000_000 }
        let beforeRestart = try original.now()
        let verified = try DecisionVerifier.verify(canonicalDecision: body, signature: signature, retained: retained,
            trust: trust, now: beforeRestart, decisionLimits: limits, requestLimits: limits, signingLimits: limits)
        XCTAssertEqual(verified.clockEpoch, original.epoch)

        nanoseconds.withLock { $0 = 175_000_000 }
        let replacement = LinuxAuthorityClock(clock: sampler), afterRestart = try replacement.now()
        XCTAssertGreaterThan(afterRestart.milliseconds, beforeRestart.milliseconds)
        XCTAssertLessThan(afterRestart.milliseconds, retained.deadlineMilliseconds)
        XCTAssertNotEqual(afterRestart.epoch, retained.admittedAt.epoch)
        expect(.invalidClock) {
            try DecisionVerifier.verify(canonicalDecision: body, signature: signature, retained: retained,
                trust: trust, now: afterRestart, decisionLimits: limits, requestLimits: limits, signingLimits: limits)
        }
    }
    #endif

    func testAmbiguousTrustedIdentitiesAndInvalidDeadlinesFail() throws {
        let request = try request(), snapshot = try trust(request)
        XCTAssertThrowsError(try RetainedApprovalRequest(payload: request, phase: .queued,
            admittedAt: AuthorityMoment(epoch: epoch, milliseconds: 100), deadlineMilliseconds: 100))
        XCTAssertThrowsError(try ApprovalTrustSnapshot(macID: id(1), accountID: id(2), revision: revision,
            authorityCapabilities: snapshot.authorityCapabilities, allowedContracts: snapshot.allowedContracts,
            enrollments: [snapshot.enrollments[0], snapshot.enrollments[0]]))
        let enrolled = snapshot.enrollments[0]
        XCTAssertThrowsError(try ApprovalEnrollment(phoneID: id(5), active: true, capabilities: enrolled.capabilities,
            keys: [enrolled.keys[0], enrolled.keys[0]]))
    }

    func testUntrustedBytesAreBoundedBeforeVerification() throws {
        let request = try request()
        XCTAssertThrowsError(try verify(request, bytes: Data(repeating: 0, count: 4097), signature: Data()))
        XCTAssertThrowsError(try verify(request, bytes: Data([0xa0]), signature: Data()))
        var trailing = try decision(request)
        trailing.append(0)
        XCTAssertThrowsError(try verify(request, bytes: trailing, signature: Data()))
    }
}
