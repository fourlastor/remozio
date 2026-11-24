import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandTerminalResultTests: XCTestCase {
    private let profile = CommandHandshakeProfile(wireVersion: 3, submissionSchemaVersion: 1, inputCarrierVersion: 4,
        callerBinding: Data(repeating: 3, count: 16), macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16))
    private let request = CommandAdmittedRequest(requestID: Data(repeating: 6, count: 16),
        requestToken: Data(repeating: 7, count: 32), challenge: Data(repeating: 8, count: 32))
    private func original(arguments: [Data] = [Data("true".utf8)]) throws -> CommandSubmission {
        try CommandSubmission(schemaVersion: 1, executablePath: Data("/usr/bin/true".utf8), arguments: arguments,
            directoryPath: Data("/tmp".utf8), requestedTargetUID: 0, environmentAdditions: [], ioMode: .pipes,
            disconnectBehavior: .terminate, unverifiedRationale: nil,
            binding: .init(id: Data(repeating: 4, count: 16), nonce: Data(repeating: 5, count: 32), callerBinding: profile.callerBinding),
            limits: CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024))
    }
    private func admission(_ outcome: CommandAdmissionOutcome? = nil) throws -> VerifiedCommandAdmissionResult {
        let original = try original()
        let payload = CommandAdmissionResultPayload(profile: profile, submission: original.binding,
            submissionDigest: Data(SHA256.hash(data: original.canonicalBytes)), outcome: outcome ?? .admitted(request))
        return try CommandAdmissionResultPayload.decode(payload.canonicalBytes, profile: profile, original: original)
    }
    private func payload(_ outcome: CommandTerminalOutcome = .exited(0)) throws -> CommandTerminalResultPayload {
        .init(profile: profile, original: try original(), request: request, outcome: outcome)
    }
    private func mutated(_ change: (inout [UInt64: CBORValue]) -> Void) throws -> Data {
        guard case .map(var fields) = try DeterministicCBOR.decode(payload().canonicalBytes, limits: CommandTerminalResultPayload.limits()) else {
            throw CommandTerminalResultError.malformed
        }
        change(&fields)
        return try DeterministicCBOR.encode(.map(fields), limits: CommandTerminalResultPayload.limits())
    }
    private func reject(_ bytes: Data) throws {
        XCTAssertThrowsError(try CommandTerminalResultPayload.decode(bytes, profile: profile, original: original(), admission: admission()))
    }
    func testAllTerminalObservationsRoundTripAndPreserveAdmittedIdentity() throws {
        for outcome: CommandTerminalOutcome in [.exited(0), .exited(255), .signalled(UInt32(SIGTERM)), .denied, .expired,
            .cancelledBeforeStart, .requesterExitedBeforeStart, .failedBeforeStart, .unknown] {
            let result = try CommandTerminalResultPayload.decode(payload(outcome).canonicalBytes,
                profile: profile, original: original(), admission: admission())
            XCTAssertEqual(result.outcome, outcome); XCTAssertEqual(result.request, request)
            XCTAssertEqual(result.submission, try original().binding)
        }
    }
    func testRetainedCaptureBindingProducesTheOriginalTerminalEnvelope() throws {
        let original = try original(), digest = Data(SHA256.hash(data: original.canonicalBytes))
        for outcome: CommandTerminalOutcome in [.denied, .expired, .cancelledBeforeStart, .unknown] {
            let retained = CommandTerminalResultPayload(profile: profile, submission: original.binding,
                submissionDigest: digest, request: request, outcome: outcome)
            XCTAssertEqual(try retained.canonicalBytes, try payload(outcome).canonicalBytes)
            XCTAssertEqual(try CommandTerminalResultPayload.decode(retained.canonicalBytes, profile: profile,
                original: original, admission: admission()).outcome, outcome)
        }
    }
    func testRetainedCaptureRejectsMalformedOriginalBindingsAndDigest() throws {
        let original = try original(), digest = Data(SHA256.hash(data: original.canonicalBytes))
        let invalid: [(CapturedSubmission, Data)] = [
            (.init(id: Data(count: 15), nonce: original.binding.nonce, callerBinding: profile.callerBinding), digest),
            (.init(id: original.binding.id, nonce: Data(count: 31), callerBinding: profile.callerBinding), digest),
            (.init(id: original.binding.id, nonce: original.binding.nonce, callerBinding: Data(count: 16)), digest),
            (original.binding, Data(count: 31)),
        ]
        for (binding, digest) in invalid {
            XCTAssertThrowsError(try CommandTerminalResultPayload(profile: profile, submission: binding,
                submissionDigest: digest, request: request, outcome: .unknown).canonicalBytes)
        }
    }
    func testEveryScopeAndSubmissionAndRequestFieldMustMatch() throws {
        for key: UInt64 in 0...5 {
            try reject(mutated { fields in
                guard case .map(var body) = fields[1] else { return }
                body[key] = key < 3 ? .unsigned(99) : .bytes(Data(repeating: 99, count: 16)); fields[1] = .map(body)
            })
        }
        for nested: UInt64 in [2, 4] {
            for key: UInt64 in 0...2 {
                try reject(mutated { fields in
                    guard case .map(var body) = fields[nested] else { return }
                    body[key] = .bytes(Data(repeating: 99, count: 32)); fields[nested] = .map(body)
                })
            }
            try reject(mutated { fields in
                guard case .map(var body) = fields[nested] else { return }; body[99] = .null; fields[nested] = .map(body)
            })
        }
        try reject(mutated { $0[3] = .bytes(Data(repeating: 99, count: 32)) })
    }
    func testStatusAndSignalRangesAndNullBodiesAreStrict() throws {
        for pair: (UInt64, CBORValue) in [(1, .unsigned(256)), (1, .null), (2, .unsigned(0)),
            (2, .unsigned(UInt64(NSIG))), (2, .null), (0, .null), (9, .null)] {
            try reject(mutated { $0[5] = .unsigned(pair.0); $0[6] = pair.1 })
        }
        for tag: UInt64 in 3...8 { try reject(mutated { $0[5] = .unsigned(tag); $0[6] = .unsigned(0) }) }
        XCTAssertThrowsError(try payload(.signalled(0)).canonicalBytes)
        XCTAssertThrowsError(try payload(.signalled(UInt32(NSIG))).canonicalBytes)
    }
    func testRefusalOrUncertaintyCannotEstablishAnExecutionSession() throws {
        for outcome: CommandAdmissionOutcome in [.notAdmitted(.updateWaiting, .updateWaiting), .uncertain(.storageFailure)] {
            XCTAssertThrowsError(try CommandTerminalResultPayload.decode(payload().canonicalBytes,
                profile: profile, original: original(), admission: admission(outcome))) {
                XCTAssertEqual($0 as? CommandTerminalResultError, .incompatible)
            }
        }
    }
    func testChangedArgumentsOrAdmittedRequestCannotReuseTheResult() throws {
        XCTAssertThrowsError(try CommandTerminalResultPayload.decode(payload().canonicalBytes, profile: profile,
            original: original(arguments: [Data([0xff])]), admission: admission())) {
            XCTAssertEqual($0 as? CommandTerminalResultError, .wrongBinding)
        }
        let wrongChallenge = CommandAdmittedRequest(requestID: request.requestID, requestToken: request.requestToken, challenge: Data(count: 32))
        let wrongToken = CommandAdmittedRequest(requestID: request.requestID, requestToken: Data(count: 32), challenge: request.challenge)
        for different in [wrongChallenge, wrongToken] {
            XCTAssertThrowsError(try CommandTerminalResultPayload.decode(payload().canonicalBytes, profile: profile,
                original: original(), admission: admission(.admitted(different))))
        }
    }
    func testNoncanonicalOversizedUnknownAndMissingFieldsFail() throws {
        try reject(Data(count: 4097))
        try reject(mutated { $0[7] = .null }); try reject(mutated { $0.removeValue(forKey: 6) })
        try reject(mutated { $0[0] = .unsigned(2) })
        var bytes = try payload().canonicalBytes
        XCTAssertEqual(bytes[0], 0xa7); bytes.replaceSubrange(1...1, with: [0x18, 0x00]); try reject(bytes)
    }
    func testOutputInterruptionRequiresStreamingProfileAndExactCanonicalMarker() throws {
        let original = try original()
        XCTAssertThrowsError(try CommandTerminalResultPayload(profile: profile, original: original, request: request,
            outcome: .unknown, outputInterrupted: true).canonicalBytes)
        let streaming = CommandHandshakeProfile(wireVersion: 4, submissionSchemaVersion: 1, inputCarrierVersion: 4,
            callerBinding: profile.callerBinding, macID: profile.macID, accountID: profile.accountID)
        let admissionPayload = CommandAdmissionResultPayload(profile: streaming, submission: original.binding,
            submissionDigest: Data(SHA256.hash(data: original.canonicalBytes)), outcome: .admitted(request))
        let admitted = try CommandAdmissionResultPayload.decode(admissionPayload.canonicalBytes, profile: streaming, original: original)
        for interrupted in [false, true] {
            let payload = CommandTerminalResultPayload(profile: streaming, original: original, request: request,
                outcome: .signalled(UInt32(SIGKILL)), outputInterrupted: interrupted)
            let decoded = try CommandTerminalResultPayload.decode(payload.canonicalBytes, profile: streaming,
                original: original, admission: admitted)
            XCTAssertEqual(decoded.outputInterrupted, interrupted)
            XCTAssertEqual(decoded.outcome, .signalled(UInt32(SIGKILL)))
            guard case .map(var fields) = try DeterministicCBOR.decode(payload.canonicalBytes, limits: CommandTerminalResultPayload.limits()) else {
                return XCTFail("The result must retain its canonical envelope")
            }
            XCTAssertEqual(fields[7], interrupted ? .unsigned(1) : nil)
            for invalid: CBORValue in [.unsigned(0), .unsigned(2), .null, .bytes(Data([1]))] {
                fields[7] = invalid
                let bytes = try DeterministicCBOR.encode(.map(fields), limits: CommandTerminalResultPayload.limits())
                XCTAssertThrowsError(try CommandTerminalResultPayload.decode(bytes, profile: streaming, original: original, admission: admitted))
            }
        }
        try reject(mutated { $0[7] = .unsigned(1) })
    }

}
