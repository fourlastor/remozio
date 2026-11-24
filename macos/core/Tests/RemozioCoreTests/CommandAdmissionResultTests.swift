import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandAdmissionResultTests: XCTestCase {
    private var profile: CommandHandshakeProfile { .init(wireVersion: 2, submissionSchemaVersion: 1, inputCarrierVersion: 3,
        callerBinding: Data(repeating: 3, count: 16), macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16)) }
    private func original(arguments: [Data] = [Data("true".utf8)]) throws -> CommandSubmission {
        try CommandSubmission(schemaVersion: 1, executablePath: Data("/usr/bin/true".utf8), arguments: arguments,
            directoryPath: Data("/tmp".utf8), requestedTargetUID: 0, environmentAdditions: [], ioMode: .pipes,
            disconnectBehavior: .terminate, unverifiedRationale: nil,
            binding: .init(id: Data(repeating: 4, count: 16), nonce: Data(repeating: 5, count: 32), callerBinding: profile.callerBinding),
            limits: CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024))
    }
    private func payload(_ outcome: CommandAdmissionOutcome = .uncertain(.admissionRejected)) throws -> CommandAdmissionResultPayload {
        let original = try original()
        return .init(profile: profile, submission: original.binding, submissionDigest: Data(SHA256.hash(data: original.canonicalBytes)), outcome: outcome)
    }
    private func mutated(_ change: (inout [UInt64: CBORValue]) throws -> Void) throws -> Data {
        guard case .map(var fields) = try DeterministicCBOR.decode(payload().canonicalBytes, limits: CommandAdmissionResultPayload.limits()) else {
            throw CommandAdmissionResultError.malformed
        }
        try change(&fields)
        return try DeterministicCBOR.encode(.map(fields), limits: CommandAdmissionResultPayload.limits())
    }
    private func reject(_ bytes: Data) throws {
        XCTAssertThrowsError(try CommandAdmissionResultPayload.decode(bytes, profile: profile, original: original()))
    }
    func testAllKnownOutcomesRoundTripWithOnlyExactBusyRetryClasses() throws {
        let request = CommandAdmittedRequest(requestID: Data(repeating: 6, count: 16), requestToken: Data(repeating: 7, count: 32), challenge: Data(repeating: 8, count: 32))
        var outcomes: [CommandAdmissionOutcome] = [.admitted(request), .uncertain(.admissionRejected), .uncertain(.duplicateSubmission), .uncertain(.storageFailure)]
        for raw: UInt64 in 1...4 { outcomes.append(.notAdmitted(CommandAdmissionRejectionReason(rawValue: raw)!, CommandAdmissionRetryClass(rawValue: raw)!)) }
        for raw: UInt64 in 10...14 { outcomes.append(.notAdmitted(CommandAdmissionRejectionReason(rawValue: raw)!, .never)) }
        for outcome in outcomes {
            let value = try CommandAdmissionResultPayload.decode(payload(outcome).canonicalBytes, profile: profile, original: original())
            XCTAssertEqual(value.outcome, outcome); XCTAssertEqual(value.submission, try original().binding)
            XCTAssertEqual(value.submissionDigest, try payload().submissionDigest)
            if case .notAdmitted(_, let retry) = outcome { XCTAssertEqual(value.retryClass, retry) }
            else { XCTAssertEqual(value.retryClass, .never) }
        }
    }
    func testEveryScopeProfileAndSubmissionBindingMustMatch() throws {
        for key: UInt64 in 0...5 {
            try reject(mutated { fields in
                guard case .map(var selected) = fields[1] else { throw CommandAdmissionResultError.malformed }
                selected[key] = key < 3 ? .unsigned(99) : .bytes(Data(repeating: 99, count: 16)); fields[1] = .map(selected)
            })
        }
        for key: UInt64 in 0...2 {
            try reject(mutated { fields in
                guard case .map(var binding) = fields[2] else { throw CommandAdmissionResultError.malformed }
                binding[key] = .bytes(Data(repeating: 99, count: key == 1 ? 32 : 16)); fields[2] = .map(binding)
            })
        }
        try reject(mutated { $0[3] = .bytes(Data(repeating: 99, count: 32)) })
    }
    func testSameIdentifiersCannotBindAnAcknowledgmentToDifferentArguments() throws {
        let bytes = try payload(.notAdmitted(.updateInstalling, .updateInstalling)).canonicalBytes
        let changed = try original(arguments: [Data("different command".utf8)])
        XCTAssertThrowsError(try CommandAdmissionResultPayload.decode(bytes, profile: profile, original: changed)) {
            XCTAssertEqual($0 as? CommandAdmissionResultError, .wrongBinding)
        }
    }
    func testUnknownFieldsVersionsKindsAndUncertaintyCodesFail() throws {
        for change: (inout [UInt64: CBORValue]) -> Void in [
            { $0[6] = .null }, { $0[0] = .unsigned(2) }, { $0[4] = .unsigned(0) }, { $0[4] = .unsigned(4) },
            { $0[5] = .map([0: .unsigned(99)]) }, { $0[5] = .map([0: .unsigned(1), 1: .null]) },
        ] { try reject(mutated(change)) }
        for key: UInt64 in [1, 2] {
            try reject(mutated { fields in
                guard case .map(var nested) = fields[key] else { throw CommandAdmissionResultError.malformed }
                nested[99] = .null; fields[key] = .map(nested)
            })
        }
    }
    func testUnknownReasonsAndContradictoryRetryPairsFail() throws {
        for pair: (UInt64, UInt64) in [(0, 0), (99, 0), (1, 0), (1, 2), (10, 1), (4, 99)] {
            try reject(mutated { $0[4] = .unsigned(2); $0[5] = .map([0: .unsigned(pair.0), 1: .unsigned(pair.1)]) })
        }
        XCTAssertThrowsError(try payload(.notAdmitted(.updateInstalling, .never)).canonicalBytes)
        XCTAssertThrowsError(try payload(.notAdmitted(.policyRejected, .authorityStarting)).canonicalBytes)
    }
    func testAdmittedIdentityRequiresExactLengthsAndFields() throws {
        for key: UInt64 in 0...2 {
            for count in [0, 15, 17, 31, 33] {
                try reject(mutated { fields in
                    var body: [UInt64: CBORValue] = [0: .bytes(Data(count: 16)), 1: .bytes(Data(count: 32)), 2: .bytes(Data(count: 32))]
                    body[key] = .bytes(Data(count: count)); fields[4] = .unsigned(1); fields[5] = .map(body)
                })
            }
        }
        try reject(mutated { $0[4] = .unsigned(1); $0[5] = .map([0: .bytes(Data(count: 16)), 1: .bytes(Data(count: 32)), 2: .bytes(Data(count: 32)), 3: .null]) })
        try reject(mutated { $0[4] = .unsigned(2); $0[5] = .map([0: .unsigned(1), 1: .unsigned(1), 2: .null]) })
    }
    func testMalformedBindingAndOversizedOrNoncanonicalDataFail() throws {
        for key: UInt64 in [1, 2, 3] { try reject(mutated { $0[key] = .bytes(Data()) }) }
        try reject(Data(count: 4097))
        var bytes = try payload().canonicalBytes
        XCTAssertEqual(bytes[0], 0xa6)
        bytes.replaceSubrange(1...1, with: [0x18, 0x00])
        try reject(bytes)
    }
    func testLegacyRawReplyProfileCannotAcquireTypedResultMeaning() throws {
        let legacy = CommandHandshakeProfile(wireVersion: 1, submissionSchemaVersion: 1, inputCarrierVersion: 3,
            callerBinding: profile.callerBinding, macID: profile.macID, accountID: profile.accountID)
        XCTAssertThrowsError(try CommandAdmissionResultPayload.decode(payload().canonicalBytes, profile: legacy, original: original())) {
            XCTAssertEqual($0 as? CommandAdmissionResultError, .incompatible)
        }
        let impossible = CommandHandshakeProfile(wireVersion: 2, submissionSchemaVersion: 1, inputCarrierVersion: 2,
            callerBinding: profile.callerBinding, macID: profile.macID, accountID: profile.accountID)
        XCTAssertFalse(impossible.supported(by: try .init(wireVersions: [2], submissionSchemaVersions: [1], inputCarrierVersions: [2])))
    }
}
