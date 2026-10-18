#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
import Foundation
import XCTest
@testable import RemozioProtocol

final class LinuxCommandCaptureTests: XCTestCase {
    private struct Bounds: Decodable {
        let maxBytes: Int
        let maxDepth: Int
        let maxItems: Int
        var value: CBORLimits { get throws { try .init(maxBytes: maxBytes, maxDepth: maxDepth, maxItems: maxItems) } }
    }
    private struct Row: Decodable {
        let name: String
        let hex: String
        let limits: Bounds?
        let arguments: [String]?
        let environmentNames: [String]?
        let requestedExecutablePath: String?
        let requesterExecutablePath: String?
        let requesterPID: UInt32?
        let processBinding: String?
        let monitorIncarnation: String?
        let execEpoch: String?
        let sessionID: UInt32?
        let codePolicyDigest: String?
        let credentialUIDs: [UInt32]?
        let credentialGIDs: [UInt32]?
        let supplementaryGroups: [UInt32]?
        let inputKind: UInt64?
        let streamKinds: [UInt64]?
        let streamAccess: [UInt64]?
        let streamFlags: [UInt64]?
        let ptyMask: UInt32?
        let ancestry: UInt64?
        let rationale: String?
        let captureSHA256: String?
    }
    private struct Mutation: Decodable {
        let name: String
        let base: String
        let field: String
        let hex: String
        let captureSHA256: String
        let validCapture: Bool
    }
    private struct ContractBinding: Decodable {
        let name: String
        let capture: String
        let outerSchema: UInt64
        let selectedSchema: UInt64
        let accepted: Bool
    }
    private struct Vectors: Decodable {
        let defaultLimits: Bounds
        let valid: [Row]
        let invalid: [Row]
        let digestMutations: [Mutation]
        let contractBindings: [ContractBinding]
    }
    private func vectorData(_ schema: Int) throws -> Data {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try Data(contentsOf: root.appendingPathComponent("vectors/command-capture-v\(schema).json"))
    }
    private func vectors() throws -> Vectors { try JSONDecoder().decode(Vectors.self, from: vectorData(4)) }
    private func hex(_ value: String) -> Data {
        var result = Data(), cursor = value.startIndex
        while cursor < value.endIndex {
            let end = value.index(cursor, offsetBy: 2)
            result.append(UInt8(value[cursor..<end], radix: 16)!)
            cursor = end
        }
        return result
    }
    private var limits: CBORLimits { get throws { try vectors().defaultLimits.value } }
    private func base() throws -> LinuxCommandCapture {
        let row = try XCTUnwrap(vectors().valid.first { $0.name == "schema4-base" })
        return try LinuxCommandCapture(canonicalBytes: hex(row.hex), limits: limits)
    }
    private func produce(_ capture: LinuxCommandCapture, schema: UInt64 = 4, arguments: [Data]? = nil,
                         input: CapturedCommandInput? = nil, mode: CommandIOMode = .pipes,
                         disconnect: StartedCommandDisconnect = .terminate, requester: CapturedLinuxRequester? = nil,
                         ancestry: CapturedAncestry? = nil, layout: CapturedCommandStdioLayout? = nil,
                         limits: CBORLimits? = nil) throws -> LinuxCommandCapture {
        try LinuxCommandCapture(schemaVersion: schema, executable: capture.executable, arguments: arguments ?? capture.arguments,
            directory: capture.directory, target: capture.target, environment: capture.environment, input: input ?? capture.input,
            ioMode: mode, disconnectBehavior: disconnect, requester: requester ?? capture.requester,
            ancestry: ancestry ?? capture.ancestry, unverifiedRationale: capture.unverifiedRationale,
            submission: capture.submission, stdioLayout: layout ?? capture.stdioLayout, limits: limits ?? self.limits)
    }
    private func requester(_ source: CapturedLinuxRequester, profile: String? = nil, pid: UInt32? = nil,
                           processBinding: Data? = nil, monitorIncarnation: Data? = nil, execEpoch: UInt64? = nil,
                           credentials: CapturedLinuxCredentials? = nil, sessionID: UInt32? = nil,
                           codePolicyDigest: Data? = nil) -> CapturedLinuxRequester {
        .init(profile: profile ?? source.profile, pid: pid ?? source.pid, processBinding: processBinding ?? source.processBinding,
            monitorIncarnation: monitorIncarnation ?? source.monitorIncarnation, execEpoch: execEpoch ?? source.execEpoch,
            executable: source.executable, credentials: credentials ?? source.credentials, sessionID: sessionID ?? source.sessionID,
            codePolicyDigest: codePolicyDigest ?? source.codePolicyDigest)
    }
    private func credentials(_ source: CapturedLinuxCredentials, effectiveUID: UInt32? = nil,
                             effectiveGID: UInt32? = nil, groups: [UInt32]? = nil) -> CapturedLinuxCredentials {
        .init(realUID: source.realUID, effectiveUID: effectiveUID ?? source.effectiveUID, savedUID: source.savedUID,
            filesystemUID: source.filesystemUID, realGID: source.realGID, effectiveGID: effectiveGID ?? source.effectiveGID,
            savedGID: source.savedGID, filesystemGID: source.filesystemGID, supplementaryGroups: groups ?? source.supplementaryGroups)
    }

    func testSharedVectorsPreserveLinuxIdentityRawBytesAndEncoderOutput() throws {
        let vectors = try vectors(), limits = try vectors.defaultLimits.value
        XCTAssertFalse(vectors.valid.isEmpty)
        for row in vectors.valid {
            let bytes = hex(row.hex), capture = try LinuxCommandCapture(canonicalBytes: bytes, limits: limits)
            XCTAssertEqual(capture.schemaVersion, 4, row.name)
            XCTAssertEqual(capture.canonicalBytes, bytes, row.name)
            XCTAssertEqual(try produce(capture), capture, row.name)
            XCTAssertEqual(capture.arguments, try XCTUnwrap(row.arguments).map(hex), row.name)
            XCTAssertEqual(capture.environment.map(\.name), try XCTUnwrap(row.environmentNames).map(hex), row.name)
            XCTAssertEqual(capture.executable.path, hex(try XCTUnwrap(row.requestedExecutablePath)), row.name)
            XCTAssertEqual(capture.requester.executable.path, hex(try XCTUnwrap(row.requesterExecutablePath)), row.name)
            XCTAssertEqual(capture.requester.profile, CapturedLinuxRequester.supportedProfile, row.name)
            XCTAssertEqual(capture.requester.pid, row.requesterPID, row.name)
            XCTAssertEqual(capture.requester.processBinding, hex(try XCTUnwrap(row.processBinding)), row.name)
            XCTAssertEqual(capture.requester.monitorIncarnation, hex(try XCTUnwrap(row.monitorIncarnation)), row.name)
            XCTAssertEqual(capture.requester.execEpoch, UInt64(try XCTUnwrap(row.execEpoch)), row.name)
            XCTAssertEqual(capture.requester.sessionID, row.sessionID, row.name)
            XCTAssertEqual(capture.requester.codePolicyDigest, hex(try XCTUnwrap(row.codePolicyDigest)), row.name)
            let credentials = capture.requester.credentials
            XCTAssertEqual([credentials.realUID, credentials.effectiveUID, credentials.savedUID, credentials.filesystemUID], row.credentialUIDs, row.name)
            XCTAssertEqual([credentials.realGID, credentials.effectiveGID, credentials.savedGID, credentials.filesystemGID], row.credentialGIDs, row.name)
            XCTAssertEqual(credentials.supplementaryGroups, row.supplementaryGroups, row.name)
            let layout = capture.stdioLayout, streams = [layout.input, layout.output, layout.error]
            XCTAssertEqual(layout.input.source, capture.input, row.name)
            XCTAssertEqual(capture.input.kind.rawValue, row.inputKind, row.name)
            XCTAssertEqual(streams.map { $0.source.kind.rawValue }, row.streamKinds, row.name)
            XCTAssertEqual(streams.map { $0.access.rawValue }, row.streamAccess, row.name)
            XCTAssertEqual(streams.map { $0.flags.rawValue }, row.streamFlags, row.name)
            XCTAssertEqual(layout.ptyMask, row.ptyMask, row.name)
            XCTAssertEqual(layout.ptyMask, 0, row.name)
            XCTAssertNil(layout.terminal, row.name)
            XCTAssertEqual(capture.ioMode, .pipes, row.name)
            XCTAssertEqual(capture.disconnectBehavior, .terminate, row.name)
            XCTAssertEqual(capture.ancestry.completeness.rawValue, row.ancestry, row.name)
            XCTAssertEqual(capture.ancestry, .init(completeness: .unavailable, entries: [], reason: .unsupported), row.name)
            XCTAssertEqual(capture.unverifiedRationale, row.rationale, row.name)
            XCTAssertEqual(Data(SHA256.hash(data: bytes)), hex(try XCTUnwrap(row.captureSHA256)), row.name)
        }
    }

    func testSharedInvalidVectorsFailWithTheirIndependentResourceBounds() throws {
        let vectors = try vectors()
        XCTAssertFalse(vectors.invalid.isEmpty)
        for row in vectors.invalid {
            let limits = try (row.limits ?? vectors.defaultLimits).value
            XCTAssertThrowsError(try LinuxCommandCapture(canonicalBytes: hex(row.hex), limits: limits), row.name)
        }
    }

    func testMacSchemaSupportAndExplicitExpectedVersionRemainSeparate() throws {
        XCTAssertEqual(CommandCapture.supportedSchemaVersions, [1, 2, 3])
        XCTAssertEqual(LinuxCommandCapture.supportedSchemaVersions, [4])
        let capture = try base()
        XCTAssertThrowsError(try CommandCapture(canonicalBytes: capture.canonicalBytes, limits: limits))
        for schema: UInt64 in [0, 1, 2, 3, 5, UInt64.max] {
            XCTAssertThrowsError(try LinuxCommandCapture(canonicalBytes: capture.canonicalBytes, limits: limits, expectedSchemaVersion: schema))
            XCTAssertThrowsError(try produce(capture, schema: schema))
        }
        XCTAssertThrowsError(try CommandCapture(canonicalBytes: capture.canonicalBytes, limits: limits, expectedSchemaVersion: 4))
        struct MacVectors: Decodable { let valid: [Row] }
        for schema in [1, 2, 3] {
            let rows = try JSONDecoder().decode(MacVectors.self, from: vectorData(schema)).valid
            for row in rows {
                XCTAssertThrowsError(try LinuxCommandCapture(canonicalBytes: hex(row.hex), limits: limits), row.name)
            }
        }
    }

    func testFullUnsignedEpochAndIndependentCredentialRolesRoundTrip() throws {
        let capture = try base()
        for epoch in [UInt64(1), UInt64(Int64.max), UInt64(Int64.max) + 1, UInt64.max] {
            let changed = try produce(capture, requester: requester(capture.requester, execEpoch: epoch))
            XCTAssertEqual(changed.requester.execEpoch, epoch)
            XCTAssertEqual(try produce(changed), changed)
        }
        let independent = CapturedLinuxCredentials(realUID: UInt32.max, effectiveUID: UInt32.max, savedUID: UInt32.max,
            filesystemUID: UInt32.max, realGID: 0, effectiveGID: 0, savedGID: 0, filesystemGID: 0, supplementaryGroups: [])
        XCTAssertEqual(try produce(capture, requester: requester(capture.requester, credentials: independent)).requester.credentials, independent)
        let highestGroups = credentials(capture.requester.credentials, groups: [0, UInt32.max])
        XCTAssertEqual(try produce(capture, requester: requester(capture.requester, credentials: highestGroups)).requester.credentials, highestGroups)
        XCTAssertEqual(try produce(capture, requester: requester(capture.requester, pid: UInt32(Int32.max), sessionID: UInt32(Int32.max))).requester.pid, UInt32(Int32.max))
    }

    func testTypedProducerRejectsUnsupportedAdmissionAndStreamClaims() throws {
        let capture = try base(), source = capture.requester
        let invalid = [requester(source, profile: "linux-other"), requester(source, pid: 0), requester(source, pid: UInt32.max),
            requester(source, processBinding: Data(repeating: 1, count: 15)), requester(source, monitorIncarnation: Data(repeating: 2, count: 17)),
            requester(source, execEpoch: 0), requester(source, sessionID: 0), requester(source, sessionID: UInt32.max),
            requester(source, codePolicyDigest: Data(repeating: 3, count: 31)),
            requester(source, credentials: credentials(source.credentials, effectiveUID: source.credentials.realUID ^ 1)),
            requester(source, credentials: credentials(source.credentials, effectiveGID: source.credentials.realGID ^ 1)),
            requester(source, credentials: credentials(source.credentials, groups: [2, 1])),
            requester(source, credentials: credentials(source.credentials, groups: [1, 1]))]
        for requester in invalid { XCTAssertThrowsError(try produce(capture, requester: requester)) }
        XCTAssertThrowsError(try produce(capture, arguments: []))
        XCTAssertThrowsError(try produce(capture, arguments: [Data([0])]))
        XCTAssertThrowsError(try produce(capture, mode: .pty))
        XCTAssertThrowsError(try produce(capture, disconnect: .continueRunning))
        XCTAssertThrowsError(try produce(capture, ancestry: .init(completeness: .complete, entries: [], reason: .none)))
        let layout = capture.stdioLayout
        XCTAssertThrowsError(try produce(capture, layout: .init(input: layout.input, output: layout.output, error: layout.error, terminal: nil, ptyMask: 1)))
        let invalidOutput = CapturedCommandStream(source: layout.output.source, access: .readOnly, flags: layout.output.flags)
        XCTAssertThrowsError(try produce(capture, layout: .init(input: layout.input, output: invalidOutput, error: layout.error, terminal: nil, ptyMask: 0)))
        let invalidFlags = CapturedCommandStream(source: layout.output.source, access: .writeOnly, flags: .init(rawValue: 16))
        XCTAssertThrowsError(try produce(capture, layout: .init(input: layout.input, output: invalidFlags, error: layout.error, terminal: nil, ptyMask: 0)))
        let otherInput = CapturedCommandInput(kind: .pipe, streamBinding: Data(repeating: 0x85, count: 16), observedPath: nil, identity: nil)
        XCTAssertThrowsError(try produce(capture, input: otherInput))
    }

    private func issued(_ bytes: Data, schema: UInt64 = 4) throws -> IssuedRequestPayload {
        try IssuedRequestPayload(contract: .init(requestKind: .command, wireVersion: 1, schemaVersion: schema),
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16), requestID: Data(repeating: 3, count: 16),
            challenge: Data(repeating: 4, count: 32), requiredFeatures: [], createdUnixMilliseconds: 10, expiresUnixMilliseconds: 20,
            canonicalCapture: bytes, permittedActions: [.init(choice: .execute, scope: .currentRequest)], bodyLimits: limits, captureLimits: limits)
    }

    func testEveryRequesterAndStreamMutationChangesBothApprovalDigests() throws {
        let vectors = try vectors()
        XCTAssertFalse(vectors.digestMutations.isEmpty)
        for mutation in vectors.digestMutations {
            let original = try XCTUnwrap(vectors.valid.first { $0.name == mutation.base }), bytes = hex(mutation.hex)
            let changed = try issued(bytes), base = try issued(hex(original.hex))
            XCTAssertNotEqual(bytes, base.canonicalCapture, mutation.name)
            XCTAssertEqual(changed.captureDigest, hex(mutation.captureSHA256), mutation.name)
            XCTAssertNotEqual(changed.captureDigest, base.captureDigest, mutation.name)
            XCTAssertNotEqual(try changed.requestDigest(bodyLimits: limits, signingLimits: limits),
                try base.requestDigest(bodyLimits: limits, signingLimits: limits), mutation.name)
            if mutation.validCapture { XCTAssertNoThrow(try LinuxCommandCapture(canonicalBytes: bytes, limits: limits), mutation.name) }
            else { XCTAssertThrowsError(try LinuxCommandCapture(canonicalBytes: bytes, limits: limits), mutation.name) }
        }
    }

    func testIssuedRequestRequiresCapabilityAndCaptureVersionBinding() throws {
        let capture = try base(), request = try issued(capture.canonicalBytes)
        let linux = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 4)
        let mac = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 3)
        let supported = ContractCapabilities(contracts: [linux: [], mac: []])
        let decoded = try IssuedRequestPayload.decode(request.encode(limits: limits), bodyLimits: limits, captureLimits: limits, localCapabilities: supported)
        XCTAssertEqual(try LinuxCommandCapture(canonicalBytes: decoded.canonicalCapture, limits: limits,
            expectedSchemaVersion: decoded.contract.schemaVersion), capture)
        XCTAssertThrowsError(try IssuedRequestPayload.decode(request.encode(limits: limits), bodyLimits: limits, captureLimits: limits,
            localCapabilities: ContractCapabilities(contracts: [mac: []]))) { XCTAssertEqual($0 as? IssuedRequestError, .unsupportedContract) }
        let mislabeled = try issued(capture.canonicalBytes, schema: 3)
        let wrongContract = try IssuedRequestPayload.decode(mislabeled.encode(limits: limits), bodyLimits: limits, captureLimits: limits, localCapabilities: supported)
        XCTAssertThrowsError(try LinuxCommandCapture(canonicalBytes: wrongContract.canonicalCapture, limits: limits,
            expectedSchemaVersion: wrongContract.contract.schemaVersion))
        XCTAssertThrowsError(try CommandCapture(canonicalBytes: wrongContract.canonicalCapture, limits: limits,
            expectedSchemaVersion: wrongContract.contract.schemaVersion))
        guard case var .map(root) = try DeterministicCBOR.decode(request.encode(limits: limits), limits: limits) else {
            return XCTFail("issued request must be a map")
        }
        root[10] = .bytes(try produce(capture, requester: requester(capture.requester, execEpoch: UInt64.max)).canonicalBytes)
        XCTAssertThrowsError(try IssuedRequestPayload.decode(DeterministicCBOR.encode(.map(root), limits: limits), bodyLimits: limits,
            captureLimits: limits, localCapabilities: supported)) { XCTAssertEqual($0 as? IssuedRequestError, .captureDigestMismatch) }
    }

    func testSharedContractBindingsRequireMatchingSelectedOuterAndInnerSchema() throws {
        let vectors = try vectors()
        XCTAssertFalse(vectors.contractBindings.isEmpty)
        for binding in vectors.contractBindings {
            let row = try XCTUnwrap(vectors.valid.first { $0.name == binding.capture })
            let request = try issued(hex(row.hex), schema: binding.outerSchema)
            let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: binding.selectedSchema)
            func receive() throws -> LinuxCommandCapture {
                let decoded = try IssuedRequestPayload.decode(request.encode(limits: limits), bodyLimits: limits,
                    captureLimits: limits, localCapabilities: ContractCapabilities(contracts: [contract: []]))
                return try LinuxCommandCapture(canonicalBytes: decoded.canonicalCapture, limits: limits,
                    expectedSchemaVersion: decoded.contract.schemaVersion)
            }
            if binding.accepted { XCTAssertNoThrow(try receive(), binding.name) }
            else { XCTAssertThrowsError(try receive(), binding.name) }
        }
    }

    func testIndependentResourceBoundsAndValueSemantics() throws {
        let capture = try base(), original = capture.canonicalBytes
        var bytes = original
        let retained = try LinuxCommandCapture(canonicalBytes: bytes, limits: limits)
        bytes[0] ^= 1
        var processBinding = retained.requester.processBinding
        processBinding[0] ^= 1
        var arguments = retained.arguments
        arguments[0][0] ^= 1
        XCTAssertEqual(retained, capture)
        XCTAssertNotEqual(processBinding, retained.requester.processBinding)
        XCTAssertNotEqual(arguments, retained.arguments)
        let limits = try self.limits
        for bound in [try CBORLimits(maxBytes: original.count - 1, maxDepth: limits.maxDepth, maxItems: limits.maxItems),
                      try CBORLimits(maxBytes: limits.maxBytes, maxDepth: 1, maxItems: limits.maxItems),
                      try CBORLimits(maxBytes: limits.maxBytes, maxDepth: limits.maxDepth, maxItems: 2)] {
            XCTAssertThrowsError(try LinuxCommandCapture(canonicalBytes: original, limits: bound))
            XCTAssertThrowsError(try produce(capture, limits: bound))
        }
    }
}
