import Darwin
import Foundation
import RemozioMach
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandChildLaunchSpecificationTests: XCTestCase {
    private func capture(ioMode: CommandIOMode = .pipes) throws -> CommandCapture {
        try .init(schemaVersion: 1,
            executable: .init(path: Data("/usr/bin/true".utf8), identity: .init(device: 1, inode: 2), sha256: Data(count: 32)),
            arguments: [Data([0xff]), Data(), Data([0xfe, 0x0a])],
            directory: .init(path: Data("/tmp".utf8), identity: .init(device: 1, inode: 3)),
            target: .init(uid: 1234, gid: 5678, supplementaryGroups: [5678, 42], observedName: nil),
            environment: [.init(name: Data("EMPTY".utf8), value: Data(), source: .requested),
                .init(name: Data("RAW".utf8), value: Data([0xff, 0x3d, 0x0a]), source: .requested)],
            input: .init(kind: .pipe, streamBinding: Data(count: 16), observedPath: nil, identity: nil),
            ioMode: ioMode, disconnectBehavior: .terminate,
            requester: .init(executablePath: Data("/fixture/caller".utf8), realUID: 501, effectiveUID: 501, pid: 10, pidVersion: 11,
                signing: .init(status: .unsigned, identifier: nil, team: nil, cdHash: nil), sessionID: nil, ttyPath: nil),
            ancestry: .init(completeness: .unavailable, entries: [], reason: .unsupported), unverifiedRationale: nil,
            submission: .init(id: Data(count: 16), nonce: Data(count: 32), callerBinding: Data(count: 16)),
            limits: .init(maxBytes: 8192, maxDepth: 16, maxItems: 1024))
    }
    private func frame() throws -> Data {
        try CommandChildLaunchSpecification(legacyCapture: capture(), preparationMilliseconds: 1000, fileCreationMask: 0o027).canonicalBytes
    }
    private func decode(_ bytes: Data, inspect: (remozio_child_spec_t) throws -> Void = { _ in }) throws -> Int32 {
        var spec = remozio_child_spec_t()
        defer { remozio_child_spec_close(&spec) }
        let result = bytes.withUnsafeBytes { remozio_child_spec_decode($0.baseAddress, $0.count, &spec) }
        if result == 0 { try inspect(spec) }
        else { XCTAssertNil(spec.storage); XCTAssertNil(spec.arguments); XCTAssertNil(spec.environment); XCTAssertNil(spec.groups) }
        return result
    }
    private func word(_ value: UInt32, offset: Int, bytes: inout Data) {
        var big = value.bigEndian
        withUnsafeBytes(of: &big) { bytes.replaceSubrange(offset..<offset + 4, with: $0) }
    }
    private func raw(_ pointer: UnsafePointer<CChar>?) throws -> Data {
        let pointer = try XCTUnwrap(pointer)
        return Data(bytes: pointer, count: strlen(pointer))
    }
    private func mappedFrame(mask: UInt32) throws -> Data {
        var bytes = try frame()
        var value = mask.bigEndian
        withUnsafeBytes(of: &value) { bytes.insert(contentsOf: $0, at: 40) }
        word(0x524d4332, offset: 0, bytes: &bytes)
        word(UInt32(bytes.count - 40), offset: 4, bytes: &bytes)
        word(2, offset: 36, bytes: &bytes)
        return bytes
    }
    private func layoutCapture(mask: UInt32, mode: CommandIOMode) throws -> CommandCapture {
        let original = try capture(ioMode: mode)
        let terminalSource = CapturedCommandInput(kind: .tty, streamBinding: Data(repeating: 9, count: 16), observedPath: nil,
            identity: .init(device: 7, inode: 8))
        let input = CapturedCommandStream(source: mask & 1 == 0 ? original.input : terminalSource, access: .readOnly, flags: [])
        let output = CapturedCommandStream(source: mask & 2 == 0 ? original.input : terminalSource, access: .writeOnly, flags: [])
        let error = CapturedCommandStream(source: mask & 4 == 0 ? original.input : terminalSource, access: .writeOnly, flags: [])
        let terminal = mode == .pty ? CapturedCommandTerminal(stream: .init(source: terminalSource, access: .readWrite, flags: []),
            sessionID: 123, terminalDevice: 9) : nil
        let requester = original.requester
        return try CommandCapture(schemaVersion: 3, executable: original.executable, arguments: original.arguments,
            directory: original.directory, target: original.target, environment: original.environment, input: input.source,
            ioMode: mode, disconnectBehavior: original.disconnectBehavior,
            requester: .init(executablePath: requester.executablePath, realUID: requester.realUID, effectiveUID: requester.effectiveUID,
                pid: requester.pid, pidVersion: requester.pidVersion, signing: requester.signing, sessionID: 123, ttyPath: nil),
            ancestry: original.ancestry, unverifiedRationale: nil, submission: original.submission,
            stdioLayout: .init(input: input, output: output, error: error, terminal: terminal, ptyMask: mask),
            limits: .init(maxBytes: 8192, maxDepth: 16, maxItems: 1024))
    }

    func testEncoderSelectsExplicitTerminalFormatFromEveryApprovedSchemaThreeMask() throws {
        for mask: UInt32 in 0...7 {
            let capture = try layoutCapture(mask: mask, mode: .pty), original = capture.canonicalBytes
            let frame = try CommandChildLaunchSpecification(legacyCapture: capture, preparationMilliseconds: 1000, fileCreationMask: 0o027).canonicalBytes
            XCTAssertEqual(frame, try mappedFrame(mask: mask))
            XCTAssertEqual(try decode(frame) { spec in
                XCTAssertEqual(spec.format_version, 2)
                XCTAssertEqual(spec.io_mode, 2)
                XCTAssertEqual(spec.stdio_pty_mask, mask)
                XCTAssertEqual(try raw(spec.arguments[0]), capture.arguments[0])
            }, 0)
            XCTAssertEqual(capture.canonicalBytes, original)
        }
    }

    func testSchemaThreePipesAndLegacyTerminalRetainTheirNativeFrameMeanings() throws {
        let pipes = try CommandChildLaunchSpecification(legacyCapture: layoutCapture(mask: 0, mode: .pipes),
            preparationMilliseconds: 1000, fileCreationMask: 0o027).canonicalBytes
        XCTAssertEqual(pipes, try frame())
        let legacy = try CommandChildLaunchSpecification(legacyCapture: capture(ioMode: .pty),
            preparationMilliseconds: 1000, fileCreationMask: 0o027).canonicalBytes
        var expected = try frame(); word(1, offset: 36, bytes: &expected)
        XCTAssertEqual(legacy, expected)
        XCTAssertEqual(try decode(legacy) { spec in
            XCTAssertEqual(spec.format_version, 1)
            XCTAssertEqual(spec.io_mode, 1)
            XCTAssertEqual(spec.stdio_pty_mask, 7)
        }, 0)
    }

    func testMappedFormatAcceptsEveryExplicitMaskWithoutChangingInvocationBytes() throws {
        let expected = try capture()
        for mask: UInt32 in 0...7 {
            XCTAssertEqual(try decode(mappedFrame(mask: mask)) { spec in
                XCTAssertEqual(spec.io_mode, 2)
                XCTAssertEqual(spec.format_version, 2); XCTAssertEqual(spec.stdio_pty_mask, mask)
                XCTAssertEqual(spec.uid, expected.target.uid); XCTAssertEqual(spec.gid, expected.target.gid)
                XCTAssertEqual(try raw(spec.executable), expected.executable.path)
                for index in 0..<3 { XCTAssertEqual(try raw(spec.arguments[index]), expected.arguments[index]) }
                XCTAssertEqual(try raw(spec.environment[1]), Data("RAW=".utf8) + Data([0xff, 0x3d, 0x0a]))
            }, 0)
        }
    }
    func testMalformedMappedMaskModeAndBodyCannotDecodeAsLegacyFormat() throws {
        let original = try mappedFrame(mask: 5)
        for (offset, values): (Int, [UInt32]) in [(0, [0x524d4331, 0x524d4333]), (4, [0, UInt32.max]),
            (36, [0, 1, 3, UInt32.max]), (40, [8, UInt32.max])] {
            for value in values {
                var changed = original; word(value, offset: offset, bytes: &changed)
                XCTAssertEqual(try decode(changed), EINVAL)
            }
        }
        for count in 0..<original.count { XCTAssertEqual(try decode(original.prefix(count)), EINVAL) }
        var extra = original + Data([0]); word(UInt32(extra.count - 40), offset: 4, bytes: &extra)
        XCTAssertEqual(try decode(extra), EINVAL)
    }
    func testMappedDescriptorsMatchEveryDeclaredDirectionWithoutReadingOrChangingStreams() throws {
        var descriptors = [Int32](repeating: -1, count: 6)
        for index in 0..<3 {
            var pair = [Int32](repeating: -1, count: 2)
            XCTAssertEqual(pipe(&pair), 0)
            descriptors[index * 2] = pair[0]; descriptors[index * 2 + 1] = pair[1]
        }
        defer { for descriptor in descriptors where descriptor >= 0 { _ = Darwin.close(descriptor) } }
        let terminal = try RetainedCommandPTY(); defer { terminal.close() }
        let expected = Data([0xff, 0x00, 0x0a, 0xfe])
        XCTAssertEqual(expected.withUnsafeBytes { Darwin.write(descriptors[1], $0.baseAddress, $0.count) }, expected.count)
        let direct = [descriptors[0], descriptors[3], descriptors[5]]
        let flags = direct.map { fcntl($0, F_GETFL) }
        try terminal.withBorrowedSlave { control in
            let terminalFlags = fcntl(control, F_GETFL)
            for mask: UInt32 in 0...7 {
                XCTAssertEqual(try decode(mappedFrame(mask: mask)) { decoded in
                    var spec = decoded
                    let streams = (0..<3).map { mask & (1 << $0) == 0 ? direct[$0] : control }
                    XCTAssertEqual(streams.withUnsafeBufferPointer { remozio_child_spec_validate_stdio(&spec, control, $0.baseAddress) }, 0)
                    for index in 0..<3 {
                        var wrong = streams; wrong[index] = mask & (1 << index) == 0 ? control : direct[index]
                        XCTAssertEqual(wrong.withUnsafeBufferPointer { remozio_child_spec_validate_stdio(&spec, control, $0.baseAddress) }, EINVAL)
                    }
                }, 0)
            }
            XCTAssertEqual(fcntl(control, F_GETFL), terminalFlags)
        }
        XCTAssertEqual(direct.map { fcntl($0, F_GETFL) }, flags)
        var received = Data(count: expected.count)
        XCTAssertEqual(received.withUnsafeMutableBytes { Darwin.read(descriptors[0], $0.baseAddress, $0.count) }, expected.count)
        XCTAssertEqual(received, expected)
    }
    func testMappedDirectOutputMayRemainOnADifferentTerminal() throws {
        let terminal = try RetainedCommandPTY(), other = try RetainedCommandPTY()
        defer { terminal.close(); other.close() }
        try terminal.withBorrowedSlave { control in
            try other.withBorrowedSlave { output in
                XCTAssertEqual(try decode(mappedFrame(mask: 5)) { decoded in
                    var spec = decoded
                    let streams = [control, output, control]
                    XCTAssertEqual(streams.withUnsafeBufferPointer { remozio_child_spec_validate_stdio(&spec, control, $0.baseAddress) }, 0)
                }, 0)
            }
        }
    }
    func testNativeDecoderRetainsEveryRawInvocationAndCredentialField() throws {
        let expected = try capture()
        XCTAssertEqual(try decode(frame()) { spec in
            XCTAssertEqual(spec.uid, expected.target.uid); XCTAssertEqual(spec.gid, expected.target.gid)
            XCTAssertEqual(spec.preparation_milliseconds, 1000); XCTAssertEqual(spec.file_creation_mask, 0o027)
            XCTAssertEqual(spec.group_count, 2); XCTAssertEqual(Array(UnsafeBufferPointer(start: spec.groups, count: 2)), [5678, 42])
            XCTAssertEqual(try raw(spec.executable), expected.executable.path)
            XCTAssertEqual(spec.argument_count, 3); XCTAssertEqual(spec.environment_count, 2)
            for index in 0..<3 { XCTAssertEqual(try raw(spec.arguments[index]), expected.arguments[index]) }
            XCTAssertNil(spec.arguments[3]); XCTAssertNil(spec.environment[2])
            XCTAssertEqual(try raw(spec.environment[0]), Data("EMPTY=".utf8))
            XCTAssertEqual(try raw(spec.environment[1]), Data("RAW=".utf8) + Data([0xff, 0x3d, 0x0a]))
        }, 0)
    }
    func testEveryTruncationAndTrailingByteIsRejectedWithoutOwnedAllocations() throws {
        let original = try frame()
        for count in 0..<original.count { XCTAssertEqual(try decode(original.prefix(count)), EINVAL) }
        XCTAssertEqual(try decode(original + Data([0])), EINVAL)
        var trailing = original + Data([0]); word(UInt32(trailing.count - 40), offset: 4, bytes: &trailing)
        XCTAssertEqual(try decode(trailing), EINVAL)
    }
    func testInvalidVersionsCountsCredentialsTimeoutAndMaskAreRejected() throws {
        let original = try frame()
        for (offset, values): (Int, [UInt32]) in [(0, [0, 0x524d4332]), (4, [0, UInt32.max]), (8, [UInt32.max]),
            (12, [UInt32.max]), (16, [17, UInt32.max]), (20, [0, 262145, UInt32.max]),
            (24, [262145, UInt32.max]), (28, [0, 99, 60001, UInt32.max]), (32, [0o1000, UInt32.max]), (36, [2, UInt32.max]), (40, [UInt32.max])] {
            for value in values { var changed = original; word(value, offset: offset, bytes: &changed); XCTAssertEqual(try decode(changed), EINVAL) }
        }
    }
    func testStringOverflowNulAndRelativeExecutableFailAfterAllocationCleanup() throws {
        var oversized = try frame(); word(UInt32.max, offset: 48, bytes: &oversized)
        XCTAssertEqual(try decode(oversized), EINVAL)
        var nul = try frame(); nul[53] = 0; XCTAssertEqual(try decode(nul), EINVAL)
        var relative = try frame(); relative[52] = 0x2e; XCTAssertEqual(try decode(relative), EINVAL)
        var environment = try frame()
        let value = try XCTUnwrap(environment.range(of: Data("EMPTY=".utf8)))
        environment[value.lowerBound + 5] = 0x2d
        XCTAssertEqual(try decode(environment), EINVAL)
    }
    func testDuplicateOrUnsortedEnvironmentNamesAreRejected() throws {
        var original = try frame()
        let name = try XCTUnwrap(original.range(of: Data("RAW=".utf8)))
        original.replaceSubrange(name.lowerBound..<name.lowerBound + 3, with: Data("AAA".utf8))
        XCTAssertEqual(try decode(original), EINVAL)
        var duplicate = try frame()
        let first = try XCTUnwrap(duplicate.range(of: Data("EMPTY=".utf8)))
        duplicate.replaceSubrange(first.lowerBound..<first.lowerBound + 5, with: Data("RAW".utf8))
        word(4, offset: first.lowerBound - 4, bytes: &duplicate)
        word(UInt32(duplicate.count - 40), offset: 4, bytes: &duplicate)
        XCTAssertEqual(try decode(duplicate), EINVAL)
    }
    func testOversizedFrameIsRejectedBeforeAllocatingDecodedStorage() throws {
        XCTAssertEqual(try decode(Data(count: CommandChildLaunchSpecification.maximumBytes + 1)), EINVAL)
    }
    func testDecodedRawStringsOwnTheirBytesAndCloseIsIdempotent() throws {
        var bytes = try frame(), spec = remozio_child_spec_t()
        XCTAssertEqual(bytes.withUnsafeBytes { remozio_child_spec_decode($0.baseAddress, $0.count, &spec) }, 0)
        defer { remozio_child_spec_close(&spec) }
        bytes.resetBytes(in: 0..<bytes.count)
        XCTAssertEqual(try raw(spec.arguments[0]), Data([0xff]))
        XCTAssertEqual(try raw(spec.environment[1]), Data("RAW=".utf8) + Data([0xff, 0x3d, 0x0a]))
        remozio_child_spec_close(&spec); remozio_child_spec_close(&spec)
        XCTAssertNil(spec.storage); XCTAssertNil(spec.arguments); XCTAssertNil(spec.environment)
    }
    func testDarwinGroupRepresentationUsesOnlyTheApprovedPrimaryAndSupplementaryIDs() throws {
        for (input, expected): ([UInt32], [UInt32]) in [([], [5678]), ([0, 42], [5678, 0, 42]),
            ([42, 5678, 42, 0], [5678, 42, 0])] {
            var spec = remozio_child_spec_t(), groups = [UInt32](repeating: 0, count: 16), count: UInt32 = 0
            spec.gid = 5678; spec.group_count = UInt32(input.count)
            var values = input
            let result = values.withUnsafeMutableBufferPointer { source in
                spec.groups = source.baseAddress
                return remozio_child_spec_groups(&spec, &groups, &count)
            }
            XCTAssertEqual(result, 0); XCTAssertEqual(Array(groups.prefix(Int(count))), expected)
        }
    }
    func testGroupUnionCannotOverflowTheDarwinLimit() throws {
        var spec = remozio_child_spec_t(), groups = [UInt32](repeating: 0, count: 16), count: UInt32 = 0
        spec.gid = 5678; spec.group_count = 16
        var input = Array(UInt32(1)...16)
        XCTAssertEqual(input.withUnsafeMutableBufferPointer { values in
            spec.groups = values.baseAddress
            return remozio_child_spec_groups(&spec, &groups, &count)
        }, EINVAL)
    }
    func testEncoderRejectsUnsupportedPreparationAndMaskWithoutChangingCapture() throws {
        let original = try capture(), bytes = original.canonicalBytes
        for budget: UInt32 in [0, 99, 60001, UInt32.max] {
            XCTAssertThrowsError(try CommandChildLaunchSpecification(legacyCapture: original, preparationMilliseconds: budget, fileCreationMask: 0o022))
        }
        XCTAssertThrowsError(try CommandChildLaunchSpecification(legacyCapture: original, preparationMilliseconds: 1000, fileCreationMask: 0o1000))
        XCTAssertEqual(original.canonicalBytes, bytes)
    }
}
