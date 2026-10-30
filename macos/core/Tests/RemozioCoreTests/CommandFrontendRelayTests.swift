import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class FrontendRelayTestTerminal: CommandFrontendTerminalIO {
    var needsRestore = false, foreground = true
    var reads: [CommandFrontendTerminalRead] = []
    var readCalls = 0, activateCalls = 0, restoreCalls = 0, closeCalls = 0
    var writeCounts: [Int] = []
    var writeBlocked = false, writeCalls = 0
    var written = Data()
    var readError: Error?
    var restoreError: Error?
    var restorationFailures: [Int32] = []
    var size = CommandFrontendTerminalSize(rows: 53, columns: 143)
    func isForeground() throws -> Bool { foreground }
    func activate() throws {
        activateCalls += 1
        guard foreground else { throw CommandFrontendTerminalError.native(EAGAIN) }
        guard !needsRestore else { throw CommandFrontendTerminalError.native(EALREADY) }
        needsRestore = true
    }
    func restore() throws {
        restoreCalls += 1
        if let restoreError { throw restoreError }
        if needsRestore, !foreground { throw CommandFrontendTerminalError.native(EAGAIN) }
        needsRestore = false
    }
    func read(maximumBytes: Int) throws -> CommandFrontendTerminalRead {
        readCalls += 1
        if let readError { throw readError }
        if reads.isEmpty { return .waiting }
        let next = reads.removeFirst()
        if case .bytes(let bytes) = next { XCTAssertLessThanOrEqual(bytes.count, maximumBytes) }
        return next
    }
    func write(_ bytes: Data) throws -> Int {
        writeCalls += 1
        if writeBlocked { return 0 }
        let count = writeCounts.isEmpty ? min(37, bytes.count) : writeCounts.removeFirst()
        if (0...bytes.count).contains(count) { written.append(bytes.prefix(count)) }
        return count
    }
    func dimensions() throws -> CommandFrontendTerminalSize { size }
    func close() throws { closeCalls += 1; try restore() }
    func closeReportingFailure() {
        do { try close() }
        catch CommandFrontendTerminalError.native(let number) { restorationFailures.append(number) }
        catch { restorationFailures.append(EIO) }
    }
}

private final class FrontendRelayTestChannel: CommandFrontendExecutionChannel {
    var executionIOMode: CommandIOMode? = .pty
    var supportsCurrentJobQueries = false
    func requestCurrentJob(timeoutMilliseconds: UInt32) throws -> Bool { throw MachCommandHandshakeError.incompatible }
    func invalidateCurrentJobQuery() {}
    var events: [CommandExecutionStreamEvent] = []
    var inputCounts: [Int] = []
    var acceptedInput = Data(), attemptedInput: [Data] = []
    var acknowledgments: [Bool] = [], ackCalls = 0
    var finishCounts: [Bool] = [], finishCalls = 0
    var resizeCounts: [Bool] = [], attemptedSizes: [CommandFrontendTerminalSize] = []
    var pollCalls = 0, closeCalls = 0
    var controlError: Error?
    var pollError: Error?
    func pollStreamEvent(timeoutMilliseconds: UInt32, nonblocking: Bool) throws -> CommandExecutionStreamEvent? {
        pollCalls += 1
        if let pollError { throw pollError }
        return events.isEmpty ? nil : events.removeFirst()
    }
    func forwardInput(_ bytes: Data) throws -> Int {
        attemptedInput.append(bytes)
        let count = inputCounts.isEmpty ? bytes.count : inputCounts.removeFirst()
        if count == bytes.count { acceptedInput.append(bytes) }
        return count
    }
    func finishInput() throws -> Bool {
        finishCalls += 1; return finishCounts.isEmpty ? true : finishCounts.removeFirst()
    }
    func acknowledgeOutput() throws -> Bool {
        ackCalls += 1; return acknowledgments.isEmpty ? true : acknowledgments.removeFirst()
    }
    func resizeTerminal(rows: UInt16, columns: UInt16, pixelWidth: UInt16, pixelHeight: UInt16) throws -> Bool {
        attemptedSizes.append(.init(rows: rows, columns: columns, pixelWidth: pixelWidth, pixelHeight: pixelHeight))
        return resizeCounts.isEmpty ? true : resizeCounts.removeFirst()
    }
    func forwardSignal(_ signal: UInt32) throws -> Bool {
        if let controlError { throw controlError }; return true
    }
    func cancelCommand() throws -> Bool {
        if let controlError { throw controlError }; return true
    }
    func close() { closeCalls += 1 }
}

final class CommandFrontendRelayTests: XCTestCase {
    func testDestructionRestoresAnExternallyRetainedActiveTerminal() throws {
        let channel = FrontendRelayTestChannel(), terminal = FrontendRelayTestTerminal()
        channel.events = [.opened]
        var relay: CommandFrontendRelay? = try CommandFrontendRelay(channel: channel, terminal: terminal)
        _ = try relay!.advance(); _ = try relay!.advance()
        XCTAssertTrue(terminal.needsRestore)
        relay = nil
        XCTAssertEqual(channel.closeCalls, 1)
        XCTAssertFalse(terminal.needsRestore); XCTAssertTrue(terminal.restorationFailures.isEmpty)
    }
    func testDestructionReportsFailedRestorationAndKeepsTheRetainedOwnerRecoverable() throws {
        let channel = FrontendRelayTestChannel(), terminal = FrontendRelayTestTerminal()
        channel.events = [.opened]
        var relay: CommandFrontendRelay? = try CommandFrontendRelay(channel: channel, terminal: terminal)
        _ = try relay!.advance(); _ = try relay!.advance()
        // Optimized builds may otherwise destroy the relay right after its last use, before the injected failure.
        withExtendedLifetime(relay) { terminal.restoreError = CommandFrontendTerminalError.native(EAGAIN) }
        relay = nil
        XCTAssertEqual(channel.closeCalls, 1); XCTAssertTrue(terminal.needsRestore)
        XCTAssertEqual(terminal.restorationFailures, [EAGAIN])
        terminal.restoreError = nil; try terminal.close()
        XCTAssertFalse(terminal.needsRestore); XCTAssertEqual(channel.closeCalls, 1)
    }
    func testNoTerminalInputOrActivationBeforeOpeningAndPipesNeverTouchTerminal() throws {
        let channel = FrontendRelayTestChannel(), terminal = FrontendRelayTestTerminal()
        let relay = try CommandFrontendRelay(channel: channel, terminal: terminal)
        guard case .waiting = try relay.advance() else { return XCTFail("Admission alone must not activate or read") }
        XCTAssertEqual(terminal.readCalls, 0); XCTAssertEqual(terminal.activateCalls, 0)
        XCTAssertThrowsError(try relay.forwardSignal(UInt32(SIGINT)))
        let pipes = FrontendRelayTestChannel(); pipes.executionIOMode = .pipes; pipes.events = [.opened]
        let pipeRelay = try CommandFrontendRelay(channel: pipes, terminal: nil)
        _ = try pipeRelay.advance(); _ = try pipeRelay.advance()
        XCTAssertTrue(pipes.attemptedInput.isEmpty); XCTAssertTrue(pipes.attemptedSizes.isEmpty)
        XCTAssertEqual(pipes.finishCalls, 0); XCTAssertEqual(pipes.ackCalls, 0)
        XCTAssertThrowsError(try CommandFrontendRelay(channel: pipes, terminal: terminal))
    }
    func testZeroProgressRetainsExactInputAndDoesNotReadAnotherChunk() throws {
        let channel = FrontendRelayTestChannel(), terminal = FrontendRelayTestTerminal()
        let bytes = Data([0, 255, 10, 13]); terminal.reads = [.bytes(bytes)]
        channel.events = [.opened]; channel.inputCounts = [0, 0, bytes.count]
        let relay = try CommandFrontendRelay(channel: channel, terminal: terminal)
        for _ in 0..<4 { _ = try relay.advance() }
        XCTAssertEqual(terminal.readCalls, 1)
        XCTAssertEqual(channel.attemptedInput, [bytes, bytes, bytes]); XCTAssertEqual(channel.acceptedInput, bytes)
        try relay.close(); XCTAssertFalse(relay.needsTerminalRestoration)
    }
    func testInputCreditBoundsConsumptionAndRestoresReadsWhenCapacityArrives() throws {
        let channel = FrontendRelayTestChannel(), terminal = FrontendRelayTestTerminal()
        let bytes = Data(repeating: 255, count: 4096)
        terminal.reads = Array(repeating: .bytes(bytes), count: 9); channel.events = [.opened]
        let relay = try CommandFrontendRelay(channel: channel, terminal: terminal)
        for _ in 0..<10 { _ = try relay.advance() }
        XCTAssertEqual(terminal.readCalls, 8); XCTAssertEqual(channel.acceptedInput.count, 32768)
        channel.events.append(.inputCapacity(4096))
        _ = try relay.advance(); XCTAssertEqual(terminal.readCalls, 8)
        _ = try relay.advance(); XCTAssertEqual(terminal.readCalls, 9)
        XCTAssertEqual(channel.acceptedInput, Data(repeating: 255, count: 36864))
        try relay.close()
    }
    func testPartialOutputRetainsSuffixAndAcknowledgesOnlyAfterFullDrain() throws {
        let channel = FrontendRelayTestChannel(), terminal = FrontendRelayTestTerminal()
        let bytes = Data([0, 255, 10, 13, 26, 128, 127])
        channel.events = [.opened, .output(bytes), .outputEnded]
        terminal.writeCounts = [2, 0, 5]; channel.acknowledgments = [false, true]
        let relay = try CommandFrontendRelay(channel: channel, terminal: terminal)
        _ = try relay.advance(); _ = try relay.advance(); _ = try relay.advance(); _ = try relay.advance()
        XCTAssertEqual(terminal.written, bytes.prefix(2)); XCTAssertEqual(channel.ackCalls, 0)
        let polls = channel.pollCalls
        guard case .waiting = try relay.advance() else { return XCTFail("Blocked output must retain its suffix") }
        XCTAssertFalse(relay.waitInterests.result); XCTAssertTrue(relay.waitInterests.write)
        XCTAssertTrue(relay.waitInterests.read)
        XCTAssertEqual(channel.pollCalls, polls); XCTAssertEqual(channel.ackCalls, 0)
        _ = try relay.advance(); XCTAssertEqual(terminal.written, bytes); XCTAssertEqual(channel.ackCalls, 0)
        _ = try relay.advance(); _ = try relay.advance(); _ = try relay.advance(); _ = try relay.advance()
        XCTAssertEqual(channel.ackCalls, 2); XCTAssertEqual(terminal.written, bytes)
        try relay.close()
    }
    func testBlockedOutputStillRelaysInputWithoutConsumingAnotherOutputFrame() throws {
        let channel = FrontendRelayTestChannel(), terminal = FrontendRelayTestTerminal()
        let output = Data([255, 0, 13]), input = Data([3])
        channel.events = [.opened, .output(output), .outputEnded]
        terminal.writeCounts = [0, 0, output.count]; channel.inputCounts = [0, input.count]
        let relay = try CommandFrontendRelay(channel: channel, terminal: terminal)
        _ = try relay.advance(); _ = try relay.advance(); _ = try relay.advance()
        let polls = channel.pollCalls
        terminal.reads = [.bytes(input)]
        _ = try relay.advance()
        XCTAssertEqual(channel.attemptedInput, [input])
        XCTAssertTrue(channel.acceptedInput.isEmpty); XCTAssertTrue(terminal.written.isEmpty)
        XCTAssertTrue(relay.waitInterests.controlRetry); XCTAssertFalse(relay.waitInterests.read)
        XCTAssertFalse(relay.waitInterests.result); XCTAssertTrue(relay.waitInterests.write)
        XCTAssertEqual(channel.pollCalls, polls); XCTAssertEqual(channel.ackCalls, 0)
        _ = try relay.advance()
        XCTAssertEqual(channel.attemptedInput, [input, input]); XCTAssertEqual(channel.acceptedInput, input)
        XCTAssertTrue(terminal.written.isEmpty); XCTAssertEqual(channel.pollCalls, polls)
        _ = try relay.advance()
        XCTAssertEqual(terminal.written, output); XCTAssertEqual(channel.pollCalls, polls)
        _ = try relay.advance(); _ = try relay.advance()
        XCTAssertEqual(channel.ackCalls, 1); XCTAssertEqual(channel.acceptedInput, input)
        try relay.close()
    }
    func testBackgroundWaitAndExplicitSuspensionRestoreBeforeFreshActivation() throws {
        let channel = FrontendRelayTestChannel(), terminal = FrontendRelayTestTerminal()
        channel.events = [.opened]; terminal.foreground = false
        let relay = try CommandFrontendRelay(channel: channel, terminal: terminal)
        _ = try relay.advance()
        guard case .foregroundRequired = try relay.advance() else { return XCTFail("The owner must not take foreground") }
        XCTAssertFalse(relay.waitInterests.result); XCTAssertFalse(relay.waitInterests.read)
        XCTAssertFalse(relay.waitInterests.write); XCTAssertTrue(relay.waitInterests.foregroundRetry)
        XCTAssertEqual(terminal.activateCalls, 0); XCTAssertEqual(terminal.readCalls, 0)
        terminal.foreground = true; _ = try relay.advance()
        XCTAssertTrue(relay.waitInterests.result); XCTAssertTrue(relay.waitInterests.read)
        XCTAssertFalse(relay.waitInterests.foregroundRetry)
        XCTAssertTrue(relay.needsTerminalRestoration)
        try relay.prepareForSuspension(); XCTAssertFalse(relay.needsTerminalRestoration)
        XCTAssertFalse(relay.waitInterests.result); XCTAssertFalse(relay.waitInterests.read)
        XCTAssertFalse(relay.waitInterests.write); XCTAssertFalse(relay.waitInterests.foregroundRetry)
        guard case .suspended = try relay.advance() else { return XCTFail("Only explicit resume permits activation") }
        relay.resume(); _ = try relay.advance(); XCTAssertEqual(terminal.activateCalls, 2)
        terminal.foreground = false
        guard case .foregroundRequired = try relay.advance() else { return XCTFail("Background cleanup must remain owned") }
        XCTAssertTrue(relay.needsTerminalRestoration)
        terminal.foreground = true; _ = try relay.advance(); XCTAssertEqual(terminal.activateCalls, 3)
        try relay.close()
    }
    func testInterruptedReadRestoresAndYieldsWithoutRetiringOriginalChannel() throws {
        let channel = FrontendRelayTestChannel(), terminal = FrontendRelayTestTerminal()
        channel.events = [.opened]; terminal.readError = CommandFrontendTerminalError.native(EINTR)
        let relay = try CommandFrontendRelay(channel: channel, terminal: terminal)
        _ = try relay.advance()
        guard case .interrupted = try relay.advance() else { return XCTFail("The local signal loop must regain control") }
        XCTAssertFalse(relay.needsTerminalRestoration); XCTAssertEqual(channel.closeCalls, 0)
        terminal.readError = nil; _ = try relay.advance()
        XCTAssertEqual(terminal.activateCalls, 2); try relay.close()
    }
    func testFatalFailureRetiresChannelAndRetainsFailedRestorationForExplicitCleanup() throws {
        let channel = FrontendRelayTestChannel(), terminal = FrontendRelayTestTerminal()
        channel.events = [.opened]
        let relay = try CommandFrontendRelay(channel: channel, terminal: terminal)
        _ = try relay.advance(); _ = try relay.advance()
        terminal.readError = CommandFrontendTerminalError.native(EIO)
        terminal.restoreError = CommandFrontendTerminalError.native(EAGAIN)
        XCTAssertThrowsError(try relay.advance()) { XCTAssertEqual($0 as? CommandFrontendTerminalError, .native(EIO)) }
        XCTAssertEqual(channel.closeCalls, 1); XCTAssertTrue(relay.needsTerminalRestoration)
        XCTAssertThrowsError(try relay.advance()) { XCTAssertEqual($0 as? CommandFrontendRelayError, .closed) }
        XCTAssertThrowsError(try relay.close()); XCTAssertTrue(relay.needsTerminalRestoration)
        terminal.restoreError = nil; try relay.close(); XCTAssertFalse(relay.needsTerminalRestoration)
    }
    func testKnownZeroResizeKeepsLatestDimensionsAndEOFKeepsDeliveryUntilAccepted() throws {
        let channel = FrontendRelayTestChannel(), terminal = FrontendRelayTestTerminal()
        channel.events = [.opened]; channel.resizeCounts = [false, true]
        channel.finishCounts = [false, true]; terminal.reads = [.end]
        let relay = try CommandFrontendRelay(channel: channel, terminal: terminal)
        _ = try relay.advance(); _ = try relay.advance()
        terminal.size = .init(rows: 71, columns: 101, pixelWidth: 321, pixelHeight: 123)
        _ = try relay.advance(); _ = try relay.advance()
        XCTAssertEqual(channel.attemptedSizes, [.init(rows: 53, columns: 143), terminal.size])
        XCTAssertEqual(channel.finishCalls, 2); XCTAssertEqual(terminal.readCalls, 1)
        try relay.close()
    }
    func testInterruptedReceivePreservesOriginalChannelAndRestoresBeforeYield() throws {
        let channel = FrontendRelayTestChannel(), terminal = FrontendRelayTestTerminal()
        channel.events = [.opened]
        let relay = try CommandFrontendRelay(channel: channel, terminal: terminal)
        _ = try relay.advance(); _ = try relay.advance()
        channel.pollError = CommandExecutionStreamPollError.interrupted
        guard case .interrupted = try relay.advance() else { return XCTFail("A zero-consumption receive must yield to the signal loop") }
        XCTAssertEqual(channel.closeCalls, 0); XCTAssertFalse(relay.needsTerminalRestoration)
        channel.pollError = nil; _ = try relay.advance()
        XCTAssertEqual(terminal.activateCalls, 2); try relay.close()
    }
    func testControlFailureRestoresTerminalAndRetiresOriginalChannel() throws {
        for cancel in [false, true] {
            let channel = FrontendRelayTestChannel(), terminal = FrontendRelayTestTerminal()
            channel.events = [.opened]
            let relay = try CommandFrontendRelay(channel: channel, terminal: terminal)
            _ = try relay.advance(); _ = try relay.advance()
            XCTAssertTrue(relay.needsTerminalRestoration)
            channel.controlError = CommandStreamError.binding
            XCTAssertThrowsError(try cancel ? relay.cancelCommand() : relay.forwardSignal(UInt32(SIGINT))) {
                XCTAssertEqual($0 as? CommandStreamError, .binding)
            }
            XCTAssertEqual(channel.closeCalls, 1); XCTAssertFalse(relay.needsTerminalRestoration)
            XCTAssertThrowsError(try relay.advance()) { XCTAssertEqual($0 as? CommandFrontendRelayError, .closed) }
        }
    }
    func testInvalidSinkProgressRetiresChannelWithoutDrainingOrClaimingDelivery() throws {
        let channel = FrontendRelayTestChannel(), terminal = FrontendRelayTestTerminal()
        channel.events = [.opened, .output(Data([1]))]; terminal.writeCounts = [2]
        let relay = try CommandFrontendRelay(channel: channel, terminal: terminal)
        _ = try relay.advance(); _ = try relay.advance(); _ = try relay.advance()
        XCTAssertThrowsError(try relay.advance()) { XCTAssertEqual($0 as? CommandFrontendRelayError, .invalidProgress) }
        XCTAssertEqual(channel.closeCalls, 1); XCTAssertEqual(channel.ackCalls, 0); XCTAssertTrue(terminal.written.isEmpty)
    }
}
