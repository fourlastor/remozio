import Darwin
import Foundation
import RemozioMach
import RemozioProtocol

/// Owns one private terminal inside the serialized command controller. This grants no execution or caller control permission.
final class RetainedCommandPTY {
    enum Read: Equatable { case waiting, bytes(Data), end }
    private var handle: OpaquePointer?

    init(attributes: termios? = nil, size: winsize? = nil, target: (uid: uid_t, gid: gid_t)? = nil) throws {
        var copiedAttributes = attributes ?? termios(), copiedSize = size ?? winsize()
        let status = withUnsafePointer(to: &copiedAttributes) { attributesPointer in
            withUnsafePointer(to: &copiedSize) { sizePointer in
                remozio_command_pty_create_for_target(attributes == nil ? nil : attributesPointer,
                    size == nil ? nil : sizePointer, target?.uid ?? 0, target?.gid ?? 0, &handle)
            }
        }
        if status != 0 { throw RetainedCommandPTYError.native(status) }
    }
    deinit { close() }

    /// Borrow only while spawning the original approved child. The callback must not close or retain this descriptor.
    func withBorrowedSlave<Value>(_ body: (Int32) throws -> Value) throws -> Value {
        guard let handle else { throw RetainedCommandPTYError.closed }
        var descriptor: Int32 = -1
        let status = remozio_command_pty_borrow_slave(handle, &descriptor)
        if status != 0 { throw RetainedCommandPTYError.native(status) }
        return try body(descriptor)
    }
    /// Selected roles use independent private descriptions. Direct roles keep their original retained descriptors.
    func withBorrowedMappedStreams<Value>(layout: CapturedCommandStdioLayout, direct: [Int32],
                                         _ body: ([Int32], Int32) throws -> Value) throws -> Value {
        guard let handle else { throw RetainedCommandPTYError.closed }
        guard direct.count == 3, layout.ptyMask <= 7 else { throw RetainedCommandPTYError.invalidLayout }
        var descriptors = direct, owned: [Int32] = []
        defer { for descriptor in owned { _ = Darwin.close(descriptor) } }
        for (index, stream) in [layout.input, layout.output, layout.error].enumerated() where layout.ptyMask & (1 << index) != 0 {
            guard let flags = UInt32(exactly: stream.flags.rawValue) else { throw RetainedCommandPTYError.invalidLayout }
            var descriptor: Int32 = -1
            let status = remozio_command_pty_copy_stream(handle, UInt32(stream.access.rawValue), flags, &descriptor)
            guard status == 0 else { throw RetainedCommandPTYError.native(status) }
            owned.append(descriptor); descriptors[index] = descriptor
        }
        return try withBorrowedSlave { try body(descriptors, $0) }
    }

    func sealSlave() {
        if let handle { remozio_command_pty_seal_slave(handle) }
    }
    func read(maximumBytes: Int = 16_384) throws -> Read {
        guard let handle else { throw RetainedCommandPTYError.closed }
        guard (1...Int(REMOZIO_PTY_MAX_CHUNK)).contains(maximumBytes) else { throw RetainedCommandPTYError.invalidChunk }
        var bytes = Data(count: maximumBytes), count = 0, eof = false
        let status = bytes.withUnsafeMutableBytes {
            remozio_command_pty_read(handle, $0.baseAddress!, $0.count, &count, &eof)
        }
        if status != 0 { throw RetainedCommandPTYError.native(status) }
        if count > 0 { bytes.removeSubrange(count...); return .bytes(bytes) }
        return eof ? .end : .waiting
    }
    /// Keep the unsent suffix when this returns less than the input count. Zero progress is ordinary backpressure.
    func write(_ bytes: Data) throws -> Int {
        guard let handle else { throw RetainedCommandPTYError.closed }
        guard bytes.count <= Int(REMOZIO_PTY_MAX_CHUNK) else { throw RetainedCommandPTYError.invalidChunk }
        var count = 0
        let status = bytes.withUnsafeBytes { remozio_command_pty_write(handle, $0.baseAddress, $0.count, &count) }
        if status != 0 { throw RetainedCommandPTYError.native(status) }
        return count
    }
    func resize(_ size: winsize) throws {
        guard let handle else { throw RetainedCommandPTYError.closed }
        var size = size
        let status = remozio_command_pty_resize(handle, &size)
        if status != 0 { throw RetainedCommandPTYError.native(status) }
    }
    /// Signals only this private terminal's current foreground group. The controller must retain native command ownership.
    func signalForeground(_ number: Int32) throws {
        guard let handle else { throw RetainedCommandPTYError.closed }
        let status = remozio_command_pty_signal(handle, number)
        if status != 0 { throw RetainedCommandPTYError.native(status) }
    }
    func foregroundGroup() throws -> pid_t? {
        guard let handle else { throw RetainedCommandPTYError.closed }
        var group: Int32 = 0
        let status = remozio_command_pty_foreground_group(handle, &group)
        if status != 0 { throw RetainedCommandPTYError.native(status) }
        return group > 0 ? group : nil
    }
    /// Raw mode has no terminal EOF character. This never changes the application's terminal attributes.
    func currentCanonicalEOFSequence() throws -> Data? {
        guard let handle else { throw RetainedCommandPTYError.closed }
        var bytes = [UInt8](repeating: 0, count: 2), count = 0
        let status = remozio_command_pty_eof_sequence(handle, &bytes, &count)
        if status != 0 { throw RetainedCommandPTYError.native(status) }
        return count == 0 ? nil : Data(bytes.prefix(count))
    }
    /// Retain this owner until the child finishes and the output drains. Closing early can hang up the private slave.
    func close() { remozio_command_pty_close(handle); handle = nil }
}

enum RetainedCommandPTYError: Error, Equatable { case closed, invalidChunk, invalidLayout, native(Int32) }
