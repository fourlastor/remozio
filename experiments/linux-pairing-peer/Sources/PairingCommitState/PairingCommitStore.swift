#if os(Linux)
import Glibc
#else
#error("PairingCommitState needs Linux: it uses CLOCK_BOOTTIME and flock between threads")
#endif
import Foundation
import RemozioProtocol

/// Why a commit did not produce a receipt-ready enrollment.
public enum PairingCommitError: Error, Equatable {
    case invalidProof
    case replacementUnsupported
    case staleRevision
    case duplicateSetupID
    case alreadyEnrolled
    case stateFull
    case expired
    case cancelled
    /// The new state is durable, but the deadline passed or the attempt was cancelled before the caller could sign.
    /// The caller must not commit again and must not send a receipt.
    case committedLate(revision: Data)
    /// The rename happened, but the directory `fsync` failed. The new state may or may not survive a power loss.
    /// The caller must not commit again and must not send a receipt.
    case committedUnconfirmed(revision: Data, errno: Int32)
    case unsafeDirectory
    case corruptState
    case storage(operation: String, errno: Int32)
}

/// Internal: the rename happened and the directory sync failed. Callers map it by what the write was for.
private struct DirectorySyncFailed: Error { let code: Int32 }

/// A step of the atomic state replacement. A crash hook runs before each step.
public enum PairingPersistenceStep: CaseIterable, Sendable {
    case createTemporary, syncTemporary, rename, syncDirectory, finished
}

public struct PairingEnrollmentSummary: Equatable, Sendable {
    public let phoneID: Data
    public let epoch: Data
    public let setupID: Data
}

/// Software-key experiment state for one Linux development peer. Not the protected host journal.
///
/// One state file holds the trust revision, the consumed setup IDs and the enrollments. A commit takes an exclusive
/// lock on `state.lock` in the state directory, checks the rules and replaces the file with one atomic rename. After a crash the
/// directory holds either the old state or the complete new state.
public final class PairingCommitStore: Sendable {
    public static let defaultMaximumEnrollments = 256
    public static let defaultMaximumConsumedSetupIDs = 4096
    public static let defaultMaximumStateBytes = 8 * 1024 * 1024
    private static let stateName = "state.json"
    private static let temporaryName = "state.json.tmp"
    private static let lockName = "state.lock"

    private let directory: URL
    private let initialRevision: Data?
    private let maximumEnrollments: Int
    private let maximumConsumedSetupIDs: Int
    private let maximumStateBytes: Int
    private let clock: @Sendable () throws -> UInt64
    private let crashHook: (@Sendable (PairingPersistenceStep) throws -> Void)?

    /// - Parameters:
    ///   - initialTrustRevision: used only when no state exists yet; a random 16-byte revision otherwise.
    ///   - clock: milliseconds on a suspend-inclusive clock. The default reads `CLOCK_BOOTTIME`.
    ///   - crashHook: tests throw from it to model a crash before a persistence step.
    ///   - maximumEnrollments, maximumConsumedSetupIDs, maximumStateBytes: bounds. A commit that would exceed one is
    ///     refused before it writes, so the store can always read back what it wrote.
    public init(directory: URL, initialTrustRevision: Data? = nil,
                maximumEnrollments: Int = PairingCommitStore.defaultMaximumEnrollments,
                maximumConsumedSetupIDs: Int = PairingCommitStore.defaultMaximumConsumedSetupIDs,
                maximumStateBytes: Int = PairingCommitStore.defaultMaximumStateBytes,
                clock: @escaping @Sendable () throws -> UInt64 = PairingCommitStore.bootTimeMilliseconds,
                crashHook: (@Sendable (PairingPersistenceStep) throws -> Void)? = nil) {
        self.directory = directory
        self.initialRevision = initialTrustRevision
        self.maximumEnrollments = maximumEnrollments
        self.maximumConsumedSetupIDs = maximumConsumedSetupIDs
        self.maximumStateBytes = maximumStateBytes
        self.clock = clock
        self.crashHook = crashHook
    }

    /// Milliseconds since boot, including time spent suspended. `ContinuousClock` stops across suspend on Linux.
    @Sendable public static func bootTimeMilliseconds() throws -> UInt64 {
        var sample = timespec()
        guard clock_gettime(CLOCK_BOOTTIME, &sample) == 0 else {
            throw PairingCommitError.storage(operation: "clock_gettime", errno: errno)
        }
        return UInt64(sample.tv_sec) * 1000 + UInt64(sample.tv_nsec) / 1_000_000
    }

    /// The trust revision a new transcript must name. Creates the initial state when none exists. The configured
    /// `initialTrustRevision` applies only to that first creation.
    public func trustRevision() throws -> Data {
        try withLockedDirectory(deadline: nil, isCancelled: { false }) { handle in try handle.loadOrCreate().trustRevision }
    }

    public func list() throws -> [PairingEnrollmentSummary] {
        try withLockedDirectory(deadline: nil, isCancelled: { false }) { handle in
            try handle.loadOrCreate().enrollments.map { stored in
                guard let transcript = try? PairingTranscript.decode(stored.transcript) else { throw PairingCommitError.corruptState }
                return PairingEnrollmentSummary(phoneID: transcript.phone.scope.phoneID,
                    epoch: transcript.phone.scope.enrollmentEpoch, setupID: transcript.setupID)
            }
        }
    }

    /// Commits one enrollment. `deadlineMilliseconds` is on the same clock as `clock`. The caller derives it from the
    /// setup limit and the transcript expiry, so the store does not read the transcript's wall-clock window.
    /// Returns the new trust revision. Never call it again after it throws `committedLate` or any other error that
    /// follows a durable write.
    public func commit(transcript: PairingTranscript, biometricProof: Data, deadlineMilliseconds: UInt64,
                       isCancelled: @Sendable () -> Bool) throws -> Data {
        guard transcript.replacement == nil else { throw PairingCommitError.replacementUnsupported }
        guard (try? transcript.verify(signature: biometricProof, publicKey: transcript.biometricKey.publicKey,
                                      purpose: .phoneBiometric)) == true else { throw PairingCommitError.invalidProof }
        try checkLive(deadline: deadlineMilliseconds, isCancelled: isCancelled)
        return try withLockedDirectory(deadline: deadlineMilliseconds, isCancelled: isCancelled) { handle in
            // The lock wait can be long, so check again after it.
            try checkLive(deadline: deadlineMilliseconds, isCancelled: isCancelled)
            let current = try handle.loadOrCreate()
            guard transcript.expectedTrustRevision == current.trustRevision else { throw PairingCommitError.staleRevision }
            guard !current.consumedSetupIDs.contains(transcript.setupID) else { throw PairingCommitError.duplicateSetupID }
            let scope = transcript.phone.scope
            let newKeys = [transcript.transportKey, transcript.decisionKey, transcript.biometricKey].map(\.publicKey)
            for stored in current.enrollments {
                guard let other = try? PairingTranscript.decode(stored.transcript) else { throw PairingCommitError.corruptState }
                let otherKeys = [other.transportKey, other.decisionKey, other.biometricKey].map(\.publicKey)
                guard other.phone.scope.phoneID != scope.phoneID, Set(otherKeys).isDisjoint(with: newKeys) else {
                    throw PairingCommitError.alreadyEnrolled
                }
            }
            guard current.enrollments.count < maximumEnrollments,
                  current.consumedSetupIDs.count < maximumConsumedSetupIDs else { throw PairingCommitError.stateFull }
            var next = current
            repeat { next.trustRevision = Data((0..<16).map { _ in UInt8.random(in: 0...255) }) }
                while next.trustRevision == current.trustRevision
            next.consumedSetupIDs.append(transcript.setupID)
            next.enrollments.append(StoredEnrollment(transcript: try transcript.encode(), biometricProof: biometricProof))
            try checkLive(deadline: deadlineMilliseconds, isCancelled: isCancelled)
            do { try handle.replace(with: next, maximumBytes: maximumStateBytes) }
            catch let failure as DirectorySyncFailed {
                throw PairingCommitError.committedUnconfirmed(revision: next.trustRevision, errno: failure.code)
            }
            let deadlinePassed = (try? clock()).map { $0 >= deadlineMilliseconds } ?? true
            if deadlinePassed || isCancelled() {
                throw PairingCommitError.committedLate(revision: next.trustRevision)
            }
            return next.trustRevision
        }
    }

    private func checkLive(deadline: UInt64, isCancelled: () -> Bool) throws {
        if isCancelled() { throw PairingCommitError.cancelled }
        guard try clock() < deadline else { throw PairingCommitError.expired }
    }

    // MARK: Locked directory

    private func withLockedDirectory<T>(deadline: UInt64?, isCancelled: () -> Bool,
                                        _ body: (DirectoryHandle) throws -> T) throws -> T {
        let handle = try DirectoryHandle.open(directory, initialRevision: initialRevision,
                                              maximumBytes: maximumStateBytes, crashHook: crashHook)
        defer { handle.close() }
        try handle.lock(wait: { () throws in
            if isCancelled() { throw PairingCommitError.cancelled }
            if let deadline, try clock() >= deadline { throw PairingCommitError.expired }
        })
        return try body(handle)
    }

    struct StoredEnrollment: Codable, Equatable { var transcript: Data; var biometricProof: Data }
    struct StoredState: Codable, Equatable {
        var format: Int
        var trustRevision: Data
        var consumedSetupIDs: [Data]
        var enrollments: [StoredEnrollment]
    }

    private final class DirectoryHandle {
        private let directoryFD: Int32
        private var lockFD: Int32 = -1
        private let initialRevision: Data?
        private let maximumBytes: Int
        private let crashHook: (@Sendable (PairingPersistenceStep) throws -> Void)?

        private init(directoryFD: Int32, initialRevision: Data?, maximumBytes: Int,
                     crashHook: (@Sendable (PairingPersistenceStep) throws -> Void)?) {
            self.directoryFD = directoryFD; self.initialRevision = initialRevision
            self.maximumBytes = maximumBytes; self.crashHook = crashHook
        }

        static func open(_ url: URL, initialRevision: Data?, maximumBytes: Int,
                         crashHook: (@Sendable (PairingPersistenceStep) throws -> Void)?) throws -> DirectoryHandle {
            if let initialRevision, initialRevision.count != 16 { throw PairingCommitError.corruptState }
            let path = url.path
            var created = false
            if mkdir(path, 0o700) == 0 { created = true }
            else if errno != EEXIST { throw PairingCommitError.storage(operation: "mkdir", errno: errno) }
            let fd = Glibc.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else {
                if errno == ELOOP || errno == ENOTDIR { throw PairingCommitError.unsafeDirectory }
                throw PairingCommitError.storage(operation: "open directory", errno: errno)
            }
            // mkdir's mode was exact, but an inherited default ACL or a setgid parent can change it. Make it exact.
            if created, fchmod(fd, 0o700) != 0 {
                let code = errno; _ = Glibc.close(fd); throw PairingCommitError.storage(operation: "fchmod directory", errno: code)
            }
            var info = stat()
            guard fstat(fd, &info) == 0 else { let code = errno; _ = Glibc.close(fd); throw PairingCommitError.storage(operation: "fstat", errno: code) }
            guard info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else { _ = Glibc.close(fd); throw PairingCommitError.unsafeDirectory }
            if created {
                // A new directory entry is durable only after its parent is synced.
                let parent = url.deletingLastPathComponent().path
                let parentFD = Glibc.open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
                guard parentFD >= 0 else { let code = errno; _ = Glibc.close(fd); throw PairingCommitError.storage(operation: "open parent", errno: code) }
                let synced = fsync(parentFD) == 0
                let code = errno
                _ = Glibc.close(parentFD)
                guard synced else { _ = Glibc.close(fd); throw PairingCommitError.storage(operation: "fsync parent", errno: code) }
            }
            return DirectoryHandle(directoryFD: fd, initialRevision: initialRevision, maximumBytes: maximumBytes, crashHook: crashHook)
        }

        func close() {
            if lockFD >= 0 { _ = Glibc.close(lockFD) }  // closing releases the flock
            _ = Glibc.close(directoryFD)
        }

        /// Polls a non-blocking exclusive lock so the caller's deadline and cancellation stay in force.
        func lock(wait check: () throws -> Void) throws {
            // O_NONBLOCK keeps a planted FIFO from blocking this open past the deadline.
            let fd = openat(directoryFD, PairingCommitStore.lockName, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
            guard fd >= 0 else {
                if errno == ELOOP { throw PairingCommitError.unsafeDirectory }
                throw PairingCommitError.storage(operation: "open lock", errno: errno)
            }
            lockFD = fd
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid() else {
                throw PairingCommitError.unsafeDirectory
            }
            guard fchmod(fd, 0o600) == 0 else { throw PairingCommitError.storage(operation: "fchmod lock", errno: errno) }
            while flock(fd, LOCK_EX | LOCK_NB) != 0 {
                guard errno == EWOULDBLOCK || errno == EINTR else { throw PairingCommitError.storage(operation: "flock", errno: errno) }
                try check()
                usleep(2_000)
            }
        }

        func loadOrCreate() throws -> StoredState {
            if let state = try load() { return state }
            let revision = initialRevision ?? Data((0..<16).map { _ in UInt8.random(in: 0...255) })
            let state = StoredState(format: 1, trustRevision: revision, consumedSetupIDs: [], enrollments: [])
            do { try replace(with: state, maximumBytes: maximumBytes) }
            catch let failure as DirectorySyncFailed {
                // Only the empty initial state was at stake; no enrollment exists to confirm.
                throw PairingCommitError.storage(operation: "fsync directory", errno: failure.code)
            }
            return state
        }

        private func load() throws -> StoredState? {
            let fd = openat(directoryFD, PairingCommitStore.stateName, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            if fd < 0 {
                if errno == ENOENT { return nil }
                if errno == ELOOP { throw PairingCommitError.unsafeDirectory }
                throw PairingCommitError.storage(operation: "open state", errno: errno)
            }
            defer { _ = Glibc.close(fd) }
            var info = stat()
            guard fstat(fd, &info) == 0 else { throw PairingCommitError.storage(operation: "fstat state", errno: errno) }
            guard info.st_uid == geteuid(), info.st_mode & 0o077 == 0, info.st_mode & S_IFMT == S_IFREG,
                  info.st_size <= maximumBytes else { throw PairingCommitError.corruptState }
            var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
            var offset = 0
            while offset < bytes.count {
                let count = bytes.withUnsafeMutableBytes { read(fd, $0.baseAddress! + offset, $0.count - offset) }
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw PairingCommitError.corruptState }
                offset += count
            }
            guard let state = try? JSONDecoder().decode(StoredState.self, from: Data(bytes)),
                  state.format == 1, state.trustRevision.count == 16,
                  state.consumedSetupIDs.allSatisfy({ $0.count == 16 }) else { throw PairingCommitError.corruptState }
            return state
        }

        /// Temporary file, fsync, rename, fsync of the directory. A crash hook runs before each step.
        func replace(with state: StoredState, maximumBytes: Int) throws {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let bytes = try encoder.encode(state)
            guard bytes.count <= maximumBytes else { throw PairingCommitError.stateFull }
            try crashHook?(.createTemporary)
            // Drop any leftover (a hard link would be truncated in place), then create the file fresh.
            if unlinkat(directoryFD, PairingCommitStore.temporaryName, 0) != 0, errno != ENOENT {
                throw PairingCommitError.storage(operation: "remove old temporary", errno: errno)
            }
            let fd = openat(directoryFD, PairingCommitStore.temporaryName,
                            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw PairingCommitError.storage(operation: "create temporary", errno: errno) }
            defer { _ = Glibc.close(fd) }
            guard fchmod(fd, 0o600) == 0 else { throw PairingCommitError.storage(operation: "fchmod temporary", errno: errno) }
            var offset = 0
            while offset < bytes.count {
                let count = bytes.withUnsafeBytes { write(fd, $0.baseAddress! + offset, $0.count - offset) }
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw PairingCommitError.storage(operation: "write temporary", errno: errno) }
                offset += count
            }
            try crashHook?(.syncTemporary)
            guard fsync(fd) == 0 else { throw PairingCommitError.storage(operation: "fsync temporary", errno: errno) }
            try crashHook?(.rename)
            guard renameat(directoryFD, PairingCommitStore.temporaryName, directoryFD, PairingCommitStore.stateName) == 0 else {
                throw PairingCommitError.storage(operation: "rename", errno: errno)
            }
            try crashHook?(.syncDirectory)
            guard fsync(directoryFD) == 0 else { throw DirectorySyncFailed(code: errno) }
            try crashHook?(.finished)
        }
    }
}
