import Darwin
import Dispatch
import Foundation

/// Temporary opt-in measurements for one test class. Nested spans are inclusive, not additive.
enum GatewayRuntimeActivationTestProfile {
    struct Scope: Sendable {
        fileprivate let prefix: String
        fileprivate let enabled: Bool
        static let disabled = Scope(prefix: "", enabled: false)

        func child(_ label: String) -> Scope {
            enabled ? Scope(prefix: prefix + "." + label, enabled: true) : .disabled
        }
        func measure<T>(_ label: String, _ body: () throws -> T) rethrows -> T {
            guard enabled else { return try body() }
            return try recorder.measure(prefix + "." + label, body)
        }
    }
    private static let recorder = Recorder()
    static func scope(_ label: String) -> Scope {
        recorder.enabled ? Scope(prefix: label, enabled: true) : .disabled
    }
    static func writeReport() throws { try recorder.writeReport() }

    // Immutable configuration and lock-protected aggregates; bodies never execute under the lock.
    private final class Recorder: @unchecked Sendable {
        struct Aggregate: Codable {
            var calls = 0
            var thrownCalls = 0
            var wallSeconds = 0.0
            var processCPUSeconds = 0.0
            var cpuMeasurementFailures = 0
        }
        struct Report: Encodable {
            let schemaVersion = 1
            let suite = "GatewayRuntimeActivationOperationTests"
            let timing = "Inclusive monotonic wall and process CPU; nested spans overlap. Process CPU includes all process threads, but excludes child processes."
            let spans: [String: Aggregate]
        }
        private let directory: String? = {
            guard let value = ProcessInfo.processInfo.environment["REMOZIO_TEST_PROFILE_DIR"], !value.isEmpty else { return nil }
            return value
        }()
        private let lock = NSLock()
        private var spans: [String: Aggregate] = [:]
        var enabled: Bool { directory != nil }

        func measure<T>(_ label: String, _ body: () throws -> T) rethrows -> T {
            let wall = DispatchTime.now().uptimeNanoseconds, cpu = clock()
            var succeeded = false
            defer {
                let elapsedWall = Double(DispatchTime.now().uptimeNanoseconds - wall) / 1_000_000_000
                let endCPU = clock()
                lock.withLock {
                    var value = spans[label, default: Aggregate()]
                    value.calls += 1
                    if !succeeded { value.thrownCalls += 1 }
                    value.wallSeconds += elapsedWall
                    if cpu != clock_t(truncatingIfNeeded: -1), endCPU != clock_t(truncatingIfNeeded: -1), endCPU >= cpu {
                        value.processCPUSeconds += Double(endCPU - cpu) / Double(CLOCKS_PER_SEC)
                    } else { value.cpuMeasurementFailures += 1 }
                    spans[label] = value
                }
            }
            let result = try body()
            succeeded = true
            return result
        }
        func writeReport() throws {
            guard let directory else { return }
            let report = lock.withLock { Report(spans: spans) }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let destination = URL(fileURLWithPath: directory, isDirectory: true)
            try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
            try encoder.encode(report).write(to: destination.appendingPathComponent(
                "GatewayRuntimeActivationOperationTests-\(getpid()).json"), options: .atomic)
        }
    }
}
