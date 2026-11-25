import Darwin
import Foundation

@main
struct DaemonTerminationChild {
    static func main() async throws {
        let mode = CommandLine.arguments[1]
        if mode == "default" {
            signal(SIGTERM, SIG_DFL)
            emit(80) // P
            _ = try FileHandle.standardInput.read(upToCount: 1)
            throw CocoaError(.executableRuntimeMismatch)
        }

        let termination = try DaemonTermination()
        if mode == "before-bind" {
            emit(73) // I
            let deadline = ContinuousClock.now + .seconds(4)
            while !termination.requested && ContinuousClock.now < deadline {
                try await Task.sleep(for: .milliseconds(5))
            }
            guard termination.requested else { throw CocoaError(.executableRuntimeMismatch) }
        }

        do {
            try await termination.run {
                emit(79) // O
                do {
                    if mode == "startup" { try await Task.sleep(for: .seconds(10)) }
                    try termination.checkCancellation()
                    emit(82) // R
                    while true { try await Task.sleep(for: .seconds(10)) }
                } catch is CancellationError {
                    emit(68) // D
                    guard try FileHandle.standardInput.read(upToCount: 1) == Data([74]) else {
                        throw CocoaError(.executableRuntimeMismatch)
                    }
                    throw CancellationError()
                }
            }
            throw CocoaError(.executableRuntimeMismatch)
        } catch is CancellationError {
            emit(74) // J
        }
    }

    private static func emit(_ marker: UInt8) {
        FileHandle.standardOutput.write(Data([marker]))
    }
}
