import Foundation
import Dispatch
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// Compiled beside the exact extracted production table/helper. Security and the
// complete XPCPeerPolicy initializer are intentionally outside this microbenchmark.
@main
struct XPCHexBenchmark {
    struct Failure: Error { let message: String }
    struct Record { let input: Data; let expected: String }
    static let initialChecksum: UInt64 = 14_695_981_039_346_656_037

    #if BASELINE
    static let variant = "baseline"
    @inline(never) static func format(_ value: Data) -> String {
        value.map { String(format: "%02x", $0) }.joined()
    }
    #else
    static let variant = "candidate"
    @inline(never) static func format(_ value: Data) -> String {
        XPCPeerPolicy.hexadecimalCodeDirectoryHash(value)
    }
    #endif

    static func records(_ value: Any?) throws -> [Record] {
        guard let entries = value as? [[String: Any]], !entries.isEmpty, entries.count <= 512 else {
            throw Failure(message: "invalid corpus records")
        }
        return try entries.map { entry in
            guard Set(entry.keys) == ["bytes", "expected"],
                  let bytes = entry["bytes"] as? [UInt8], bytes.count == 20,
                  let expected = entry["expected"] as? String, expected.utf8.count == 40,
                  expected.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                throw Failure(message: "invalid fixed twenty-byte record")
            }
            return Record(input: Data(bytes), expected: expected)
        }
    }

    // Every formatted byte contributes, including every iteration. This equal
    // checksum/UTF-8 traversal overhead is part of BOTH measured variants.
    @inline(never) static func batch(_ values: [Record], iterations: Int) -> UInt64 {
        var checksum = initialChecksum
        for iteration in 0..<iterations {
            for index in values.indices {
                let formatted = format(values[(index + iteration) % values.count].input)
                for byte in formatted.utf8 {
                    checksum = (checksum ^ UInt64(byte)) &* 1_099_511_628_211
                }
            }
        }
        return checksum
    }

    static func emit(_ value: [String: Any]) throws {
        let bytes = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        FileHandle.standardOutput.write(bytes + Data([10]))
    }

    static func run() throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard arguments.count == 4, arguments[0] == "run",
              let iterations = Int(arguments[2]), (1...50_000).contains(iterations),
              let warmup = Int(arguments[3]), (1...1_000).contains(warmup) else {
            throw Failure(message: "usage: run CORPUS ITERATIONS WARMUP; bounded positive counts required")
        }
        let bytes = try Data(contentsOf: URL(fileURLWithPath: arguments[1]))
        guard bytes.count <= 262_144,
              let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              Set(object.keys) == ["parity", "timed"] else { throw Failure(message: "invalid corpus") }
        let parity = try records(object["parity"]), timed = try records(object["timed"])
        for value in parity + timed {
            guard format(value.input) == value.expected else { throw Failure(message: "independent oracle mismatch") }
        }
        // Warm Foundation and the helper inside EACH fresh measured process.
        let warmupChecksum = batch(timed, iterations: warmup)
        let cpuStart = clock(), wallStart = DispatchTime.now().uptimeNanoseconds
        let checksum = batch(timed, iterations: iterations)
        let wallEnd = DispatchTime.now().uptimeNanoseconds, cpuEnd = clock()
        guard cpuStart >= 0, cpuEnd >= cpuStart else { throw Failure(message: "CPU clock unavailable") }
        try emit(["schemaVersion": 1, "variant": variant, "iterations": iterations,
                  "warmupIterations": warmup, "parityRecords": parity.count,
                  "recordsPerIteration": timed.count, "formatCalls": iterations * timed.count,
                  "checksumFNV1a64": String(checksum), "warmupChecksumFNV1a64": String(warmupChecksum),
                  "wallSeconds": Double(wallEnd - wallStart) / 1_000_000_000,
                  "processCPUSeconds": Double(cpuEnd - cpuStart) / Double(CLOCKS_PER_SEC)])
    }

    static func main() {
        do { try run() }
        catch {
            FileHandle.standardError.write(Data("hex benchmark refused: \(error)\n".utf8))
            exit(1)
        }
    }
}
