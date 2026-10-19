import Foundation
import Dispatch
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// Synthetic public data only. This is not an actual retained-state plan or a full test-suite benchmark.
@main
struct CBORDecodeBenchmark {
    static let limits = try! CBORLimits(maxBytes: 65_536, maxDepth: 32, maxItems: 4_096)

    static func corpus(_ name: String) throws -> [CBORValue] {
        switch name {
        case "scalar-heavy":
            return [0, 23, 24, 255, 256, 65_535, 65_536, UInt64.max].map(CBORValue.unsigned)
                + [.text(""), .bytes(Data()), .array([]), .map([:]), .boolean(false), .boolean(true), .null]
        case "nested-synthetic":
            var entries: [CBORValue] = []
            for i in 0..<8 {
                let identifier = Data((0..<32).map { UInt8(($0 + i) % 256) })
                let reference: [UInt64: CBORValue] = [
                    0: .text("synthetic-reference"), 1: .unsigned(65_536),
                    2: .bytes(Data(repeating: UInt8(i), count: 64))]
                let entry: [UInt64: CBORValue] = [
                    0: .unsigned(UInt64(i)), 1: .bytes(identifier),
                    2: .text("owned-synthetic-fixture-\(i)-é-e\u{301}"),
                    3: .array([.unsigned(1), .boolean(true), .null]), 4: .map(reference)]
                entries.append(.map(entry))
            }
            let root = CBORValue.map([
                0: .unsigned(1), 1: .array(entries),
                2: .map([0: .bytes(Data(repeating: 0x5a, count: 128)),
                         1: .text("synthetic-nested-retained-state-shape"),
                         2: .array([.unsigned(24), .unsigned(256), .unsigned(UInt64.max)])]),
                3: .boolean(false)])
            return [root, .array([root, root])]
        default: throw Failure("unknown corpus")
        }
    }

    static func framed(_ values: [Data]) -> [UInt8] {
        var bytes: [UInt8] = []
        for value in values {
            let size = UInt64(value.count)
            for shift in stride(from: 56, through: 0, by: -8) {
                bytes.append(UInt8(truncatingIfNeeded: size >> shift))
            }
            bytes.append(contentsOf: value)
        }
        return bytes
    }

    static func checksum(_ values: [Data]) -> String {
        var hash: UInt64 = 14_695_981_039_346_656_037
        for byte in framed(values) { hash = (hash ^ UInt64(byte)) &* 1_099_511_628_211 }
        return String(format: "%016llx", hash)
    }

    static func emit(_ object: [String: Any]) throws {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        print(String(decoding: data, as: UTF8.self))
    }

    static func run() throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard arguments.count >= 2 else { throw Failure("usage: describe CORPUS | run CORPUS ITERATIONS") }
        let name = arguments[1]
        let expected = try corpus(name)
        let encoded = try expected.map { try DeterministicCBOR.encode($0, limits: limits) }
        let initial = try encoded.map { try DeterministicCBOR.decode($0, limits: limits) }
        guard initial == expected else { throw Failure("initial decoded values differ") }
        let reencoded = try initial.map { try DeterministicCBOR.encode($0, limits: limits) }
        guard reencoded == encoded else { throw Failure("initial exact roundtrip differs") }
        let inputChecksum = checksum(encoded)
        if arguments[0] == "describe", arguments.count == 2 {
            try emit(["schemaVersion": 1, "corpus": name,
                      "label": "synthetic, not actual retained plans or whole-suite speedup",
                      "framing": "uint64 big-endian byte length then bytes for each record",
                      "wireHex": encoded.map { $0.map { String(format: "%02x", $0) }.joined() },
                      "recordsPerIteration": encoded.count,
                      "bytesPerIteration": encoded.reduce(0) { $0 + $1.count },
                      "decodedResultChecksumFNV1a64": inputChecksum])
            return
        }
        guard arguments[0] == "run", arguments.count == 3,
              let iterations = Int(arguments[2]), iterations > 0, iterations <= 2_000_000 else {
            throw Failure("invalid bounded iteration count")
        }
        var results = initial
        let cpuStart = clock()
        let wallStart = DispatchTime.now().uptimeNanoseconds
        for _ in 0..<iterations {
            for index in encoded.indices {
                results[index] = try DeterministicCBOR.decode(encoded[index], limits: limits)
            }
        }
        let wallEnd = DispatchTime.now().uptimeNanoseconds
        let cpuEnd = clock()
        guard cpuStart >= 0, cpuEnd >= cpuStart else { throw Failure("process CPU measurement failed") }
        // Exact byte/result validation stays outside the timed region. The timed batch includes
        // loop and result-retention/destruction overhead, but no encoding, hashing or construction.
        guard results == expected else { throw Failure("final decoded values differ") }
        let outputBytes = try results.map { try DeterministicCBOR.encode($0, limits: limits) }
        guard outputBytes == encoded else { throw Failure("final exact roundtrip differs") }
        let outputChecksum = checksum(outputBytes)
        guard outputChecksum == inputChecksum else { throw Failure("decoded-result checksum differs") }
        try emit(["schemaVersion": 1, "corpus": name, "iterations": iterations,
                  "recordsPerIteration": encoded.count,
                  "decodeCalls": iterations * encoded.count,
                  "bytesPerIteration": encoded.reduce(0) { $0 + $1.count },
                  "wallSeconds": Double(wallEnd - wallStart) / 1_000_000_000,
                  "processCPUSeconds": Double(cpuEnd - cpuStart) / Double(CLOCKS_PER_SEC),
                  "decodedResultChecksumFNV1a64": outputChecksum])
    }

    static func main() {
        do { try run() }
        catch {
            FileHandle.standardError.write(Data("benchmark failed: \(error)\n".utf8))
            exit(1)
        }
    }
    struct Failure: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }
}
