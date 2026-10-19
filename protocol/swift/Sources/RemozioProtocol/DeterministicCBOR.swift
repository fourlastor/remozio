import Foundation

public indirect enum CBORValue: Equatable, Sendable {
    case unsigned(UInt64)
    case bytes(Data)
    case text(String)
    case array([CBORValue])
    case map([UInt64: CBORValue])
    case boolean(Bool)
    case null

    public static func == (lhs: CBORValue, rhs: CBORValue) -> Bool {
        switch (lhs, rhs) {
        case let (.unsigned(a), .unsigned(b)): a == b
        case let (.bytes(a), .bytes(b)): a == b
        case let (.text(a), .text(b)): a.utf8.elementsEqual(b.utf8)
        case let (.array(a), .array(b)): a == b
        case let (.map(a), .map(b)): a == b
        case let (.boolean(a), .boolean(b)): a == b
        case (.null, .null): true
        default: false
        }
    }
}

public struct CBORLimits: Sendable {
    public let maxBytes: Int
    public let maxDepth: Int
    public let maxItems: Int

    public init(maxBytes: Int, maxDepth: Int, maxItems: Int) throws {
        guard maxBytes > 0, maxDepth >= 0, maxDepth <= 64, maxItems > 0 else {
            throw CBORError.invalidLimits
        }
        self.maxBytes = maxBytes
        self.maxDepth = maxDepth
        self.maxItems = maxItems
    }
}

public enum CBORLimit: Sendable { case bytes, depth, items }

public enum CBORError: Error, Equatable {
    case invalidLimits
    case limitExceeded(CBORLimit)
    case truncated
    case nonCanonical
    case unsupportedType
    case invalidUTF8
    case trailingBytes
}

/// A deterministic CBOR subset. Successful decoding does not authenticate a message.
public enum DeterministicCBOR {
    public static func encode(_ value: CBORValue, limits: CBORLimits) throws -> Data {
        var writer = Writer(limits: limits)
        try writer.write(value, depth: 0)
        return Data(writer.output)
    }

    public static func decode(_ data: Data, limits: CBORLimits) throws -> CBORValue {
        guard data.count <= limits.maxBytes else { throw CBORError.limitExceeded(.bytes) }
        var reader = Reader(input: Array(data), limits: limits)
        let value = try reader.read(depth: 0)
        guard reader.offset == reader.input.count else { throw CBORError.trailingBytes }
        return value
    }
}

private struct Writer {
    let limits: CBORLimits
    var output: [UInt8] = []
    var items = 0

    mutating func byte(_ value: UInt8) throws {
        guard output.count < limits.maxBytes else { throw CBORError.limitExceeded(.bytes) }
        output.append(value)
    }

    mutating func argument(_ value: UInt64, major: UInt8) throws {
        if value < 24 {
            try byte(major << 5 | UInt8(value))
            return
        }
        let width: Int
        let additional: UInt8
        switch value {
        case ...0xff: (width, additional) = (1, 24)
        case ...0xffff: (width, additional) = (2, 25)
        case ...0xffff_ffff: (width, additional) = (4, 26)
        default: (width, additional) = (8, 27)
        }
        try byte(major << 5 | additional)
        for shift in stride(from: (width - 1) * 8, through: 0, by: -8) {
            try byte(UInt8(truncatingIfNeeded: value >> shift))
        }
    }

    mutating func write(_ value: CBORValue, depth: Int) throws {
        guard depth <= limits.maxDepth else { throw CBORError.limitExceeded(.depth) }
        guard items < limits.maxItems else { throw CBORError.limitExceeded(.items) }
        items += 1
        switch value {
        case let .unsigned(value): try argument(value, major: 0)
        case let .bytes(value):
            try argument(UInt64(value.count), major: 2)
            guard value.count <= limits.maxBytes - output.count else { throw CBORError.limitExceeded(.bytes) }
            output.append(contentsOf: value)
        case let .text(value):
            try argument(UInt64(value.utf8.count), major: 3)
            guard value.utf8.count <= limits.maxBytes - output.count else { throw CBORError.limitExceeded(.bytes) }
            output.append(contentsOf: value.utf8)
        case let .array(values):
            guard values.count <= limits.maxItems - items else { throw CBORError.limitExceeded(.items) }
            try argument(UInt64(values.count), major: 4)
            for value in values { try write(value, depth: depth + 1) }
        case let .map(values):
            guard values.count <= (limits.maxItems - items) / 2 else { throw CBORError.limitExceeded(.items) }
            try argument(UInt64(values.count), major: 5)
            for key in values.keys.sorted() {
                try write(.unsigned(key), depth: depth + 1)
                try write(values[key]!, depth: depth + 1)
            }
        case let .boolean(value): try byte(value ? 0xf5 : 0xf4)
        case .null: try byte(0xf6)
        }
    }
}

private struct Reader {
    let input: [UInt8]
    let limits: CBORLimits
    var offset = 0
    var items = 0

    mutating func byte() throws -> UInt8 {
        guard offset < input.count else { throw CBORError.truncated }
        defer { offset += 1 }
        return input[offset]
    }

    mutating func argument(_ additional: UInt8) throws -> UInt64 {
        if additional < 24 { return UInt64(additional) }
        let width: Int
        let minimum: UInt64
        switch additional {
        case 24: (width, minimum) = (1, 24)
        case 25: (width, minimum) = (2, 0x100)
        case 26: (width, minimum) = (4, 0x1_0000)
        case 27: (width, minimum) = (8, 0x1_0000_0000)
        default: throw CBORError.unsupportedType
        }
        var result: UInt64 = 0
        for _ in 0..<width { result = result << 8 | UInt64(try byte()) }
        guard result >= minimum else { throw CBORError.nonCanonical }
        return result
    }

    mutating func read(depth: Int) throws -> CBORValue {
        guard depth <= limits.maxDepth else { throw CBORError.limitExceeded(.depth) }
        guard items < limits.maxItems else { throw CBORError.limitExceeded(.items) }
        items += 1
        let head = try byte()
        let major = head >> 5
        if major == 7 {
            switch head {
            case 0xf4: return .boolean(false)
            case 0xf5: return .boolean(true)
            case 0xf6: return .null
            default: throw CBORError.unsupportedType
            }
        }
        switch major {
        case 0, 2, 3, 4, 5: break
        default: throw CBORError.unsupportedType
        }
        let value = try argument(head & 31)
        if major == 0 { return .unsigned(value) }
        guard let count = Int(exactly: value), count <= input.count - offset else {
            throw CBORError.truncated
        }
        switch major {
        case 2, 3:
            let bytes = input[offset..<(offset + count)]
            offset += count
            if major == 2 { return .bytes(Data(bytes)) }
            guard let text = String(validating: bytes, as: UTF8.self) else { throw CBORError.invalidUTF8 }
            return .text(text)
        case 4:
            guard count <= limits.maxItems - items else { throw CBORError.limitExceeded(.items) }
            var values: [CBORValue] = []
            for _ in 0..<count { values.append(try read(depth: depth + 1)) }
            return .array(values)
        case 5:
            guard count <= (limits.maxItems - items) / 2 else { throw CBORError.limitExceeded(.items) }
            var values: [UInt64: CBORValue] = [:]
            var previous: UInt64?
            for _ in 0..<count {
                guard case let .unsigned(key) = try read(depth: depth + 1) else { throw CBORError.unsupportedType }
                guard previous == nil || key > previous! else { throw CBORError.nonCanonical }
                previous = key
                values[key] = try read(depth: depth + 1)
            }
            return .map(values)
        default: throw CBORError.unsupportedType
        }
    }
}
