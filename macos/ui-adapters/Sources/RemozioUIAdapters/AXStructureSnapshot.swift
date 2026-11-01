import Foundation

public enum AXStructureFailure: String, Codable, Equatable, Sendable, Error {
    case permissionDenied, invalidElement, wrongProcess, unsupported, noValue, cannotComplete, malformed, unavailable, limitExceeded
}

public enum AXStructureRead<Value: Codable & Equatable & Sendable>: Codable, Equatable, Sendable {
    case value(Value)
    case unavailable(AXStructureFailure)
}

public struct AXStructureLimits: Sendable {
    public let maximumNodes: Int
    public let maximumDepth: Int
    public let maximumChildren: Int
    public let maximumNames: Int
    public let maximumNameBytes: Int
    public let maximumRetainedTextBytes: Int
    public let maximumOperations: Int
    public let durationSeconds: Double
    public let messagingTimeoutSeconds: Float

    public static let standard = try! AXStructureLimits()
    public init(maximumNodes: Int = 256, maximumDepth: Int = 16, maximumChildren: Int = 64,
                maximumNames: Int = 128, maximumNameBytes: Int = 128,
                maximumRetainedTextBytes: Int = 131_072, maximumOperations: Int = 4096,
                durationSeconds: Double = 2, messagingTimeoutSeconds: Float = 0.2) throws {
        guard (1...4096).contains(maximumNodes), (0...64).contains(maximumDepth),
              (1...256).contains(maximumChildren), (1...128).contains(maximumNames),
              (1...256).contains(maximumNameBytes), (1...1_048_576).contains(maximumRetainedTextBytes),
              (1...32_768).contains(maximumOperations), durationSeconds.isFinite,
              durationSeconds > 0, durationSeconds <= 10, messagingTimeoutSeconds.isFinite,
              messagingTimeoutSeconds > 0, messagingTimeoutSeconds <= 1 else { throw AXStructureFailure.limitExceeded }
        self.maximumNodes = maximumNodes; self.maximumDepth = maximumDepth
        self.maximumChildren = maximumChildren; self.maximumNames = maximumNames
        self.maximumNameBytes = maximumNameBytes; self.maximumRetainedTextBytes = maximumRetainedTextBytes
        self.maximumOperations = maximumOperations; self.durationSeconds = durationSeconds
        self.messagingTimeoutSeconds = messagingTimeoutSeconds
    }
}

public enum AXStructureStop: String, Codable, Equatable, Sendable {
    case finished, durationLimit, operationLimit, invalidClock
}

/// Local diagnostics only. Node IDs are meaningful only within this observation, not across captures or process restarts.
public struct AXStructureSnapshot: Codable, Equatable, Sendable {
    public let formatVersion: Int
    public let observationID: UUID
    public let processID: Int32
    public let nodes: [AXStructureNode]
    public let stop: AXStructureStop
    public let operations: Int
    public let retainedTextBytes: Int
}

public struct AXStructureNode: Codable, Equatable, Sendable {
    public let id: Int
    public let depth: Int
    public var role: AXStructureRead<String>
    public var subrole: AXStructureRead<String>
    public var attributeNames: AXStructureRead<[String]>
    public var actionNames: AXStructureRead<[String]>
    public var children: [Int]
    public var childrenRead: AXStructureRead<Int>
    public var visited: Bool
}

/// Structural metadata has no title, description, identifier value, field value, selected text or action method.
enum AXStructureField { case role, subrole, attributeNames, actionNames }
protocol AXStructureSource {
    associatedtype Element: Hashable
    func prepare(_ element: Element, timeoutSeconds: Float) throws
    func string(_ field: AXStructureField, element: Element) throws -> String
    func names(_ field: AXStructureField, element: Element) throws -> [String]
    func children(_ element: Element, maximumCount: Int) throws -> (elements: [Element], totalCount: Int)
}

struct AXStructureCollector<Source: AXStructureSource> {
    let source: Source
    let limits: AXStructureLimits
    let now: () -> Double

    func capture(root: Source.Element, processID: Int32) -> AXStructureSnapshot {
        let start = now()
        var last = start, stop = AXStructureStop.finished, operations = 0, textBytes = 0
        var elements = [root], ids = [root: 0], nodes = [placeholder(id: 0, depth: 0)]
        func admitted() -> Bool {
            let time = now()
            guard start.isFinite, time.isFinite, time >= last else { stop = .invalidClock; return false }
            last = time
            guard time - start < limits.durationSeconds else { stop = .durationLimit; return false }
            guard operations < limits.maximumOperations else { stop = .operationLimit; return false }
            operations += 1
            return true
        }
        func read<T: Codable & Equatable & Sendable>(_ operation: () throws -> T) -> AXStructureRead<T> {
            guard admitted() else { return .unavailable(.limitExceeded) }
            do { return .value(try operation()) }
            catch { return .unavailable(error as? AXStructureFailure ?? .unavailable) }
        }
        func retain(_ values: [String], maximumCount: Int) throws -> [String] {
            guard values.count <= maximumCount else { throw AXStructureFailure.limitExceeded }
            var size = 0
            for value in values {
                let count = value.utf8.count
                guard count <= limits.maximumNameBytes else { throw AXStructureFailure.limitExceeded }
                size += count
            }
            guard size <= limits.maximumRetainedTextBytes - textBytes else { throw AXStructureFailure.limitExceeded }
            textBytes += size
            return values
        }
        var index = 0
        while index < nodes.count, stop == .finished {
            let element = elements[index]
            let prepared: AXStructureRead<Bool> = read { try source.prepare(element, timeoutSeconds: limits.messagingTimeoutSeconds); return true }
            if case .unavailable(let failure) = prepared {
                nodes[index] = placeholder(id: index, depth: nodes[index].depth, failure: failure)
                nodes[index].visited = stop == .finished
                index += 1; continue
            }
            var node = nodes[index]; node.visited = true
            node.role = read { try retain([source.string(.role, element: element)], maximumCount: 1)[0] }
            if stop == .finished { node.subrole = read { try retain([source.string(.subrole, element: element)], maximumCount: 1)[0] } }
            if stop == .finished { node.attributeNames = read { try retain(source.names(.attributeNames, element: element), maximumCount: limits.maximumNames) } }
            if stop == .finished { node.actionNames = read { try retain(source.names(.actionNames, element: element), maximumCount: limits.maximumNames) } }
            if stop == .finished {
                let page: AXStructureRead<Bool> = read {
                    let page = try source.children(element, maximumCount: limits.maximumChildren)
                    guard page.totalCount >= 0, page.elements.count <= limits.maximumChildren,
                          page.elements.count <= page.totalCount else { throw AXStructureFailure.malformed }
                    node.childrenRead = page.elements.count == page.totalCount ? .value(page.totalCount) : .unavailable(.limitExceeded)
                    for child in page.elements {
                        if let existing = ids[child] { node.children.append(existing); continue }
                        guard node.depth < limits.maximumDepth, nodes.count < limits.maximumNodes else {
                            node.childrenRead = .unavailable(.limitExceeded); continue
                        }
                        let id = nodes.count; ids[child] = id; elements.append(child)
                        nodes.append(placeholder(id: id, depth: node.depth + 1)); node.children.append(id)
                    }
                    return true
                }
                if case .unavailable(let failure) = page { node.childrenRead = .unavailable(failure) }
            }
            nodes[index] = node; index += 1
        }
        return AXStructureSnapshot(formatVersion: 1, observationID: UUID(), processID: processID,
            nodes: nodes, stop: stop, operations: operations, retainedTextBytes: textBytes)
    }
    private func placeholder(id: Int, depth: Int, failure: AXStructureFailure = .unavailable) -> AXStructureNode {
        .init(id: id, depth: depth, role: .unavailable(failure), subrole: .unavailable(failure),
            attributeNames: .unavailable(failure), actionNames: .unavailable(failure), children: [],
            childrenRead: .unavailable(failure), visited: false)
    }
}
