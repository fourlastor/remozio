import Foundation
import XCTest
@testable import RemozioUIAdapters

final class AXStructureRecorderTests: XCTestCase {
    final class Source: AXStructureSource {
        var links: [Int: [Int]] = [0: [1, 2], 1: [], 2: []]
        var role = "AXTextField", subrole = "AXSecureTextField"
        var attributes = ["AXRole", "AXSubrole", "AXValue", "AXSelectedText"]
        var actions = ["AXPress"]
        var failures: [Int: AXStructureFailure] = [:]
        var events: [String] = []
        var onOperation: (() -> Void)?
        var malformedPage = false
        func prepare(_ element: Int, timeoutSeconds: Float) throws {
            events.append("prepare:\(element)"); onOperation?()
            XCTAssertGreaterThan(timeoutSeconds, 0)
            if let failure = failures[element] { throw failure }
        }
        func string(_ field: AXStructureField, element: Int) throws -> String {
            onOperation?()
            switch field {
            case .role: events.append("role:\(element)"); return role
            case .subrole: events.append("subrole:\(element)"); return subrole
            default: XCTFail("No content attribute may be read"); throw AXStructureFailure.malformed
            }
        }
        func names(_ field: AXStructureField, element: Int) throws -> [String] {
            onOperation?()
            switch field {
            case .attributeNames: events.append("attributes:\(element)"); return attributes
            case .actionNames: events.append("actions:\(element)"); return actions
            default: XCTFail("No content attribute may be read"); throw AXStructureFailure.malformed
            }
        }
        func children(_ element: Int, maximumCount: Int) throws -> (elements: [Int], totalCount: Int) {
            events.append("children:\(element)"); onOperation?()
            let all = links[element] ?? []
            return (Array(all.prefix(maximumCount)), malformedPage ? -1 : all.count)
        }
    }
    private func capture(_ source: Source, limits: AXStructureLimits = .standard,
                         now: @escaping () -> Double = { 0 }) -> AXStructureSnapshot {
        AXStructureCollector(source: source, limits: limits, now: now).capture(root: 0, processID: 42)
    }
    func testRecordsOnlyStructureIncludingSecureFieldsWithoutReadingTheirValues() throws {
        let source = Source(), result = capture(source)
        XCTAssertEqual(result.nodes.count, 3); XCTAssertEqual(result.stop, .finished)
        XCTAssertEqual(result.nodes[0].children, [1, 2]); XCTAssertEqual(result.operations, 18)
        XCTAssertEqual(result.nodes[1].subrole, .value("AXSecureTextField"))
        XCTAssertEqual(result.nodes[1].attributeNames, .value(source.attributes))
        XCTAssertTrue(result.nodes.allSatisfy(\.visited))
        let data = try JSONEncoder().encode(result)
        XCTAssertEqual(try JSONDecoder().decode(AXStructureSnapshot.self, from: data), result)
        // Names advertise availability; their underlying content is not requested by this source contract.
        XCTAssertEqual(source.events.count, 18)
    }
    func testCyclesAndAliasesDoNotDuplicateOrLoop() throws {
        let source = Source(); source.links = [0: [1, 1, 0], 1: [0]]
        let result = capture(source)
        XCTAssertEqual(result.nodes.count, 2); XCTAssertEqual(result.nodes[0].children, [1, 1, 0])
        XCTAssertEqual(result.nodes[1].children, [0]); XCTAssertEqual(result.operations, 12)
    }
    func testNodeDepthAndChildLimitsReportOmissionWithoutInventingAnEmptyTree() throws {
        let source = Source(); source.links = [0: [1, 2, 3], 1: [4]]
        for limits in [try AXStructureLimits(maximumNodes: 2), try AXStructureLimits(maximumDepth: 1),
                       try AXStructureLimits(maximumChildren: 1)] {
            let result = capture(source, limits: limits)
            XCTAssertLessThanOrEqual(result.nodes.count, limits.maximumNodes)
            XCTAssertTrue(result.nodes.contains { $0.childrenRead == .unavailable(.limitExceeded) })
            for node in result.nodes { XCTAssertTrue(node.children.allSatisfy { result.nodes.indices.contains($0) }) }
        }
        let depthZero = capture(source, limits: try .init(maximumDepth: 0))
        XCTAssertEqual(depthZero.nodes.count, 1); XCTAssertEqual(depthZero.nodes[0].childrenRead, .unavailable(.limitExceeded))
    }
    func testOversizedMetadataAndTotalTextAreRejectedWithoutTruncatedSelectors() throws {
        let source = Source(); source.role = String(repeating: "é", count: 65)
        source.actions = Array(repeating: "AXPress", count: 129)
        let result = capture(source)
        XCTAssertEqual(result.nodes[0].role, .unavailable(.limitExceeded))
        XCTAssertEqual(result.nodes[0].actionNames, .unavailable(.limitExceeded))
        let bounded = capture(Source(), limits: try .init(maximumRetainedTextBytes: 12))
        XCTAssertLessThanOrEqual(bounded.retainedTextBytes, 12)
        XCTAssertEqual(bounded.nodes[0].subrole, .unavailable(.limitExceeded))
    }
    func testOperationBudgetLeavesDiscoveredNodesExplicitlyUnread() throws {
        let source = Source(), result = capture(source, limits: try .init(maximumOperations: 6))
        XCTAssertEqual(result.stop, .operationLimit); XCTAssertEqual(result.operations, 6)
        XCTAssertEqual(result.nodes.count, 3); XCTAssertFalse(result.nodes[1].visited)
        XCTAssertFalse(result.nodes[2].visited); XCTAssertEqual(source.events.count, 6)
    }
    func testElapsedBudgetStopsAfterOneSlowReadWithoutRetry() throws {
        let source = Source(); var time = 0.0
        source.onOperation = { time += 3 }
        let result = capture(source, now: { time })
        XCTAssertEqual(result.stop, .durationLimit); XCTAssertEqual(result.operations, 1)
        XCTAssertEqual(source.events, ["prepare:0"])
        XCTAssertEqual(result.nodes[0].role, .unavailable(.limitExceeded))
    }
    func testInvalidOrRegressingClockStopsWithoutContinuingReadOperations() throws {
        for invalid in [Double.nan, .infinity, -1] {
            let source = Source(); var reads = 0
            let result = capture(source, now: { reads += 1; return reads == 1 ? 0 : invalid })
            XCTAssertEqual(result.stop, .invalidClock); XCTAssertTrue(source.events.isEmpty)
            XCTAssertEqual(result.operations, 0); XCTAssertFalse(result.nodes[0].visited)
        }
    }
    func testUnavailableAndForeignElementsNeverTriggerMetadataReadsAndRemainVisible() throws {
        for failure in [AXStructureFailure.permissionDenied, .invalidElement, .wrongProcess, .cannotComplete] {
            let source = Source(); source.failures[1] = failure
            let result = capture(source)
            XCTAssertEqual(result.nodes[1].role, .unavailable(failure)); XCTAssertTrue(result.nodes[1].visited)
            XCTAssertFalse(source.events.contains("role:1")); XCTAssertFalse(source.events.contains("children:1"))
            XCTAssertEqual(result.nodes[2].role, .value(source.role))
        }
    }
    func testMalformedChildCountsRemainUnknown() throws {
        let source = Source(); source.malformedPage = true
        let result = capture(source)
        XCTAssertEqual(result.nodes.count, 1); XCTAssertEqual(result.nodes[0].childrenRead, .unavailable(.malformed))
    }
    func testEveryCaptureHasASeparateObservationIdentityAndInvalidTargetsAreRejectedBeforeTCC() throws {
        let source = Source(); XCTAssertNotEqual(capture(source).observationID, capture(source).observationID)
        for target: Int32 in [0, -1] {
            XCTAssertThrowsError(try NativeAXStructureRecorder.capture(processID: target)) { XCTAssertEqual($0 as? AXStructureFailure, .wrongProcess) }
        }
    }
    func testInvalidLimitsAreRefused() throws {
        for duration in [0, -1, Double.nan, .infinity, 11] {
            XCTAssertThrowsError(try AXStructureLimits(durationSeconds: duration))
        }
        for timeout in [Float(0), -1, .nan, .infinity, 2] {
            XCTAssertThrowsError(try AXStructureLimits(messagingTimeoutSeconds: timeout))
        }
        XCTAssertThrowsError(try AXStructureLimits(maximumNodes: 0))
        XCTAssertThrowsError(try AXStructureLimits(maximumDepth: 65))
        XCTAssertThrowsError(try AXStructureLimits(maximumChildren: 0))
        XCTAssertThrowsError(try AXStructureLimits(maximumNames: 129))
        XCTAssertThrowsError(try AXStructureLimits(maximumNameBytes: 0))
        XCTAssertThrowsError(try AXStructureLimits(maximumRetainedTextBytes: 0))
        XCTAssertThrowsError(try AXStructureLimits(maximumOperations: 0))
    }
}
