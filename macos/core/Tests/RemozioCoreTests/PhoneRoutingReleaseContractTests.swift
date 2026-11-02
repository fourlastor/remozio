import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class PhoneRoutingReleaseContractTests: XCTestCase {
    private let names = ["authority.routing-ipc", "phone.routing-frame", "routing.away-challenge",
                         "routing.away-control", "routing.status-response"]
    private let writers: [AuthorityCodeRole: Set<String>] = [
        .authority: ["authority.routing-ipc", "phone.routing-frame", "routing.away-challenge", "routing.status-response"],
        .transport: ["authority.routing-ipc", "phone.routing-frame"]
    ]

    private func replacing(_ component: ReleaseComponent, formats: [ReleaseFormat]? = nil,
                           path: String? = nil, hash: Data? = nil) throws -> ReleaseComponent {
        try .init(role: component.role, identifier: component.identifier, generation: component.generation,
            relativePath: path ?? component.relativePath, codeDirectoryHash: hash ?? component.codeDirectoryHash,
            build: component.build, teamID: component.teamID, formats: formats ?? component.formats,
            requests: component.requests)
    }

    private func release(_ fixture: RuntimeActivationFixture,
                         edit: (ReleaseComponent) throws -> ReleaseComponent = { $0 }) throws -> SignedReleaseEvidence {
        try NativeHostReleaseFixture.make(policy: fixture.plan.host.codePolicy) { component in
            var additions: [(String, Set<UInt64>, Set<UInt64>)] = []
            if let selected = self.writers[component.role] {
                additions += self.names.map { ($0, [1], selected.contains($0) ? [1] : []) }
            }
            if component.role == .authority || component.role == .setupController {
                additions.append((RuntimeActivationPlan.formatName, [3], component.role == .setupController ? [3] : []))
            }
            var formats = component.formats
            for (name, readers, writers) in additions {
                if let index = formats.firstIndex(where: { $0.name == name }) {
                    let old = formats[index]
                    formats[index] = try .init(name: name, readers: old.readers.union(readers), writers: old.writers.union(writers))
                } else { formats.append(try .init(name: name, readers: readers, writers: writers)) }
            }
            return try edit(self.replacing(component, formats: formats))
        }
    }

    func testExactRoleDeclarationsSelectTheSupportedRoutingVersion() throws {
        let fixture = try RuntimeActivationFixture(nativeConsumerHosts: true)
        let candidate = try release(fixture), policy = fixture.plan.host.codePolicy
        XCTAssertTrue(PhoneRoutingReleaseContract.hasDeclarations(in: candidate))
        XCTAssertNoThrow(try PhoneRoutingReleaseContract.validate(candidate, policy: policy))
        XCTAssertEqual(try PhoneRoutingReleaseContract.selectedVersion(in: candidate, policy: policy,
            nativeHosts: true, maximumPayloadBytes: PhoneRoutingFrame.maximumBytes), 1)
    }

    func testCapacityAndNativeHostAdmissionStayExplicit() throws {
        let fixture = try RuntimeActivationFixture(nativeConsumerHosts: true)
        let candidate = try release(fixture), policy = fixture.plan.host.codePolicy
        for budget in [0, PhoneRoutingFrame.maximumBytes - 1] {
            XCTAssertNil(try PhoneRoutingReleaseContract.selectedVersion(in: candidate, policy: policy,
                nativeHosts: true, maximumPayloadBytes: budget))
        }
        XCTAssertNil(try PhoneRoutingReleaseContract.selectedVersion(in: candidate, policy: policy,
            nativeHosts: false, maximumPayloadBytes: PhoneRoutingFrame.maximumBytes))
    }

    func testAbsentDeclarationsKeepLegacySelectionAndPartialDeclarationsFailClosed() throws {
        let fixture = try RuntimeActivationFixture(nativeConsumerHosts: true), policy = fixture.plan.host.codePolicy
        let legacy = try NativeHostReleaseFixture.make(policy: policy)
        XCTAssertFalse(PhoneRoutingReleaseContract.hasDeclarations(in: legacy))
        XCTAssertNil(try PhoneRoutingReleaseContract.selectedVersion(in: legacy, policy: policy,
            nativeHosts: true, maximumPayloadBytes: PhoneRoutingFrame.maximumBytes))
        for role in [AuthorityCodeRole.authority, .transport] {
            for name in names {
                let partial = try release(fixture) { component in
                    component.role == role ? try self.replacing(component, formats: component.formats.filter { $0.name != name }) : component
                }
                XCTAssertThrowsError(try PhoneRoutingReleaseContract.selectedVersion(in: partial, policy: policy,
                    nativeHosts: true, maximumPayloadBytes: PhoneRoutingFrame.maximumBytes))
            }
        }
    }

    func testEveryReaderAndWriterNeedsTheExactSelectedVersion() throws {
        let fixture = try RuntimeActivationFixture(nativeConsumerHosts: true), policy = fixture.plan.host.codePolicy
        var expected: [(AuthorityCodeRole, String, UInt64, Bool)] = []
        for role in [AuthorityCodeRole.authority, .transport] {
            expected += names.map { (role, $0, 1, writers[role]!.contains($0)) }
        }
        expected += [(.authority, RuntimeActivationPlan.formatName, 3, false),
                     (.setupController, RuntimeActivationPlan.formatName, 3, true)]
        for (role, name, version, writes) in expected {
            for missingWriter in writes ? [false, true] : [false] {
                let candidate = try release(fixture) { component in
                    guard component.role == role else { return component }
                    return try self.replacing(component, formats: component.formats.map { format in
                        guard format.name == name else { return format }
                        let later: Set<UInt64> = [version + 1]
                        return try .init(name: name, readers: missingWriter ? format.readers : later,
                            writers: missingWriter ? format.writers.subtracting([version]) : format.writers.isEmpty ? [] : later)
                    })
                }
                XCTAssertThrowsError(try PhoneRoutingReleaseContract.validate(candidate, policy: policy), "\(role):\(name)")
            }
        }
    }

    func testUnexpectedAuthorityOrTransportPathsCannotSatisfyTheContract() throws {
        let fixture = try RuntimeActivationFixture(nativeConsumerHosts: true), policy = fixture.plan.host.codePolicy
        for role in [AuthorityCodeRole.authority, .transport] {
            let candidate = try release(fixture) { component in
                component.role == role ? try self.replacing(component, path: "Contents/Helpers/UnexpectedRoutingHost") : component
            }
            XCTAssertThrowsError(try PhoneRoutingReleaseContract.validate(candidate, policy: policy)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
        }
    }

    func testChangedCodeCannotBorrowTheInstalledPolicy() throws {
        let fixture = try RuntimeActivationFixture(nativeConsumerHosts: true), policy = fixture.plan.host.codePolicy
        let original = try release(fixture), changedHash = Data(repeating: 98, count: 20)
        let components = try original.manifest.components.map { component in
            component.role == .transport ? try replacing(component, hash: changedHash) : component
        }
        var hashes = original.codeDirectoryHashes
        hashes[.transport] = changedHash
        let candidate = try SignedReleaseEvidence(manifest: .init(release: "0.1.0", build: "1", components: components),
            codeDirectoryHashes: hashes)
        XCTAssertNotEqual(try XCTUnwrap(original.codeDirectoryHashes[.transport]), changedHash)
        XCTAssertEqual(try PhoneRoutingReleaseContract.selectedVersion(in: candidate, policy: policy,
            nativeHosts: true, maximumPayloadBytes: PhoneRoutingFrame.maximumBytes), 1)
        XCTAssertEqual(try GatewaySettingsNativeSupport.mode(release: original, policy: policy), .native)
        XCTAssertThrowsError(try GatewaySettingsNativeSupport.mode(release: candidate, policy: policy)) {
            XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
        }
    }
}
