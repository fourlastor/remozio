import Darwin
import Foundation
import Synchronization
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class SetupRetainedStatusV3WireTests: XCTestCase {
    private typealias Wire = SetupRetainedStatusV3Wire

    private func request(_ byte: UInt8 = 3) throws -> Wire.Request {
        try .init(legacy: .init(requestID: Data(repeating: byte, count: 16)))
    }

    func testVersionThreeRequestIsCanonicalAndDoesNotDecodeAsVersionOne() throws {
        let request = try request()
        let bytes = try request.bytes
        XCTAssertEqual(try Wire.Request.decode(bytes).legacy, request.legacy)
        XCTAssertThrowsError(try SetupRetainedStatusWire.Request.decode(bytes))
        var noncanonical = bytes
        XCTAssertEqual(Array(bytes.prefix(3)), [0xa3, 0, 3])
        noncanonical.replaceSubrange(2..<3, with: [0x18, 3])
        XCTAssertThrowsError(try Wire.Request.decode(noncanonical))
    }

    func testUnknownAndObservedNoActionStayDistinct() throws {
        let request = try request()
        let unavailable = try Wire.reply(request, .unavailable)
        XCTAssertNil(try Wire.decodeReply(unavailable, matching: request).applicability)
        let noAction = try Wire.reply(request, .init(retained: .unavailable, restart: nil, applicability: .noAction))
        XCTAssertEqual(try Wire.decodeReply(noAction, matching: request).applicability, .noAction)
        XCTAssertThrowsError(try Wire.decodeReply(unavailable, matching: self.request(4)))
    }

    func testActionEvidenceCannotBeDecodedWithoutAnExactIdentity() throws {
        let request = try request()
        for action: Wire.Applicability in [.restore, .adoptRecordedCompletion, .releaseWindowFree] {
            let reply = try Wire.reply(request, .init(retained: .unavailable, restart: nil, applicability: action))
            XCTAssertThrowsError(try Wire.decodeReply(reply, matching: request))
        }
    }

    func testUnknownApplicabilityCodeAndNoncanonicalReplyAreRefused() throws {
        let request = try request()
        let reply = try Wire.reply(request, .unavailable)
        let limits = try CBORLimits(maxBytes: SetupRetainedStatusWire.maximumReplyBytes, maxDepth: 4, maxItems: 64)
        guard case .map(var fields) = try DeterministicCBOR.decode(reply, limits: limits) else {
            return XCTFail("Expected a version 3 map")
        }
        fields[11] = .unsigned(99)
        let unknown = try DeterministicCBOR.encode(.map(fields), limits: limits)
        XCTAssertThrowsError(try Wire.decodeReply(unknown, matching: request))
        var noncanonical = reply
        XCTAssertEqual(Array(reply.prefix(3)), [0xac, 0, 3])
        noncanonical.replaceSubrange(2..<3, with: [0x18, 3])
        XCTAssertThrowsError(try Wire.decodeReply(noncanonical, matching: request))
    }

    func testStatusV3HonorsInstallationRefusalBeforeReadingTheProjection() throws {
        let peer = XPCPeerCredentials(processID: getpid(), userID: getuid(), auditSessionID: 1)
        let closed = Mutex(0), checked = Mutex(0), reads = Mutex(0)
        let facade = AdministrativeSetupConnectionFacade(verify: { peer }, select: { _ in true },
            openNormal: { _ in throw AdministrativeSetupError.unavailable }, status: { _ in .unavailable },
            statusV3: { _ in reads.withLock { $0 += 1 }; return .unavailable },
            check: { checked.withLock { $0 += 1 }; return .refused },
            invalidate: { closed.withLock { $0 += 1 } })
        let response = Mutex<[Data?]>([])
        facade.retainedInvocationStatus(try request().bytes) { bytes in response.withLock { $0.append(bytes) } }
        XCTAssertEqual(response.withLock { $0 }, [nil])
        XCTAssertEqual(checked.withLock { $0 }, 1)
        XCTAssertEqual(reads.withLock { $0 }, 0)
        XCTAssertEqual(closed.withLock { $0 }, 1)
        XCTAssertEqual(facade.state, .closed)
    }

    func testProductionRoutingPreservesLegacyFactsBeforeServingAndDuringRetirement() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let manifest = f.candidate.manifest
            let components = try manifest.components.map { component in
                guard component.role == .app || component.role == .setupController else { return component }
                let status = try ReleaseFormat(name: Wire.formatName, readers: [3], writers: [3])
                return try ReleaseComponent(role: component.role, identifier: component.identifier,
                    generation: component.generation, relativePath: component.relativePath,
                    codeDirectoryHash: component.codeDirectoryHash, build: component.build, teamID: component.teamID,
                    formats: component.formats + [status], requests: component.requests)
            }
            let release = SignedReleaseEvidence(manifest: try .init(release: manifest.release, build: manifest.build,
                components: components, dependencies: manifest.dependencies), codeDirectoryHashes: f.candidate.codeDirectoryHashes)
            let peer = XPCPeerCredentials(processID: getpid(), userID: getuid(), auditSessionID: 1)
            let account = LocalAccountIdentity(uid: peer.userID, primaryGroupID: getgid(), directoryID: UUID())
            let owner = try SetupAccountOwner(machine: f.machine(), expectedReleaseDigest: InstallationInventory.digest(release),
                resume: { _, value in value }, lookupAccount: { _ in account })
            defer { try? owner.close() }
            let routing = AdministrativeSetupLifecycle.Routing(validateStartup: {})
            try routing.install(owner)
            try AdministrativeSetupLifecycle.Runtime.configureRetainedStatus(owner: owner, candidate: release)
            try AdministrativeSetupLifecycle.Runtime.configureRetainedStatus(owner: owner, candidate: release)
            let reservation = try owner.reserveRetainedInvocation(authenticatedPeer: peer,
                incarnation: UUID(), authenticatedOwner: account).record
            defer { reservation.abortConstruction() }

            let legacy = AdministrativeSetupXPCListener.statusApplicabilityReader(
                available: Wire.supports(f.candidate), routing: routing)
            XCTAssertNil(legacy)
            let legacyFacade = AdministrativeSetupConnectionFacade(verify: { peer }, select: { _ in true },
                openNormal: { _ in throw AdministrativeSetupError.unavailable }, status: { routing.status($0) },
                statusV3: legacy, check: { routing.checkStatus() }, invalidate: {})
            let refused = Mutex<[Data?]>([])
            legacyFacade.retainedInvocationStatus(try request().bytes) { bytes in refused.withLock { $0.append(bytes) } }
            XCTAssertEqual(refused.withLock { $0 }, [nil])
            XCTAssertEqual(legacyFacade.state, .closed)

            let current = try XCTUnwrap(AdministrativeSetupXPCListener.statusApplicabilityReader(
                available: Wire.supports(release), routing: routing))
            for state: AdministrativeSetupLifecycle.State in [.starting, .discovering, .serving, .retiring] {
                routing.move(to: state)
                let projection = current(peer)
                XCTAssertEqual(projection.v1, routing.status(peer))
                XCTAssertEqual(projection.v1.reservation, .observed(.reserved))
                XCTAssertNil(projection.applicability)
            }
        }
    }

}
