import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Disposable local state and synthetic HTTP exercise composition, without native publication or installed services.
final class SharedSetupRelayConnectorOwnerTests: XCTestCase, @unchecked Sendable {
    private struct Interrupted: Error {}
    private struct Fixture: Sendable {
        let dns: DNSRecordFixture
        let intent: SharedSetupImportIntent
        let runtime: RuntimeMaterialReference
        let reference: RelayRunCredentialReference
        let token: Data
        init(retainReference: Bool = true, native: Bool = false) throws {
            let f = try DNSRecordFixture(); dns = f; _ = try f.retainCreated()
            let h = f.base.h, account = h.f.account
            let activity: ServiceReleaseActivityReference? = native ? try .init(services: h.services,
                identities: [.transport: .init(device: 1, inode: 100), .gateway: .init(device: 1, inode: 101)]) : nil
            let material = try RuntimePreparationMaterial.create(services: h.services, notValidBefore: Date().addingTimeInterval(-60),
                notValidAfter: Date().addingTimeInterval(600), serviceActivity: activity)
            runtime = try material.reference
            try h.machine { machine in try machine.retainRuntimeMaterial(material.reference); try machine.completeRuntimePublication(material.reference) }
            let journal = try h.f.open(); intent = try journal.advance(h.intent, to: .runtimePublished); try journal.close()
            let tunnel = try f.base.tunnel.createdTunnel(expected: intent, plan: f.base.plan)
            let encodedToken = try JSONSerialization.data(withJSONObject: ["a": tunnel.accountID, "t": tunnel.tunnelID,
                "s": Data(repeating: 0x72, count: 32).base64EncodedString()], options: [.sortedKeys, .withoutEscapingSlashes]).base64EncodedString()
            token = Data(encodedToken.utf8)
            let credential = try CloudflareTunnelRunCredential.restore(token, tunnel: tunnel)
            let selected = try RelayRunCredentialMaterial(expected: intent, plan: f.base.plan, created: f.base.tunnel,
                runtime: runtime, account: account, inventory: h.f.inventory, credential: credential).reference
            reference = selected
            if retainReference {
                let retained = intent, runtime = runtime
                try h.directory { directory in _ = try SharedSetupRelayRunReferenceStorage.retain(selected, expected: retained,
                    plan: f.base.plan, created: f.base.tunnel, runtime: runtime, directory: directory, owner: getuid(), verifyCurrent: {}) }
            }
        }
        var runPath: String { URL(fileURLWithPath: dns.path).deletingLastPathComponent()
            .appendingPathComponent(AdministrativeSetupPublication.File.importRelayRunReference(accountID: intent.scope.accountID).name).path }
    }
    private func publish(_ f: Fixture, owner: SetupAccountOwner, probe: RelayIngressProbe,
                         operations: RelayConnectorSetupOperations) async throws -> AdministrativeSetupPublicationResult {
        try await owner.publishImportedRelayConnector(callerUID: getuid(), expected: f.dns.base.h.progress(owner),
            proposal: f.dns.base.h.f.proposal(), operations: operations, send: { try await probe.send($0) })
    }
    private func replace(_ path: String) throws {
        let bytes = try Data(contentsOf: URL(fileURLWithPath: path)), next = path + ".replacement"
        try bytes.write(to: URL(fileURLWithPath: next)); XCTAssertEqual(chmod(next, 0o600), 0); XCTAssertEqual(rename(next, path), 0)
    }
    func testProviderReadsReleaseLeasesAndPublicationUsesTheExactAcceptedReference() async throws {
        let f = try Fixture(), h = f.dns.base.h, owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.progress(owner), published = Mutex(0)
        let probe = try RelayIngressProbe(RelayConnectorPreflightReplies.ownerSteps(f.dns), hook: { _, _ in try h.machine { _ in } })
        let operations = RelayConnectorSetupOperations(publish: { context, reference, mode, verify in
            try verify(); XCTAssertEqual(context.runtime, f.runtime); XCTAssertEqual(context.expected, f.intent)
            XCTAssertEqual(context.reference, f.reference); XCTAssertEqual(reference, f.reference)
            if case .validateRetained = mode { XCTFail("Unactivated state selected validation-only mode") }
            published.withLock { $0 += 1 }; try verify(); return .created
        })
        let result = try await publish(f, owner: owner, probe: probe, operations: operations)
        XCTAssertEqual(result, .created); XCTAssertEqual(published.withLock { $0 }, 1)
        XCTAssertEqual(try h.progress(owner), expected)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 11); XCTAssertTrue(requests.allSatisfy { $0.httpMethod == "GET" })
    }
    func testLocalScopeChangeAtEveryReceiptPreventsPublication() async throws {
        for index in 1...11 {
            let f = try Fixture(), owner = try f.dns.base.h.owner(); defer { try? owner.close() }
            let probe = try RelayIngressProbe(RelayConnectorPreflightReplies.ownerSteps(f.dns), hook: { count, _ in
                if count == index { try f.dns.base.h.machine { machine in
                    let inventory = try XCTUnwrap(machine.inventory()); _ = try machine.writeInventory(inventory, expectedRevision: inventory.revision)
                } }
            })
            do { _ = try await publish(f, owner: owner, probe: probe, operations: .init(publish: { _, _, _, _ in XCTFail(); return .created })); XCTFail() }
            catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, index)
        }
    }
    func testIdenticalDependencyReplacementAtTheFinalReceiptPreventsPublication() async throws {
        for selected in 0..<4 {
            let f = try Fixture(), owner = try f.dns.base.h.owner(); defer { try? owner.close() }
            let paths = [f.dns.path, f.dns.base.path, f.dns.base.h.path, f.runPath]
            let probe = try RelayIngressProbe(RelayConnectorPreflightReplies.ownerSteps(f.dns), hook: { count, _ in
                if count == 11 { try self.replace(paths[selected]) }
            })
            do { _ = try await publish(f, owner: owner, probe: probe, operations: .init(publish: { _, _, _, _ in XCTFail(); return .created })); XCTFail() }
            catch {}
            let requests = await probe.all(); XCTAssertEqual(requests.count, 11)
        }
    }
    func testMissingAcceptedReferenceCannotFetchOrInventAToken() async throws {
        let f = try Fixture(retainReference: false), owner = try f.dns.base.h.owner(); defer { try? owner.close() }
        let probe = try RelayIngressProbe([RelayConnectorPreflightReplies.ownerSteps(f.dns)[0]])
        do { _ = try await publish(f, owner: owner, probe: probe, operations: .init(publish: { _, _, _, _ in XCTFail(); return .created })); XCTFail() } catch {}
        let requests = await probe.all(); XCTAssertEqual(requests.count, 1); XCTAssertFalse(FileManager.default.fileExists(atPath: f.runPath))
    }
    func testProviderFailureOrShutdownDoesNotPublishOrAdvanceTheImport() async throws {
        for closing in [false, true] {
            let f = try Fixture(), owner = try f.dns.base.h.owner(); defer { try? owner.close() }
            let expected = try f.dns.base.h.progress(owner)
            var replies = try RelayConnectorPreflightReplies.ownerSteps(f.dns); if !closing { replies[10] = .lost }
            let probe = RelayIngressProbe(replies, hook: { count, _ in
                if closing && count == 11 { XCTAssertThrowsError(try owner.close()) }
            })
            do { _ = try await publish(f, owner: owner, probe: probe, operations: .init(publish: { _, _, _, _ in XCTFail(); return .created })); XCTFail() } catch {}
            if !closing { XCTAssertEqual(try f.dns.base.h.progress(owner), expected) }
            XCTAssertNoThrow(try owner.close())
        }
    }
    func testLostPublicationReplyRequiresFreshProviderReadsAndPreservesAcceptedState() async throws {
        let f = try Fixture(), owner = try f.dns.base.h.owner(); defer { try? owner.close() }
        let first = try RelayIngressProbe(RelayConnectorPreflightReplies.ownerSteps(f.dns))
        do { _ = try await publish(f, owner: owner, probe: first, operations: .init(publish: { _, _, _, verify in try verify(); throw Interrupted() })); XCTFail() }
        catch { XCTAssertTrue(error is Interrupted) }
        let second = try RelayIngressProbe(RelayConnectorPreflightReplies.ownerSteps(f.dns))
        let result = try await publish(f, owner: owner, probe: second, operations: .init(publish: { _, reference, _, verify in
            try verify(); XCTAssertEqual(reference, f.reference); return .retained
        }))
        XCTAssertEqual(result, .retained); let requests = await second.all(); XCTAssertEqual(requests.count, 11)
    }
    func testNativeRetainedReferencePreservesTheTransportReaderDuringUpdateAdmission() throws {
        for native in [false, true] {
            let f = try Fixture(native: native)
            let snapshot = try f.dns.base.h.machine { try RuntimeReleaseCompatibilitySnapshot.capture(machine: $0) }
            let reader = snapshot.requirements.formats.first { $0.role == .transport && $0.name == RelayRunCredentialReference.formatName }
            if native {
                XCTAssertEqual(reader?.readVersions, [1]); XCTAssertEqual(reader?.writeVersions, [])
            } else { XCTAssertNil(reader) }
            let privateMaterial = try XCTUnwrap(snapshot.requirements.formats.first {
                $0.role == .setupController && $0.name == RelayRunCredentialMaterial.formatName
            })
            XCTAssertEqual(privateMaterial.readVersions, [1]); XCTAssertEqual(privateMaterial.writeVersions, [1])
            XCTAssertFalse(snapshot.requirements.formats.contains { $0.role == .transport && $0.name == RelayRunCredentialMaterial.formatName })
        }
    }
    func testWrongCallerAndChangedProposalHaveNoProviderOrPublicationEffects() async throws {
        let f = try Fixture(), owner = try f.dns.base.h.owner(); defer { try? owner.close() }
        let proposal = try f.dns.base.h.f.proposal(), expected = try f.dns.base.h.progress(owner), probe = RelayIngressProbe([])
        let operations = RelayConnectorSetupOperations(publish: { _, _, _, _ in XCTFail(); return .created })
        for (uid, selected) in [(getuid() + 1, proposal), (getuid(), PortableSetup(defaults: proposal.defaults))] {
            do {
                _ = try await owner.publishImportedRelayConnector(callerUID: uid, expected: expected, proposal: selected,
                    operations: operations, send: { try await probe.send($0) }); XCTFail()
            } catch {}
        }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
    }

    func testOwnerComposesRealPublicationAndRefusesADependencyChangedBeforeCommit() async throws {
        for replaceDuringStage in [false, true] {
            let f = try Fixture(native: true), h = f.dns.base.h, owner = try h.owner(); defer { try? owner.close() }
            let initialization = try h.machine { try XCTUnwrap($0.initialization(accountID: f.intent.scope.accountID)) }
            let bootstrap = try RuntimeConfigurationBundle.initial(account: h.f.account, initialization: initialization,
                reference: f.runtime, inventory: h.f.inventory, importIntent: f.intent, relayPlan: f.dns.base.plan).transport
            let base = "/private/tmp/remozio-owner-publication-" + UUID().uuidString
            try FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: false)
            defer { try? FileManager.default.removeItem(atPath: base) }
            XCTAssertEqual(chmod(base, 0o755), 0)
            let directory = try ProtectedSetupDirectory(anchor: base, relativePath: "Artifacts", owner: getuid(), visibility: .sharedMetadata)
            defer { directory.close() }
            let probe = try RelayIngressProbe(RelayConnectorPreflightReplies.ownerSteps(f.dns))
            let operations = RelayConnectorSetupOperations(publish: { context, reference, mode, verify in
                let publicationDirectory = try ProtectedSetupDirectory(anchor: base, relativePath: "Artifacts", owner: getuid(),
                    visibility: .sharedMetadata, createIfMissing: false)
                defer { publicationDirectory.close() }
                return try RelayConnectorStartupPublication.publishPrepared(context: context, reference: reference,
                    directory: publicationDirectory, owner: getuid(), mode: mode, readBootstrap: { bootstrap.canonicalBytes },
                    readToken: { f.token }, verifyCurrent: verify, didStage: { stage in
                        if replaceDuringStage, stage == .staged { try self.replace(f.runPath) }
                    })
            })
            let path = directory.path + "/" + AdministrativeSetupPublication.File.transportRelayReference.name
            if replaceDuringStage {
                do { _ = try await publish(f, owner: owner, probe: probe, operations: operations); XCTFail() } catch {}
                XCTAssertFalse(FileManager.default.fileExists(atPath: path))
            } else {
                let result = try await publish(f, owner: owner, probe: probe, operations: operations)
                XCTAssertEqual(result, .created)
                let bytes = try Data(contentsOf: URL(fileURLWithPath: path))
                XCTAssertEqual(bytes, try f.reference.encoded); XCTAssertNil(bytes.range(of: f.token))
                let loaded = try RelayConnectorStartupReference.load(runtime: f.runtime, relayPort: f.dns.base.plan.port,
                    read: { try ProtectedServiceConfiguration.readOptional(anchor: directory.path,
                        relativePath: AdministrativeSetupPublication.File.transportRelayReference.name, owner: getuid()) },
                    verifyCurrent: { try directory.validate() })
                XCTAssertEqual(loaded?.reference, f.reference)
            }
            let requests = await probe.all(); XCTAssertEqual(requests.count, 11)
        }
    }

}
