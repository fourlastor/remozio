import CryptoKit
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

/// Signs owned historical fixtures only. It proves no live peer, fresh challenge, protected writer, or startup admission.
final class RetainedSetupReadinessArchiveTests: XCTestCase {
    final class Fixture {
        let source: RetainedSetupPromotionArchiveTests.Fixture
        let promotion: MachineUpdateRetainedSetupPromotionIntentRecord
        let rootKey: P256.Signing.PrivateKey
        let transportKey: P256.Signing.PrivateKey
        let rootFields: [UInt64: CBORValue]
        let transportFields: [UInt64: CBORValue]
        let id = UUID(), revision = UUID()
        let limits = try! CBORLimits(maxBytes: 4_194_304, maxDepth: 4, maxItems: 4096)

        init() throws {
            let source = try RetainedSetupPromotionArchiveTests.Fixture(changedPolicy: true)
            var promotionFields = source.recordFields; promotionFields[4] = .unsigned(3)
            let promotion = try MachineUpdateRetainedSetupPromotionIntentRecord.decode(source.record(promotionFields))
            let publication = try promotion.publication(), archive = publication.configuration.archive
            let activation = try archive.originalActivation(), completion = try archive.completionIntent()
            let runtime = source.configuration.completion.activationFixture.source.f.f
            let rootKey = runtime.f.signingKey
            guard case .map(let identity) = try DeterministicCBOR.decode(runtime.material.transportIdentity,
                limits: CBORLimits(maxBytes: 16384, maxDepth: 1, maxItems: 9)),
                  case .bytes(let privateBytes) = identity[2] else { throw RuntimeActivationError.invalidPlan }
            let transportKey = try P256.Signing.PrivateKey(x963Representation: privateBytes)
            XCTAssertEqual(rootKey.publicKey.x963Representation, activation.reference.services.authorityPublicKey)
            XCTAssertEqual(transportKey.publicKey.x963Representation, try activation.reference.transportPublicKeyX963)
            let policy = try XCTUnwrap(completion.committedPolicy?.snapshot())
            let checkpoint = try XCTUnwrap(completion.committedCheckpoint)
            let boundary = try DeterministicCBOR.encode(.map([
                0: .bytes(completion.startupIntent.macID), 1: .bytes(completion.startupIntent.accountID),
                2: .bytes(policy.storedBytes), 3: .bytes(checkpoint),
                4: .bytes(Self.bytes(policy.revision))]), limits: CBORLimits(maxBytes: 524288, maxDepth: 1, maxItems: 11))
            let boundaryDigest = MachineUpdateActivationRecord.digest(Data("Remozio/RetainedSetupCompletionHealthBoundary/v2\0".utf8) + boundary)
            let promotionDigest = try MachineUpdateActivationRecord.digest(Data("Remozio/RetainedSetupPromotionHealthScope/v3\0".utf8) + promotion.encoded)
            func scope(_ role: AuthorityCodeRole, uid: UInt32, key: Data) throws -> [UInt64: CBORValue] {
                let code = try XCTUnwrap(publication.configuration.host.codePolicy.entries.first { $0.role == role && $0.active })
                return [0: .unsigned(3), 1: .text("retained-setup-health-scope"), 2: .bytes(try archive.binding.startupBinding.encoded),
                    3: .bytes(MachineUpdateActivationRecord.digest(archive.originalActivationBytes)),
                    4: .bytes(MachineUpdateActivationRecord.digest(archive.recordedInventoryBytes)),
                    5: .unsigned(role.rawValue), 6: .unsigned(UInt64(uid)),
                    7: .bytes(try AuthorityCodePolicy(entries: [code]).bytes), 8: .bytes(key),
                    9: .bytes(boundaryDigest), 10: .bytes(promotionDigest)]
            }
            let transportHost = try XCTUnwrap(publication.configuration.transport.settingsHost)
            self.source = source; self.promotion = promotion; self.rootKey = rootKey; self.transportKey = transportKey
            self.rootFields = try scope(.authority, uid: 0, key: rootKey.publicKey.x963Representation)
            self.transportFields = try scope(.transport, uid: transportHost.serviceUID, key: transportKey.publicKey.x963Representation)
        }
        static func bytes(_ id: UUID) -> Data { var value = id.uuid; return withUnsafeBytes(of: &value) { Data($0) } }
        func encode(_ fields: [UInt64: CBORValue]) throws -> Data { try DeterministicCBOR.encode(.map(fields), limits: limits) }
        func map(_ bytes: Data) throws -> [UInt64: CBORValue] {
            guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits) else {
                throw RuntimeActivationError.invalidPlan
            }
            return fields
        }
        func exchange(root: [UInt64: CBORValue]? = nil, transport: [UInt64: CBORValue]? = nil,
            childNonce: Data? = nil, rootNonce: UInt8 = 9, rootSigner: P256.Signing.PrivateKey? = nil,
            transportSigner: P256.Signing.PrivateKey? = nil) throws -> (request: Data, response: Data) {
            let request = try encode([0: .unsigned(1), 1: .text("retained-setup-health-challenge"),
                2: .bytes(Data(repeating: rootNonce, count: 32)), 3: .bytes(try encode(root ?? rootFields))])
            let nonce = childNonce ?? MachineUpdateActivationRecord.digest(Data("Remozio/RetainedSetupTransportNonce/v1\0".utf8) + request)
            let child = try encode([0: .unsigned(1), 1: .text("retained-setup-health-challenge"),
                2: .bytes(nonce), 3: .bytes(try encode(transport ?? transportFields))])
            let childSignature = try (transportSigner ?? transportKey).signature(for:
                Data("Remozio/RetainedSetupHealthReply/v1\0".utf8) + child).rawRepresentation
            let childReply = try encode([0: .unsigned(1), 1: .text("retained-setup-health-reply"),
                2: .bytes(child), 3: .bytes(childSignature)])
            let digestBytes = try encode([0: .unsigned(1), 1: .text("retained-setup-joint-transport-proof"),
                2: .bytes(child), 3: .bytes(childReply)])
            let digest = MachineUpdateActivationRecord.digest(digestBytes)
            let rootReply = try jointReply(request: request, digest: digest, signer: rootSigner)
            let packet = try encode([0: .unsigned(1), 1: .text("retained-setup-joint-health"),
                2: .bytes(rootReply), 3: .bytes(child), 4: .bytes(childReply)])
            return (request, packet)
        }
        func jointReply(request: Data, digest: Data, signer: P256.Signing.PrivateKey? = nil) throws -> Data {
            let signature = try (signer ?? rootKey).signature(for:
                Data("Remozio/RetainedSetupJointRootReply/v1\0".utf8) + digest + request).rawRepresentation
            return try encode([0: .unsigned(1), 1: .text("retained-setup-joint-root-reply"),
                2: .bytes(request), 3: .bytes(digest), 4: .bytes(signature)])
        }
        func readyFields(exchange supplied: (request: Data, response: Data)? = nil) throws -> [UInt64: CBORValue] {
            let pair = try supplied ?? exchange()
            return [0: .unsigned(1), 1: .text(MachineUpdateRetainedSetupPromotionReadyRecord.formatName),
                2: .bytes(Self.bytes(id)), 3: .bytes(Self.bytes(revision)),
                4: .bytes(Self.bytes(promotion.id)), 5: .bytes(Self.bytes(promotion.revision)),
                6: .bytes(try MachineUpdateActivationRecord.digest(Data("Remozio/RetainedSetupPromotionHealthScope/v3\0".utf8) + promotion.encoded)),
                7: .bytes(pair.request), 8: .bytes(pair.response)]
        }
    }

    func testRoundTripsTheSignedHistoricalRecordAndExactPublication() throws {
        let f = try Fixture(), fields = try f.readyFields(), bytes = try f.encode(fields)
        let record = try MachineUpdateRetainedSetupPromotionReadyRecord.decode(bytes)
        XCTAssertEqual(try record.encoded, bytes)
        XCTAssertEqual(record.id, f.id); XCTAssertEqual(record.revision, f.revision)
        XCTAssertEqual(record.promotionID, f.promotion.id)
        XCTAssertEqual(record.promotionRevision, f.promotion.revision)
        XCTAssertNoThrow(try record.requirePublication(f.promotion))
        let transcript = try f.encode([0: .bytes(record.request), 1: .bytes(record.response)])
        XCTAssertEqual(try record.transcriptDigest,
            MachineUpdateActivationRecord.digest(Data("Remozio/RetainedSetupPromotionReadyTranscript/v1\0".utf8) + transcript))
        XCTAssertEqual(record.description, "MachineUpdateRetainedSetupPromotionReadyRecord(redacted)")
        XCTAssertEqual(record.debugDescription, record.description)
    }

    func testRejectsEitherInvalidSignatureAndEitherWrongSigner() throws {
        let f = try Fixture()
        for wrongRoot in [false, true] {
            let exchange = try f.exchange(rootSigner: wrongRoot ? P256.Signing.PrivateKey() : nil,
                transportSigner: wrongRoot ? nil : P256.Signing.PrivateKey())
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(f.readyFields(exchange: exchange))))
        }
        let pair = try f.exchange()
        for (packetKey, signatureKey): (UInt64, UInt64) in [(2, 4), (4, 3)] {
            var packet = try f.map(pair.response)
            guard case .bytes(let reply) = packet[packetKey] else { throw RuntimeActivationError.invalidPlan }
            var fields = try f.map(reply)
            guard case .bytes(var signature) = fields[signatureKey] else { throw RuntimeActivationError.invalidPlan }
            signature[signature.startIndex] ^= 64; fields[signatureKey] = .bytes(signature)
            packet[packetKey] = .bytes(try f.encode(fields))
            if packetKey == 4 {
                guard case .bytes(let child) = packet[3], case .bytes(let reply) = packet[4] else { throw RuntimeActivationError.invalidPlan }
                let digest = MachineUpdateActivationRecord.digest(try f.encode([0: .unsigned(1),
                    1: .text("retained-setup-joint-transport-proof"), 2: .bytes(child), 3: .bytes(reply)]))
                let rootReply = try f.jointReply(request: pair.request, digest: digest)
                packet[2] = .bytes(rootReply)
                XCTAssertNoThrow(try MachineUpdateRetainedSetupHealthEvidence.verifyJointRootReply(request: pair.request,
                    response: rootReply, expected: .decode(f.encode(f.rootFields)), transportDigest: digest))
            } else {
                guard case .bytes(let child) = packet[3], case .bytes(let reply) = packet[4] else { throw RuntimeActivationError.invalidPlan }
                XCTAssertNoThrow(try MachineUpdateRetainedSetupHealthEvidence.verifyTransportReply(request: child,
                    response: reply, expected: .decode(f.encode(f.transportFields)), boundTo: pair.request))
            }
            let changed = try f.readyFields(exchange: (pair.request, f.encode(packet)))
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(changed)))
        }
    }

    func testRejectsAStandaloneRootSignatureAndAnUnboundChildNonce() throws {
        let f = try Fixture(), pair = try f.exchange()
        let signature = try f.rootKey.signature(for: Data("Remozio/RetainedSetupHealthReply/v1\0".utf8) + pair.request).rawRepresentation
        let standalone = try f.encode([0: .unsigned(1), 1: .text("retained-setup-health-reply"),
            2: .bytes(pair.request), 3: .bytes(signature)])
        var packet = try f.map(pair.response); packet[2] = .bytes(standalone)
        XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionReadyRecord.decode(
            f.encode(f.readyFields(exchange: (pair.request, f.encode(packet))))))
        let unbound = try f.exchange(childNonce: Data(repeating: 4, count: 32))
        XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(f.readyFields(exchange: unbound))))
    }

    func testRequiresTheExactPublishedPromotionPhaseAndIdentities() throws {
        let f = try Fixture(), record = try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(f.readyFields()))
        for key in [UInt64(2), 3] {
            var changed = f.source.recordFields; changed[4] = .unsigned(3); changed[key] = .bytes(Fixture.bytes(UUID()))
            let promotion = try MachineUpdateRetainedSetupPromotionIntentRecord.decode(f.source.record(changed))
            XCTAssertThrowsError(try record.requirePublishedIntent(promotion))
        }
        for phase in [UInt64(1), 2] {
            var changed = f.source.recordFields; changed[4] = .unsigned(phase)
            let promotion = try MachineUpdateRetainedSetupPromotionIntentRecord.decode(f.source.record(changed))
            XCTAssertThrowsError(try record.requirePublishedIntent(promotion))
        }
        let foreign = try RetainedSetupPromotionArchiveTests.Fixture()
        var foreignFields = foreign.recordFields; foreignFields[4] = .unsigned(3)
        XCTAssertThrowsError(try record.requirePublication(.decode(foreign.record(foreignFields)))) {
            XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
        }
        foreignFields[2] = .bytes(Fixture.bytes(f.promotion.id))
        foreignFields[3] = .bytes(Fixture.bytes(f.promotion.revision))
        let changedPublication = try MachineUpdateRetainedSetupPromotionIntentRecord.decode(foreign.record(foreignFields))
        XCTAssertEqual(changedPublication.id, f.promotion.id)
        XCTAssertEqual(changedPublication.revision, f.promotion.revision)
        XCTAssertEqual(changedPublication.phase, .filesPublished)
        XCTAssertThrowsError(try record.requirePublishedIntent(changedPublication)) {
            XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
        }
    }

    func testRejectsValidSignaturesWithDifferentArchivedOperandsOrCode() throws {
        let f = try Fixture()
        let foreignScope = try Fixture()
        let otherBinding = try XCTUnwrap(foreignScope.rootFields[2])
        XCTAssertNotEqual(otherBinding, f.rootFields[2])
        for key in [UInt64(2), 3, 4, 9] {
            var root = f.rootFields, transport = f.transportFields
            root[key] = key == 2 ? otherBinding : .bytes(Data(repeating: 42, count: 32))
            transport[key] = root[key]
            let pair = try f.exchange(root: root, transport: transport)
            let record = try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(f.readyFields(exchange: pair)))
            XCTAssertThrowsError(try record.requirePublication(f.promotion)) {
                XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope)
            }
        }
        let policy = try f.promotion.publication().configuration.host.codePolicy
        let old = try XCTUnwrap(policy.entries.first { $0.role == .authority && $0.active })
        let other = try AuthorityCodeEntry(role: old.role, teamID: old.teamID, identifier: old.identifier + ".other",
            installedGeneration: old.installedGeneration, minimumGeneration: old.minimumGeneration,
            codeDirectoryHash: old.codeDirectoryHash, active: true)
        var root = f.rootFields; root[7] = .bytes(try AuthorityCodePolicy(entries: [other]).bytes)
        let pair = try f.exchange(root: root)
        let record = try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(f.readyFields(exchange: pair)))
        XCTAssertThrowsError(try record.requirePublication(f.promotion)) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope)
        }
    }

    func testRequiresPromotionScopeInsteadOfEarlierHealthVersions() throws {
        let f = try Fixture()
        for version in [UInt64(1), 2] {
            var root = f.rootFields, transport = f.transportFields
            for key in [UInt64(10)] + (version == 1 ? [UInt64(9)] : []) { root[key] = nil; transport[key] = nil }
            root[0] = .unsigned(version); transport[0] = .unsigned(version)
            let pair = try f.exchange(root: root, transport: transport)
            XCTAssertNoThrow(try MachineUpdateRetainedSetupHealthEvidence.decodeRequestedRequirement(pair.request))
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(f.readyFields(exchange: pair))))
        }
    }

    func testRejectsMalformedNoncanonicalUnknownAndOversizedReadyRecords() throws {
        let f = try Fixture(), original = try f.readyFields()
        for key in original.keys {
            var fields = original; fields[key] = nil
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(fields)))
        }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("wrong-purpose")), (9, .null),
            (2, .bytes(Data(repeating: 1, count: 15))), (3, .bytes(Data(repeating: 1, count: 17))),
            (4, .bytes(Data())), (5, .bytes(Data(repeating: 1, count: 17))),
            (6, .bytes(Data(repeating: 1, count: 31))), (7, .bytes(Data())), (7, .bytes(Data(repeating: 0, count: 16513))),
            (8, .bytes(Data())), (8, .bytes(Data(repeating: 0, count: 50241))), (8, .bytes(Data([0])))] {
            var fields = original; fields[key] = value
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(fields)))
        }
        let bytes = try f.encode(original)
        for bytes in [Data(), bytes + Data([0]), Data(repeating: 0, count: MachineUpdateRetainedSetupPromotionReadyRecord.maximumBytes + 1)] {
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionReadyRecord.decode(bytes)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    func testComposesTheExactRootRequestAndActualTransportPacket() throws {
        let f = try Fixture(), pair = try f.exchange()
        let packet = try MachineUpdateRetainedSetupJointHealthPacket.decode(pair.response)
        let root = try MachineUpdateRetainedSetupHealthEvidence.decodeRequestedRequirement(pair.request)
        let child = try MachineUpdateRetainedSetupHealthEvidence.decodeRequestedRequirement(packet.transportRequest)
        let digest = try MachineUpdateRetainedSetupJointHealthPacket.transportDigest(request: packet.transportRequest, reply: packet.transportReply)
        XCTAssertNoThrow(try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(f.readyFields(exchange: pair))))
        XCTAssertNoThrow(try MachineUpdateRetainedSetupHealthEvidence.verifyTransportReply(request: packet.transportRequest,
            response: packet.transportReply, expected: child, boundTo: pair.request))
        let other = try f.exchange(rootNonce: 8)
        let replyForOther = try f.jointReply(request: other.request, digest: digest)
        XCTAssertNoThrow(try MachineUpdateRetainedSetupHealthEvidence.verifyJointRootReply(request: other.request,
            response: replyForOther, expected: root, transportDigest: digest))
        let wrongRequest = MachineUpdateRetainedSetupJointHealthPacket(rootReply: replyForOther,
            transportRequest: packet.transportRequest, transportReply: packet.transportReply)
        XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionReadyRecord.decode(
            f.encode(f.readyFields(exchange: (pair.request, wrongRequest.encoded)))))
        let wrongDigest = Data(repeating: 42, count: 32)
        XCTAssertNotEqual(wrongDigest, digest)
        let replyForOtherDigest = try f.jointReply(request: pair.request, digest: wrongDigest)
        XCTAssertNoThrow(try MachineUpdateRetainedSetupHealthEvidence.verifyJointRootReply(request: pair.request,
            response: replyForOtherDigest, expected: root, transportDigest: wrongDigest))
        let wrongPacket = MachineUpdateRetainedSetupJointHealthPacket(rootReply: replyForOtherDigest,
            transportRequest: packet.transportRequest, transportReply: packet.transportReply)
        XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionReadyRecord.decode(
            f.encode(f.readyFields(exchange: (pair.request, wrongPacket.encoded)))))
    }

    func testRecordedPromotionDigestMustMatchTheValidSignedScopes() throws {
        let f = try Fixture(), original = try f.readyFields()
        XCTAssertNoThrow(try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(original)))
        var fields = original; fields[6] = .bytes(Data(repeating: 42, count: 32))
        XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(fields)))
    }

    func testPublicationChecksBothRecordedKeysAndTransportExecutionUID() throws {
        let f = try Fixture(), valid = try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(f.readyFields()))
        XCTAssertNoThrow(try valid.requirePublication(f.promotion))
        let otherRoot = P256.Signing.PrivateKey(), otherTransport = P256.Signing.PrivateKey()
        var root = f.rootFields; root[8] = .bytes(otherRoot.publicKey.x963Representation)
        var child = f.transportFields; child[8] = .bytes(otherTransport.publicKey.x963Representation)
        let wrongRoot = try f.exchange(root: root, rootSigner: otherRoot)
        let wrongChild = try f.exchange(transport: child, transportSigner: otherTransport)
        child = f.transportFields
        guard case .unsigned(let uid) = child[6] else { throw RuntimeActivationError.invalidPlan }
        child[6] = .unsigned(uid + 1)
        let wrongUID = try f.exchange(transport: child)
        for pair in [wrongRoot, wrongChild, wrongUID] {
            let decoded = try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(f.readyFields(exchange: pair)))
            XCTAssertThrowsError(try decoded.requirePublication(f.promotion)) {
                XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope)
            }
        }
    }

    func testPublicationChecksTheRecordedTransportCode() throws {
        let f = try Fixture(), valid = try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(f.readyFields()))
        XCTAssertNoThrow(try valid.requirePublication(f.promotion))
        let host = try XCTUnwrap(f.promotion.publication().configuration.transport.settingsHost)
        let old = host.consumerCode
        let changed = try AuthorityCodeEntry(role: old.role, teamID: old.teamID, identifier: old.identifier + ".other",
            installedGeneration: old.installedGeneration, minimumGeneration: old.minimumGeneration,
            codeDirectoryHash: old.codeDirectoryHash, active: true)
        var child = f.transportFields; child[7] = .bytes(try AuthorityCodePolicy(entries: [changed]).bytes)
        let pair = try f.exchange(transport: child)
        let decoded = try MachineUpdateRetainedSetupPromotionReadyRecord.decode(f.encode(f.readyFields(exchange: pair)))
        XCTAssertThrowsError(try decoded.requirePublication(f.promotion)) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope)
        }
    }

    func testReadyReaderDeclarationsRequireOnlyTheirExactReadDirections() throws {
        let f = try Fixture(), consumer = f.source.configuration.completion.activationFixture.source.f
        let inherited = try MachineUpdateRetainedSetupCompletionStorage.readerRequirements + MachineUpdateRetainedSetupPromotionStorage.readerRequirements
        let all = try inherited + MachineUpdateRetainedSetupPromotionReadyStorage.readerRequirements
        func candidate(role changedRole: AuthorityCodeRole? = nil, name changedName: String? = nil,
                       remove: Bool = false, omitVersion: Bool = false) throws -> SignedReleaseEvidence {
            try consumer.release { component in
                var formats = component.formats
                for requirement in all where requirement.role == component.role {
                    if let index = formats.firstIndex(where: { $0.name == requirement.name }) {
                        let current = formats[index]
                        formats[index] = try .init(name: current.name, readers: current.readers.union(requirement.readVersions), writers: current.writers)
                    } else { formats.append(try .init(name: requirement.name, readers: requirement.readVersions, writers: [])) }
                }
                if component.role == changedRole, let name = changedName,
                   let index = formats.firstIndex(where: { $0.name == name }) {
                    if remove { formats.remove(at: index) }
                    else if omitVersion {
                        let selected = formats[index]
                        let readers: Set<UInt64> = name == MachineUpdateRetainedSetupPromotionReadyRecord.formatName ? [2] : selected.readers.subtracting([28])
                        formats[index] = try .init(name: name, readers: readers, writers: [])
                    }
                }
                return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                    relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                    build: component.build, teamID: component.teamID, formats: formats, requests: component.requests)
            }
        }
        let complete = try candidate()
        XCTAssertNoThrow(try MachineUpdateRetainedSetupPromotionReadyStorage.requireReaderFormats(complete))
        for role: AuthorityCodeRole in [.authority, .setupController] {
            for (name, remove) in [(MachineUpdateRetainedSetupPromotionReadyRecord.formatName, true),
                                   (MachineUpdateRetainedSetupPromotionReadyRecord.formatName, false),
                                   ("authority.installation-preparation", false)] {
                let selected = try candidate(role: role, name: name, remove: remove, omitVersion: !remove)
                XCTAssertNoThrow(try MachineUpdateRetainedSetupPromotionStorage.requireReaderFormats(selected))
                XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionReadyStorage.requireReaderFormats(selected)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
                }
            }
        }
    }

    func testReadinessDeclarationIsInertAndReaderOnly() throws {
        XCTAssertEqual(MachineUpdateRetainedSetupPromotionReadyStorage.schemaVersion, 28)
        XCTAssertFalse(PreparationIntentStore.supportedSchemaVersions.contains(28))
        XCTAssertTrue(try MachineUpdateRetainedSetupPromotionReadyStorage.readerRequirements.allSatisfy { $0.writeVersions.isEmpty })
        XCTAssertTrue(try MachineUpdateRetainedSetupPromotionReadyRecord.readerRequirements.allSatisfy { $0.writeVersions.isEmpty })
        var db: OpaquePointer?; XCTAssertEqual(sqlite3_open(":memory:", &db), SQLITE_OK)
        let opened = try XCTUnwrap(db); defer { sqlite3_close(opened) }
        XCTAssertEqual(sqlite3_exec(opened, MachineUpdateRetainedSetupPromotionReadyStorage.createSQL, nil, nil, nil), SQLITE_OK)
        func insert(account: String = "zeroblob(16)", id: String = "zeroblob(16)",
                    revision: String = "zeroblob(16)", record: String) -> Int32 {
            XCTAssertEqual(sqlite3_exec(opened, "DELETE FROM retained_setup_promotion_ready_v1", nil, nil, nil), SQLITE_OK)
            return sqlite3_exec(opened, "INSERT INTO retained_setup_promotion_ready_v1 VALUES(\(account),\(id),\(revision),\(record))", nil, nil, nil)
        }
        XCTAssertEqual(insert(record: "zeroblob(71680)"), SQLITE_OK)
        XCTAssertNotEqual(insert(record: "zeroblob(71681)"), SQLITE_OK)
        XCTAssertNotEqual(insert(record: "zeroblob(0)"), SQLITE_OK)
        XCTAssertNotEqual(insert(record: "'x'"), SQLITE_OK)
        XCTAssertEqual(insert(record: "zeroblob(1)"), SQLITE_OK)
        XCTAssertEqual(insert(account: "zeroblob(15)", record: "zeroblob(1)"), SQLITE_CONSTRAINT)
        XCTAssertEqual(insert(id: "zeroblob(15)", record: "zeroblob(1)"), SQLITE_CONSTRAINT)
        XCTAssertEqual(insert(revision: "zeroblob(15)", record: "zeroblob(1)"), SQLITE_CONSTRAINT)
        XCTAssertEqual(insert(account: "'0123456789abcdef'", record: "zeroblob(1)"), SQLITE_CONSTRAINT)
    }
}
