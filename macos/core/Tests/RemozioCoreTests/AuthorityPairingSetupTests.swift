import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import Security
import XCTest
@testable import RemozioCore

final class AuthorityPairingSetupTests: XCTestCase, @unchecked Sendable {
    private enum Failure: Error { case denied }
    private final class Box<Value>: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: Value
        init(_ value: Value) { stored = value }
        var value: Value { get { lock.withLock { stored } } set { lock.withLock { stored = newValue } } }
    }
    private final class Environment: @unchecked Sendable {
        let epoch = UUID()
        let time = Box<UInt64>(100)
        let denied = Box(false), selfDenied = Box(false), peerDenied = Box(false)
        let authorized = Box(0), invalidated = Box(0), signed = Box(0)
        func now() -> AuthorityMoment { .init(epoch: epoch, milliseconds: time.value) }
    }
    private final class Fixture: @unchecked Sendable {
        let root: URL
        let journal: AuthorityJournal
        let continuity: ContinuityStore
        let authority = P256.Signing.PrivateKey(), transport = P256.Signing.PrivateKey(), biometric = P256.Signing.PrivateKey()
        let environment = Environment()
        let access: AuthorityPairingSetupAccess
        let policy: XPCPeerPolicy
        let writer: AuditEpochWriter
        let limits = try! CBORLimits(maxBytes: 16384, maxDepth: 12, maxItems: 1024)
        var mac: Data { Data(repeating: 1, count: 16) }
        var account: Data { Data(repeating: 2, count: 16) }
        init(auditVersions: Set<UInt64> = [1]) throws {
            root = URL(fileURLWithPath: "/private/tmp/remozio-local-pairing-" + UUID().uuidString)
            let ownedRoot = root
            var complete = false
            defer { if !complete { try? FileManager.default.removeItem(at: ownedRoot) } }
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["store", "continuity"] {
                let directory = root.appendingPathComponent(name)
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
                for file in ["writer.lock", name == "store" ? "journal.sqlite" : "continuity.sqlite"] {
                    let fd = Darwin.open(directory.appendingPathComponent(file).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                    guard fd >= 0 else { throw Failure.denied }; Darwin.close(fd)
                }
            }
            let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16), limits = self.limits
            let db = try JournalDatabase(lease: .init(anchor: root.path, relativeDirectory: "store", owner: getuid()),
                macID: mac, accountID: account, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 20, busyMilliseconds: 100, initialize: true)
            let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
            _ = try db.write { try $0.configureApprovalAuthority(capabilities: .init(contracts: [contract: []]), allowedContracts: [contract]) }
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(mac),
                2: .bytes(account), 3: .bytes(Data(repeating: 3, count: 16)), 4: .unsigned(1), 5: .unsigned(1),
                6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
            let epochWriter = try db.write { try $0.createEpoch(descriptor) }
            writer = epochWriter
            let app = try Self.appEntry()
            _ = try db.write { try $0.installCodePolicy(.init(entries: [app]), expectedRevision: nil) }
            let initial = try db.read { try CheckpointedJournal.checkpoint(transaction: $0, epoch: epochWriter.epoch, generation: 1, authorityGeneration: 1) }
            continuity = try .init(lease: .init(anchor: root.path, relativeDirectory: "continuity", owner: getuid()),
                macID: mac, accountID: account, initialize: initial)
            let requests = try ApprovalRequestCoordinator(database: db, continuity: continuity, writer: epochWriter,
                clockEpoch: environment.epoch, maximumRequests: 4, maximumRetainedBytes: 16384,
                requestLimits: limits, captureLimits: limits, decisionLimits: limits, signingLimits: limits, auditLimits: limits)
            journal = AuthorityJournal(requests: requests)
            policy = try .init(teamID: app.teamID, componentIdentifier: app.identifier,
                approvedCodeDirectoryHashes: [app.codeDirectoryHash], expectedUserID: getuid())
            let journal = journal, environment = environment, authority = authority
            access = try .init(journal: journal, macID: mac, accountID: account, authorityPublicKey: authority.publicKey.x963Representation,
                appPolicy: policy, configuration: .init(transportPublicKey: transport.publicKey.x963Representation, lifetimeMilliseconds: 1000),
                minimumEnvelopeVersion: 1, auditVersions: auditVersions, now: { environment.now() }, unixMilliseconds: { 1000 }, validateSelf: { _ in
                    if environment.selfDenied.value { throw Failure.denied }
                }, commit: { attempt, proof, event, authorize, validate in
                    try journal.commitPairingFixture(attempt, biometricProof: proof, authorityPublicKey: authority.publicKey.x963Representation,
                        addEventID: event, recheckAdministrator: authorize, now: { environment.now() }, validate: validate, sign: {
                            environment.signed.value += 1
                            return try authority.signature(for: $0).rawRepresentation
                        })
                })
            complete = true
        }
        deinit { try? journal.close(); continuity.close(); try? FileManager.default.removeItem(at: root) }
        static func appEntry(active: Bool = true) throws -> AuthorityCodeEntry {
            try .init(role: .app, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.app", installedGeneration: 1,
                minimumGeneration: 1, codeDirectoryHash: Data(repeating: 4, count: 20), active: active)
        }
        func endpoint() throws -> AuthorityPairingXPCEndpoint {
            let environment = environment
            return try .init(access: access, budget: .init(maximum: 1), verify: {
                if environment.peerDenied.value { throw Failure.denied }
            }, authorize: { _ in
                environment.authorized.value += 1
                if environment.denied.value { throw Failure.denied }
            }, invalidate: { environment.invalidated.value += 1 })
        }
        func proposal() throws -> PairingTranscript {
            let trust = try journal.read { try $0.approvalTrustSnapshot() }, scope = try ChannelScope(macID: mac,
                accountID: account, phoneID: Data(repeating: 8, count: 16), enrollmentEpoch: Data(repeating: 9, count: 16))
            let offers = try [ChannelRole.phone, .mac].enumerated().map { index, role in
                try ChannelOffer(role: role, scope: scope, nonce: Data(repeating: UInt8(20 + index), count: 32), envelopeVersions: [1],
                    requests: [.init(kind: 0, wireVersion: 1, schemaVersion: 1, features: [])], auditVersions: [1])
            }
            var revision = trust.revision.uuid
            return try .init(setupID: Data(repeating: 30, count: 16), challenge: Data(repeating: 31, count: 32), phone: offers[0], mac: offers[1],
                minimumEnvelopeVersion: 1, selectedEnvelopeVersion: 1, macAuthorityKey: authority.publicKey.x963Representation,
                macTransportKey: transport.publicKey.x963Representation,
                transportKey: .init(keyID: Data(repeating: 32, count: 16), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                decisionKey: .init(keyID: Data(repeating: 33, count: 16), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                biometricKey: .init(keyID: Data(repeating: 34, count: 16), publicKey: biometric.publicKey.x963Representation),
                enrollmentTag: Data(repeating: 35, count: 32), replacement: nil,
                expectedTrustRevision: withUnsafeBytes(of: &revision) { Data($0) }, issuedAtUnixMillis: 1, expiresAtUnixMillis: 2)
        }
        func records() throws -> UInt64 {
            try journal.read { try $0.epoch(Data(repeating: 3, count: 16))?.head ?? 0 }
        }
        func assertCheckpoint() throws {
            let state = try continuity.read(), epoch = writer.epoch
            XCTAssertNil(state.pending)
            XCTAssertEqual(state.committed, try journal.read {
                try CheckpointedJournal.checkpoint(transaction: $0, epoch: epoch, generation: state.committed.generation,
                    authorityGeneration: state.committed.authorityGeneration)
            })
        }
    }
    private var authorization: Data { Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size) }
    private func hello(_ endpoint: AuthorityPairingXPCEndpoint) throws {
        let result = Box<UInt64>(0); endpoint.pairingHello { result.value = $0 }; XCTAssertEqual(result.value, 1)
    }
    private func staged(_ endpoint: AuthorityPairingXPCEndpoint, proposal: PairingTranscript) throws -> PairingTranscript {
        let result = Box<Data?>(nil)
        endpoint.stagePairing(try proposal.encode(), authorization: authorization) { result.value = $0 }
        return try .decode(XCTUnwrap(result.value))
    }
    private func commit(_ endpoint: AuthorityPairingXPCEndpoint, transcript: PairingTranscript, fixture: Fixture,
                        digest: Data? = nil, proof: Data? = nil) throws -> Data? {
        let result = Box<Data?>(nil)
        let proof = try proof ?? fixture.biometric.signature(for: transcript.signingInput(purpose: .phoneBiometric)).rawRepresentation
        endpoint.commitPairing(transcript.setupID, confirmedDigest: try digest ?? transcript.digest(), biometricProof: proof,
            authorization: authorization) { result.value = $0 }
        return result.value
    }

    private final class ClientDriver: PairingClientDriver, @unchecked Sendable {
        enum Hold: Sendable { case none, stage, commit }
        let endpoint: AuthorityPairingXPCEndpoint
        let sends = Box(0), stageSends = Box(0), commitSends = Box(0)
        let hold = Box(Hold.none)
        let late = Box<(@Sendable () -> Void)?>(nil)
        private let transform: @Sendable (PairingClientCall, PairingClientReply) throws -> PairingClientReply
        init(_ fixture: Fixture, transform: @escaping @Sendable (PairingClientCall, PairingClientReply) throws -> PairingClientReply = { _, value in value }) throws {
            endpoint = try fixture.endpoint(); self.transform = transform
        }
        func start(closed: @escaping @Sendable () -> Void) {}
        func invoke(_ call: PairingClientCall, reply: @escaping @Sendable (PairingClientReply) -> Void) {
            sends.value += 1
            let complete: @Sendable (PairingClientReply) -> Void = { [self] value in
                let result: PairingClientReply
                do { result = try transform(call, value) } catch { reply(.failed); return }
                let held: Bool
                switch (hold.value, call) { case (.stage, .stage), (.commit, .commit): held = true; default: held = false }
                if held { late.value = { reply(result) } } else { reply(result) }
            }
            switch call {
            case .hello: endpoint.pairingHello { complete(.version($0)) }
            case .context: endpoint.pairingContext { complete(.bytes($0)) }
            case .stage(let proposal, let authorization):
                stageSends.value += 1; endpoint.stagePairing(proposal, authorization: authorization) { complete(.bytes($0)) }
            case .commit(let setup, let digest, let proof, let authorization):
                commitSends.value += 1
                endpoint.commitPairing(setup, confirmedDigest: digest, biometricProof: proof, authorization: authorization) { complete(.bytes($0)) }
            case .cancel: endpoint.cancelPairing { complete(.cancelled($0)) }
            }
        }
        func close() { endpoint.close() }
    }
    /// Anonymous same-process wire fixture. It pins this test binary and grants no native administrator rights.
    private final class NativeServer: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
        let listener = NSXPCListener.anonymous()
        private let lock = NSRecursiveLock()
        private let fixture: Fixture
        private let requirement: String
        private var connections: [(NSXPCConnection, AuthorityAppXPCEndpoint)] = []
        private var closed = false
        init(_ fixture: Fixture, requirement: String) {
            self.fixture = fixture; self.requirement = requirement
            super.init(); listener.setConnectionCodeSigningRequirement(requirement); listener.delegate = self; listener.activate()
        }
        deinit { close() }
        func close() {
            let removed = lock.withLock {
                closed = true; listener.invalidate(); listener.delegate = nil
                let result = connections; connections.removeAll(); return result
            }
            for (connection, endpoint) in removed { endpoint.pairing.close(); endpoint.presence.close(); connection.invalidate() }
        }
        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            lock.withLock {
                guard !closed, listener === self.listener, connections.count < 4 else { return false }
                do {
                    let f = fixture, environment = f.environment
                    let credentials = try f.policy.verifyCredentials(connection)
                    guard credentials.processID == getpid() else { throw Failure.denied }
                    let invocation = XPCInvocationGuard(connection: connection, policy: f.policy)
                    let verify = {
                        guard try invocation.verifyInvocation() == credentials else { throw Failure.denied }
                    }
                    let binding = try AuthorityPresenceBinding(macID: f.mac, accountID: f.account,
                        clockEpoch: environment.epoch, connectionID: UUID())
                    let presence = try AuthorityPresenceXPCEndpoint(binding: binding, budget: .init(maximum: 1), verify: verify,
                        verifyCurrent: { try f.access.verifyCurrent() }, invalidate: { [weak connection] in connection?.invalidate() },
                        withdraw: {}, status: { throw Failure.denied }, publish: { _ in throw Failure.denied }, setMode: { _ in throw Failure.denied })
                    let pairing = try AuthorityPairingXPCEndpoint(access: f.access, budget: .init(maximum: 1), verify: verify,
                        authorize: { _ in
                            try verify(); environment.authorized.value += 1
                            if environment.denied.value { throw Failure.denied }
                        }, invalidate: { [weak connection] in connection?.invalidate() })
                    let endpoint = AuthorityAppXPCEndpoint(presence: presence, pairing: pairing)
                    connection.setCodeSigningRequirement(requirement)
                    connection.exportedInterface = NSXPCInterface(with: AuthorityAppXPCProtocol.self)
                    connection.exportedObject = endpoint
                    connection.invalidationHandler = { [weak endpoint] in endpoint?.pairing.close(); endpoint?.presence.close() }
                    connection.interruptionHandler = { [weak endpoint] in endpoint?.pairing.close(); endpoint?.presence.close() }
                    connections.append((connection, endpoint)); connection.activate(); return true
                } catch { connection.invalidate(); return false }
            }
        }
    }
    /// Wire-only driver: expected peer UID and hash identify this test process, not a deployed Root service.
    private final class NativeDriver: PairingClientDriver, @unchecked Sendable {
        private let connection: NSXPCConnection
        private let policy: XPCPeerPolicy
        init(endpoint: NSXPCListenerEndpoint, policy: XPCPeerPolicy, requirement: String) {
            self.policy = policy; connection = NSXPCConnection(listenerEndpoint: endpoint)
            connection.remoteObjectInterface = NSXPCInterface(with: AuthorityPairingXPCProtocol.self)
            connection.setCodeSigningRequirement(requirement)
        }
        func start(closed: @escaping @Sendable () -> Void) {
            connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
        }
        func invoke(_ call: PairingClientCall, reply: @escaping @Sendable (PairingClientReply) -> Void) {
            let complete: @Sendable (PairingClientReply) -> Void = { [self] value in
                do { guard try policy.verifyCredentials(connection).processID == getpid() else { throw Failure.denied }; reply(value) }
                catch { reply(.failed) }
            }
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in complete(.failed) }) as? any AuthorityPairingXPCProtocol else {
                complete(.failed); return
            }
            switch call {
            case .hello: proxy.pairingHello { complete(.version($0)) }
            case .context: proxy.pairingContext { complete(.bytes($0)) }
            case .stage(let proposal, let authorization): proxy.stagePairing(proposal, authorization: authorization) { complete(.bytes($0)) }
            case .commit(let setup, let digest, let proof, let authorization):
                proxy.commitPairing(setup, confirmedDigest: digest, biometricProof: proof, authorization: authorization) { complete(.bytes($0)) }
            case .cancel: proxy.cancelPairing { complete(.cancelled($0)) }
            }
        }
        func close() { connection.invalidate() }
        deinit { connection.invalidate() }
    }
    private final class WireHelloReply: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<UInt64, any Error>?
        init(_ continuation: CheckedContinuation<UInt64, any Error>) { self.continuation = continuation }
        func complete(_ result: Result<UInt64, any Error>) {
            let current = lock.withLock { let current = continuation; continuation = nil; return current }
            current?.resume(with: result)
        }
    }
    private func testRequirement() throws -> String {
        var code: SecCode?, staticCode: SecStaticCode?, info: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess, let fields = info as? [String: Any],
              let hash = fields[kSecCodeInfoUnique as String] as? Data, hash.count == 20 else { throw Failure.denied }
        return "cdhash H\"" + hash.map { String(format: "%02x", $0) }.joined() + "\""
    }
    func testNativeCombinedProtocolKeepsLegacyHelloAndPairingInvocationChecks() async throws {
        let f = try Fixture(), requirement = try testRequirement(), server = NativeServer(f, requirement: requirement)
        defer { server.close() }
        let legacy = NSXPCConnection(listenerEndpoint: server.listener.endpoint)
        legacy.remoteObjectInterface = NSXPCInterface(with: AuthorityPresenceXPCProtocol.self)
        legacy.setCodeSigningRequirement(requirement); legacy.activate()
        defer { legacy.invalidate() }
        let hello: UInt64 = try await withCheckedThrowingContinuation { continuation in
            let delivery = WireHelloReply(continuation)
            DispatchQueue.global().asyncAfter(deadline: .now() + 3) { delivery.complete(.failure(Failure.denied)) }
            guard let proxy = legacy.remoteObjectProxyWithErrorHandler({ _ in delivery.complete(.failure(Failure.denied)) })
                as? any AuthorityPresenceXPCProtocol else { delivery.complete(.failure(Failure.denied)); return }
            proxy.hello { delivery.complete(.success($0)) }
        }
        XCTAssertEqual(hello, 1); XCTAssertEqual(try f.policy.verifyCredentials(legacy).processID, getpid())
        let driver = NativeDriver(endpoint: server.listener.endpoint, policy: f.policy, requirement: requirement)
        let channel = AuthorityPairingChannel(driver: driver, macID: f.mac, accountID: f.account, timeoutMilliseconds: 3000)
        _ = try await channel.start()
        let value = try await channel.stage(f.proposal(), authorization: authorization)
        let receipt = try await channel.commit(confirmedDigest: value.digest(), biometricProof: proof(value, f), authorization: authorization)
        XCTAssertTrue(try value.verify(signature: receipt, publicKey: f.authority.publicKey.x963Representation, purpose: .macCommit))
        XCTAssertEqual(f.environment.authorized.value, 2); XCTAssertEqual(try f.records(), 1); try f.assertCheckpoint()
        await channel.close()
    }

    private func client(_ fixture: Fixture, driver: ClientDriver, timeout: UInt64 = 1000,
                        verify: @escaping @Sendable () throws -> Void = {}) -> AuthorityPairingChannel {
        .init(driver: driver, macID: fixture.mac, accountID: fixture.account, timeoutMilliseconds: timeout, verifyAccount: verify)
    }
    private func proof(_ value: PairingTranscript, _ fixture: Fixture) throws -> Data {
        try fixture.biometric.signature(for: value.signingInput(purpose: .phoneBiometric)).rawRepresentation
    }

    func testPhoneOnlyProposalStagesThroughTheExistingVersionOneRootChannel() async throws {
        let f = try Fixture(), driver = try ClientDriver(f), channel = client(f, driver: driver)
        let original = try f.proposal()
        let proposal = try PairingPhoneProposal(phone: original.phone, transportKey: original.transportKey,
            decisionKey: original.decisionKey, biometricKey: original.biometricKey)
        _ = try await channel.start()
        let value = try await channel.stage(proposal, authorization: authorization)
        try proposal.validate(value)
        XCTAssertNotEqual(value.setupID, Data(count: 16)); XCTAssertNotEqual(value.challenge, Data(count: 32))
        XCTAssertNotEqual(value.enrollmentTag, Data(count: 32)); XCTAssertEqual(value.issuedAtUnixMillis, 1000)
        let receipt = try await channel.commit(confirmedDigest: value.digest(), biometricProof: proof(value, f), authorization: authorization)
        XCTAssertTrue(try value.verify(signature: receipt, publicKey: f.authority.publicKey.x963Representation, purpose: .macCommit))
        XCTAssertEqual(driver.commitSends.value, 1); XCTAssertEqual(try f.records(), 1); try f.assertCheckpoint()
        await channel.close()
    }
    func testClientAuthenticatesParametersStagesAndVerifiesReceipt() async throws {
        let f = try Fixture(), driver = try ClientDriver(f), channel = client(f, driver: driver)
        let context = try await channel.start()
        XCTAssertEqual(context.macID, f.mac); XCTAssertEqual(context.accountID, f.account)
        XCTAssertEqual(context.authorityPublicKey, f.authority.publicKey.x963Representation)
        XCTAssertEqual(context.transportPublicKey, f.transport.publicKey.x963Representation)
        let value = try await channel.stage(f.proposal(), authorization: authorization)
        let receipt = try await channel.commit(confirmedDigest: value.digest(), biometricProof: proof(value, f), authorization: authorization)
        XCTAssertTrue(try value.verify(signature: receipt, publicKey: context.authorityPublicKey, purpose: .macCommit))
        XCTAssertEqual(driver.commitSends.value, 1); XCTAssertEqual(try f.records(), 1); try f.assertCheckpoint()
        await channel.close()
    }
    func testClientDoesNotSendAuthorizationBeforeHandshakeOrAfterAccountChange() async throws {
        let f = try Fixture(), driver = try ClientDriver(f), denied = Box(false)
        let channel = client(f, driver: driver, verify: { if denied.value { throw Failure.denied } })
        do { _ = try await channel.stage(f.proposal(), authorization: authorization); XCTFail("Sent before handshake") } catch {}
        XCTAssertEqual(driver.stageSends.value, 0)
        _ = try await channel.start(); denied.value = true
        do { _ = try await channel.stage(f.proposal(), authorization: authorization); XCTFail("Sent from changed account") } catch {}
        XCTAssertEqual(driver.stageSends.value, 0); XCTAssertEqual(f.environment.authorized.value, 0)
    }
    func testClientRejectsUnsupportedVersionAndCrossedRootParameters() async throws {
        for version in [false, true] {
            let f = try Fixture(), driver = try ClientDriver(f) { call, reply in
                if version, case .hello = call { return .version(2) }
                if !version, case .context = call, case .bytes(let bytes) = reply, let bytes,
                   case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: .init(maxBytes: 512, maxDepth: 1, maxItems: 15)) {
                    fields[1] = .bytes(Data(repeating: 99, count: 16))
                    return .bytes(try DeterministicCBOR.encode(.map(fields), limits: .init(maxBytes: 512, maxDepth: 1, maxItems: 15)))
                }
                return reply
            }
            let channel = client(f, driver: driver)
            do { _ = try await channel.start(); XCTFail("Accepted unsupported Root context") } catch {}
            XCTAssertEqual(driver.stageSends.value, 0); XCTAssertEqual(f.environment.authorized.value, 0)
        }
    }
    func testClientRejectsAlteredRootPinOrPhoneKeyBeforeCommit() async throws {
        for field in [7, 9] {
            let replacement = P256.Signing.PrivateKey().publicKey.x963Representation
            let f = try Fixture(), driver = try ClientDriver(f) { call, reply in
                if case .stage = call, case .bytes(let bytes) = reply, let bytes,
                   case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: .init(maxBytes: 132000, maxDepth: 4, maxItems: 80)) {
                    if field == 7 { fields[7] = .bytes(replacement) }
                    else if case .array(var keys) = fields[9], case .array(var key) = keys[2] {
                        key[1] = .bytes(replacement); keys[2] = .array(key); fields[9] = .array(keys)
                    }
                    return .bytes(try DeterministicCBOR.encode(.map(fields), limits: .init(maxBytes: 132000, maxDepth: 4, maxItems: 80)))
                }
                return reply
            }
            let channel = client(f, driver: driver); _ = try await channel.start()
            do { _ = try await channel.stage(f.proposal(), authorization: authorization); XCTFail("Accepted changed setup claims") } catch {}
            XCTAssertEqual(driver.commitSends.value, 0); XCTAssertEqual(try f.records(), 0)
        }
    }
    func testClientRequiresExactHumanConfirmationAndRejectsInvalidReceipt() async throws {
        let f = try Fixture(), driver = try ClientDriver(f) { call, reply in
            if case .commit = call { return .bytes(Data(repeating: 0, count: 64)) }; return reply
        }
        let channel = client(f, driver: driver); _ = try await channel.start()
        let value = try await channel.stage(f.proposal(), authorization: authorization)
        do {
            _ = try await channel.commit(confirmedDigest: Data(repeating: 0, count: 32), biometricProof: proof(value, f), authorization: authorization)
            XCTFail("Accepted wrong confirmation")
        } catch {}
        XCTAssertEqual(driver.commitSends.value, 0)
        do {
            _ = try await channel.commit(confirmedDigest: value.digest(), biometricProof: proof(value, f), authorization: authorization)
            XCTFail("Accepted invalid receipt")
        } catch {}
        XCTAssertEqual(driver.commitSends.value, 1); XCTAssertEqual(try f.records(), 1)
    }
    func testClientLostCommitReplyRemainsAmbiguousAndNeverRetries() async throws {
        let f = try Fixture(), driver = try ClientDriver(f), channel = client(f, driver: driver, timeout: 20)
        _ = try await channel.start()
        let value = try await channel.stage(f.proposal(), authorization: authorization)
        driver.hold.value = .commit
        do {
            _ = try await channel.commit(confirmedDigest: value.digest(), biometricProof: proof(value, f), authorization: authorization)
            XCTFail("Confirmed lost reply")
        } catch { XCTAssertEqual(error as? AuthorityPairingChannelError, .timedOut) }
        driver.late.value?()
        do {
            _ = try await channel.commit(confirmedDigest: value.digest(), biometricProof: proof(value, f), authorization: authorization)
            XCTFail("Retried ambiguous commit")
        } catch {}
        XCTAssertEqual(driver.commitSends.value, 1); XCTAssertEqual(try f.records(), 1); try f.assertCheckpoint()
    }
    func testClientCancellationClearsStagingWithoutAnotherAuthorization() async throws {
        let f = try Fixture(), driver = try ClientDriver(f), channel = client(f, driver: driver)
        _ = try await channel.start(); _ = try await channel.stage(f.proposal(), authorization: authorization)
        let count = f.environment.authorized.value
        try await channel.cancelStaged()
        XCTAssertEqual(f.environment.authorized.value, count); XCTAssertEqual(try f.records(), 0)
        _ = try await channel.stage(f.proposal(), authorization: authorization)
        channel.abort()
        do { try await channel.cancelStaged(); XCTFail("Sent after abort") } catch {}
        XCTAssertEqual(try f.records(), 0)
    }
    func testClientBusyStageDoesNotDestroyTheOriginalAttempt() async throws {
        let f = try Fixture(), driver = try ClientDriver(f), channel = client(f, driver: driver)
        _ = try await channel.start(); driver.hold.value = .stage
        let proposal = try f.proposal(), authorization = authorization
        let first = Task { try await channel.stage(proposal, authorization: authorization) }
        for _ in 0..<100 { if driver.late.value != nil { break }; try await Task.sleep(for: .milliseconds(1)) }
        XCTAssertNotNil(driver.late.value)
        do { _ = try await channel.stage(proposal, authorization: authorization); XCTFail("Accepted concurrent stage") }
        catch { XCTAssertEqual(error as? AuthorityPairingChannelError, .busy) }
        driver.hold.value = .none; driver.late.value?()
        let value = try await first.value
        _ = try await channel.commit(confirmedDigest: value.digest(), biometricProof: proof(value, f), authorization: authorization)
        XCTAssertEqual(driver.stageSends.value, 1); XCTAssertEqual(try f.records(), 1)
    }

    func testConfigurationRoundTripAndStrictBounds() throws {
        let key = P256.Signing.PrivateKey().publicKey.x963Representation, limits = try CBORLimits(maxBytes: 512, maxDepth: 2, maxItems: 20)
        let original = try AuthorityPairingSetupConfiguration(transportPublicKey: key)
        XCTAssertEqual(try AuthorityPairingSetupConfiguration.decode(original.canonicalBytes).canonicalBytes, original.canonicalBytes)
        for lifetime in [UInt64(0), 300001, UInt64.max] { XCTAssertThrowsError(try AuthorityPairingSetupConfiguration(transportPublicKey: key, lifetimeMilliseconds: lifetime)) }
        XCTAssertThrowsError(try AuthorityPairingSetupConfiguration(transportPublicKey: Data(repeating: 0, count: 65)))
        guard case .map(let fields) = try DeterministicCBOR.decode(original.canonicalBytes, limits: limits) else { return XCTFail("Map required") }
        for (field, value): (UInt64, CBORValue?) in [(0, .unsigned(2)), (1, nil), (2, .text("120000")), (3, .unsigned(1))] {
            var changed = fields; changed[field] = value
            XCTAssertThrowsError(try AuthorityPairingSetupConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
    }
    func testConfiguredAuditVersionsMatchStagedAndLiveEnrollmentOffers() throws {
        for versions: Set<UInt64> in [[], [1], [2, 3]] {
            let f = try Fixture(auditVersions: versions), endpoint = try f.endpoint(); try hello(endpoint)
            let value = try staged(endpoint, proposal: f.proposal())
            XCTAssertEqual(value.mac.auditVersions, versions)
            XCTAssertNotNil(try commit(endpoint, transcript: value, fixture: f))
            let trust = try f.journal.read { try $0.directApprovalTrust(maximumPayloadBytes: 4096, auditVersions: versions) }
            XCTAssertEqual(trust.peers.count, 1); XCTAssertEqual(trust.peers.first?.auditVersions, versions)
            try f.assertCheckpoint()
        }
    }
    func testInvalidAuditConfigurationIsRejectedBeforeSetup() throws {
        for versions in [Set([UInt64(0)]), Set(UInt64(1)...17)] {
            XCTAssertThrowsError(try Fixture(auditVersions: versions)) {
                XCTAssertEqual($0 as? AuthorityPairingSetupError, .invalidConfiguration)
            }
        }
    }

    func testStageUsesFreshRootValuesAndNoAuthorityWrite() throws {
        let f = try Fixture(), endpoint = try f.endpoint(), proposal = try f.proposal()
        try hello(endpoint)
        let value = try staged(endpoint, proposal: proposal)
        XCTAssertNotEqual(value.setupID, proposal.setupID); XCTAssertNotEqual(value.challenge, proposal.challenge)
        XCTAssertNotEqual(value.enrollmentTag, proposal.enrollmentTag); XCTAssertNotEqual(value.mac.nonce, proposal.mac.nonce)
        XCTAssertEqual(value.issuedAtUnixMillis, 1000); XCTAssertEqual(value.expiresAtUnixMillis, 2000)
        XCTAssertEqual(value.macAuthorityKey, f.authority.publicKey.x963Representation)
        XCTAssertEqual(value.macTransportKey, f.transport.publicKey.x963Representation)
        XCTAssertEqual(value.phone.nonce, proposal.phone.nonce); XCTAssertEqual(value.biometricKey.publicKey, proposal.biometricKey.publicKey)
        XCTAssertEqual(try f.records(), 0); XCTAssertEqual(f.environment.authorized.value, 1); try f.assertCheckpoint()
    }
    func testConfirmedProofCommitsAndSignsThroughTheExistingOwner() throws {
        let f = try Fixture(), endpoint = try f.endpoint(); try hello(endpoint)
        let value = try staged(endpoint, proposal: f.proposal()), receipt = try XCTUnwrap(commit(endpoint, transcript: value, fixture: f))
        XCTAssertTrue(try value.verify(signature: receipt, publicKey: f.authority.publicKey.x963Representation, purpose: .macCommit))
        XCTAssertEqual(f.environment.authorized.value, 2); XCTAssertEqual(f.environment.signed.value, 1)
        XCTAssertEqual(try f.records(), 1); try f.assertCheckpoint()
        XCTAssertNil(try commit(endpoint, transcript: value, fixture: f)); XCTAssertEqual(try f.records(), 1)
    }
    func testHandshakePeerAndAdministratorFailuresCannotStage() throws {
        for mode in 0...2 {
            let f = try Fixture(), endpoint = try f.endpoint(), result = Box<Data?>(nil)
            if mode != 0 { try hello(endpoint) }
            if mode == 1 { f.environment.peerDenied.value = true }
            if mode == 2 { f.environment.denied.value = true }
            endpoint.stagePairing(try f.proposal().encode(), authorization: authorization) { result.value = $0 }
            XCTAssertNil(result.value); XCTAssertEqual(try f.records(), 0); XCTAssertEqual(f.environment.signed.value, 0)
        }
    }
    func testConfirmationProofExpiryAndRevokedConsentCannotCommit() throws {
        for mode in 0...3 {
            let f = try Fixture(), endpoint = try f.endpoint(); try hello(endpoint)
            let value = try staged(endpoint, proposal: f.proposal())
            if mode == 2 { f.environment.time.value = 1100 }
            if mode == 3 { f.environment.denied.value = true }
            XCTAssertNil(try commit(endpoint, transcript: value, fixture: f,
                digest: mode == 0 ? Data(repeating: 0, count: 32) : nil,
                proof: mode == 1 ? Data(repeating: 0, count: 64) : nil))
            XCTAssertEqual(try f.records(), 0); XCTAssertEqual(f.environment.signed.value, 0); try f.assertCheckpoint()
        }
    }
    func testCancelAndDisconnectDiscardOnlyTheUncommittedAttempt() throws {
        for close in [false, true] {
            let f = try Fixture(), endpoint = try f.endpoint(); try hello(endpoint)
            let value = try staged(endpoint, proposal: f.proposal()), authorized = f.environment.authorized.value
            if close { endpoint.close() } else {
                let result = Box(false); endpoint.cancelPairing { result.value = $0 }; XCTAssertTrue(result.value)
            }
            XCTAssertEqual(f.environment.authorized.value, authorized)
            XCTAssertNil(try commit(endpoint, transcript: value, fixture: f)); XCTAssertEqual(try f.records(), 0)
        }
    }
    func testOneConnectionCannotCommitAnotherConnectionsTranscript() throws {
        let f = try Fixture(), first = try f.endpoint(), second = try f.endpoint(); try hello(first); try hello(second)
        let proposal = try f.proposal(), firstValue = try staged(first, proposal: proposal)
        _ = try staged(second, proposal: proposal)
        XCTAssertNil(try commit(second, transcript: firstValue, fixture: f)); XCTAssertEqual(try f.records(), 0)
        XCTAssertNotNil(try commit(first, transcript: firstValue, fixture: f)); try f.assertCheckpoint()
    }
    func testChangedAppRoleAndRootPolicyRejectPendingSetup() throws {
        for role in [false, true] {
            let f = try Fixture(), endpoint = try f.endpoint(); try hello(endpoint)
            let value = try staged(endpoint, proposal: f.proposal())
            if role {
                let changed = try AuthorityCodePolicy(entries: [Fixture.appEntry(active: false)])
                _ = try f.journal.write { tx in try tx.installCodePolicy(changed, expectedRevision: tx.codePolicy()?.revision) }
            } else { f.environment.selfDenied.value = true }
            XCTAssertNil(try commit(endpoint, transcript: value, fixture: f)); XCTAssertEqual(try f.records(), 0)
            XCTAssertEqual(f.environment.signed.value, 0)
        }
    }
}
