import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import Security
import SQLite3
import XCTest
@testable import RemozioCore

final class AuthorityPairingSetupTests: XCTestCase, @unchecked Sendable {
    private enum Failure: Error { case denied }
    fileprivate final class Box<Value>: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: Value
        init(_ value: Value) { stored = value }
        var value: Value { get { lock.withLock { stored } } set { lock.withLock { stored = newValue } } }
    }
    fileprivate final class Environment: @unchecked Sendable {
        let epoch = UUID()
        let time = Box<UInt64>(100)
        let denied = Box(false), selfDenied = Box(false), peerDenied = Box(false)
        let authorized = Box(0), invalidated = Box(0), signed = Box(0)
        func now() -> AuthorityMoment { .init(epoch: epoch, milliseconds: time.value) }
    }
    fileprivate final class Fixture: @unchecked Sendable {
        let root: URL
        let journal: AuthorityJournal
        let continuity: ContinuityStore
        let authority = P256.Signing.PrivateKey(), transport = P256.Signing.PrivateKey(), biometric = P256.Signing.PrivateKey()
        let environment = Environment()
        let access: AuthorityPairingSetupAccess
        let gatewayRevocations: AuthorityGatewayRevocationState?
        let policy: XPCPeerPolicy
        let writer: AuditEpochWriter
        let limits = try! CBORLimits(maxBytes: 16384, maxDepth: 12, maxItems: 1024)
        var mac: Data { Data(repeating: 1, count: 16) }
        let account: Data
        init(auditVersions: Set<UInt64> = [1], activity: ReleaseActivityBarrier? = nil, configureGateway: Bool = false,
             accountByte: UInt8 = 2, observePairingContention: @escaping @Sendable () -> Void = {}) throws {
            self.account = Data(repeating: accountByte, count: 16)
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
            let mac = Data(repeating: 1, count: 16), account = Data(repeating: accountByte, count: 16), limits = self.limits
            let db = try JournalDatabase(lease: .init(anchor: root.path, relativeDirectory: "store", owner: getuid()),
                macID: mac, accountID: account, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 20, busyMilliseconds: 100, initialize: true,
                gatewayPolicy: configureGateway ? GatewayAuthorityPolicy(payloadLimits: limits, signingLimits: limits,
                    maximumControls: 32, candidateLifetimeMillis: 1000, clockEpoch: environment.epoch) : nil,
                updateSchedulingPolicy: UpdateSchedulingJournalPolicy(clockEpoch: environment.epoch,
                    challengeLifetimeMillis: 1000, maximumOperations: 32, payloadLimits: limits, signingLimits: limits))
            if configureGateway {
                let registration = try GatewayRegistrationIdentity(ownerID: Data(repeating: 40, count: 16), macID: mac, accountID: account,
                    gatewayID: Data(repeating: 41, count: 16), lifecycleEpoch: Data(repeating: 42, count: 16),
                    rootPublicKey: authority.publicKey.x963Representation)
                try db.write { try $0.configureGatewayAuthority(registration) }
                gatewayRevocations = AuthorityGatewayRevocationState(registration: registration)
            } else { gatewayRevocations = nil }
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
            journal = AuthorityJournal(requests: requests, observePairingContention: observePairingContention)
            if let activity { try journal.attachReleaseActivityBarrier(activity) }
            policy = try .init(teamID: app.teamID, componentIdentifier: app.identifier,
                approvedCodeDirectoryHashes: [app.codeDirectoryHash], expectedUserID: getuid())
            let journal = journal, environment = environment, authority = authority
            access = try .init(journal: journal, macID: mac, accountID: account, authorityPublicKey: authority.publicKey.x963Representation,
                appPolicy: policy, configuration: .init(transportPublicKey: transport.publicKey.x963Representation, lifetimeMilliseconds: 1000),
                minimumEnvelopeVersion: 1, auditVersions: auditVersions, now: { environment.now() }, unixMilliseconds: { 1000 }, validateSelf: { _ in
                    if environment.selfDenied.value { throw Failure.denied }
                }, gatewayRevocations: gatewayRevocations, commit: { attempt, proof, event, authorize, validate in
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
        func endpoint(budget: AuthorityXPCWorkBudget? = nil) throws -> AuthorityPairingXPCEndpoint {
            let environment = environment
            return try .init(access: access, budget: budget ?? .init(maximum: 1), verify: {
                if environment.peerDenied.value { throw Failure.denied }
            }, authorize: { _ in
                environment.authorized.value += 1
                if environment.denied.value { throw Failure.denied }
            }, invalidate: { environment.invalidated.value += 1 })
        }
        func proposal(phone: UInt8 = 8, epoch: UInt8 = 9, keyBase: UInt8 = 32,
                      biometric: P256.Signing.PrivateKey? = nil, keyNamespace: UInt8? = nil) throws -> PairingTranscript {
            func keyID(_ offset: UInt8) -> Data {
                var id = Data(repeating: keyBase + offset, count: 16)
                if let keyNamespace { id[0] = keyNamespace }
                return id
            }
            let trust = try journal.read { try $0.approvalTrustSnapshot() }, scope = try ChannelScope(macID: mac,
                accountID: account, phoneID: Data(repeating: phone, count: 16), enrollmentEpoch: Data(repeating: epoch, count: 16))
            let offers = try [ChannelRole.phone, .mac].enumerated().map { index, role in
                try ChannelOffer(role: role, scope: scope, nonce: Data(repeating: UInt8(20 + index), count: 32), envelopeVersions: [1],
                    requests: [.init(kind: 0, wireVersion: 1, schemaVersion: 1, features: [])], auditVersions: [1])
            }
            var revision = trust.revision.uuid
            return try .init(setupID: Data(repeating: 30, count: 16), challenge: Data(repeating: 31, count: 32), phone: offers[0], mac: offers[1],
                minimumEnvelopeVersion: 1, selectedEnvelopeVersion: 1, macAuthorityKey: authority.publicKey.x963Representation,
                macTransportKey: transport.publicKey.x963Representation,
                transportKey: .init(keyID: keyID(0), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                decisionKey: .init(keyID: keyID(1), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                biometricKey: .init(keyID: keyID(2), publicKey: (biometric ?? self.biometric).publicKey.x963Representation),
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
        enum Hold: Sendable { case none, stage, commit, revoke }
        let endpoint: AuthorityPairingXPCEndpoint
        let sends = Box(0), stageSends = Box(0), commitSends = Box(0), revocationSends = Box(0)
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
                switch (hold.value, call) {
                case (.stage, .stage), (.commit, .commit), (.revoke, .managePhone(.revoke, _, _)): held = true
                default: held = false
                }
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
            case .phoneManagementHello: endpoint.pairedPhoneHello { complete(.version($0)) }
            case .managePhone(let operation, let selection, let authorization):
                if operation == .revoke { revocationSends.value += 1 }
                endpoint.managePairedPhone(operation.rawValue, selection: selection, authorization: authorization) { complete(.bytes($0)) }
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
            connection.remoteObjectInterface = NSXPCInterface(with: AuthorityAppXPCProtocol.self)
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
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in complete(.failed) }) as? any AuthorityAppXPCProtocol else {
                complete(.failed); return
            }
            switch call {
            case .hello: proxy.pairingHello { complete(.version($0)) }
            case .context: proxy.pairingContext { complete(.bytes($0)) }
            case .stage(let proposal, let authorization): proxy.stagePairing(proposal, authorization: authorization) { complete(.bytes($0)) }
            case .commit(let setup, let digest, let proof, let authorization):
                proxy.commitPairing(setup, confirmedDigest: digest, biometricProof: proof, authorization: authorization) { complete(.bytes($0)) }
            case .cancel: proxy.cancelPairing { complete(.cancelled($0)) }
            case .phoneManagementHello: proxy.pairedPhoneHello { complete(.version($0)) }
            case .managePhone(let operation, let selection, let authorization):
                proxy.managePairedPhone(operation.rawValue, selection: selection, authorization: authorization) { complete(.bytes($0)) }
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
    private func pairForRevocation(_ fixture: Fixture) async throws -> (AuthorityPairingChannel, ClientDriver) {
        let driver = try ClientDriver(fixture), channel = client(fixture, driver: driver)
        _ = try await channel.start()
        let transcript = try await channel.stage(fixture.proposal(), authorization: authorization)
        _ = try await channel.commit(confirmedDigest: transcript.digest(), biometricProof: proof(transcript, fixture),
            authorization: authorization)
        return (channel, driver)
    }

    private func rePairProposal(_ fixture: Fixture, predecessor: PairingReplacement,
                                biometric: P256.Signing.PrivateKey, transportPoint: Data? = nil,
                                epoch: UInt8 = 50, keyBase: UInt8 = 52) throws -> PairingPhoneProposal {
        let scope = try ChannelScope(macID: fixture.mac, accountID: fixture.account,
            phoneID: predecessor.phoneID, enrollmentEpoch: Data(repeating: epoch, count: 16))
        let offer = try ChannelOffer(role: .phone, scope: scope, nonce: Data(repeating: 51, count: 32),
            envelopeVersions: [1], requests: [.init(kind: 0, wireVersion: 1, schemaVersion: 1, features: [])], auditVersions: [1])
        return try PairingPhoneProposal(phone: offer,
            transportKey: .init(keyID: Data(repeating: keyBase, count: 16),
                publicKey: transportPoint ?? P256.Signing.PrivateKey().publicKey.x963Representation),
            decisionKey: .init(keyID: Data(repeating: keyBase + 1, count: 16),
                publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            biometricKey: .init(keyID: Data(repeating: keyBase + 2, count: 16), publicKey: biometric.publicKey.x963Representation),
            replacement: predecessor)
    }

    func testRePairStagesAndCommitsOnlyAfterRevocation() async throws {
        let f = try Fixture(configureGateway: true), (channel, _) = try await pairForRevocation(f)
        let listed = try await channel.pairedPhones()
        let selection = try XCTUnwrap(listed.selection(for: XCTUnwrap(listed.phones.first)))
        let predecessor = try PairingReplacement(phoneID: selection.phone.phoneID, epoch: selection.phone.enrollmentEpoch)
        let biometric = P256.Signing.PrivateKey()
        let proposal = try rePairProposal(f, predecessor: predecessor, biometric: biometric)
        let status = try await channel.revokePhone(selection, authorization: authorization)
        XCTAssertEqual(status, .gatewayPending)

        let afterRevocation = try await channel.pairedPhonesForRePair()
        XCTAssertTrue(afterRevocation.phones.isEmpty)
        XCTAssertEqual(afterRevocation.rePairablePhones, [selection.phone])
        let eligible = try XCTUnwrap(afterRevocation.rePairSelection(for: selection.phone))
        let accepted = try await channel.canRePair(eligible)
        let stale = try await channel.canRePair(selection)
        XCTAssertTrue(accepted)
        XCTAssertFalse(stale)
        let missing = PairedPhoneSelection(macID: eligible.macID, accountID: eligible.accountID, revision: eligible.revision,
            phone: DeliveryRecipient(phoneID: predecessor.phoneID, enrollmentEpoch: Data(repeating: 99, count: 16)))
        let acceptedMissing = try await channel.canRePair(missing)
        XCTAssertFalse(acceptedMissing)
        let crossed = PairedPhoneSelection(macID: Data(repeating: 99, count: 16), accountID: eligible.accountID,
            revision: eligible.revision, phone: eligible.phone)
        do { _ = try await channel.canRePair(crossed); XCTFail("Accepted a foreign Mac") }
        catch { XCTAssertEqual(error as? AuthorityPairingChannelError, .wrongAccount) }

        let staged = try await channel.stage(proposal, authorization: authorization)
        try proposal.validate(staged)
        let proof = try biometric.signature(for: staged.signingInput(purpose: .phoneBiometric)).rawRepresentation
        let receipt = try await channel.commit(confirmedDigest: staged.digest(), biometricProof: proof, authorization: authorization)
        XCTAssertTrue(try staged.verify(signature: receipt, publicKey: f.authority.publicKey.x963Representation, purpose: .macCommit))
        let retained = try f.journal.read { try $0.approvalEnrollments() }
        XCTAssertEqual(retained.count, 2)
        let old = try XCTUnwrap(retained.first { $0.epoch == predecessor.epoch })
        XCTAssertFalse(old.approval.active)
        XCTAssertEqual(old.gatewayRevocation?.progress, .pending)
        XCTAssertEqual(retained.first { $0.approval.active }?.epoch, staged.phone.scope.enrollmentEpoch)
        let afterCommit = try await channel.pairedPhonesForRePair()
        XCTAssertTrue(afterCommit.rePairablePhones.isEmpty)
        let trust = try f.journal.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024) }
        let peer = try XCTUnwrap(trust.peers.first)
        let recovered = try f.journal.withRequests { requests in
            try requests.pairingReceipt(setupID: staged.setupID, binding: AuthorityPeerBinding(peer: peer, revision: trust.revision),
                authorityPublicKey: f.authority.publicKey.x963Representation, verifyHost: { _ in },
                sign: { try f.authority.signature(for: $0).rawRepresentation })
        }
        XCTAssertTrue(try staged.verify(signature: XCTUnwrap(recovered), publicKey: f.authority.publicKey.x963Representation, purpose: .macCommit))
        XCTAssertEqual(try f.records(), 3)
        try f.assertCheckpoint()
        await channel.close()
    }

    func testRePairRefusesAnOlderEpochAfterItsSuccessorIsRevoked() async throws {
        let f = try Fixture(), (channel, _) = try await pairForRevocation(f)
        let firstList = try await channel.pairedPhones()
        let first = try XCTUnwrap(firstList.phones.first)
        let firstSelection = try XCTUnwrap(firstList.selection(for: first))
        _ = try await channel.revokePhone(firstSelection, authorization: authorization)

        let losingKey = P256.Signing.PrivateKey()
        let oldPredecessor = try firstSelection.predecessor
        let losingProposal = try rePairProposal(f, predecessor: oldPredecessor, biometric: losingKey, epoch: 3, keyBase: 63)
        let losingAttempt = try f.access.stage(losingProposal.encode())
        f.environment.time.value = 1_100
        XCTAssertTrue(try f.access.isExpired(losingAttempt))
        let winnerKey = P256.Signing.PrivateKey()
        let winningProposal = try rePairProposal(f, predecessor: oldPredecessor, biometric: winnerKey, epoch: 2)
        let transcript = try await channel.stage(winningProposal, authorization: authorization)
        let proof = try winnerKey.signature(for: transcript.signingInput(purpose: .phoneBiometric)).rawRepresentation
        _ = try await channel.commit(confirmedDigest: transcript.digest(), biometricProof: proof, authorization: authorization)

        let successorList = try await channel.pairedPhones()
        let successor = try XCTUnwrap(successorList.phones.first)
        let successorSelection = try XCTUnwrap(successorList.selection(for: successor))
        _ = try await channel.revokePhone(successorSelection, authorization: authorization)
        let available = try await channel.pairedPhonesForRePair()
        XCTAssertEqual(available.rePairablePhones, [successor])
        XCTAssertNil(available.rePairSelection(for: first))
        let currentOldRow = PairedPhoneSelection(macID: f.mac, accountID: f.account, revision: available.revision, phone: first)
        let oldEligible = try await channel.canRePair(currentOldRow)
        let newest = try XCTUnwrap(available.rePairSelection(for: successor))
        let newestEligible = try await channel.canRePair(newest)
        XCTAssertFalse(oldEligible)
        XCTAssertTrue(newestEligible)
        XCTAssertThrowsError(try f.access.stage(losingProposal.encode())) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment)
        }

        let loser = losingAttempt.transcript
        let losingProof = try losingKey.signature(for: loser.signingInput(purpose: .phoneBiometric)).rawRepresentation
        XCTAssertThrowsError(try f.access.commit(losingAttempt, setupID: loser.setupID, confirmedDigest: loser.digest(),
            proof: losingProof, authorize: {})) {
            XCTAssertEqual($0 as? PairingRecoveryStageError, .noPendingStage)
        }
        let current = try f.access.stage(rePairProposal(f, predecessor: newest.predecessor, biometric: losingKey,
            epoch: 3, keyBase: 63).encode()).transcript
        // Build a test-only attempt at the current revision to reach the commit's lineage check.
        let superseded = try PairingTranscript(setupID: current.setupID, challenge: current.challenge, phone: current.phone, mac: current.mac,
            minimumEnvelopeVersion: current.minimumEnvelopeVersion, selectedEnvelopeVersion: current.selectedEnvelopeVersion,
            macAuthorityKey: current.macAuthorityKey, macTransportKey: current.macTransportKey,
            transportKey: current.transportKey, decisionKey: current.decisionKey, biometricKey: current.biometricKey,
            enrollmentTag: current.enrollmentTag, replacement: oldPredecessor, expectedTrustRevision: current.expectedTrustRevision,
            issuedAtUnixMillis: current.issuedAtUnixMillis, expiresAtUnixMillis: current.expiresAtUnixMillis)
        let trust = try f.journal.read { try $0.approvalTrustSnapshot() }
        XCTAssertEqual(trust.revision, available.revision)
        let forgedAttempt = try PairingEnrollmentAttempt(transcript: superseded, trusted: trust, replacement: .requireRevoked(oldPredecessor),
            authorityPublicKey: f.authority.publicKey.x963Representation, transportPublicKey: f.transport.publicKey.x963Representation,
            minimumEnvelopeVersion: 1, started: f.environment.now(), startedAtUnixMillis: current.issuedAtUnixMillis,
            deadlineMilliseconds: f.environment.now().milliseconds + 1000)
        let currentProof = try losingKey.signature(for: superseded.signingInput(purpose: .phoneBiometric)).rawRepresentation
        XCTAssertThrowsError(try f.access.commit(forgedAttempt, setupID: superseded.setupID, confirmedDigest: superseded.digest(),
            proof: currentProof, authorize: {})) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment)
        }
        XCTAssertEqual(try f.records(), 4)
        try f.assertCheckpoint()
        await channel.close()
    }

    func testUnreadableRePairHistoryLeavesAnotherRevokedPhoneEligible() async throws {
        let f = try Fixture(), (channel, _) = try await pairForRevocation(f)
        let before = try await channel.pairedPhones()
        let original = try XCTUnwrap(before.phones.first)
        let originalSelection = try XCTUnwrap(before.selection(for: original))
        _ = try await channel.revokePhone(originalSelection, authorization: authorization)

        let healthyKey = P256.Signing.PrivateKey()
        let healthySetup = try await channel.stage(f.proposal(phone: 7, epoch: 10, keyBase: 60, biometric: healthyKey),
            authorization: authorization)
        let healthyProof = try healthyKey.signature(for: healthySetup.signingInput(purpose: .phoneBiometric)).rawRepresentation
        _ = try await channel.commit(confirmedDigest: healthySetup.digest(), biometricProof: healthyProof, authorization: authorization)
        let active = try await channel.pairedPhones()
        let healthy = try XCTUnwrap(active.phones.first)
        let healthySelection = try XCTUnwrap(active.selection(for: healthy))
        _ = try await channel.revokePhone(healthySelection, authorization: authorization)
        let eligible = try await channel.pairedPhonesForRePair()
        XCTAssertEqual(Set(eligible.rePairablePhones), [original, healthy])

        let nextKey = P256.Signing.PrivateKey()
        let successor = try f.access.stage(rePairProposal(f, predecessor: originalSelection.predecessor, biometric: nextKey).encode()).transcript
        let newEpoch = successor.phone.scope.enrollmentEpoch
        let row = try StoredApprovalEnrollment(epoch: newEpoch, notificationTag: successor.enrollmentTag,
            identityPublicKey: successor.transportKey.publicKey,
            approval: ApprovalEnrollment(phoneID: original.phoneID, active: true, capabilities: PairingEnrollmentAttempt.capabilities(successor), keys: [
                EnrolledApprovalKey(id: successor.decisionKey.keyID, keyClass: .decision, publicKey: successor.decisionKey.publicKey),
                EnrolledApprovalKey(id: successor.biometricKey.keyID, keyClass: .biometric, publicKey: successor.biometricKey.publicKey),
            ]))
        // Seed one unreadable retained proof in this disposable journal after the checkpointed setup steps.
        let revision = try f.journal.write { tx in
            let activeRevision = try tx.addApprovalEnrollment(row, expectedTrustRevision: eligible.revision,
                eventID: Data(repeating: 100, count: 16), receiptTimeMs: 1000, writer: f.writer, expectedAuditHead: 4)
            try tx.retainPairing(successor, biometricProof: Data(count: 64), enrollment: row)
            return try tx.revokeApprovalEnrollment(phoneID: original.phoneID, epoch: newEpoch, expectedTrustRevision: activeRevision,
                eventID: Data(repeating: 101, count: 16), receiptTimeMs: 1000, writer: f.writer, expectedAuditHead: 5).revision
        }

        let projected = try await channel.pairedPhonesForRePair()
        XCTAssertEqual(projected.revision, revision)
        XCTAssertEqual(projected.rePairablePhones, [healthy])
        let healthyCandidate = try XCTUnwrap(projected.rePairSelection(for: healthy))
        let healthyAccepted = try await channel.canRePair(healthyCandidate)
        XCTAssertTrue(healthyAccepted)
        for phone in [original, DeliveryRecipient(phoneID: original.phoneID, enrollmentEpoch: newEpoch)] {
            let candidate = PairedPhoneSelection(macID: f.mac, accountID: f.account, revision: revision, phone: phone)
            let accepted = try await channel.canRePair(candidate)
            XCTAssertFalse(accepted)
        }
        await channel.close()
    }

    func testRePairEligibilityRefusesARestrictedRevokedPhoneAtTheCurrentRevision() async throws {
        let f = try Fixture(configureGateway: true), (channel, _) = try await pairForRevocation(f)
        let firstList = try await channel.pairedPhones()
        let phone = try XCTUnwrap(firstList.phones.first)
        let selection = try XCTUnwrap(firstList.selection(for: phone))
        _ = try await channel.revokePhone(selection, authorization: authorization)
        let before = try await channel.pairedPhonesForRePair()
        let eligible = try XCTUnwrap(before.rePairSelection(for: phone))
        let beforeRestriction = try await channel.canRePair(eligible)
        XCTAssertTrue(beforeRestriction)

        let registration = try XCTUnwrap(f.gatewayRevocations?.registration)
        let binding = try GatewayTokenBinding(ownerID: registration.ownerID, macID: registration.macID,
            accountID: registration.accountID, gatewayID: registration.gatewayID, lifecycleEpoch: registration.lifecycleEpoch,
            phoneID: phone.phoneID, enrollmentEpoch: Data(repeating: 97, count: 16), candidateID: Data(repeating: 98, count: 16),
            tokenDigest: Data(repeating: 95, count: 32), challenge: Data(repeating: 96, count: 32),
            enrollmentTag: Data(repeating: 97, count: 32))
        let unknown = try GatewayTokenCandidate(binding: binding, revision: 99, operationID: Data(repeating: 99, count: 16),
            issuedAtUnixMillis: 100, expiresAtUnixMillis: 200)
        let payload = try unknown.encode(limits: f.limits)
        let signature = try f.authority.signature(for: GatewayTokenCandidateSigningInput.make(wireVersion: 1,
            canonicalPayload: payload, payloadLimits: f.limits, inputLimits: f.limits)).rawRepresentation
        // Inject verified gateway evidence into the disposable fixture to exercise the authenticated eligibility read.
        let result = try f.journal.write {
            try $0.restrictUnknownGatewayTrust(kind: .candidate, canonicalPayload: payload, signature: signature,
                registration: registration, expectedTrustRevision: before.revision, eventID: Data(repeating: 100, count: 16),
                receiptTimeMs: 1000, writer: f.writer, expectedAuditHead: 2)
        }
        XCTAssertEqual(result.disposition, .restricted)
        let restricted = PairedPhoneSelection(macID: f.mac, accountID: f.account, revision: result.trustRevision, phone: phone)
        let accepted = try await channel.canRePair(restricted)
        XCTAssertFalse(accepted)
        let after = try await channel.pairedPhonesForRePair()
        XCTAssertEqual(after.revision, result.trustRevision)
        XCTAssertTrue(after.rePairablePhones.isEmpty)
        await channel.close()
    }

    func testRePairRejectsActiveMissingAndReusedPredecessorMaterial() async throws {
        let f = try Fixture(), (channel, _) = try await pairForRevocation(f)
        let listed = try await channel.pairedPhones()
        let selection = try XCTUnwrap(listed.selection(for: XCTUnwrap(listed.phones.first)))
        let predecessor = try PairingReplacement(phoneID: selection.phone.phoneID, epoch: selection.phone.enrollmentEpoch)
        let missing = try PairingReplacement(phoneID: selection.phone.phoneID, epoch: Data(repeating: 55, count: 16))
        let biometric = P256.Signing.PrivateKey()
        for target in [predecessor, missing] {
            let proposal = try rePairProposal(f, predecessor: target, biometric: biometric)
            XCTAssertThrowsError(try f.access.stage(proposal.encode())) {
                XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment)
            }
        }
        XCTAssertEqual(try f.records(), 1)
        _ = try await channel.revokePhone(selection, authorization: authorization)
        let old = try XCTUnwrap(f.journal.read { try $0.approvalEnrollments().first })
        let reused = try rePairProposal(f, predecessor: predecessor, biometric: biometric, transportPoint: old.identityPublicKey)
        XCTAssertThrowsError(try f.access.stage(reused.encode())) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .reusedIdentity)
        }
        XCTAssertEqual(try f.records(), 2)
        try f.assertCheckpoint()
        await channel.close()
    }

    func testVersionOneRefusesTheRevokedPhoneIDAndAllowsANewPhone() async throws {
        let f = try Fixture(), (channel, _) = try await pairForRevocation(f)
        let listed = try await channel.pairedPhones()
        let selection = try XCTUnwrap(listed.selection(for: XCTUnwrap(listed.phones.first)))
        _ = try await channel.revokePhone(selection, authorization: authorization)
        let biometric = P256.Signing.PrivateKey()
        let reused = try f.proposal(epoch: 57, keyBase: 58, biometric: biometric)
        XCTAssertThrowsError(try f.access.stage(reused.encode())) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .reusedIdentity)
        }
        XCTAssertEqual(try f.records(), 2)

        let fresh = try f.proposal(phone: 56, epoch: 57, keyBase: 58, biometric: biometric)
        let staged = try await channel.stage(fresh, authorization: authorization)
        let proof = try biometric.signature(for: staged.signingInput(purpose: .phoneBiometric)).rawRepresentation
        let receipt = try await channel.commit(confirmedDigest: staged.digest(), biometricProof: proof, authorization: authorization)
        XCTAssertTrue(try staged.verify(signature: receipt, publicKey: f.authority.publicKey.x963Representation, purpose: .macCommit))
        XCTAssertEqual(try f.records(), 3)
        try f.assertCheckpoint()
        await channel.close()
    }

    func testRePairRefusesAConcurrentCommitAndKeepsTheNewEnrollment() async throws {
        let f = try Fixture(), (channel, _) = try await pairForRevocation(f)
        let listed = try await channel.pairedPhones()
        let selection = try XCTUnwrap(listed.selection(for: XCTUnwrap(listed.phones.first)))
        let predecessor = try PairingReplacement(phoneID: selection.phone.phoneID, epoch: selection.phone.enrollmentEpoch)
        _ = try await channel.revokePhone(selection, authorization: authorization)
        let firstKey = P256.Signing.PrivateKey(), secondKey = P256.Signing.PrivateKey()
        let first = try f.access.stage(rePairProposal(f, predecessor: predecessor, biometric: firstKey).encode())
        let second = try rePairProposal(f, predecessor: predecessor, biometric: secondKey)
        func commitAttempt(_ attempt: PairingEnrollmentAttempt, key: P256.Signing.PrivateKey) throws {
            let transcript = attempt.transcript
            _ = try f.access.commit(attempt, setupID: transcript.setupID, confirmedDigest: transcript.digest(),
                proof: key.signature(for: transcript.signingInput(purpose: .phoneBiometric)).rawRepresentation, authorize: {})
        }
        XCTAssertThrowsError(try f.access.stage(second.encode())) {
            XCTAssertEqual($0 as? PairingRecoveryStageError, .pendingForIdentity)
        }
        try commitAttempt(first, key: firstKey)
        XCTAssertThrowsError(try commitAttempt(first, key: firstKey)) {
            XCTAssertEqual($0 as? PairingRecoveryStageError, .noPendingStage)
        }
        let new = try XCTUnwrap(f.journal.read { try $0.approvalEnrollments().first { $0.approval.active } })
        XCTAssertEqual(new.identityPublicKey, first.transcript.transportKey.publicKey)
        XCTAssertEqual(try f.records(), 3)
        try f.assertCheckpoint()
        await channel.close()
    }

    func testPairedPhoneRevocationIsCheckpointedAndRejectsOldSelection() async throws {
        let f = try Fixture(), (channel, driver) = try await pairForRevocation(f)
        let listed = try await channel.pairedPhones()
        let phone = try XCTUnwrap(listed.phones.first), selection = try XCTUnwrap(listed.selection(for: phone))
        XCTAssertEqual(listed.phones.count, 1)
        let peer = try XCTUnwrap(f.journal.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024).peers.first })
        let originalBinding = AuthorityPeerBinding(peer: peer, revision: listed.revision)
        try f.journal.read { try $0.requireDirectApprovalBinding(originalBinding) }
        let before = try await channel.revocationStatus(selection)
        XCTAssertEqual(before, .active)
        let approvals = f.environment.authorized.value
        let result = try await channel.revokePhone(selection, authorization: authorization)
        XCTAssertEqual(result, .revokedOnMac)
        XCTAssertEqual(f.environment.authorized.value, approvals + 2)
        let stale = try await channel.revokePhone(selection, authorization: authorization)
        XCTAssertEqual(stale, .staleSelection)
        let current = try await channel.pairedPhones()
        XCTAssertTrue(current.phones.isEmpty)
        XCTAssertThrowsError(try f.journal.read { try $0.requireDirectApprovalBinding(originalBinding) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision)
        }
        let refreshedBinding = AuthorityPeerBinding(peer: peer, revision: current.revision)
        XCTAssertThrowsError(try f.journal.read { try $0.requireDirectApprovalBinding(refreshedBinding) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment)
        }
        let retained = try await channel.revocationStatus(selection)
        XCTAssertEqual(retained, .revokedOnMac)
        XCTAssertEqual(try f.records(), 2)
        XCTAssertEqual(driver.revocationSends.value, 2)
        try f.assertCheckpoint()
        await channel.close()
    }

    func testLocalRevocationCommitsIntentWhileTheGatewayIsOffline() async throws {
        let f = try Fixture(configureGateway: true), (channel, _) = try await pairForRevocation(f)
        let before = try await channel.pairedPhones()
        XCTAssertEqual(before.revocationAvailability, .gatewayUnavailable)
        let phone = try XCTUnwrap(before.phones.first), selection = try XCTUnwrap(before.selection(for: phone))
        let binding = try XCTUnwrap(f.journal.read { try $0.directApprovalTrust(maximumPayloadBytes: 1024).peers.first })
        let status = try await channel.revokePhone(selection, authorization: authorization)
        XCTAssertEqual(status, .gatewayPending)
        let retained = try XCTUnwrap(f.journal.read { try $0.approvalEnrollments().first })
        let intent = try XCTUnwrap(retained.gatewayRevocation)
        XCTAssertFalse(retained.approval.active)
        XCTAssertEqual(intent.progress, .pending)
        XCTAssertEqual(try f.journal.read { try $0.gatewayAuthorityHead(intent.registration) }, 0)
        let after = try await channel.pairedPhones()
        XCTAssertTrue(after.phones.isEmpty)
        XCTAssertEqual(after.gatewayRevocationHealth, .pending)
        XCTAssertThrowsError(try f.journal.read {
            try $0.requireDirectApprovalBinding(AuthorityPeerBinding(peer: binding, revision: after.revision))
        }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment)
        }
        try f.assertCheckpoint()
        await channel.close()
    }

    func testPairedPhoneReaderReportsGatewayHealthWithoutAnEnrollmentOrAWrite() async throws {
        let f = try Fixture(configureGateway: true), gateway = try XCTUnwrap(f.gatewayRevocations)
        let channel = client(f, driver: try ClientDriver(f))
        _ = try await channel.start()
        let previous = try f.continuity.read(), owner = UUID()
        let clear = try await channel.gatewayRevocationStatus()
        XCTAssertEqual(clear.health, .clear)
        gateway.begin(owner)
        gateway.recordGrantHealth(.gatewayUpdateNeeded, owner: owner)
        let overview = try await channel.gatewayRevocationStatus()
        let sheet = try await channel.pairedPhones()
        XCTAssertTrue(sheet.phones.isEmpty)
        XCTAssertEqual(overview.health, .gatewayUpdateNeeded)
        XCTAssertEqual(overview, sheet.gatewayRevocationStatus)
        gateway.recordGrantHealth(.grantAbandonmentInconclusive, owner: owner)
        let inconclusive = try await channel.gatewayRevocationStatus()
        XCTAssertEqual(inconclusive.health, .grantAbandonmentInconclusive)
        XCTAssertEqual(try f.continuity.read(), previous)
        XCTAssertEqual(f.environment.authorized.value, 0)
        await channel.close()
    }

    func testLostRevocationReplyReadsTheExactEpochWithoutReplayingTheWrite() async throws {
        let f = try Fixture(), (paired, _) = try await pairForRevocation(f)
        let list = try await paired.pairedPhones()
        let selection = try XCTUnwrap(list.selection(for: XCTUnwrap(list.phones.first)))
        await paired.close()
        let driver = try ClientDriver(f)
        let channel = client(f, driver: driver, timeout: 100)
        _ = try await channel.start(); _ = try await channel.pairedPhones()
        driver.hold.value = .revoke
        do {
            _ = try await channel.revokePhone(selection, authorization: authorization)
            XCTFail("Accepted a withheld reply")
        } catch { XCTAssertEqual(error as? AuthorityPairingChannelError, .timedOut) }
        driver.late.value?()
        let fresh = client(f, driver: try ClientDriver(f))
        _ = try await fresh.start()
        let observed = try await fresh.revocationStatus(selection)
        XCTAssertEqual(observed, .revokedOnMac)
        let other = PairedPhoneSelection(macID: f.mac, accountID: f.account, revision: list.revision,
            phone: DeliveryRecipient(phoneID: selection.phone.phoneID, enrollmentEpoch: Data(repeating: 17, count: 16)))
        let otherStatus = try await fresh.revocationStatus(other)
        XCTAssertEqual(otherStatus, .unknown)
        XCTAssertEqual(driver.revocationSends.value, 1)
        XCTAssertEqual(try f.records(), 2)
        try f.assertCheckpoint()
        await fresh.close()
    }

    func testPairedPhoneEndpointRejectsForeignMacAndAccountWithoutWriting() async throws {
        let f = try Fixture(), (channel, _) = try await pairForRevocation(f)
        let list = try await channel.pairedPhones()
        let selected = try XCTUnwrap(list.selection(for: XCTUnwrap(list.phones.first)))
        let foreign = Data(repeating: 200, count: 16)
        for (mac, account) in [(foreign, f.account), (f.mac, foreign)] {
            let selection = PairedPhoneSelection(macID: mac, accountID: account, revision: selected.revision, phone: selected.phone)
            let endpoint = try AuthorityPairingXPCEndpoint(access: f.access, budget: .init(maximum: 1), verify: {},
                authorize: { _ in }, invalidate: {})
            try hello(endpoint)
            let version = Box<UInt64>(0)
            endpoint.pairedPhoneHello { version.value = $0 }
            XCTAssertEqual(version.value, 1)
            let bytes = try selection.encode()
            let read = Box<Data?>(Data())
            endpoint.managePairedPhone(PairedPhoneOperation.status.rawValue, selection: bytes, authorization: Data()) {
                read.value = $0
            }
            XCTAssertNil(read.value)
            let write = Box<Data?>(Data())
            endpoint.managePairedPhone(PairedPhoneOperation.revoke.rawValue, selection: bytes, authorization: authorization) {
                write.value = $0
            }
            XCTAssertNil(write.value)
        }
        let status = try await channel.revocationStatus(selected)
        XCTAssertEqual(status, .active)
        XCTAssertEqual(try f.records(), 1)
        try f.assertCheckpoint()
        await channel.close()
    }

    func testPhoneRevocationRechecksAdministratorAtTheWrite() async throws {
        let f = try Fixture(), (channel, _) = try await pairForRevocation(f)
        let listed = try await channel.pairedPhones()
        let selection = try XCTUnwrap(listed.selection(for: XCTUnwrap(listed.phones.first)))
        let endpoint = try AuthorityPairingXPCEndpoint(access: f.access, budget: .init(maximum: 1), verify: {},
            authorize: { [calls = Box(0)] _ in
                calls.value += 1
                if calls.value == 2 { throw Failure.denied }
            }, invalidate: {})
        try hello(endpoint)
        let version = Box<UInt64>(0)
        endpoint.pairedPhoneHello { version.value = $0 }
        XCTAssertEqual(version.value, 1)
        let reply = Box<Data?>(nil)
        endpoint.managePairedPhone(PairedPhoneOperation.revoke.rawValue, selection: try selection.encode(),
            authorization: authorization) { reply.value = $0 }
        XCTAssertNil(reply.value)
        let current = try await channel.revocationStatus(selection)
        XCTAssertEqual(current, .active)
        XCTAssertEqual(try f.records(), 1)
        try f.assertCheckpoint()
        await channel.close()
    }

    func testPhoneManagementRequiresItsOwnVersionAndRejectsMalformedSelection() throws {
        let f = try Fixture()
        let endpoint = try f.endpoint()
        try hello(endpoint)
        let unnegotiated = Box<Data?>(nil)
        endpoint.managePairedPhone(PairedPhoneOperation.list.rawValue, selection: Data(), authorization: Data()) {
            unnegotiated.value = $0
        }
        XCTAssertNil(unnegotiated.value)
        let second = try f.endpoint()
        try hello(second)
        let negotiated = Box<UInt64>(0)
        second.pairedPhoneHello { negotiated.value = $0 }
        XCTAssertEqual(negotiated.value, 1)
        let malformed = Box<Data?>(nil)
        second.managePairedPhone(PairedPhoneOperation.revoke.rawValue, selection: Data(repeating: 0, count: 129),
            authorization: authorization) { malformed.value = $0 }
        XCTAssertNil(malformed.value)
        XCTAssertEqual(f.environment.authorized.value, 0)
        XCTAssertEqual(try f.records(), 0)
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

    func testReleaseActivityRetainsIndependentPairingAttemptsUntilCancelAndDisconnect() throws {
        let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture(activity: activity.open())
        let one = try f.endpoint(), two = try f.endpoint(); try hello(one); try hello(two)
        _ = try staged(one, proposal: f.proposal()); _ = try staged(two, proposal: f.proposal())
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        let cancelled = Box(false); one.cancelPairing { cancelled.value = $0 }; XCTAssertTrue(cancelled.value)
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        two.close()
        let update = try installer.acquireExclusive(); update.close()
        XCTAssertEqual(try f.records(), 0); XCTAssertEqual(f.environment.signed.value, 0); try f.assertCheckpoint()
    }
    func testReleaseActivityUsesTheBarrierAttachedAfterPairingAccessConstruction() throws {
        let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture()
        try f.journal.attachReleaseActivityBarrier(activity.open())
        let endpoint = try f.endpoint(); try hello(endpoint)
        _ = try staged(endpoint, proposal: f.proposal())
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        endpoint.close()
        let update = try installer.acquireExclusive(); update.close()
    }
    func testReleaseActivityEndpointDestructionDiscardsOnlyItsUncommittedAttempt() throws {
        let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture(activity: activity.open())
        var endpoint: AuthorityPairingXPCEndpoint? = try f.endpoint()
        try hello(XCTUnwrap(endpoint)); _ = try staged(XCTUnwrap(endpoint), proposal: f.proposal())
        XCTAssertThrowsError(try installer.acquireExclusive())
        endpoint = nil
        let update = try installer.acquireExclusive(); update.close()
        XCTAssertEqual(try f.records(), 0); XCTAssertEqual(f.environment.signed.value, 0)
    }

    func testReleaseActivityCoversTheCommittedReceiptReplyAndThenReleases() throws {
        let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture(activity: activity.open())
        let endpoint = try f.endpoint(); try hello(endpoint)
        let value = try staged(endpoint, proposal: f.proposal()), reply = Box<Data?>(nil)
        let proof = try f.biometric.signature(for: value.signingInput(purpose: .phoneBiometric)).rawRepresentation
        let blocked = Box(false)
        endpoint.commitPairing(value.setupID, confirmedDigest: try value.digest(), biometricProof: proof, authorization: authorization) { response in
            do { let unexpected = try installer.acquireExclusive(); unexpected.close() }
            catch ReleaseActivityError.busy { blocked.value = true }
            catch { }
            reply.value = response
        }
        XCTAssertTrue(blocked.value)
        XCTAssertTrue(try value.verify(signature: XCTUnwrap(reply.value), publicKey: f.authority.publicKey.x963Representation, purpose: .macCommit))
        let update = try installer.acquireExclusive(); update.close()
        XCTAssertEqual(try f.records(), 1); try f.assertCheckpoint()
    }
    func testReleaseActivityExpiryUsesTheOriginalMonotonicDeadlineWithoutEnrollment() throws {
        for current: UInt64 in [99, 1100, 100_000] {
            let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture(activity: activity.open())
            let endpoint = try f.endpoint(); try hello(endpoint)
            let value = try staged(endpoint, proposal: f.proposal())
            f.environment.time.value = 1099; endpoint.expireStagedIfNeeded()
            XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
            f.environment.time.value = current; endpoint.expireStagedIfNeeded()
            let update = try installer.acquireExclusive(); update.close()
            XCTAssertNil(try commit(endpoint, transcript: value, fixture: f))
            XCTAssertEqual(try f.records(), 0); XCTAssertEqual(f.environment.signed.value, 0); try f.assertCheckpoint()
        }
    }
    func testReleaseActivityTimerClearsAnExpiredAttemptWithoutAnotherInvocation() async throws {
        let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture(activity: activity.open())
        let endpoint = try f.endpoint(); try hello(endpoint)
        _ = try staged(endpoint, proposal: f.proposal()); f.environment.time.value = 1100
        let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
        var update: ReleaseActivityToken?
        while update == nil, DispatchTime.now().uptimeNanoseconds < deadline {
            do { update = try installer.acquireExclusive() }
            catch ReleaseActivityError.busy { try await Task.sleep(for: .milliseconds(20)) }
        }
        try XCTUnwrap(update).close()
        XCTAssertEqual(try f.records(), 0); endpoint.close()
    }
    func testReleaseActivityStageFailureAndExclusiveRefusalCannotEnrollOrLeakReferences() throws {
        for exclusive in [false, true] {
            let activity = try ReleaseActivityFixture(), installer = try activity.open(), f = try Fixture(activity: activity.open())
            let endpoint = try f.endpoint(); try hello(endpoint)
            let update = try exclusive ? installer.acquireExclusive() : nil
            f.environment.denied.value = !exclusive
            let reply = Box<Data?>(nil)
            endpoint.stagePairing(try f.proposal().encode(), authorization: authorization) { reply.value = $0 }
            XCTAssertNil(reply.value); update?.close()
            let available = try installer.acquireExclusive(); available.close()
            XCTAssertEqual(try f.records(), 0); XCTAssertEqual(f.environment.signed.value, 0)
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

extension AuthorityPairingSetupTests {
    func testMaintenancePairingObservationRetainsStagedWorkWithoutClockOrJournalMutation() throws {
        let activity = try ReleaseActivityFixture(), f = try Fixture(activity: activity.open())
        let endpoint = try f.endpoint(); defer { endpoint.close() }
        XCTAssertFalse(try endpoint.maintenancePairingWork().ready)
        try hello(endpoint)
        let value = try staged(endpoint, proposal: f.proposal()), records = try f.records(), time = f.environment.time.value
        let observed = try endpoint.maintenancePairingWork()
        XCTAssertTrue(observed.ready); XCTAssertEqual(observed.stagedAttempts, 1)
        XCTAssertEqual(observed.activityOwners, 1); XCTAssertFalse(observed.operationActive)
        XCTAssertEqual(try endpoint.maintenancePairingWork(), observed)
        XCTAssertEqual(try f.journal.maintenanceJournalWork().requests.liveRequests, 0)
        XCTAssertEqual(try f.records(), records); XCTAssertEqual(f.environment.time.value, time)
        XCTAssertThrowsError(try activity.open().acquireExclusive())
        XCTAssertEqual(value.setupID.count, 16)
        endpoint.cancelPairing { XCTAssertTrue($0) }
        XCTAssertEqual(try endpoint.maintenancePairingWork().stagedAttempts, 0)
        XCTAssertEqual(try endpoint.maintenancePairingWork().activityOwners, 0)
        XCTAssertEqual(observed.stagedAttempts, 1)
        let replacement = try activity.open().acquireExclusive(); replacement.close()
    }
    func testMaintenancePairingObservationFromAnotherThreadSeesCommitAfterStagingClears() throws {
        let activity = try ReleaseActivityFixture(), f = try Fixture(activity: activity.open())
        let hold = Box(false), entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0)
        let completed = DispatchSemaphore(value: 0), result = Box<Data?>(nil), operationThread = Box<UInt32>(0)
        let endpoint = try AuthorityPairingXPCEndpoint(access: f.access, budget: .init(maximum: 1), verify: {},
            authorize: { _ in
                if hold.value {
                    operationThread.value = pthread_mach_thread_np(pthread_self()); entered.signal()
                    XCTAssertEqual(resume.wait(timeout: .now() + 3), .success)
                }
            }, invalidate: {})
        defer { resume.signal(); endpoint.close() }
        try hello(endpoint)
        let value = try staged(endpoint, proposal: f.proposal()), authorization = authorization
        let digest = try value.digest(), proof = try f.biometric.signature(for: value.signingInput(purpose: .phoneBiometric)).rawRepresentation
        hold.value = true
        DispatchQueue.global().async {
            endpoint.commitPairing(value.setupID, confirmedDigest: digest, biometricProof: proof,
                authorization: authorization) { result.value = $0 }
            completed.signal()
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
        XCTAssertNotEqual(operationThread.value, pthread_mach_thread_np(pthread_self()))
        let observed = try endpoint.maintenancePairingWork()
        XCTAssertTrue(observed.operationActive); XCTAssertEqual(observed.stagedAttempts, 0)
        XCTAssertEqual(observed.activityOwners, 1)
        XCTAssertThrowsError(try activity.open().acquireExclusive())
        resume.signal(); XCTAssertEqual(completed.wait(timeout: .now() + 3), .success)
        XCTAssertNotNil(result.value); XCTAssertEqual(try f.records(), 1); try f.assertCheckpoint()
        XCTAssertFalse(try endpoint.maintenancePairingWork().operationActive)
        XCTAssertEqual(try endpoint.maintenancePairingWork().activityOwners, 0)
        endpoint.close(); XCTAssertThrowsError(try endpoint.maintenancePairingWork())
    }
    func testMaintenancePairingOwnerSurvivesWorkReturnBeforeReplyStarts() throws {
        let activity = try ReleaseActivityFixture(), f = try Fixture(activity: activity.open())
        let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0), completed = DispatchSemaphore(value: 0)
        let result = Box<UInt64>(0), budget = try AuthorityXPCWorkBudget(maximum: 1)
        let endpoint = try AuthorityPairingXPCEndpoint(access: f.access, budget: budget, verify: {},
            authorize: { _ in }, invalidate: {}, onHandshake: {
                entered.signal(); XCTAssertEqual(resume.wait(timeout: .now() + 3), .success)
            })
        defer { resume.signal(); endpoint.close() }
        DispatchQueue.global().async {
            endpoint.pairingHello { result.value = $0 }; completed.signal()
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(result.value, 0)
        XCTAssertTrue(budget.acquire()); budget.release()
        let observed = try endpoint.maintenancePairingWork()
        XCTAssertTrue(observed.ready); XCTAssertTrue(observed.operationActive)
        XCTAssertEqual(observed.stagedAttempts, 0); XCTAssertEqual(observed.activityOwners, 1)
        XCTAssertThrowsError(try activity.open().acquireExclusive())
        resume.signal(); XCTAssertEqual(completed.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(result.value, 1); XCTAssertFalse(try endpoint.maintenancePairingWork().operationActive)
        XCTAssertEqual(try endpoint.maintenancePairingWork().activityOwners, 0)
        let update = try activity.open().acquireExclusive(); update.close()
    }
    func testMaintenancePairingOwnerSurvivesReplyUntilItsActivityActuallyCloses() throws {
        let activity = try ReleaseActivityFixture(), f = try Fixture(activity: activity.open())
        let endpoint = try f.endpoint(); try hello(endpoint)
        let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0), completed = DispatchSemaphore(value: 0)
        let result = Box<Data?>(nil)
        defer { resume.signal(); endpoint.close() }
        DispatchQueue.global().async {
            endpoint.pairingContext { bytes in
                result.value = bytes; entered.signal(); XCTAssertEqual(resume.wait(timeout: .now() + 3), .success)
            }
            completed.signal()
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
        XCTAssertNotNil(result.value)
        let observed = try endpoint.maintenancePairingWork()
        XCTAssertTrue(observed.operationActive); XCTAssertEqual(observed.activityOwners, 1)
        XCTAssertEqual(observed.stagedAttempts, 0)
        XCTAssertThrowsError(try activity.open().acquireExclusive())
        resume.signal(); XCTAssertEqual(completed.wait(timeout: .now() + 3), .success)
        XCTAssertFalse(try endpoint.maintenancePairingWork().operationActive)
        XCTAssertEqual(try endpoint.maintenancePairingWork().activityOwners, 0)
        let update = try activity.open().acquireExclusive(); update.close()
    }
    func testMaintenanceStageReservationBlocksNewStagesAcrossAllPairingConnections() throws {
        let f = try Fixture(), one = try f.endpoint(), two = try f.endpoint(), admission = f.access.maintenanceAdmission
        defer { one.close(); two.close() }; try hello(one); try hello(two)
        _ = try staged(one, proposal: f.proposal()); XCTAssertEqual(try admission.stagedReservations(), 1)
        let owner = try admission.openConnection(attemptID: Data(repeating: 6, count: 16), revision: Data(repeating: 7, count: 16))
        XCTAssertEqual(try owner.blockNewStages(matching: owner.binding), 1)
        XCTAssertThrowsError(try owner.transferToShutdown(matching: owner.binding)) { XCTAssertEqual($0 as? AuthorityMaintenancePairingAdmission.TransferError, .stagesPending(1)) }
        let reply = Box<Data?>(nil); two.stagePairing(try f.proposal().encode(), authorization: authorization) { reply.value = $0 }
        XCTAssertNil(reply.value); XCTAssertEqual(try admission.stagedReservations(), 1)
        one.cancelPairing { XCTAssertTrue($0); XCTAssertEqual(try? admission.stagedReservations(), 1) }
        XCTAssertEqual(try admission.stagedReservations(), 0)
        let armed = try owner.transferToShutdown(matching: owner.binding); owner.close()
        XCTAssertThrowsError(try admission.reserveStage()); try armed.reopen(matching: owner.binding)
        let stage = try admission.reserveStage(); stage.close()
    }
    func testMaintenanceStageReservationSurvivesCommitUntilTheReceiptReplyReturns() throws {
        let f = try Fixture(), endpoint = try f.endpoint(), admission = f.access.maintenanceAdmission
        defer { endpoint.close() }; try hello(endpoint); let value = try staged(endpoint, proposal: f.proposal())
        let proof = try f.biometric.signature(for: value.signingInput(purpose: .phoneBiometric)).rawRepresentation
        let result = Box<Data?>(nil)
        endpoint.commitPairing(value.setupID, confirmedDigest: try value.digest(), biometricProof: proof, authorization: authorization) {
            result.value = $0; XCTAssertEqual(try? admission.stagedReservations(), 1)
            XCTAssertEqual(try? endpoint.maintenancePairingWork().stagedAttempts, 0)
        }
        XCTAssertNotNil(result.value); XCTAssertEqual(try admission.stagedReservations(), 0); try f.assertCheckpoint()
    }
    func testMaintenanceStageReservationSurvivesACommitAfterTheAttemptClearsOnAnotherThread() throws {
        let f = try Fixture(), admission = f.access.maintenanceAdmission
        let hold = Box(false), entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
        let endpoint = try AuthorityPairingXPCEndpoint(access: f.access, budget: .init(maximum: 1), verify: {}, authorize: { _ in
            if hold.value { entered.signal(); XCTAssertEqual(resume.wait(timeout: .now() + 3), .success) }
        }, invalidate: {})
        defer { resume.signal(); endpoint.close() }; try hello(endpoint); let value = try staged(endpoint, proposal: f.proposal())
        let digest = try value.digest(), proof = try f.biometric.signature(for: value.signingInput(purpose: .phoneBiometric)).rawRepresentation, authorization = authorization
        hold.value = true
        DispatchQueue.global().async {
            endpoint.commitPairing(value.setupID, confirmedDigest: digest, biometricProof: proof, authorization: authorization) { XCTAssertNotNil($0) }; done.signal()
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(try endpoint.maintenancePairingWork().stagedAttempts, 0); XCTAssertEqual(try admission.stagedReservations(), 1)
        let owner = try admission.openConnection(attemptID: Data(repeating: 6, count: 16), revision: Data(repeating: 7, count: 16))
        _ = try owner.blockNewStages(matching: owner.binding); XCTAssertThrowsError(try owner.transferToShutdown(matching: owner.binding))
        resume.signal(); XCTAssertEqual(done.wait(timeout: .now() + 3), .success); XCTAssertEqual(try admission.stagedReservations(), 0); owner.close()
    }
    func testMaintenanceStageReservationExpiryAndDisconnectReleaseOnlyTheirOwnStage() throws {
        for expire in [false, true] {
            let f = try Fixture(), one = try f.endpoint(), two = try f.endpoint(), admission = f.access.maintenanceAdmission
            try hello(one); try hello(two); _ = try staged(one, proposal: f.proposal()); _ = try staged(two, proposal: f.proposal())
            XCTAssertEqual(try admission.stagedReservations(), 2)
            if expire { f.environment.time.value = 1100; one.expireStagedIfNeeded() } else { one.close() }
            XCTAssertEqual(try admission.stagedReservations(), 1); two.close(); one.close(); XCTAssertEqual(try admission.stagedReservations(), 0)
        }
    }
    func testMaintenanceStageFailureAndEndpointDestructionCannotLeakReservations() throws {
        let f = try Fixture(), admission = f.access.maintenanceAdmission
        var endpoint: AuthorityPairingXPCEndpoint? = try f.endpoint(); try hello(XCTUnwrap(endpoint))
        f.environment.selfDenied.value = true
        endpoint?.stagePairing(try f.proposal().encode(), authorization: authorization) { XCTAssertNil($0) }
        XCTAssertEqual(try admission.stagedReservations(), 0); endpoint = nil
        f.environment.selfDenied.value = false; endpoint = try f.endpoint(); try hello(XCTUnwrap(endpoint)); _ = try staged(XCTUnwrap(endpoint), proposal: f.proposal())
        XCTAssertEqual(try admission.stagedReservations(), 1); endpoint = nil; XCTAssertEqual(try admission.stagedReservations(), 0)
    }

    func testMaintenanceStageReservationSurvivesEndpointCloseInsideItsStageReply() throws {
        let f = try Fixture(), endpoint = try f.endpoint(), admission = f.access.maintenanceAdmission
        try hello(endpoint)
        endpoint.stagePairing(try f.proposal().encode(), authorization: authorization) { reply in
            XCTAssertNotNil(reply); endpoint.close(); XCTAssertEqual(try? admission.stagedReservations(), 1)
        }
        XCTAssertEqual(try admission.stagedReservations(), 0)
    }

    func testMaintenanceStageCannotTransferAReservationAfterReentrantAuthorizationClose() throws {
        let f = try Fixture(), holder = Box<AuthorityPairingXPCEndpoint?>(nil), admission = f.access.maintenanceAdmission
        let endpoint = try AuthorityPairingXPCEndpoint(access: f.access, budget: .init(maximum: 1), verify: {},
            authorize: { _ in holder.value?.close() }, invalidate: {})
        holder.value = endpoint; defer { holder.value = nil; endpoint.close() }; try hello(endpoint)
        endpoint.stagePairing(try f.proposal().encode(), authorization: authorization) { XCTAssertNil($0) }
        XCTAssertEqual(try admission.stagedReservations(), 0); XCTAssertEqual(try f.records(), 0)
        XCTAssertEqual(f.environment.signed.value, 0); XCTAssertThrowsError(try endpoint.maintenancePairingWork())
        try f.assertCheckpoint()
    }

}


extension AuthorityPairingSetupTests {
    func testMaintenanceOwnersCaptureBothActualEndpointsAndPruneOnlySettledClose() throws {
        let activity = try ReleaseActivityFixture(), f = try Fixture(activity: activity.open())
        let first = try f.endpoint(), second = try f.endpoint(), owner = AuthorityMaintenancePairingOwners(admission: f.access.maintenanceAdmission)
        try owner.retain(first, id: UUID()); try owner.retain(second, id: UUID())
        defer { first.close(); second.close() }
        XCTAssertFalse(try owner.capture().ready); try hello(first); try hello(second)
        _ = try staged(first, proposal: f.proposal()); _ = try staged(second, proposal: f.proposal())
        let both = try owner.capture(); XCTAssertTrue(both.ready); XCTAssertEqual(both.stagedAttempts, 2); XCTAssertEqual(both.activityOwners, 2)
        first.close(); let one = try owner.capture(); XCTAssertTrue(one.ready); XCTAssertEqual(one.stagedAttempts, 1); XCTAssertEqual(one.activityOwners, 1)
        second.close(); let empty = try owner.capture(); XCTAssertEqual(empty.stagedAttempts, 0); XCTAssertEqual(empty.activityOwners, 0)
        XCTAssertFalse(empty.operationActive); try f.assertCheckpoint()
    }
    func testMaintenanceOwnersKeepClosedStageReplyUntilItsActualActivityCloses() throws {
        let activity = try ReleaseActivityFixture(), f = try Fixture(activity: activity.open()), endpoint = try f.endpoint()
        let owner = AuthorityMaintenancePairingOwners(admission: f.access.maintenanceAdmission)
        try owner.retain(endpoint, id: UUID()); try hello(endpoint); defer { endpoint.close() }
        endpoint.stagePairing(try f.proposal().encode(), authorization: authorization) { bytes in
            XCTAssertNotNil(bytes); endpoint.close()
            let during = try? owner.capture(); XCTAssertEqual(during?.stagedAttempts, 1)
            XCTAssertFalse(during?.ready ?? true); XCTAssertTrue(during?.operationActive ?? false)
            XCTAssertGreaterThan(during?.activityOwners ?? 0, 0)
        }
        let after = try owner.capture(); XCTAssertEqual(after.stagedAttempts, 0); XCTAssertEqual(after.activityOwners, 0)
        XCTAssertFalse(after.operationActive); XCTAssertNil(endpoint.retainedMaintenancePairingWork())
    }
    func testMaintenanceOwnersKeepCommitReplyAfterTheAttemptTransfers() throws {
        let activity = try ReleaseActivityFixture(), f = try Fixture(activity: activity.open()), endpoint = try f.endpoint()
        let owner = AuthorityMaintenancePairingOwners(admission: f.access.maintenanceAdmission)
        try owner.retain(endpoint, id: UUID()); try hello(endpoint); defer { endpoint.close() }
        let value = try staged(endpoint, proposal: f.proposal()), proof = try f.biometric.signature(for: value.signingInput(purpose: .phoneBiometric)).rawRepresentation
        endpoint.commitPairing(value.setupID, confirmedDigest: try value.digest(), biometricProof: proof, authorization: authorization) { bytes in
            XCTAssertNotNil(bytes); endpoint.close()
            let during = try? owner.capture(); XCTAssertEqual(during?.stagedAttempts, 1); XCTAssertTrue(during?.operationActive ?? false)
        }
        XCTAssertEqual(try owner.capture().stagedAttempts, 0); XCTAssertEqual(try f.records(), 1); try f.assertCheckpoint()
    }
    func testMaintenanceOwnersRejectAnEndpointFromAnotherAdmissionWithoutAdoptingItsStage() throws {
        let first = try Fixture(), second = try Fixture(), endpoint = try second.endpoint()
        let owner = AuthorityMaintenancePairingOwners(admission: first.access.maintenanceAdmission)
        defer { endpoint.close() }; try hello(endpoint); _ = try staged(endpoint, proposal: second.proposal())
        XCTAssertThrowsError(try owner.retain(endpoint, id: UUID())); XCTAssertEqual(try owner.capture().stagedAttempts, 0)
        XCTAssertEqual(try second.access.maintenanceAdmission.stagedReservations(), 1)
        first.access.maintenanceAdmission.close(); XCTAssertThrowsError(try owner.capture())
    }
    func testMaintenanceBindingUsesTheActualAuthorityClockEpoch() throws {
        let f = try Fixture(), admission = f.access.maintenanceAdmission
        var epoch = f.environment.now().epoch.uuid
        let expected = withUnsafeBytes(of: &epoch) { Data($0) }
        let connection = try admission.openConnection(attemptID: Data(repeating: 70, count: 16), revision: Data(repeating: 71, count: 16))
        defer { connection.close() }; XCTAssertEqual(connection.binding.incarnation, expected)
        XCTAssertNotEqual(connection.binding.incarnation, Data(repeating: 0, count: 16))
    }
}

final class AuthorityJournalSchema19MigrationTests: XCTestCase, @unchecked Sendable {
    private typealias Fixture = AuthorityPairingSetupTests.Fixture
    private typealias Box<Value> = AuthorityPairingSetupTests.Box<Value>
    private enum Fault: Error { case injected }
    private var authorization: Data { Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size) }

    private func open(_ f: Fixture, readOnly: Bool = false) throws -> sending AuthorityStorage {
        try AuthorityStorage(openJournal: {
            try JournalDatabase(lease: .init(anchor: f.root.path, relativeDirectory: "store", owner: getuid()),
                macID: f.mac, accountID: f.account, recordLimits: f.limits, descriptorLimits: f.limits,
                decisionLimits: f.limits, maximumConsumptions: 20, busyMilliseconds: 100,
                initialize: false, readOnlyForCutover: readOnly)
        }, openContinuity: { directory in
            try ContinuityStore(lease: .init(anchor: f.root.path, relativeDirectory: "continuity",
                owner: getuid(), excludingDirectory: directory), macID: f.mac, accountID: f.account,
                initialize: nil, readOnlyForCutover: readOnly)
        })
    }

    private func close(_ f: Fixture) throws { try f.journal.close(); f.continuity.close() }

    private func sql(_ f: Fixture, _ statement: String, continuity: Bool = false) throws {
        let relative = continuity ? "continuity/continuity.sqlite" : "store/journal.sqlite"
        var connection: OpaquePointer?
        let result = sqlite3_open_v2(f.root.appendingPathComponent(relative).path, &connection, SQLITE_OPEN_READWRITE, nil)
        defer { sqlite3_close(connection) }
        guard result == SQLITE_OK, let connection else { throw JournalDatabaseError.storage(result) }
        let execute = sqlite3_exec(connection, statement, nil, nil, nil)
        guard execute == SQLITE_OK else { throw JournalDatabaseError.storage(execute) }
    }

    private func files(_ f: Fixture) throws -> [String: Data] {
        var bytes: [String: Data] = [:]
        for name in ["store", "continuity"] {
            let directory = f.root.appendingPathComponent(name)
            for file in try FileManager.default.contentsOfDirectory(atPath: directory.path) {
                bytes["\(name)/\(file)"] = try Data(contentsOf: directory.appendingPathComponent(file))
            }
        }
        return bytes
    }

    private func ordinary(_ f: Fixture, phone: UInt8 = 8, key: P256.Signing.PrivateKey = .init()) throws -> PairingTranscript {
        let attempt = try f.access.stage(f.proposal(phone: phone, epoch: phone, biometric: key, keyNamespace: phone).encode())
        _ = try commit(f, attempt, key: key)
        return attempt.transcript
    }

    private func commit(_ f: Fixture, _ attempt: PairingEnrollmentAttempt, key: P256.Signing.PrivateKey,
                        authorize: @escaping () throws -> Void = {}) throws -> Data {
        let transcript = attempt.transcript
        let proof = try key.signature(for: transcript.signingInput(purpose: .phoneBiometric)).rawRepresentation
        return try f.access.commit(attempt, setupID: transcript.setupID, confirmedDigest: transcript.digest(), proof: proof, authorize: authorize)
    }

    private func proposal(_ f: Fixture, phone: UInt8 = 8) throws -> (PairingPhoneProposal, P256.Signing.PrivateKey) {
        let original = try ordinary(f, phone: phone)
        let recipient = DeliveryRecipient(phoneID: original.phone.scope.phoneID, enrollmentEpoch: original.phone.scope.enrollmentEpoch)
        let selection = try XCTUnwrap(f.access.pairedPhones().selection(for: recipient))
        _ = try f.access.revokePhone(selection, authorize: {})
        return try replacement(f, selection: selection)
    }

    private func replacement(_ f: Fixture, selection: PairedPhoneSelection, epoch: UInt8 = 50) throws -> (PairingPhoneProposal, P256.Signing.PrivateKey) {
        let key = P256.Signing.PrivateKey()
        let scope = try ChannelScope(macID: f.mac, accountID: f.account, phoneID: selection.phone.phoneID,
                                    enrollmentEpoch: Data(repeating: epoch, count: 16))
        let phone = try ChannelOffer(role: .phone, scope: scope, nonce: Data(repeating: epoch, count: 32),
            envelopeVersions: [1], requests: [.init(kind: 0, wireVersion: 1, schemaVersion: 1, features: [])], auditVersions: [1])
        return (try PairingPhoneProposal(phone: phone,
            transportKey: .init(keyID: Data(repeating: 70, count: 16), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            decisionKey: .init(keyID: Data(repeating: 71, count: 16), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            biometricKey: .init(keyID: Data(repeating: 72, count: 16), publicKey: key.publicKey.x963Representation),
            replacement: selection.predecessor), key)
    }

    private func stage(_ f: Fixture, _ proposal: PairingPhoneProposal) throws -> PairingEnrollmentAttempt {
        try f.access.stage(proposal.encode())
    }

    private func retained(_ f: Fixture, _ attempt: PairingEnrollmentAttempt) throws -> PairingRecoveryStage? {
        let id = attempt.transcript.setupID
        return try f.journal.read { try $0.recoveryStage(setupID: id) }
    }

    private func endpoint(_ f: Fixture, budget: AuthorityXPCWorkBudget? = nil) throws -> AuthorityPairingXPCEndpoint {
        let endpoint = try f.endpoint(budget: budget), hello = Box<UInt64>(0)
        endpoint.pairingHello { hello.value = $0 }
        XCTAssertEqual(hello.value, 1)
        return endpoint
    }

    private func stageBytes(_ endpoint: AuthorityPairingXPCEndpoint, _ bytes: Data) -> Data? {
        let reply = Box<Data?>(nil)
        endpoint.stagePairing(bytes, authorization: authorization) { reply.value = $0 }
        return reply.value
    }

    private func writes<Value: Sendable>(_ f: Fixture, _ body: @escaping @Sendable (JournalTransaction) throws -> Value) throws -> Value {
        try f.journal.withRequests { requests in
            try CheckpointedJournal(journal: requests.database, continuity: f.continuity)
                .write(epoch: f.writer.epoch, recoverRejectedBody: true, body)
        }
    }

    func testOrdinaryPairingAndStartupKeepTheExistingFormat() throws {
        let f = try Fixture()
        let original = try f.continuity.read().committed
        let transcript = try ordinary(f)
        XCTAssertNil(transcript.replacement)
        XCTAssertEqual(try f.journal.read { try $0.featureTier }, 13)
        XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 13)
        XCTAssertGreaterThan(try f.continuity.read().committed.journalHead, original.journalHead)
        try close(f)
        let restarted = try AuthorityJournal(storage: open(f))
        defer { try? restarted.close() }
        try restarted.prepareRequests(clockEpoch: UUID(), maximumPayloadBytes: 16_384)
        XCTAssertEqual(try restarted.read { try $0.storageSchemaVersion }, 13)
    }

    func testFirstAuthorizedRePairStageCommitsMigrationAndStageOnce() throws {
        let f = try Fixture(), (proposal, _) = try proposal(f)
        let before = try f.continuity.read().committed
        let connection = try endpoint(f)
        defer { connection.close() }
        let bytes = try XCTUnwrap(stageBytes(connection, proposal.encode()))
        let transcript = try PairingTranscript.decode(bytes)
        let stage = try XCTUnwrap(f.journal.read { try $0.recoveryStage(setupID: transcript.setupID) })
        XCTAssertEqual(stage.state, .pending)
        XCTAssertEqual(try stage.transcript.encode(), bytes)
        XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 19)
        XCTAssertEqual(try f.journal.read { try $0.featureTier }, 13)
        let after = try f.continuity.read().committed
        XCTAssertEqual(after.generation, before.generation + 1)
        XCTAssertEqual(after.ledgerDigest, before.ledgerDigest)
        XCTAssertNotEqual(after.authorityDigest, before.authorityDigest)
        f.environment.time.value += 17
        let retry = try self.stage(f, proposal)
        XCTAssertEqual(try retry.transcript.encode(), bytes)
        XCTAssertEqual(try retry.recoveryStage().deadline, stage.deadline)
        XCTAssertEqual(try f.continuity.read().committed, after)
        connection.close()
        try close(f)
        let storage = try open(f)
        defer { try? storage.close() }
        XCTAssertEqual(try storage.journal.read { try $0.recoveryStage(setupID: transcript.setupID)?.transcriptDigest }, stage.transcriptDigest)
        XCTAssertEqual(try storage.continuity.read().committed, after)
    }

    func testRejectedRePairDoesNotMigrateOrReserve() throws {
        let f = try Fixture(), (proposal, _) = try proposal(f)
        let before = try f.continuity.read()
        XCTAssertThrowsError(try f.access.stage(proposal.encode()) { throw Fault.injected })
        let bogus = try PairingPhoneProposal(phone: proposal.phone, transportKey: proposal.transportKey,
            decisionKey: proposal.decisionKey, biometricKey: proposal.biometricKey,
            replacement: .init(phoneID: proposal.phone.scope.phoneID, epoch: Data(repeating: 99, count: 16)))
        XCTAssertThrowsError(try f.access.stage(bogus.encode()))
        let budget = try AuthorityXPCWorkBudget(maximum: 1), connection = try endpoint(f, budget: budget)
        defer { connection.close() }
        XCTAssertTrue(budget.acquire())
        defer { budget.release() }
        XCTAssertNil(try stageBytes(connection, proposal.encode()))
        XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 13)
        XCTAssertEqual(try f.continuity.read(), before)
    }

    func testConcurrentFirstStagesMigrateAndTransitionOnlyOnce() throws {
        let f = try Fixture()
        let first = try proposal(f, phone: 8).0, second = try proposal(f, phone: 10).0
        let before = try f.continuity.read().committed
        let resultA = Box<Result<PairingEnrollmentAttempt, any Error>?>(nil)
        let resultB = Box<Result<PairingEnrollmentAttempt, any Error>?>(nil)
        DispatchQueue.concurrentPerform(iterations: 2) { index in
            let result = Result { try self.stage(f, index == 0 ? first : second) }
            if index == 0 { resultA.value = result } else { resultB.value = result }
        }
        let ids = try [resultA.value, resultB.value].map { result in try XCTUnwrap(result).get().transcript.setupID }
        XCTAssertEqual(Set(ids).count, 2)
        XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 19)
        XCTAssertEqual(try f.continuity.read().committed.generation, before.generation + 2)
        XCTAssertEqual(try f.continuity.read().committed.ledgerDigest, before.ledgerDigest)
        for id in ids { XCTAssertEqual(try f.journal.read { try $0.recoveryStage(setupID: id)?.state }, .pending) }
    }

    func testOrdinaryPairingOnSchemaNineteenPreservesTheRecoveryState() throws {
        let f = try Fixture(), (proposal, _) = try proposal(f)
        let pending = try stage(f, proposal)
        let before = try f.continuity.read().committed
        _ = try ordinary(f, phone: 80)
        XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 19)
        XCTAssertEqual(try f.journal.read { try $0.featureTier }, 13)
        XCTAssertEqual(try retained(f, pending)?.state, .pending)
        XCTAssertNotEqual(try f.continuity.read().committed.authorityDigest, before.authorityDigest)
        try f.assertCheckpoint()
    }

    func testVersionTwoStageSlotIsUniqueForAnIdentity() throws {
        let f = try Fixture(), (proposal, _) = try proposal(f)
        let first = try stage(f, proposal)
        let before = try f.continuity.read()
        let other = try PairingPhoneProposal(phone: proposal.phone, transportKey: proposal.transportKey,
            decisionKey: proposal.decisionKey, biometricKey: .init(keyID: proposal.biometricKey.keyID, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            replacement: proposal.replacement)
        XCTAssertThrowsError(try stage(f, other)) { XCTAssertEqual($0 as? PairingRecoveryStageError, .pendingForIdentity) }
        XCTAssertEqual(try stage(f, proposal).transcript.setupID, first.transcript.setupID)
        XCTAssertEqual(try f.continuity.read(), before)
    }

    func testVersionTwoStageLimitIsThirtyTwoPerAccount() throws {
        let f = try Fixture()
        let proposals = try (0...32).map { try proposal(f, phone: UInt8($0 + 10)).0 }
        let first = try stage(f, XCTUnwrap(proposals.first))
        f.environment.time.value += 1
        let pending = try proposals.dropFirst().dropLast().map { try stage(f, $0) }
        f.environment.time.value = try first.recoveryStage().deadline
        XCTAssertTrue(try f.access.isExpired(first))
        let before = try f.continuity.read()
        let connection = try endpoint(f)
        defer { connection.close() }
        XCTAssertNil(try stageBytes(connection, XCTUnwrap(proposals.last).encode()))
        XCTAssertEqual(try f.continuity.read(), before)
        XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 19)
        for attempt in pending { XCTAssertEqual(try retained(f, attempt)?.state, .pending) }
        let other = try Fixture(accountByte: 6)
        let own = try proposal(other).0
        XCTAssertEqual(try retained(other, stage(other, own))?.state, .pending)
        try close(f)
        let reopened = try open(f)
        defer { try? reopened.close() }
        XCTAssertEqual(try reopened.continuity.read(), before)
        XCTAssertEqual(try reopened.journal.read { try $0.recoveryStage(setupID: first.transcript.setupID)?.state }, .deadlineElapsed)
        for attempt in pending {
            XCTAssertEqual(try reopened.journal.read { try $0.recoveryStage(setupID: attempt.transcript.setupID)?.state }, .pending)
        }
    }

    func testExpiryUsesOnlyTheRootClockUnderTheCurrentWriterLease() throws {
        let f = try Fixture(), (proposal, _) = try proposal(f), attempt = try stage(f, proposal)
        let deadline = try XCTUnwrap(retained(f, attempt)).deadline
        f.environment.time.value = deadline - 1
        let before = try f.continuity.read()
        XCTAssertFalse(try f.access.isExpired(attempt))
        XCTAssertEqual(try f.continuity.read(), before)
        f.environment.time.value = deadline
        XCTAssertTrue(try f.access.isExpired(attempt))
        XCTAssertEqual(try retained(f, attempt)?.state.expiryReason, .deadlineElapsed)
        let expired = try f.continuity.read()
        f.environment.time.value += 1
        XCTAssertTrue(try f.access.isExpired(attempt))
        XCTAssertEqual(try f.continuity.read(), expired)
        try close(f)
        XCTAssertThrowsError(try f.access.isExpired(attempt))
    }

    func testOwnerMaintenanceExpiresDisconnectedStage() throws {
        let f = try Fixture(), candidate = try proposal(f).0
        let connection = try endpoint(f)
        let transcript = try PairingTranscript.decode(XCTUnwrap(stageBytes(connection, candidate.encode())))
        let setupID = transcript.setupID
        connection.close()
        let stage = try XCTUnwrap(f.journal.read { try $0.recoveryStage(setupID: setupID) })
        XCTAssertEqual(stage.state, .pending)
        f.environment.time.value = stage.deadline - 1
        let before = try f.continuity.read().committed
        let tick = DispatchSemaphore(value: 0), error = Box<(any Error)?>(nil)
        let maintenance = try AuthorityMaintenanceLoop(intervalMilliseconds: 100, work: {
            do {
                try f.journal.withRequests { owner in
                    _ = try owner.expirePending(now: f.environment.now(), receiptTimeMs: nil)
                }
                tick.signal()
            } catch let failure {
                error.value = failure
                tick.signal()
                throw failure
            }
        }, failed: {})
        defer { maintenance.close() }
        try maintenance.start()
        XCTAssertEqual(tick.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(try f.journal.read { try $0.recoveryStage(setupID: setupID)?.state }, .pending)
        XCTAssertEqual(try f.continuity.read().committed.authorityDigest, before.authorityDigest)
        f.environment.time.value = stage.deadline
        let timeout = DispatchTime.now() + 3
        while try f.journal.read({ try $0.recoveryStage(setupID: setupID)?.state }) == .pending {
            guard tick.wait(timeout: timeout) == .success, error.value == nil else {
                return XCTFail("Authority maintenance did not expire the disconnected stage")
            }
        }
        maintenance.close()
        XCTAssertNil(error.value)
        XCTAssertEqual(try f.journal.read { try $0.recoveryStage(setupID: setupID)?.state }, .deadlineElapsed)
        try f.assertCheckpoint()
        try close(f)
        let reopened = try open(f)
        defer { try? reopened.close() }
        XCTAssertEqual(try reopened.journal.read { try $0.recoveryStage(setupID: setupID)?.state }, .deadlineElapsed)
    }

    func testCommitAndExpirySerializeAndPreserveTheDurableCommit() throws {
        for expiryWins in [false, true] {
            let contenderBlocked = DispatchSemaphore(value: 0)
            let f = try Fixture(observePairingContention: { contenderBlocked.signal() })
            let (proposal, key) = try proposal(f), attempt = try stage(f, proposal)
            let deadline = try XCTUnwrap(retained(f, attempt)).deadline
            let entered = DispatchSemaphore(value: 0), proceed = DispatchSemaphore(value: 0)
            let completed = DispatchGroup()
            let commitResult = Box<Result<Data, any Error>?>(nil)
            let expiryResult = Box<Result<Bool, any Error>?>(nil)
            let serialize: @Sendable () throws -> Void = {
                entered.signal()
                guard proceed.wait(timeout: .now() + 5) == .success else { throw Fault.injected }
            }
            let commitWork: @Sendable () -> Void = {
                commitResult.value = Result {
                    try self.commit(f, attempt, key: key) { if !expiryWins { try serialize() } }
                }
            }
            let expiryWork: @Sendable () -> Void = {
                expiryResult.value = Result {
                    var sampledClock = false
                    return try f.journal.expireRePair(attempt) {
                        if expiryWins && !sampledClock { try serialize() }
                        sampledClock = true
                        return AuthorityMoment(epoch: f.environment.epoch, milliseconds: deadline)
                    }
                }
            }
            DispatchQueue.global().async(group: completed, execute: expiryWins ? expiryWork : commitWork)
            let holder = entered.wait(timeout: .now() + 5)
            DispatchQueue.global().async(group: completed) {
                if expiryWins { commitWork() } else { expiryWork() }
            }
            let waiting = contenderBlocked.wait(timeout: .now() + 5)
            let bothStillRunning = commitResult.value == nil && expiryResult.value == nil
            proceed.signal()
            XCTAssertEqual(completed.wait(timeout: .now() + 5), .success)
            XCTAssertEqual(holder, .success)
            XCTAssertEqual(waiting, .success)
            XCTAssertTrue(bothStillRunning)
            if expiryWins {
                XCTAssertTrue(try XCTUnwrap(expiryResult.value).get())
                XCTAssertThrowsError(try XCTUnwrap(commitResult.value).get())
                XCTAssertEqual(try retained(f, attempt)?.state, .deadlineElapsed)
            } else {
                XCTAssertThrowsError(try XCTUnwrap(expiryResult.value).get()) {
                    XCTAssertEqual($0 as? PairingRecoveryStageError, .noPendingStage)
                }
                let receipt = try XCTUnwrap(commitResult.value).get()
                XCTAssertTrue(try attempt.transcript.verify(signature: receipt, publicKey: f.authority.publicKey.x963Representation, purpose: .macCommit))
                XCTAssertNil(try retained(f, attempt))
                XCTAssertNotNil(try f.journal.read { try $0.committedPairing(setupID: attempt.transcript.setupID,
                    authenticatedPhoneID: attempt.transcript.phone.scope.phoneID,
                    authenticatedEnrollmentEpoch: attempt.transcript.phone.scope.enrollmentEpoch) })
            }
            try f.assertCheckpoint()
        }
        let f = try Fixture(), (proposal, key) = try proposal(f), attempt = try stage(f, proposal)
        try sql(f, "CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT, 'fixture'); END", continuity: true)
        XCTAssertThrowsError(try commit(f, attempt, key: key))
        XCTAssertNotNil(try f.continuity.read().pending)
        try close(f)
        try sql(f, "DROP TRIGGER fail_finalize", continuity: true)
        let restarted = try AuthorityJournal(storage: open(f))
        defer { try? restarted.close() }
        try restarted.prepareRequests(clockEpoch: UUID(), maximumPayloadBytes: 16_384)
        XCTAssertNil(try restarted.read { try $0.recoveryStage(setupID: attempt.transcript.setupID) })
        XCTAssertNotNil(try restarted.read { try $0.committedPairing(setupID: attempt.transcript.setupID,
            authenticatedPhoneID: attempt.transcript.phone.scope.phoneID,
            authenticatedEnrollmentEpoch: attempt.transcript.phone.scope.enrollmentEpoch) })
    }

    func testRevocationOrRemovalDuringStagePreventsEnrollment() throws {
        let f = try Fixture(), (proposal, key) = try proposal(f), attempt = try stage(f, proposal)
        let before = try f.continuity.read()
        let predecessor = try XCTUnwrap(proposal.replacement)
        let snapshot = try f.access.pairedPhones(includeRePair: true)
        let selection = try XCTUnwrap(snapshot.rePairSelection(for: .init(phoneID: predecessor.phoneID, enrollmentEpoch: predecessor.epoch)))
        XCTAssertThrowsError(try f.access.revokePhone(selection) { throw Fault.injected })
        XCTAssertEqual(try f.continuity.read(), before)
        XCTAssertEqual(try retained(f, attempt)?.state, .pending)
        let oldHead = try f.records()
        XCTAssertEqual(try f.access.revokePhone(selection, authorize: {}), .revokedOnMac)
        let events = try f.journal.read {
            try $0.page(epoch: f.writer.epoch, after: oldHead, maximumRecords: 2, maximumBytes: f.limits.maxBytes).canonicalRecords
        }
        let event = try AuditEventMetadata.decode(XCTUnwrap(events.first), limits: f.limits)
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(event.kind, .recovery)
        XCTAssertEqual(event.reason, .revoked)
        XCTAssertEqual(event.peerDeviceID, predecessor.phoneID)
        XCTAssertNil(try retained(f, attempt))
        XCTAssertThrowsError(try f.access.isExpired(attempt)) { XCTAssertEqual($0 as? PairingRecoveryStageError, .noPendingStage) }
        XCTAssertThrowsError(try commit(f, attempt, key: key))
        XCTAssertFalse(try f.journal.read { try $0.approvalEnrollments().contains { $0.approval.active } })
        try close(f)
        let storage = try open(f)
        defer { try? storage.close() }
        XCTAssertNil(try storage.journal.read { try $0.recoveryStage(setupID: attempt.transcript.setupID) })
    }

    func testGatewayRecoveryPagePreservesPendingRePairAndCheckpointsBothRevocations() throws {
        let f = try Fixture(configureGateway: true)
        let stage = try self.stage(f, proposal(f).0)
        let predecessor = try XCTUnwrap(stage.transcript.replacement)
        let other = try ordinary(f, phone: 12).phone.scope
        let registration = try XCTUnwrap(f.gatewayRevocations?.registration)
        func receipt(phone: Data, epoch: Data, revision: UInt64) throws -> GatewayControlReceipt {
            let binding = try GatewayPhoneEpochBinding(ownerID: registration.ownerID, macID: registration.macID,
                accountID: registration.accountID, gatewayID: registration.gatewayID, lifecycleEpoch: registration.lifecycleEpoch,
                phoneID: phone, enrollmentEpoch: epoch)
            let control = try GatewayPhoneRevocation(binding: binding, revision: revision,
                operationID: GatewayHostSnapshot.bytes(UUID()), issuedAtUnixMillis: 1_000, expiresAtUnixMillis: 2_000)
            let payload = try control.encode(limits: f.limits)
            let input = try GatewayRecipientSigningInput.make(wireVersion: 1, kind: .phoneRevocation,
                canonicalPayload: payload, payloadLimits: f.limits, inputLimits: f.limits)
            return .recipient(GatewayRecipientReceipt(control: .revocation(control), canonicalPayload: payload,
                signature: try f.authority.signature(for: input).rawRepresentation))
        }
        let page = GatewayControlHistoryPage(registration: registration, afterRevision: 0, throughRevision: 2, records: [
            try receipt(phone: predecessor.phoneID, epoch: predecessor.epoch, revision: 1),
            try receipt(phone: other.phoneID, epoch: other.enrollmentEpoch, revision: 2),
        ], hasMore: false)
        let evidence = VerifiedGatewayControlHistory(page: page, receivedAt: f.environment.now(), queryOwnerID: UUID())
        let head = try f.records()
        let revision = try f.journal.read { try $0.approvalTrustSnapshot().revision }
        let result = try writes(f) {
            try $0.recoverGatewayTrust(from: evidence, expectedTrustRevision: revision, receiptTimeMs: nil,
                writer: f.writer, expectedAuditHead: head)
        }
        XCTAssertEqual(result.changedPhoneIDs, [predecessor.phoneID, other.phoneID])
        XCTAssertEqual(result.auditHead, head + 2)
        XCTAssertEqual(try f.records(), result.auditHead)
        XCTAssertEqual(try f.continuity.read().committed.journalHead, result.auditHead)
        XCTAssertEqual(try retained(f, stage)?.state, .pending)
        XCTAssertFalse(try f.journal.read { try $0.approvalEnrollments().contains(where: \.approval.active) })
        let repeated = try writes(f) {
            try $0.recoverGatewayTrust(from: evidence, expectedTrustRevision: result.trustRevision,
                receiptTimeMs: nil, writer: f.writer, expectedAuditHead: result.auditHead)
        }
        XCTAssertEqual(repeated.auditHead, result.auditHead)
        XCTAssertTrue(repeated.changedPhoneIDs.isEmpty)
        XCTAssertEqual(try retained(f, stage)?.state, .pending)
        try f.assertCheckpoint()
    }

    func testThirtyTwoRevocationsReleaseRecoverySlots() throws {
        let f = try Fixture()
        let proposals = try (10...42).map { try proposal(f, phone: UInt8($0)).0 }
        let stages = try proposals.dropLast().map { try stage(f, $0) }
        let extra = try XCTUnwrap(proposals.last)
        XCTAssertThrowsError(try stage(f, extra)) { XCTAssertEqual($0 as? PairingRecoveryStageError, .capacity) }
        for attempt in stages {
            let predecessor = try XCTUnwrap(attempt.transcript.replacement)
            let selection = try XCTUnwrap(f.access.pairedPhones(includeRePair: true).rePairSelection(
                for: .init(phoneID: predecessor.phoneID, enrollmentEpoch: predecessor.epoch)))
            XCTAssertEqual(try f.access.revokePhone(selection, authorize: {}), .revokedOnMac)
            XCTAssertNil(try retained(f, attempt))
        }
        XCTAssertEqual(try retained(f, stage(f, extra))?.state, .pending)
        try f.assertCheckpoint()
    }

    func testBindingMismatchRemovesStageAndAuditsOnce() throws {
        let f = try Fixture(configureGateway: true)
        let (proposal, key) = try proposal(f)
        let attempt = try stage(f, proposal)
        let registration = try XCTUnwrap(f.gatewayRevocations?.registration)
        let phone = proposal.phone.scope.phoneID
        let binding = try GatewayTokenBinding(ownerID: registration.ownerID, macID: registration.macID,
            accountID: registration.accountID, gatewayID: registration.gatewayID, lifecycleEpoch: registration.lifecycleEpoch,
            phoneID: phone, enrollmentEpoch: Data(repeating: 97, count: 16), candidateID: Data(repeating: 98, count: 16),
            tokenDigest: Data(repeating: 95, count: 32), challenge: Data(repeating: 96, count: 32),
            enrollmentTag: Data(repeating: 97, count: 32))
        let candidate = try GatewayTokenCandidate(binding: binding, revision: 99, operationID: Data(repeating: 99, count: 16),
            issuedAtUnixMillis: 100, expiresAtUnixMillis: 200)
        let payload = try candidate.encode(limits: f.limits)
        let input = try GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: payload,
            payloadLimits: f.limits, inputLimits: f.limits)
        let signature = try f.authority.signature(for: input).rawRepresentation
        let revision = try f.journal.read { try $0.approvalTrustSnapshot().revision }
        let beforeRestriction = try f.records()
        let restriction = try writes(f) {
            try $0.restrictUnknownGatewayTrust(kind: .candidate, canonicalPayload: payload, signature: signature,
                registration: registration, expectedTrustRevision: revision, eventID: GatewayHostSnapshot.bytes(UUID()),
                receiptTimeMs: nil, writer: f.writer, expectedAuditHead: beforeRestriction)
        }
        XCTAssertEqual(restriction.disposition, .restricted)
        XCTAssertEqual(try retained(f, attempt)?.state, .pending)
        let head = try f.records()
        XCTAssertThrowsError(try commit(f, attempt, key: key)) { XCTAssertEqual($0 as? EnrollmentJournalError, .recoveryRequired) }
        XCTAssertNil(try retained(f, attempt))
        XCTAssertThrowsError(try commit(f, attempt, key: key)) { XCTAssertEqual($0 as? PairingRecoveryStageError, .noPendingStage) }
        let records = try f.journal.read {
            try $0.page(epoch: f.writer.epoch, after: head, maximumRecords: 2, maximumBytes: f.limits.maxBytes).canonicalRecords
        }
        XCTAssertEqual(records.count, 1)
        let event = try AuditEventMetadata.decode(XCTUnwrap(records.first), limits: f.limits)
        XCTAssertEqual(event.kind, .recovery)
        XCTAssertEqual(event.reason, .bindingMismatch)
        XCTAssertEqual(event.peerDeviceID, phone)
        XCTAssertFalse(try f.journal.read { try $0.approvalEnrollments().contains(where: \.approval.active) })
        try f.assertCheckpoint()
    }

    func testStageSlotsReleaseOnlyOnAuthorizedTransitions() throws {
        let f = try Fixture(), (proposal, key) = try proposal(f), first = try stage(f, proposal)
        let other = try stage(f, self.proposal(f, phone: 12).0)
        let digest = try first.transcript.digest()
        XCTAssertThrowsError(try f.access.discardExpiredRePair(setupID: first.transcript.setupID, digest: digest, authorize: {}))
        f.environment.time.value = try first.recoveryStage().deadline
        XCTAssertTrue(try f.access.isExpired(first))
        let before = try f.continuity.read()
        XCTAssertThrowsError(try f.access.stage(proposal.encode()) { throw Fault.injected })
        XCTAssertThrowsError(try f.access.discardExpiredRePair(setupID: first.transcript.setupID,
            digest: Data(repeating: 0, count: 32), authorize: {}))
        XCTAssertEqual(try f.continuity.read(), before)
        XCTAssertEqual(try retained(f, first)?.state, .deadlineElapsed)
        let next = try stage(f, proposal)
        XCTAssertNotEqual(next.transcript.setupID, first.transcript.setupID)
        XCTAssertNil(try retained(f, first))
        XCTAssertThrowsError(try f.access.discardExpiredRePair(setupID: first.transcript.setupID, digest: digest, authorize: {}))
        XCTAssertEqual(try retained(f, next)?.state, .pending)
        _ = try commit(f, next, key: key)
        XCTAssertNil(try retained(f, next))
        XCTAssertNotNil(try f.journal.read { try $0.committedPairing(setupID: next.transcript.setupID,
            authenticatedPhoneID: next.transcript.phone.scope.phoneID, authenticatedEnrollmentEpoch: next.transcript.phone.scope.enrollmentEpoch) })
        let predecessor = try XCTUnwrap(other.transcript.replacement)
        let revoked = try XCTUnwrap(f.access.pairedPhones(includeRePair: true).rePairSelection(
            for: .init(phoneID: predecessor.phoneID, enrollmentEpoch: predecessor.epoch)))
        XCTAssertEqual(try retained(f, other)?.state, .deadlineElapsed)
        let oldHead = try f.records()
        XCTAssertEqual(try f.access.revokePhone(revoked, authorize: {}), .revokedOnMac)
        XCTAssertNil(try retained(f, other))
        let records = try f.journal.read {
            try $0.page(epoch: f.writer.epoch, after: oldHead, maximumRecords: 2, maximumBytes: f.limits.maxBytes).canonicalRecords
        }
        let event = try AuditEventMetadata.decode(XCTUnwrap(records.first), limits: f.limits)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(event.kind, .cancelled)
        XCTAssertEqual(event.reason, .revoked)
        XCTAssertEqual(event.peerDeviceID, predecessor.phoneID)
        XCTAssertThrowsError(try f.access.discardExpiredRePair(setupID: other.transcript.setupID,
            digest: other.transcript.digest(), authorize: {}))
    }

    func testPairedPhonesDiscardRequiresAnExpiredTerminalStage() throws {
        let f = try Fixture(), (proposal, _) = try proposal(f), attempt = try stage(f, proposal)
        var selection = attempt.transcript.setupID
        selection.append(try attempt.transcript.digest())
        func discard() throws -> Data? {
            let connection = try endpoint(f), hello = Box<UInt64>(0), reply = Box<Data?>(nil)
            defer { connection.close() }
            connection.pairedPhoneHello { hello.value = $0 }
            XCTAssertEqual(hello.value, 1)
            connection.managePairedPhone(PairedPhoneOperation.discardExpiredRePair.rawValue, selection: selection,
                authorization: authorization) { reply.value = $0 }
            return reply.value
        }
        let before = try f.continuity.read()
        XCTAssertNil(try discard())
        XCTAssertEqual(try f.continuity.read(), before)
        XCTAssertEqual(try retained(f, attempt)?.state, .pending)
        f.environment.time.value = try attempt.recoveryStage().deadline
        XCTAssertTrue(try f.access.isExpired(attempt))
        let oldHead = try f.records()
        XCTAssertEqual(try discard(), Data([1]))
        XCTAssertNil(try retained(f, attempt))
        XCTAssertNil(try discard())
        let records = try f.journal.read {
            try $0.page(epoch: f.writer.epoch, after: oldHead, maximumRecords: 2, maximumBytes: f.limits.maxBytes).canonicalRecords
        }
        let event = try AuditEventMetadata.decode(XCTUnwrap(records.first), limits: f.limits)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(event.kind, .recovery)
        XCTAssertEqual(event.reason, .userCancelled)
        XCTAssertEqual(event.peerDeviceID, attempt.transcript.phone.scope.phoneID)
    }

    func testThirtyThreeFailedOrdinaryPairingsDoNotConsumeRecoverySlots() throws {
        let f = try Fixture(), before = try f.continuity.read()
        let bytes = try f.proposal().encode()
        for _ in 0..<33 {
            let connection = try endpoint(f)
            let staged = try PairingTranscript.decode(XCTUnwrap(stageBytes(connection, bytes)))
            let reply = Box<Data?>(nil)
            connection.commitPairing(staged.setupID, confirmedDigest: try staged.digest(),
                biometricProof: Data(repeating: 0, count: 64), authorization: authorization) { reply.value = $0 }
            XCTAssertNil(reply.value)
            connection.close()
        }
        XCTAssertEqual(try f.continuity.read(), before)
        _ = try ordinary(f)
        XCTAssertEqual(try f.records(), 1)
        XCTAssertEqual(try f.access.maintenanceAdmission.stagedReservations(), 0)
        XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 13)
    }

    private func syntheticStage(_ f: Fixture, phone: UInt8 = 80, incarnation: UUID? = nil) throws -> PairingRecoveryStage {
        let seed = try f.proposal(phone: phone, biometric: .init())
        let scope = seed.phone.scope
        let transcript = try PairingTranscript(setupID: GatewayHostSnapshot.bytes(UUID()), challenge: seed.challenge,
            phone: seed.phone, mac: seed.mac, minimumEnvelopeVersion: seed.minimumEnvelopeVersion,
            selectedEnvelopeVersion: seed.selectedEnvelopeVersion, macAuthorityKey: seed.macAuthorityKey,
            macTransportKey: seed.macTransportKey, transportKey: seed.transportKey, decisionKey: seed.decisionKey,
            biometricKey: seed.biometricKey, enrollmentTag: seed.enrollmentTag,
            replacement: .init(phoneID: scope.phoneID, epoch: Data(repeating: 1, count: 16)),
            expectedTrustRevision: seed.expectedTrustRevision, issuedAtUnixMillis: 1_000, expiresAtUnixMillis: 2_000)
        return try PairingRecoveryStage(transcript: transcript, proposalDigest: transcript.digest(),
            incarnation: incarnation ?? f.environment.epoch, started: 100, deadline: 1_100)
    }

    private func installHistory(_ f: Fixture) throws {
        let before = try f.continuity.read()
        let intent = try HistoryRecoveryIntent(previous: before, authorityDigest: before.committed.authorityDigest,
            ledgerDigest: before.committed.ledgerDigest, recoveryEpoch: Data(repeating: 97, count: 16))
        try writes(f) { try $0.recordHistoryRecovery(intent) }
    }

    private func eligibleGrant(_ f: Fixture) throws -> GatewayControlTombstone {
        let transcript = try ordinary(f, phone: 90), scope = transcript.phone.scope
        let registration = try XCTUnwrap(f.gatewayRevocations?.registration)
        let enrollment = try GatewayPhoneEnrollment(phoneID: scope.phoneID, epoch: scope.enrollmentEpoch,
            tag: transcript.enrollmentTag, active: true)
        let trust = GatewayAuthorityTrust(registration: registration, enrollment: enrollment, active: true)
        return try writes(f) { tx in
            let grant = try tx.prepareGatewayCandidate(registrationToken: "fixture-stage-grant",
                authenticatedPhoneID: scope.phoneID, authenticatedEnrollmentEpoch: scope.enrollmentEpoch, trust: trust,
                expectedHead: 0, nowUnixMillis: 1_000, now: f.environment.now(), sign: { candidate in
                    try f.authority.signature(for: GatewayTokenCandidateSigningInput.make(wireVersion: 1,
                        canonicalPayload: candidate.encode(limits: f.limits), payloadLimits: f.limits, inputLimits: f.limits)).rawRepresentation
                })
            guard case .eligible(let control) = try tx.gatewayGrantRetirement(at: grant.revision,
                registration: registration, wall: 2_001) else { throw Fault.injected }
            return control
        }
    }

    private func abandon(_ control: GatewayControlTombstone, _ f: Fixture) throws -> Data {
        try writes(f) { tx in
            try tx.stageGatewayGrantAbandonment(control, wall: 2_001)
            return try tx.finishGatewayGrantAbandonment(control, wall: 2_001) { input in
                try f.authority.signature(for: input).rawRepresentation
            }
        }
    }

    func testMigrationPreservesTheCatalogAndContinuityAtEachLegacyTier() throws {
        let template = try Fixture(), raw = try CutoverJournalFixture()
        let synthetic = try syntheticStage(template)
        let legacy = try raw.store.read().committed
        try CheckpointedJournal(journal: raw.journal, continuity: raw.store).write(epoch: raw.epoch) {
            try $0.reserveRecoveryStage(synthetic, now: .init(epoch: synthetic.incarnation, milliseconds: synthetic.started))
        }
        XCTAssertEqual(try raw.journal.read { try $0.featureTier }, 12)
        XCTAssertEqual(try raw.store.read().committed.ledgerDigest, legacy.ledgerDigest)

        for tier in 13...18 {
            let f = try Fixture(configureGateway: tier == 16 || tier == 18)
            if tier == 14 { try installHistory(f) }
            if tier >= 15 { try writes(f) { try $0.installCommandSubmissionReplay() } }
            if tier == 16 {
                let registration = try XCTUnwrap(f.gatewayRevocations?.registration)
                try writes(f) { try $0.installGatewaySubmissionHistory(registration) }
            }
            if tier >= 17 { try writes(f) { try $0.installUpdateSchedulingStorage() } }
            let control = tier == 18 ? try eligibleGrant(f) : nil
            let signature = try control.map { try abandon($0, f) }
            let candidate = try proposal(f).0
            let before = try f.continuity.read().committed
            XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, UInt64(tier))
            let attempt = try stage(f, candidate)
            XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 19)
            XCTAssertEqual(try f.journal.read { try $0.featureTier }, UInt64(tier))
            XCTAssertEqual(try retained(f, attempt)?.state, .pending)
            XCTAssertEqual(try f.continuity.read().committed.ledgerDigest, before.ledgerDigest)
            XCTAssertNotEqual(try f.continuity.read().committed.authorityDigest, before.authorityDigest)
            if let control { XCTAssertEqual(try f.journal.read { try $0.signedGatewayGrantAbandonment(control) }, signature) }
        }
    }

    func testSchemaNineteenInstallersPromoteTheTierWithoutChangingTheFormat() throws {
        let f = try Fixture(configureGateway: true), candidate = try proposal(f).0
        let attempt = try stage(f, candidate), before = try f.continuity.read()
        XCTAssertThrowsError(try writes(f) { tx in
            try tx.installCommandSubmissionReplay()
            throw Fault.injected
        })
        XCTAssertEqual(try f.continuity.read(), before)
        XCTAssertEqual(try f.journal.read { try $0.featureTier }, 13)
        try installHistory(f)
        XCTAssertEqual(try f.journal.read { try $0.featureTier }, 14)
        try writes(f) { try $0.installCommandSubmissionReplay() }
        XCTAssertEqual(try f.journal.read { try $0.featureTier }, 15)
        let registration = try XCTUnwrap(f.gatewayRevocations?.registration)
        try writes(f) { try $0.installGatewaySubmissionHistory(registration) }
        XCTAssertEqual(try f.journal.read { try $0.featureTier }, 16)
        try writes(f) { try $0.installUpdateSchedulingStorage() }
        XCTAssertEqual(try f.journal.read { try $0.featureTier }, 17)
        _ = try abandon(eligibleGrant(f), f)
        XCTAssertEqual(try f.journal.read { try $0.featureTier }, 18)
        XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 19)
        XCTAssertEqual(try retained(f, attempt)?.state, .pending)
        try f.assertCheckpoint()
    }

    func testTierSeventeenAbandonmentPromotesToEighteenAndSurvivesReopen() throws {
        let f = try Fixture(configureGateway: true), proposal = try proposal(f).0
        try writes(f) { tx in try tx.installCommandSubmissionReplay(); try tx.installUpdateSchedulingStorage() }
        let control = try eligibleGrant(f)
        _ = try stage(f, proposal)
        XCTAssertEqual(try f.journal.read { try $0.featureTier }, 17)
        let signature = try abandon(control, f)
        XCTAssertEqual(try f.journal.read { try $0.featureTier }, 18)
        XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 19)
        try close(f)
        let reopened = try JournalDatabase(lease: .init(anchor: f.root.path, relativeDirectory: "store", owner: getuid()),
            macID: f.mac, accountID: f.account, recordLimits: f.limits, descriptorLimits: f.limits, decisionLimits: f.limits,
            maximumConsumptions: 20, busyMilliseconds: 100, initialize: false, gatewayPolicy: GatewayAuthorityPolicy(
                payloadLimits: f.limits, signingLimits: f.limits, maximumControls: 32, candidateLifetimeMillis: 1000,
                clockEpoch: f.environment.epoch))
        defer { try? reopened.close() }
        XCTAssertEqual(try reopened.read { try $0.signedGatewayGrantAbandonment(control) }, signature)
        XCTAssertEqual(try reopened.read { try $0.gatewayGrantRetirement(at: control.revision, registration: control.registration,
                                                                         wall: 2_001) }, .eligible(control))
        XCTAssertEqual(try reopened.read { try $0.firstUnconfirmedGrantAbandonment() }, 2_001)
    }

    func testStageAndCheckpointPreparationFailuresKeepTheExactOldBoundary() throws {
        let f = try Fixture(), candidate = try proposal(f).0
        let before = try f.continuity.read()
        let specimen = try syntheticStage(f)
        let bad = try PairingRecoveryStage(transcript: specimen.transcript, proposalDigest: specimen.proposalDigest,
            incarnation: specimen.incarnation, started: specimen.started, deadline: specimen.deadline, state: .deadlineElapsed)
        XCTAssertThrowsError(try writes(f) { try $0.reserveRecoveryStage(bad, now: f.environment.now()) })
        XCTAssertEqual(try f.continuity.read(), before)
        XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 13)
        try sql(f, "CREATE TRIGGER fail_prepare BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NOT NULL BEGIN SELECT RAISE(ABORT, 'fixture'); END", continuity: true)
        let connection = try endpoint(f)
        defer { connection.close() }
        XCTAssertNil(try stageBytes(connection, candidate.encode()))
        XCTAssertEqual(try f.continuity.read(), before)
        try close(f)
        try sql(f, "DROP TRIGGER fail_prepare", continuity: true)
        let storage = try open(f)
        defer { try? storage.close() }
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: storage.journal, continuity: storage.continuity), .unchanged(before.committed))
        XCTAssertEqual(try storage.journal.read { try $0.storageSchemaVersion }, 13)
    }

    func testStartupDiscardsNewCheckpointAfterJournalRollback() throws {
        let f = try Fixture(), stage = try syntheticStage(f), before = try f.continuity.read()
        XCTAssertThrowsError(try writes(f) { tx in
            try tx.reserveRecoveryStage(stage, now: f.environment.now())
            do { try tx.discardExpiredRecoveryStage(setupID: stage.transcript.setupID, digest: stage.transcriptDigest) }
            catch PairingRecoveryStageError.notExpired { /* Keep the poisoned transaction to exercise recovery. */ }
        })
        XCTAssertNotNil(try f.continuity.read().pending)
        try close(f)
        let storage = try open(f)
        defer { try? storage.close() }
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: storage.journal, continuity: storage.continuity), .discarded(before.committed))
        XCTAssertEqual(try storage.continuity.read(), before)
        XCTAssertEqual(try storage.journal.read { try $0.storageSchemaVersion }, 13)
        XCTAssertNil(try storage.journal.read { try $0.recoveryStage(setupID: stage.transcript.setupID) })
    }

    func testStartupFinalizesTheMigratedCheckpointWithoutRestaging() throws {
        let f = try Fixture(), candidate = try proposal(f).0
        try sql(f, "CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT, 'fixture'); END", continuity: true)
        let connection = try endpoint(f)
        defer { connection.close() }
        XCTAssertNil(try stageBytes(connection, candidate.encode()))
        let prepared = try XCTUnwrap(f.continuity.read().pending)
        try close(f)
        try sql(f, "DROP TRIGGER fail_finalize", continuity: true)
        let storage = try open(f)
        defer { try? storage.close() }
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: storage.journal, continuity: storage.continuity), .finalized(prepared))
        let pending = try XCTUnwrap(storage.journal.read { try $0.pendingRecoveryStage(phoneID: candidate.phone.scope.phoneID) })
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: storage.journal, continuity: storage.continuity), .unchanged(prepared))
        XCTAssertEqual(try storage.journal.read { try $0.pendingRecoveryStage(phoneID: candidate.phone.scope.phoneID)?.transcript.setupID },
                       pending.transcript.setupID)
    }

    func testStartupClosesOnlyPendingStagesFromRetiredIncarnations() throws {
        let f = try Fixture(), (proposal, key) = try proposal(f)
        let committed = try stage(f, proposal)
        _ = try commit(f, committed, key: key)
        let retired = try stage(f, self.proposal(f, phone: 12).0)
        let fresh = UUID(), current = try syntheticStage(f, incarnation: fresh)
        try writes(f) { try $0.reserveRecoveryStage(current, now: f.environment.now()) }
        try close(f)
        for _ in 0..<2 {
            let restarted = try AuthorityJournal(storage: open(f))
            defer { try? restarted.close() }
            try restarted.prepareRequests(clockEpoch: fresh, maximumPayloadBytes: 16_384)
            XCTAssertEqual(try restarted.read { try $0.recoveryStage(setupID: retired.transcript.setupID)?.state.expiryReason }, .retiredIncarnation)
            XCTAssertNil(try restarted.read { try $0.recoveryStage(setupID: committed.transcript.setupID) })
            XCTAssertNotNil(try restarted.read { try $0.committedPairing(setupID: committed.transcript.setupID,
                authenticatedPhoneID: committed.transcript.phone.scope.phoneID,
                authenticatedEnrollmentEpoch: committed.transcript.phone.scope.enrollmentEpoch) })
            XCTAssertEqual(try restarted.read { try $0.recoveryStage(setupID: current.transcript.setupID)?.state }, .pending)
            try restarted.close()
        }
    }

    func testSchemaNineteenRejectsInvalidTierAndCatalogWithoutOpeningAdmission() throws {
        for mutation in [
            "DELETE FROM authority_feature_tier_v1",
            "PRAGMA ignore_check_constraints=ON; UPDATE authority_feature_tier_v1 SET tier=99",
            "DROP TABLE pairing_recovery_stages_v1",
            "DROP INDEX pairing_recovery_phone_v1",
            "DROP INDEX pairing_recovery_phone_v1; CREATE INDEX pairing_recovery_phone_v1 ON pairing_recovery_stages_v1(phone)",
            "CREATE TABLE extra_fixture_table(value INTEGER)",
            "UPDATE authority_feature_tier_v1 SET tier=15",
            "DELETE FROM pairing_recovery_stages_v1",
        ] {
            let f = try Fixture(), p = try proposal(f).0
            _ = try stage(f, p)
            try close(f)
            try sql(f, mutation)
            let before = try files(f)
            XCTAssertThrowsError(try AuthorityJournal(storage: open(f)), mutation)
            XCTAssertEqual(try files(f), before, mutation)
        }
    }

    func testOfflineFormatTierAndStageTamperingKeepsAdmissionClosed() throws {
        let mutations = [
            "UPDATE authority_feature_tier_v1 SET tier=17",
            "UPDATE authority_feature_tier_v1 SET tier=17; DROP TABLE gateway_abandoned_grants_v1",
            "UPDATE pairing_recovery_stages_v1 SET proposal=zeroblob(32) WHERE state=0",
            "UPDATE pairing_recovery_stages_v1 SET proposal=zeroblob(32) WHERE state=2",
            "PRAGMA user_version=18",
        ]
        for mutation in mutations {
            let f = try Fixture(configureGateway: true)
            let p = try proposal(f).0
            let expired = try stage(f, p)
            f.environment.time.value = try expired.recoveryStage().deadline
            XCTAssertTrue(try f.access.isExpired(expired))
            _ = try stage(f, proposal(f, phone: 12).0)
            _ = try abandon(eligibleGrant(f), f)
            XCTAssertEqual(try f.journal.read { try $0.featureTier }, 18)
            try close(f)
            try sql(f, mutation)
            let before = try files(f)
            XCTAssertThrowsError(try AuthorityJournal(storage: open(f)), mutation)
            XCTAssertEqual(try files(f), before, mutation)
        }
    }

    func testCutoverChecksPhysicalFormatTierAndCheckpoint() throws {
        for mutation in [
            "PRAGMA user_version=13",
            "UPDATE authority_feature_tier_v1 SET tier=14",
            "DELETE FROM pairing_recovery_stages_v1",
        ] {
            let f = try Fixture(), p = try proposal(f).0
            _ = try stage(f, p)
            let checkpoint = try f.continuity.read().committed
            let policy = try XCTUnwrap(f.journal.read { try $0.codePolicy()?.policy })
            try close(f)
            let inspection = try AuthorityJournalCutoverInspection(storage: open(f, readOnly: true),
                expectedPolicy: policy, verifyCurrent: {})
            defer { try? inspection.close() }
            XCTAssertEqual(inspection.snapshot.schemaVersion, 19)
            XCTAssertEqual(inspection.snapshot.featureTier, 13)
            XCTAssertEqual(inspection.snapshot.checkpoint, checkpoint)
            try inspection.validate()
            try sql(f, mutation)
            let before = try files(f)
            XCTAssertThrowsError(try inspection.validate(), mutation)
            XCTAssertEqual(try files(f), before)
        }
    }

    func testAuditChainSpansTheAuthorityFormatTransition() throws {
        let f = try Fixture(), candidate = try proposal(f).0
        let nextProposal = try f.proposal(phone: 80, epoch: 80, keyNamespace: 80).encode()
        let epoch = f.writer.epoch, previousHead = try f.records()
        let previous = try XCTUnwrap(f.journal.read { try $0.page(epoch: epoch, after: previousHead - 1,
            maximumRecords: 1, maximumBytes: 16_384).canonicalRecords.last })
        _ = try stage(f, candidate)
        XCTAssertEqual(try f.records(), previousHead)
        try close(f)
        let clock = UUID(), restarted = try AuthorityJournal(storage: open(f))
        defer { try? restarted.close() }
        try restarted.prepareRequests(clockEpoch: clock, maximumPayloadBytes: 16_384)
        let now: @Sendable () -> AuthorityMoment = { .init(epoch: clock, milliseconds: 100) }
        let access = try AuthorityPairingSetupAccess(journal: restarted, macID: f.mac, accountID: f.account,
            authorityPublicKey: f.authority.publicKey.x963Representation, appPolicy: f.policy,
            configuration: .init(transportPublicKey: f.transport.publicKey.x963Representation, lifetimeMilliseconds: 1_000),
            minimumEnvelopeVersion: 1, auditVersions: [1], now: now, unixMilliseconds: { 2_000 }, validateSelf: { _ in },
            commit: { attempt, proof, event, authorize, validate in
                try restarted.commitPairingFixture(attempt, biometricProof: proof, authorityPublicKey: f.authority.publicKey.x963Representation,
                    addEventID: event, recheckAdministrator: authorize, now: now, validate: validate,
                    sign: { try f.authority.signature(for: $0).rawRepresentation })
            })
        let attempt = try access.stage(nextProposal), transcript = attempt.transcript
        _ = try access.commit(attempt, setupID: transcript.setupID, confirmedDigest: transcript.digest(),
            proof: f.biometric.signature(for: transcript.signingInput(purpose: .phoneBiometric)).rawRepresentation, authorize: {})
        try restarted.close()
        let storage = try open(f)
        defer { try? storage.close() }
        let checkpointState = try storage.continuity.read().committed
        let descriptor = try XCTUnwrap(storage.journal.read { try $0.epoch(checkpointState.journalEpoch)?.descriptor })
        XCTAssertEqual(descriptor.previousEpoch, epoch)
        XCTAssertEqual(descriptor.previousSequence, previousHead)
        XCTAssertEqual(descriptor.previousEventDigest, Data(SHA256.hash(data: previous)))
        XCTAssertEqual(checkpointState.journalHead, 1)
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: storage.journal, continuity: storage.continuity), .unchanged(checkpointState))
        let retained = try storage.journal.read { try $0.page(epoch: epoch, after: previousHead - 1,
            maximumRecords: 1, maximumBytes: 16_384).canonicalRecords.last }
        XCTAssertEqual(retained, previous)
    }
}
