import CryptoKit
import Darwin
import Foundation
import Network
import RemozioProtocol
import Security
import SQLite3
import Synchronization
import XCTest
@testable import RemozioCore

@objc private protocol LegacyPhoneManagementAppXPCProtocol:
    AuthorityPresenceXPCProtocol, AuthorityPairingXPCProtocol, AuthorityPairedPhoneXPCProtocol {}

extension AuthorityAppXPCEndpoint: LegacyPhoneManagementAppXPCProtocol {}

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
             accountByte: UInt8 = 2, configureTransport: Bool = false, observePairingContention: @escaping @Sendable () -> Void = {}) throws {
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
            let entries = configureTransport ? [app, try Self.transportEntry()] : [app]
            _ = try db.write { try $0.installCodePolicy(.init(entries: entries), expectedRevision: nil) }
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
        static func transportEntry(active: Bool = true) throws -> AuthorityCodeEntry {
            try .init(role: .transport, teamID: "ABCDEFGHIJ", identifier: "dev.sebastiano.remozio.macos.transport",
                installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 5, count: 20), active: active)
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
        let discardSends = Box(0)
        let hold = Box(Hold.none)
        let late = Box<(@Sendable () -> Void)?>(nil)
        private let transform: @Sendable (PairingClientCall, PairingClientReply) throws -> PairingClientReply
        init(_ fixture: Fixture, transform: @escaping @Sendable (PairingClientCall, PairingClientReply) throws -> PairingClientReply = { _, value in value }) throws {
            endpoint = try fixture.endpoint(); self.transform = transform
        }
        func start(closed: @escaping @Sendable () -> Void) {}
        func invoke(_ call: PairingClientCall, onSend: () -> Void, reply: @escaping @Sendable (PairingClientReply) -> Void) {
            onSend()
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
            case .versionedPhoneManagementHello(let maximumVersion):
                endpoint.pairedPhoneHello(maximumVersion: maximumVersion) { complete(.version($0)) }
            case .managePhone(let operation, let selection, let authorization):
                if operation == .revoke { revocationSends.value += 1 }
                if operation == .discardExpiredRePair { discardSends.value += 1 }
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
        private let servesLegacyPhoneManagement: Bool
        private let acceptsConnections: Bool
        private var connections: [(NSXPCConnection, AuthorityAppXPCEndpoint)] = []
        private var closed = false
        init(_ fixture: Fixture, requirement: String, servesLegacyPhoneManagement: Bool = false, acceptsConnections: Bool = true) {
            self.fixture = fixture; self.requirement = requirement
            self.servesLegacyPhoneManagement = servesLegacyPhoneManagement
            self.acceptsConnections = acceptsConnections
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
                guard acceptsConnections, !closed, listener === self.listener, connections.count < 4 else { return false }
                do {
                    let f = fixture, environment = f.environment
                    let credentials = try f.policy.verifyCredentials(connection)
                    guard credentials.processID == getpid() else { throw Failure.denied }
                    let invocation = XPCInvocationGuard(connection: connection, policy: f.policy)
                    let verify = {
                        guard !environment.peerDenied.value, try invocation.verifyInvocation() == credentials else { throw Failure.denied }
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
                    connection.exportedInterface = servesLegacyPhoneManagement
                        ? NSXPCInterface(with: LegacyPhoneManagementAppXPCProtocol.self)
                        : NSXPCInterface(with: AuthorityAppXPCProtocol.self)
                    connection.exportedObject = endpoint
                    connection.invalidationHandler = { [weak endpoint] in endpoint?.pairing.close(); endpoint?.presence.close() }
                    connection.interruptionHandler = { [weak endpoint] in endpoint?.pairing.close(); endpoint?.presence.close() }
                    connections.append((connection, endpoint)); connection.activate(); return true
                } catch { connection.invalidate(); return false }
            }
        }
    }
    private final class PhoneManagementTrace: Sendable {
        let opens = Box(0), legacyHellos = Box(0), versionedHellos = Box(0), expiredLists = Box(0)
        let legacyReply = Box<UInt64>(0), versionedReply = Box<UInt64>(0)
    }

    /// Wire-only driver: expected peer UID and hash identify this test process, not a deployed Root service.
    private final class NativeDriver: PairingClientDriver, @unchecked Sendable {
        private let connection: NSXPCConnection
        private let policy: XPCPeerPolicy
        private let trace: PhoneManagementTrace?
        private let onVersionedHello: @Sendable () -> Void
        init(endpoint: NSXPCListenerEndpoint, policy: XPCPeerPolicy, requirement: String,
             trace: PhoneManagementTrace? = nil, onVersionedHello: @escaping @Sendable () -> Void = {}) {
            self.policy = policy; self.trace = trace; self.onVersionedHello = onVersionedHello
            connection = NSXPCConnection(listenerEndpoint: endpoint)
            connection.remoteObjectInterface = NSXPCInterface(with: AuthorityAppXPCProtocol.self)
            connection.setCodeSigningRequirement(requirement)
        }
        func start(closed: @escaping @Sendable () -> Void) {
            connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
        }
        func invoke(_ call: PairingClientCall, onSend: () -> Void, reply: @escaping @Sendable (PairingClientReply) -> Void) {
            let complete: @Sendable (PairingClientReply) -> Void = { [self] value in
                do { guard try policy.verifyCredentials(connection).processID == getpid() else { throw Failure.denied }; reply(value) }
                catch { reply(.failed) }
            }
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in complete(.failed) }) as? any AuthorityAppXPCProtocol else {
                complete(.failed); return
            }
            onSend()
            switch call {
            case .hello: proxy.pairingHello { complete(.version($0)) }
            case .context: proxy.pairingContext { complete(.bytes($0)) }
            case .stage(let proposal, let authorization): proxy.stagePairing(proposal, authorization: authorization) { complete(.bytes($0)) }
            case .commit(let setup, let digest, let proof, let authorization):
                proxy.commitPairing(setup, confirmedDigest: digest, biometricProof: proof, authorization: authorization) { complete(.bytes($0)) }
            case .cancel: proxy.cancelPairing { complete(.cancelled($0)) }
            case .phoneManagementHello:
                if let trace { trace.legacyHellos.value += 1 }
                proxy.pairedPhoneHello { [trace] version in
                    trace?.legacyReply.value = version
                    complete(.version(version))
                }
            case .versionedPhoneManagementHello(let maximumVersion):
                if let trace { trace.versionedHellos.value += 1 }
                proxy.pairedPhoneHello(maximumVersion: maximumVersion) { [trace, onVersionedHello] version in
                    trace?.versionedReply.value = version
                    onVersionedHello()
                    complete(.version(version))
                }
            case .managePhone(let operation, let selection, let authorization):
                if operation == .listExpiredRePairs, let trace { trace.expiredLists.value += 1 }
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

    private actor DiscardAdministrator: MacPairingAdministrator {
        let failure: SetupAdministratorAuthorizationError?
        private(set) var closed = false

        init(failure: SetupAdministratorAuthorizationError? = nil) { self.failure = failure }

        func authorization() async throws -> Data {
            if let failure { throw failure }
            return Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)
        }

        func close() async { closed = true }
    }

    @MainActor
    private func nativeExpiredListControls(_ f: Fixture, server: NativeServer, requirement: String,
                                           trace: PhoneManagementTrace, onVersionedHello: @escaping @Sendable () -> Void = {})
        -> MacExpiredRePairControls {
        MacExpiredRePairControls(openChannel: {
            trace.opens.value += 1
            let driver = NativeDriver(endpoint: server.listener.endpoint, policy: f.policy, requirement: requirement,
                trace: trace, onVersionedHello: onVersionedHello)
            return AuthorityPairingChannel(driver: driver, macID: f.mac, accountID: f.account, timeoutMilliseconds: 3000)
        })
    }

    @MainActor
    func testNativeLegacyRootRequiresFreshHelloAndNoExpiredListRequest() async throws {
        let f = try Fixture(), requirement = try testRequirement(), trace = PhoneManagementTrace()
        let server = NativeServer(f, requirement: requirement, servesLegacyPhoneManagement: true)
        defer { server.close() }
        let controls = nativeExpiredListControls(f, server: server, requirement: requirement, trace: trace)
        await controls.refresh()
        XCTAssertEqual(controls.availability, .updateRequired)
        XCTAssertNil(controls.records)
        XCTAssertEqual(trace.opens.value, 2)
        XCTAssertEqual(trace.versionedHellos.value, 1)
        XCTAssertEqual(trace.legacyHellos.value, 1)
        XCTAssertEqual(trace.legacyReply.value, 1)
        XCTAssertEqual(trace.expiredLists.value, 0)
    }

    @MainActor
    func testNativeVersionTwoRootClosingDuringExpiredListReportsUnavailable() async throws {
        let f = try Fixture(), requirement = try testRequirement(), trace = PhoneManagementTrace()
        let server = NativeServer(f, requirement: requirement)
        defer { server.close() }
        let controls = nativeExpiredListControls(f, server: server, requirement: requirement, trace: trace,
            onVersionedHello: { f.environment.peerDenied.value = true })
        await controls.refresh()
        XCTAssertEqual(controls.availability, .unavailable)
        XCTAssertNil(controls.records)
        XCTAssertEqual(trace.opens.value, 1)
        XCTAssertEqual(trace.versionedReply.value, 2)
        XCTAssertEqual(trace.expiredLists.value, 1)
        XCTAssertEqual(trace.legacyHellos.value, 0)
    }

    @MainActor
    func testNativeUnreachableRootDoesNotRequireAnUpdate() async throws {
        let f = try Fixture(), requirement = try testRequirement(), trace = PhoneManagementTrace()
        let server = NativeServer(f, requirement: requirement, acceptsConnections: false)
        defer { server.close() }
        let controls = nativeExpiredListControls(f, server: server, requirement: requirement, trace: trace)
        await controls.refresh()
        XCTAssertEqual(controls.availability, .unavailable)
        XCTAssertNil(controls.records)
        XCTAssertEqual(trace.opens.value, 2)
        XCTAssertEqual(trace.legacyReply.value, 0)
        XCTAssertEqual(trace.expiredLists.value, 0)
    }

    func testNativeLegacyClientReceivesVersionOneFromCurrentRoot() async throws {
        let f = try Fixture(), requirement = try testRequirement(), server = NativeServer(f, requirement: requirement)
        defer { server.close() }
        let legacy = NSXPCConnection(listenerEndpoint: server.listener.endpoint)
        legacy.remoteObjectInterface = NSXPCInterface(with: LegacyPhoneManagementAppXPCProtocol.self)
        legacy.setCodeSigningRequirement(requirement)
        legacy.activate()
        defer { legacy.invalidate() }
        for pairing in [true, false] {
            let version: UInt64 = try await withCheckedThrowingContinuation { continuation in
                let delivery = WireHelloReply(continuation)
                DispatchQueue.global().asyncAfter(deadline: .now() + 3) { delivery.complete(.failure(Failure.denied)) }
                guard let proxy = legacy.remoteObjectProxyWithErrorHandler({ _ in delivery.complete(.failure(Failure.denied)) })
                    as? any LegacyPhoneManagementAppXPCProtocol else { delivery.complete(.failure(Failure.denied)); return }
                let reply: @Sendable (UInt64) -> Void = { delivery.complete(.success($0)) }
                if pairing { proxy.pairingHello(reply: reply) }
                else { proxy.pairedPhoneHello(reply: reply) }
            }
            XCTAssertEqual(version, 1)
        }
    }

    func testDiscardAuthorizationCancellationAndDenialSendNothing() async throws {
        let f = try Fixture()
        for failure: SetupAdministratorAuthorizationError in [.cancelled, .denied(-60005)] {
            let driver = try ClientDriver(f), administrator = DiscardAdministrator(failure: failure)
            let channel = AuthorityPairingChannel(driver: driver, macID: f.mac, accountID: f.account)
            defer { channel.abort() }
            _ = try await channel.start()
            do {
                try await channel.discardExpiredRePair(expiredRecord(f), administrator: administrator)
                XCTFail("Discard accepted without authorization")
            } catch {
                if failure == .cancelled {
                    XCTAssertEqual(error as? SetupAdministratorAuthorizationError, .cancelled)
                } else {
                    XCTAssertEqual(error as? ExpiredRePairDiscardError, .notSubmitted)
                }
            }
            XCTAssertEqual(driver.discardSends.value, 0)
            let closed = await administrator.closed
            XCTAssertTrue(closed)
        }
    }

    func testDiscardAfterDispatchReportsLossAndSendsOnlyOnce() async throws {
        let f = try Fixture(), administrator = DiscardAdministrator()
        let driver = try ClientDriver(f, transform: { call, reply in
            if case .managePhone(.discardExpiredRePair, _, _) = call { return .failed }
            return reply
        })
        let channel = AuthorityPairingChannel(driver: driver, macID: f.mac, accountID: f.account)
        defer { channel.abort() }
        _ = try await channel.start()
        do {
            try await channel.discardExpiredRePair(expiredRecord(f), administrator: administrator)
            XCTFail("A lost discard reply cannot confirm the result")
        } catch {
            XCTAssertEqual(error as? ExpiredRePairDiscardError, .replyUnconfirmed)
        }
        XCTAssertEqual(driver.discardSends.value, 1)
        let closed = await administrator.closed
        XCTAssertTrue(closed)
    }

    private func expiredRecord(_ f: Fixture) -> ExpiredRePairRecord {
        ExpiredRePairRecord(macID: f.mac, accountID: f.account, phoneID: Data(repeating: 9, count: 16),
            originalExpiryUnixMilliseconds: 2_000, reason: .deadlineElapsed,
            setupID: Data(repeating: 3, count: 16), transcriptDigest: Data(repeating: 4, count: 32))
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
        let versions: [(UInt64, UInt64)] = [(0, 0), (1, 1), (2, 2), (UInt64.max, 2)]
        for (maximum, expected) in versions {
            second.pairedPhoneHello(maximumVersion: maximum) { negotiated.value = $0 }
            XCTAssertEqual(negotiated.value, expected)
        }
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

    private func proposal(_ f: Fixture, phone: UInt8 = 8,
                          transportKey: P256.Signing.PublicKey = P256.Signing.PrivateKey().publicKey) throws -> (PairingPhoneProposal, P256.Signing.PrivateKey) {
        let original = try ordinary(f, phone: phone)
        let recipient = DeliveryRecipient(phoneID: original.phone.scope.phoneID, enrollmentEpoch: original.phone.scope.enrollmentEpoch)
        let selection = try XCTUnwrap(f.access.pairedPhones().selection(for: recipient))
        _ = try f.access.revokePhone(selection, authorize: {})
        return try replacement(f, selection: selection, transportKey: transportKey)
    }

    private func replacement(_ f: Fixture, selection: PairedPhoneSelection, epoch: UInt8 = 50,
                             transportKey: P256.Signing.PublicKey = P256.Signing.PrivateKey().publicKey) throws -> (PairingPhoneProposal, P256.Signing.PrivateKey) {
        let key = P256.Signing.PrivateKey()
        let scope = try ChannelScope(macID: f.mac, accountID: f.account, phoneID: selection.phone.phoneID,
                                    enrollmentEpoch: Data(repeating: epoch, count: 16))
        let phone = try ChannelOffer(role: .phone, scope: scope, nonce: Data(repeating: epoch, count: 32),
            envelopeVersions: [1], requests: [.init(kind: 0, wireVersion: 1, schemaVersion: 1, features: [])], auditVersions: [1])
        return (try PairingPhoneProposal(phone: phone,
            transportKey: .init(keyID: Data(repeating: 70, count: 16), publicKey: transportKey.x963Representation),
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

    private func lookupEndpoint(_ f: Fixture, journal: AuthorityJournal? = nil,
                                clock: (@Sendable () -> AuthorityMoment)? = nil) throws -> AuthorityXPCEndpoint {
        let journal = journal ?? f.journal
        let now: @Sendable () -> AuthorityMoment = clock ?? { f.environment.now() }
        let result = try AuthorityXPCEndpoint(macID: f.mac, accountID: f.account, budget: .init(maximum: 1),
            activityJournal: journal, verify: {
                if f.environment.peerDenied.value { throw Fault.injected }
            }, verifyHandshakePolicy: {
                if f.environment.selfDenied.value { throw Fault.injected }
            }, invalidate: {}, snapshot: { throw Fault.injected }, validate: { _ in false },
            pairingLookup: { query, input, proof in
                try journal.withRequests { owner in
                    try owner.recoverPairing(query, signingInput: input, proof: proof,
                        authorityPublicKey: f.authority.publicKey.x963Representation,
                        now: now, verifyHost: { _ in
                            if f.environment.selfDenied.value { throw Fault.injected }
                        }, sign: { try f.authority.signature(for: $0).rawRepresentation })
                }
            }, pairingLookupBudget: .init(maximum: 1))
        result.hello { XCTAssertEqual($0, 1) }
        result.pairingLookupVersion { version, capacity in
            XCTAssertEqual(version, 1)
            XCTAssertEqual(capacity, 1)
        }
        return result
    }

    private func lookupBytes(_ endpoint: AuthorityXPCEndpoint, _ request: Data) throws -> Data {
        let response = Box<Data?>(nil)
        endpoint.pairingLookup(request) { response.value = $0 }
        return try XCTUnwrap(response.value)
    }

    private func lookupQuery(_ transcript: PairingTranscript) throws -> PairingRecoveryQuery {
        try PairingRecoveryQuery(setupID: transcript.setupID, transcriptDigest: transcript.digest(), scope: transcript.phone.scope)
    }

    private func recover(_ f: Fixture, query: PairingRecoveryQuery, key: P256.Signing.PrivateKey,
                         signingQuery: PairingRecoveryQuery? = nil, wrongExporter: Bool = false,
                         wrongChallenge: Bool = false, endpoint existing: AuthorityXPCEndpoint? = nil) throws -> Data {
        let endpoint = try existing ?? lookupEndpoint(f)
        defer { endpoint.close() }
        let exporter = Data(repeating: 81, count: 32)
        let response = try lookupBytes(endpoint, PairingRecoveryIPC.encodeBegin(query, exporter: exporter,
            deadline: DispatchTime.now().uptimeNanoseconds + 5_000_000_000))
        guard case let .challenge(nonce) = try PairingRecoveryFrame.decode(response) else { throw Fault.injected }
        let input = try (signingQuery ?? query).signingInput(
            exporter: wrongExporter ? Data(repeating: 82, count: 32) : exporter,
            challenge: wrongChallenge ? Data(repeating: 83, count: 32) : nonce)
        let proof = try PairingRecoveryFrame.proof(key.signature(for: input).rawRepresentation).encode()
        let result = try lookupBytes(endpoint, proof)
        XCTAssertEqual(try lookupBytes(endpoint, proof), try PairingRecoveryFrame.refused.encode())
        return result
    }

    func testRecoveryReadsStayInconclusiveUntilTheOwnerRecordsExpiry() throws {
        let f = try Fixture(), transport = P256.Signing.PrivateKey()
        let (proposal, _) = try proposal(f, transportKey: transport.publicKey)
        let attempt = try stage(f, proposal), query = try lookupQuery(attempt.transcript)
        let deadline = try XCTUnwrap(retained(f, attempt)).deadline
        let pending = try files(f)
        let refusal = try PairingRecoveryFrame.refused.encode()
        for time in [deadline - 1, deadline] {
            f.environment.time.value = time
            XCTAssertEqual(try recover(f, query: query, key: transport), refusal)
            XCTAssertEqual(try files(f), pending)
        }
        XCTAssertTrue(try f.access.isExpired(attempt))
        let expired = try files(f)
        guard case let .expired(receipt) = try PairingRecoveryFrame.decode(recover(f, query: query, key: transport)) else {
            return XCTFail("Expected durable expiry proof")
        }
        XCTAssertEqual(receipt.reason, .deadlineElapsed)
        XCTAssertTrue(try receipt.verify(transcript: attempt.transcript))
        XCTAssertEqual(try files(f), expired)
    }

    func testRecoverySignsRetiredIncarnationAfterStartupReconciliation() throws {
        let f = try Fixture(), transport = P256.Signing.PrivateKey()
        let (proposal, _) = try proposal(f, transportKey: transport.publicKey)
        let attempt = try stage(f, proposal), query = try lookupQuery(attempt.transcript)
        try close(f)
        let restarted = try AuthorityJournal(storage: open(f))
        defer { try? restarted.close() }
        let epoch = UUID()
        try restarted.prepareRequests(clockEpoch: epoch, maximumPayloadBytes: 16_384)
        let stored = try restarted.read { try $0.recoveryStage(setupID: query.setupID) }
        XCTAssertEqual(stored?.state, .retiredIncarnation)
        let retired = try files(f)
        let endpoint = try lookupEndpoint(f, journal: restarted, clock: { .init(epoch: epoch, milliseconds: 1_000) })
        let response = try recover(f, query: query, key: transport, endpoint: endpoint)
        guard case let .expired(receipt) = try PairingRecoveryFrame.decode(response) else {
            return XCTFail("Expected retired-incarnation proof")
        }
        XCTAssertEqual(receipt.reason, .retiredIncarnation)
        XCTAssertTrue(try receipt.verify(transcript: attempt.transcript))
        XCTAssertEqual(try files(f), retired)
    }

    func testRecoveryRecoversTheCommittedProofAfterTheStageSlotIsReleased() throws {
        let f = try Fixture(), transport = P256.Signing.PrivateKey()
        let (proposal, biometric) = try proposal(f, transportKey: transport.publicKey)
        let attempt = try stage(f, proposal), query = try lookupQuery(attempt.transcript)
        _ = try commit(f, attempt, key: biometric)
        XCTAssertNil(try retained(f, attempt))
        let committed = try files(f)
        for _ in 0..<2 {
            guard case let .committed(signature) = try PairingRecoveryFrame.decode(recover(f, query: query, key: transport)) else {
                return XCTFail("Expected committed pairing proof")
            }
            XCTAssertTrue(try attempt.transcript.verify(signature: signature, publicKey: f.authority.publicKey.x963Representation,
                purpose: .macCommit))
        }
        XCTAssertEqual(try files(f), committed)
        try close(f)
        let restarted = try AuthorityJournal(storage: open(f))
        defer { try? restarted.close() }
        let epoch = UUID()
        try restarted.prepareRequests(clockEpoch: epoch, maximumPayloadBytes: 16_384)
        let endpoint = try lookupEndpoint(f, journal: restarted, clock: { .init(epoch: epoch, milliseconds: 1_000) })
        let before = try files(f)
        let recovered = try recover(f, query: query, key: transport, endpoint: endpoint)
        guard case let .committed(signature) = try PairingRecoveryFrame.decode(recovered) else {
            return XCTFail("Restart could not recover the committed proof")
        }
        XCTAssertTrue(try attempt.transcript.verify(signature: signature, publicKey: f.authority.publicKey.x963Representation,
            purpose: .macCommit))
        XCTAssertNil(try restarted.read { try $0.recoveryStage(setupID: query.setupID) })
        XCTAssertEqual(try files(f), before)
    }

    func testRecoveryUsesOneRefusalForUnknownAndWrongBindings() throws {
        let f = try Fixture(), transport = P256.Signing.PrivateKey()
        let (proposal, _) = try proposal(f, transportKey: transport.publicKey)
        let attempt = try stage(f, proposal), query = try lookupQuery(attempt.transcript)
        f.environment.time.value = try XCTUnwrap(retained(f, attempt)).deadline
        XCTAssertTrue(try f.access.isExpired(attempt))
        let unknown = try PairingRecoveryQuery(setupID: Data(repeating: 91, count: 16),
            transcriptDigest: query.transcriptDigest, scope: query.scope)
        let wrongDigest = try PairingRecoveryQuery(setupID: query.setupID,
            transcriptDigest: Data(repeating: 92, count: 32), scope: query.scope)
        let replacementID = Data(repeating: 93, count: 16)
        let scope = query.scope
        let wrongScopes = [
            try ChannelScope(macID: replacementID, accountID: scope.accountID,
                phoneID: scope.phoneID, enrollmentEpoch: scope.enrollmentEpoch),
            try ChannelScope(macID: scope.macID, accountID: replacementID,
                phoneID: scope.phoneID, enrollmentEpoch: scope.enrollmentEpoch),
            try ChannelScope(macID: scope.macID, accountID: scope.accountID,
                phoneID: replacementID, enrollmentEpoch: scope.enrollmentEpoch),
            try ChannelScope(macID: scope.macID, accountID: scope.accountID,
                phoneID: scope.phoneID, enrollmentEpoch: replacementID),
        ]
        let refusal = try recover(f, query: unknown, key: transport)
        XCTAssertEqual(refusal, try PairingRecoveryFrame.refused.encode())
        XCTAssertEqual(try recover(f, query: wrongDigest, key: transport), refusal)
        for wrongScope in wrongScopes {
            let mismatch = try PairingRecoveryQuery(setupID: query.setupID, transcriptDigest: query.transcriptDigest, scope: wrongScope)
            XCTAssertEqual(try recover(f, query: mismatch, key: transport), refusal)
        }
        XCTAssertEqual(try recover(f, query: query, key: P256.Signing.PrivateKey()), refusal)
        XCTAssertEqual(try recover(f, query: query, key: transport, signingQuery: unknown), refusal)
        XCTAssertEqual(try recover(f, query: query, key: transport, wrongExporter: true), refusal)
        XCTAssertEqual(try recover(f, query: query, key: transport, wrongChallenge: true), refusal)
    }

    func testRecoveryRefusesRemovedSupersededAndRevokedAttempts() throws {
        let f = try Fixture(), transport = P256.Signing.PrivateKey()
        let original = try ordinary(f)
        let recipient = DeliveryRecipient(phoneID: original.phone.scope.phoneID, enrollmentEpoch: original.phone.scope.enrollmentEpoch)
        let selection = try XCTUnwrap(f.access.pairedPhones().selection(for: recipient))
        _ = try f.access.revokePhone(selection, authorize: {})
        let (first, _) = try replacement(f, selection: selection, transportKey: transport.publicKey)
        let discarded = try stage(f, first)
        f.environment.time.value = try XCTUnwrap(retained(f, discarded)).deadline
        XCTAssertTrue(try f.access.isExpired(discarded))
        let discardQuery = try lookupQuery(discarded.transcript)
        try f.access.discardExpiredRePair(setupID: discardQuery.setupID, digest: discardQuery.transcriptDigest, authorize: {})
        let refusal = try PairingRecoveryFrame.refused.encode()
        XCTAssertEqual(try recover(f, query: discardQuery, key: transport), refusal)

        let (second, _) = try replacement(f, selection: selection, epoch: 51, transportKey: transport.publicKey)
        let superseded = try stage(f, second)
        f.environment.time.value = try XCTUnwrap(retained(f, superseded)).deadline
        XCTAssertTrue(try f.access.isExpired(superseded))
        let (third, biometric) = try replacement(f, selection: selection, epoch: 52, transportKey: transport.publicKey)
        let committed = try stage(f, third)
        XCTAssertEqual(try recover(f, query: lookupQuery(superseded.transcript), key: transport), refusal)
        _ = try commit(f, committed, key: biometric)
        let committedQuery = try lookupQuery(committed.transcript)
        let active = DeliveryRecipient(phoneID: committedQuery.scope.phoneID, enrollmentEpoch: committedQuery.scope.enrollmentEpoch)
        let activeSelection = try XCTUnwrap(f.access.pairedPhones().selection(for: active))
        _ = try f.access.revokePhone(activeSelection, authorize: {})
        XCTAssertEqual(try recover(f, query: committedQuery, key: transport), refusal)
    }

    func testRecoveryOnAnOlderJournalUsesTheSameRefusalForMissingEvidence() throws {
        let f = try Fixture(), transport = P256.Signing.PrivateKey()
        let scope = try ChannelScope(macID: f.mac, accountID: f.account,
            phoneID: Data(repeating: 15, count: 16), enrollmentEpoch: Data(repeating: 16, count: 16))
        let query = try PairingRecoveryQuery(setupID: Data(repeating: 13, count: 16),
            transcriptDigest: Data(repeating: 14, count: 32), scope: scope)
        XCTAssertEqual(try f.journal.read { try $0.featureTier }, 13)
        let before = try files(f)
        XCTAssertEqual(try recover(f, query: query, key: transport), try PairingRecoveryFrame.refused.encode())
        XCTAssertEqual(try files(f), before)
    }

    func testRecoveryDropsValidProofWhenTheJournalCannotBeVerified() async throws {
        let f = try Fixture(configureTransport: true), transport = P256.Signing.PrivateKey()
        let (proposal, _) = try proposal(f, transportKey: transport.publicKey)
        let attempt = try stage(f, proposal), query = try lookupQuery(attempt.transcript)
        f.environment.time.value = try XCTUnwrap(retained(f, attempt)).deadline
        XCTAssertTrue(try f.access.isExpired(attempt))
        let root = try RecoveryRoot(f)
        defer { root.registry.close() }
        let link = try root.open(onClose: {})
        try await link.start()
        let exporter = Data(repeating: 81, count: 32)
        let challenge = try await link.beginPairingLookup(query, exporter: exporter,
            deadline: DispatchTime.now().uptimeNanoseconds + 5_000_000_000)
        let input = try query.signingInput(exporter: exporter, challenge: challenge)
        let proof = try transport.signature(for: input).rawRepresentation
        try sql(f, "DROP TABLE main.pairing_recovery_stages_v1")
        do {
            _ = try await link.finishPairingLookup(proof)
            XCTFail("Unverified storage returned a result")
        } catch {}
        await link.close()
    }

    func testRecoveryDropsTheSignedResultWhenItsReleaseLeaseBecomesInvalid() async throws {
        let f = try Fixture(configureTransport: true), transport = P256.Signing.PrivateKey()
        let (proposal, _) = try proposal(f, transportKey: transport.publicKey)
        let attempt = try stage(f, proposal), query = try lookupQuery(attempt.transcript)
        f.environment.time.value = try XCTUnwrap(retained(f, attempt)).deadline
        XCTAssertTrue(try f.access.isExpired(attempt))
        let activity = try ReleaseActivityFixture()
        try f.journal.attachReleaseActivityBarrier(activity.open())
        let lockPath = activity.directory.appendingPathComponent(ReleaseActivityBarrier.fileName).path
        let root = try RecoveryRoot(f, signing: { input in
            let signature = try f.authority.signature(for: input).rawRepresentation
            guard chmod(lockPath, 0o644) == 0 else { throw Fault.injected }
            return signature
        })
        defer { root.registry.close() }
        let link = try root.open(onClose: {})
        try await link.start()
        let exporter = Data(repeating: 81, count: 32)
        let challenge = try await link.beginPairingLookup(query, exporter: exporter,
            deadline: DispatchTime.now().uptimeNanoseconds + 5_000_000_000)
        let input = try query.signingInput(exporter: exporter, challenge: challenge)
        let proof = try transport.signature(for: input).rawRepresentation
        do {
            _ = try await link.finishPairingLookup(proof)
            XCTFail("Proof returned after lease loss")
        } catch {}
        XCTAssertNotEqual(try FileManager.default.attributesOfItem(atPath: lockPath)[.posixPermissions] as? Int, 0o600)
        await link.close()
    }

    func testRecoveryWithholdsProofAfterTheTransportCallerIsRetired() throws {
        let f = try Fixture(), transport = P256.Signing.PrivateKey()
        let (proposal, _) = try proposal(f, transportKey: transport.publicKey)
        let attempt = try stage(f, proposal), query = try lookupQuery(attempt.transcript)
        f.environment.time.value = try XCTUnwrap(retained(f, attempt)).deadline
        XCTAssertTrue(try f.access.isExpired(attempt))
        let exporter = Data(repeating: 81, count: 32)
        let endpoint = try lookupEndpoint(f)
        let request = try PairingRecoveryIPC.encodeBegin(query, exporter: exporter,
            deadline: DispatchTime.now().uptimeNanoseconds + 5_000_000_000)
        guard case let .challenge(nonce) = try PairingRecoveryFrame.decode(lookupBytes(endpoint, request)) else {
            return XCTFail("Expected a challenge")
        }
        let input = try query.signingInput(exporter: exporter, challenge: nonce)
        let proof = try PairingRecoveryFrame.proof(transport.signature(for: input).rawRepresentation).encode()
        f.environment.peerDenied.value = true
        endpoint.pairingLookup(proof) { XCTAssertNil($0) }
    }

    private func identity(_ key: P256.Signing.PrivateKey) throws -> SecIdentity {
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits as String: 256]
        let native = try XCTUnwrap(SecKeyCreateWithData(key.x963Representation as CFData, attributes as CFDictionary, nil))
        let now = Date()
        let leaf = try TransportTLSCertificate.issue(key: native, notValidBefore: now.addingTimeInterval(-60),
            notValidAfter: now.addingTimeInterval(600))
        let certificate = try XCTUnwrap(SecCertificateCreateWithData(nil, leaf as CFData))
        return try XCTUnwrap(SecIdentityCreate(nil, certificate, native))
    }

    private func waitForPort(_ value: Box<UInt16?>) async throws -> UInt16 {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while value.value == nil {
            guard ContinuousClock.now < deadline else { throw Fault.injected }
            try await Task.sleep(for: .milliseconds(5))
        }
        return try XCTUnwrap(value.value)
    }

    private func connectLookup(port: UInt16, purpose: String, serverKey: Data, identity: SecIdentity)
        throws -> (NetworkByteChannel, NWConnection) {
        let tls = NWProtocolTLS.Options(), options = tls.securityProtocolOptions
        sec_protocol_options_set_local_identity(options, try XCTUnwrap(sec_identity_create(identity)))
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_tls_resumption_enabled(options, false)
        sec_protocol_options_add_tls_application_protocol(options, purpose)
        sec_protocol_options_set_verify_block(options, { metadata, _, complete in
            complete(PairingSetupListener.candidatePoint(metadata: metadata) == serverKey)
        }, DispatchQueue(label: "dev.remozio.tests.recovery-tls"))
        let params = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        let connection = NWConnection(host: .ipv4(.loopback), port: try XCTUnwrap(NWEndpoint.Port(rawValue: port)), using: params)
        return (NetworkByteChannel(connection: connection) { _ in true }, connection)
    }

    private func sendNativeFrame(_ bytes: Data, to channel: NetworkByteChannel) async throws {
        let size = UInt32(bytes.count).bigEndian
        try await channel.send(withUnsafeBytes(of: size) { Data($0) } + bytes)
    }

    private func sendRecovery(_ frame: PairingRecoveryFrame, to channel: NetworkByteChannel) async throws {
        try await sendNativeFrame(frame.encode(), to: channel)
    }

    private func readNativeFrame(from channel: NetworkByteChannel, maximum: Int) async throws -> Data {
        var bytes = Data()
        while bytes.count < 4 {
            guard let chunk = try await channel.receive() else { throw Fault.injected }
            bytes.append(chunk)
        }
        let size = bytes.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
        guard (1...maximum).contains(size) else { throw Fault.injected }
        while bytes.count < size + 4 {
            guard let chunk = try await channel.receive() else { throw Fault.injected }
            bytes.append(chunk)
        }
        guard bytes.count == size + 4 else { throw Fault.injected }
        return Data(bytes.dropFirst(4))
    }

    private func readRecovery(from channel: NetworkByteChannel) async throws -> PairingRecoveryFrame {
        try await PairingRecoveryFrame.decode(readNativeFrame(from: channel, maximum: PairingRecoveryFrame.maximumBytes))
    }

    private func approvalOffer(scope: ChannelScope) throws -> ChannelOffer {
        try ChannelOffer(role: .phone, scope: scope, nonce: Data(repeating: 88, count: 32), envelopeVersions: [1],
            requests: [.init(kind: 0, wireVersion: 1, schemaVersion: 1, features: [])], auditVersions: [])
    }

    private func lookupNative(port: UInt16, fixture: Fixture, transcript: PairingTranscript,
                                     phone: P256.Signing.PrivateKey, phoneIdentity: SecIdentity) async throws -> PairingRecoveryFrame {
        let (channel, connection) = try connectLookup(port: port, purpose: PairingRecoveryFrame.applicationProtocol,
            serverKey: fixture.transport.publicKey.x963Representation, identity: phoneIdentity)
        defer { channel.abort() }
        try await channel.start(timeoutMilliseconds: 5_000)
        let metadata = try XCTUnwrap(PairingRecoveryTLS.metadata(connection))
        let exporter = try PairingRecoveryTLS.exporter(metadata)
        let query = try lookupQuery(transcript)
        try await sendRecovery(.lookup(query), to: channel)
        guard case let .challenge(challenge) = try await readRecovery(from: channel) else {
            throw Fault.injected
        }
        let proof = try phone.signature(for: query.signingInput(exporter: exporter, challenge: challenge)).rawRepresentation
        try await sendRecovery(.proof(proof), to: channel)
        let response = try await readRecovery(from: channel)
        let tail = try? await channel.receive()
        XCTAssertNil(tail)
        await channel.close()
        return response
    }

    private func checkNativeRecovery(port: UInt16, fixture: Fixture, transcript: PairingTranscript,
                                     phone: P256.Signing.PrivateKey, phoneIdentity: SecIdentity) async throws {
        let response = try await lookupNative(port: port, fixture: fixture, transcript: transcript,
            phone: phone, phoneIdentity: phoneIdentity)
        guard case let .expired(receipt) = response else { return XCTFail("Expected signed expiry") }
        XCTAssertEqual(receipt.reason, .deadlineElapsed)
        XCTAssertTrue(try receipt.verify(transcript: transcript))
    }

    /// The test client bridges raw TLS bytes into the production localhost WebSocket carrier.
    private final class ClientRelay: @unchecked Sendable {
        let webSocketConnections = Mutex(0)
        let port = Box<UInt16?>(nil)
        private let listener: NWListener
        private let operations = OwnedTaskHandoffRegistry()
        private let state = NSLock()
        private var closed = false
        private let target: NWEndpoint

        init(target: UInt16) throws {
            let url = try XCTUnwrap(URL(string: "ws://127.0.0.1:\(target)/approval"))
            self.target = .url(url)
            let parameters = NWParameters.tcp
            parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
            listener = try NWListener(using: parameters)
            listener.stateUpdateHandler = { [weak self] event in
                if case .ready = event { self?.port.value = self?.listener.port?.rawValue }
            }
            listener.newConnectionHandler = { [weak self] tcp in
                guard let self else { tcp.cancel(); return }
                self.accept(tcp)
            }
            listener.start(queue: DispatchQueue(label: "dev.remozio.tests.recovery-client-relay"))
        }

        private func accept(_ tcp: NWConnection) {
            state.withLock {
                guard !closed else { tcp.cancel(); return }
                let socketOptions = NWProtocolWebSocket.Options()
                socketOptions.skipHandshake = false
                socketOptions.setSubprotocols([ApprovalWebSocketRelay.subprotocol])
                let parameters = NWParameters.tcp
                parameters.defaultProtocolStack.applicationProtocols.insert(socketOptions, at: 0)
                let socket = NWConnection(to: target, using: parameters)
                let local = NetworkByteChannel(connection: tcp) { _ in true }
                let relay = NetworkByteChannel(driver: WebSocketByteConnection(socket))
                let work = operations.reserve()
                work.install(Task { [self] in
                    do {
                        try await local.start(timeoutMilliseconds: 5_000)
                        try await relay.start(timeoutMilliseconds: 5_000)
                        webSocketConnections.withLock { $0 += 1 }
                        try await ApprovalWebSocketRelay.forward(local, relay)
                    } catch { }
                    await local.close()
                    await relay.close()
                })
            }
        }

        func close() {
            state.withLock { closed = true }
            listener.cancel()
            operations.cancelAll()
        }

        func closeAndWait() async {
            close()
            await operations.waitAll()
        }
    }

    /// Uses the production endpoint, peer-policy lease, provider, and connection registry.
    /// The fixture driver carries Swift calls in-process so the suite can run as an ordinary user.
    private final class RecoveryRoot: Sendable {
        private final class Driver: AuthorityXPCDriver, OwnedAuthorityConnection, Sendable {
            let endpoint: AuthorityXPCEndpoint
            private let invalidation = Mutex<(@Sendable () -> Void)?>(nil)
            private let preserveReservation = Mutex(false)
            private let observeRouting: @Sendable (Driver) -> Void

            init(endpoint: AuthorityXPCEndpoint, observeRouting: @escaping @Sendable (Driver) -> Void) {
                self.endpoint = endpoint
                self.observeRouting = observeRouting
            }
            func activate() {}
            func start(invalidated: @escaping @Sendable () -> Void) {
                invalidation.withLock { $0 = invalidated }
            }
            func interruptKeepingReservation() {
                preserveReservation.withLock { $0 = true }
                let callback = invalidation.withLock { current in
                    let callback = current
                    current = nil
                    return callback
                }
                callback?()
            }
            func routingVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
                endpoint.phoneRoutingVersion { version in reply(.routingVersion(version)) }
                observeRouting(self)
            }
            func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
                endpoint.hello { reply(.hello($0)) }
            }
            func releasePreservedReservation() {
                preserveReservation.withLock { $0 = false }
                close()
            }
            func pairingLookupVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
                endpoint.pairingLookupVersion { reply(.pairingLookupVersion($0, $1)) }
            }
            func pairingLookup(_ request: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
                endpoint.pairingLookup(request) { reply($0.map(AuthorityXPCReply.pairingLookup) ?? .failed) }
            }
            func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
                endpoint.trustSnapshot { reply($0.map(AuthorityXPCReply.snapshot) ?? .failed) }
            }
            func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
                endpoint.validatePeer(binding) { reply(.validation($0)) }
            }
            func close() { if !preserveReservation.withLock({ $0 }) { endpoint.close() } }
        }

        let registry: AuthorityConnectionRegistry
        let connections = Mutex(0)
        let access: AuthorityTransportAccess
        private let journal: AuthorityJournal
        private let fixture: Fixture
        private let budget: AuthorityXPCWorkBudget
        private let handler: AuthorityPairingLookupHandler?
        private let pairingLookupBudget: AuthorityXPCWorkBudget?
        private let validity: @Sendable () throws -> Void
        private let routingSupported: Bool
        private let routing = Mutex<Driver?>(nil)

        init(_ f: Fixture, supported: Bool = true, routingSupported: Bool = false, maximumConnections: Int = 8,
             validity: @escaping @Sendable () throws -> Void = {},
             signing: (@Sendable (Data) throws -> Data)? = nil) throws {
            fixture = f; journal = f.journal; self.validity = validity; self.routingSupported = routingSupported
            registry = try .init(maximum: maximumConnections, timeoutMilliseconds: 5_000)
            budget = try .init(maximum: 8)
            let entry = try Fixture.transportEntry()
            let configuration = try AuthorityServiceConfiguration(macID: f.mac, accountID: f.account,
                journalDirectory: f.root.appendingPathComponent("store").path,
                serviceName: "dev.remozio.authority.test", teamID: entry.teamID,
                transportIdentifier: entry.identifier, transportHashes: [entry.codeDirectoryHash],
                transportUID: getuid(), maximumPayloadBytes: 16_384, maximumConnections: maximumConnections)
            access = try AuthorityTransportAccess(journal: journal, peerPolicy: configuration.transportPolicy,
                macID: f.mac, accountID: f.account, maximumPayloadBytes: configuration.maximumPayloadBytes,
                minimumEnvelopeVersion: 1, auditVersions: [])
            let sign: @Sendable (Data) throws -> Data = signing ?? { try f.authority.signature(for: $0).rawRepresentation }
            let providers = try AuthorityRequestProviders(configuration: configuration,
                publicKey: f.authority.publicKey.x963Representation, signing: sign,
                routing: { throw Fault.injected }, receiptValidation: { _ in try validity() })
            let quota = AuthorityTransportConnectionCapacity.recoveryQuota(maximumConnections)
            if supported, quota > 0 {
                pairingLookupBudget = try .init(maximum: quota)
                handler = access.pairingLookupHandler(providers.pairingLookupProvider(clock: f.environment.now))
            } else {
                pairingLookupBudget = nil
                handler = nil
            }
            try registry.start()
        }

        func open(onClose: @escaping @Sendable () -> Void) throws -> AuthorityXPCChannel {
            connections.withLock { $0 += 1 }
            let registry = registry, access = access, validity = validity
            guard let id = registry.reserve() else { throw AuthorityXPCEndpointError.unavailable }
            let route: (@Sendable (AuthorityPeerBinding, PhoneRoutingFrame) throws -> PhoneRoutingFrame)?
            if routingSupported { route = { _, _ in throw Fault.injected } } else { route = nil }
            let endpoint = AuthorityXPCEndpoint(macID: fixture.mac, accountID: fixture.account, budget: budget,
                activityJournal: journal, verify: { try validity() }, verifyHandshakePolicy: { try access.verifyCurrent() },
                invalidate: { [weak registry] in registry?.remove(id) },
                onHandshake: { [weak registry] in registry?.handshake(id) },
                snapshot: { try access.snapshot() }, validate: { try access.validate($0) }, pairingLookup: handler, pairingLookupBudget: pairingLookupBudget, phoneRouting: route)
            let driver = Driver(endpoint: endpoint) { [weak self] observed in
                self?.routing.withLock { $0 = observed }
            }
            guard registry.install(driver, id: id) else { throw AuthorityXPCEndpointError.unavailable }
            return AuthorityXPCChannel(driver: driver, timeoutMilliseconds: 2_000, onClose: onClose)
        }

        func retireRoutingLinkKeepingReservation() throws -> @Sendable () -> Void {
            let retired = routing.withLock { current in
                let old = current
                current = nil
                return old
            }
            let driver = try XCTUnwrap(retired)
            driver.interruptKeepingReservation()
            return { driver.releasePreservedReservation() }
        }
    }

    private func recoveryService(_ f: Fixture, root: RecoveryRoot, timeout: UInt64 = 5_000, feed existing: AuthorityTrustFeed? = nil)
        throws -> DirectApprovalTransportService {
        let feed = existing ?? AuthorityTrustFeed(macID: f.mac, accountID: f.account, factory: { try root.open(onClose: $0) })
        let host = try DirectApprovalTransportHost(macID: f.mac, accountID: f.account, identity: identity(f.transport),
            binding: .loopback, timeoutMilliseconds: timeout, validatePeer: { try await feed.validatePeer($0, revision: $1) },
            handler: { _, _ in XCTFail("Unenrolled candidate entered the approval handler") })
        return DirectApprovalTransportService(feed: feed, host: host, useDefaultDelivery: true)
    }

    private func waitForService(_ service: DirectApprovalTransportService) async throws -> UInt16 {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while ContinuousClock.now < deadline {
            if case let .ready(port) = await service.state { return port }
            try await Task.sleep(for: .milliseconds(5))
        }
        throw Fault.injected
    }

    func testNativeRecoveryUsesTheSameListenerDirectlyAndThroughTheWebSocketRelay() async throws {
        let f = try Fixture(configureTransport: true), phone = P256.Signing.PrivateKey()
        let (proposal, _) = try proposal(f, transportKey: phone.publicKey)
        let setup = try endpoint(f)
        let transcript = try PairingTranscript.decode(XCTUnwrap(stageBytes(setup, proposal.encode())))
        setup.close()
        let stage = try XCTUnwrap(f.journal.read { try $0.recoveryStage(setupID: transcript.setupID) })
        f.environment.time.value = stage.deadline
        try f.journal.withRequests { owner in _ = try owner.expirePending(now: f.environment.now(), receiptTimeMs: nil) }
        let before = try files(f)
        let root = try RecoveryRoot(f)
        defer { root.registry.close() }
        XCTAssertTrue(try root.access.snapshot().peers.isEmpty)
        let service = try recoveryService(f, root: root)
        try await service.start()
        let direct = try await waitForService(service)
        let phoneIdentity = try identity(phone)
        try await checkNativeRecovery(port: direct, fixture: f, transcript: transcript, phone: phone, phoneIdentity: phoneIdentity)
        let (approval, _) = try connectLookup(port: direct, purpose: EnrolledChannelPurpose.approvals.applicationProtocol,
            serverKey: f.transport.publicKey.x963Representation, identity: phoneIdentity)
        defer { approval.abort() }
        let approvalData: Data?
        do {
            try await approval.start(timeoutMilliseconds: 2_000)
            approvalData = try await approval.receive()
        } catch { approvalData = nil }
        XCTAssertNil(approvalData)
        await approval.close()

        let relayPort = Box<UInt16?>(nil)
        let relay = try ApprovalWebSocketRelay(listenPort: 0, targetPort: direct, event: { event in
            if case let .ready(port) = event { relayPort.value = port }
        })
        try relay.start()
        defer { relay.close() }
        let carrierPort = try await waitForPort(relayPort)
        let client = try ClientRelay(target: carrierPort)
        defer { client.close() }
        let tunnel = try await waitForPort(client.port)
        let rootConnectionsBeforeRelay = root.connections.withLock { $0 }
        try await checkNativeRecovery(port: tunnel, fixture: f, transcript: transcript, phone: phone, phoneIdentity: phoneIdentity)
        XCTAssertEqual(client.webSocketConnections.withLock { $0 }, 1)
        XCTAssertEqual(root.connections.withLock { $0 }, rootConnectionsBeforeRelay + 1)
        await client.closeAndWait()
        await relay.closeAndWait()
        await service.closeAndWait()
        XCTAssertEqual(try files(f), before)
    }

    private func availableRootSlots(_ root: RecoveryRoot) -> Int {
        var available: [UUID] = []
        while let id = root.registry.reserve() { available.append(id) }
        for id in available { root.registry.remove(id) }
        return available.count
    }

    private func waitForRootSlots(_ count: Int, in root: RecoveryRoot) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while availableRootSlots(root) != count {
            guard ContinuousClock.now < deadline else { throw Fault.injected }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    func testNativeRecoveryRejectsMalformedAndSecondLookupWithoutAnotherRootLink() async throws {
        let f = try Fixture(configureTransport: true), client = P256.Signing.PrivateKey()
        let fRoot = try RecoveryRoot(f)
        defer { fRoot.registry.close() }
        let service = try recoveryService(f, root: fRoot)
        try await service.start()
        let port = try await waitForService(service), phoneIdentity = try identity(client)
        let before = fRoot.connections.withLock { $0 }
        let scope = try ChannelScope(macID: f.mac, accountID: f.account,
            phoneID: Data(repeating: 11, count: 16), enrollmentEpoch: Data(repeating: 12, count: 16))
        let query = try PairingRecoveryQuery(setupID: Data(repeating: 13, count: 16),
            transcriptDigest: Data(repeating: 14, count: 32), scope: scope)
        for malformed in [true, false] {
            let (channel, _) = try connectLookup(port: port, purpose: PairingRecoveryFrame.applicationProtocol,
                serverKey: f.transport.publicKey.x963Representation, identity: phoneIdentity)
            defer { channel.abort() }
            try await channel.start(timeoutMilliseconds: 5_000)
            if malformed {
                try await channel.send(Data([0, 0, 0, 1, 255]))
            } else {
                try await sendRecovery(.lookup(query), to: channel)
                guard case .challenge = try await readRecovery(from: channel) else { throw Fault.injected }
                try await sendRecovery(.lookup(query), to: channel)
            }
            let data = try? await channel.receive()
            XCTAssertNil(data)
            XCTAssertEqual(fRoot.connections.withLock { $0 }, before + (malformed ? 0 : 1))
            await channel.close()
        }
        await service.closeAndWait()
    }

    func testNativeRecoveryIdleDeadlineAndCancellationReleaseBothBudgets() async throws {
        let f = try Fixture(configureTransport: true), client = P256.Signing.PrivateKey()
        let root = try RecoveryRoot(f, maximumConnections: 9)
        defer { root.registry.close() }
        let service = try recoveryService(f, root: root, timeout: 1_500)
        try await service.start()
        let port = try await waitForService(service), phoneIdentity = try identity(client)
        let before = root.connections.withLock { $0 }
        let capacity = availableRootSlots(root)
        let scope = try ChannelScope(macID: f.mac, accountID: f.account,
            phoneID: Data(repeating: 21, count: 16), enrollmentEpoch: Data(repeating: 22, count: 16))
        let query = try PairingRecoveryQuery(setupID: Data(repeating: 23, count: 16),
            transcriptDigest: Data(repeating: 24, count: 32), scope: scope)
        func connect() throws -> NetworkByteChannel {
            try connectLookup(port: port, purpose: PairingRecoveryFrame.applicationProtocol,
                serverKey: f.transport.publicKey.x963Representation, identity: phoneIdentity).0
        }
        let idle = try connect()
        defer { idle.abort() }
        try await idle.start(timeoutMilliseconds: 2_000)
        let eof = try? await idle.receive()
        XCTAssertNil(eof)
        XCTAssertEqual(root.connections.withLock { $0 }, before)

        let cancelled = try connect()
        defer { cancelled.abort() }
        try await cancelled.start(timeoutMilliseconds: 2_000)
        try await sendRecovery(.lookup(query), to: cancelled)
        guard case .challenge = try await readRecovery(from: cancelled) else { throw Fault.injected }
        cancelled.abort()
        await cancelled.close()
        try await waitForRootSlots(capacity, in: root)
        XCTAssertEqual(root.connections.withLock { $0 }, before + 1)
        let first = try connect(), second = try connect()
        for fresh in [first, second] {
            try await fresh.start(timeoutMilliseconds: 2_000)
            try await sendRecovery(.lookup(query), to: fresh)
            guard case .challenge = try await readRecovery(from: fresh) else { throw Fault.injected }
        }
        await first.close()
        await second.close()
        try await waitForRootSlots(capacity, in: root)
        await service.closeAndWait()
    }

    func testNativeRecoverySharesRootCapacityWithoutEvictingPersistentLinks() async throws {
        let f = try Fixture(configureTransport: true), phone = P256.Signing.PrivateKey()
        let root = try RecoveryRoot(f)
        defer { root.registry.close() }
        let service = try recoveryService(f, root: root)
        try await service.start()
        let port = try await waitForService(service), phoneIdentity = try identity(phone)
        var persistent: [AuthorityXPCChannel] = []
        while availableRootSlots(root) > 0 {
            let link = try root.open(onClose: {})
            try await link.start()
            persistent.append(link)
        }
        XCTAssertFalse(persistent.isEmpty)
        let scope = try ChannelScope(macID: f.mac, accountID: f.account,
            phoneID: Data(repeating: 31, count: 16), enrollmentEpoch: Data(repeating: 32, count: 16))
        let query = try PairingRecoveryQuery(setupID: Data(repeating: 33, count: 16),
            transcriptDigest: Data(repeating: 34, count: 32), scope: scope)
        for hasFreeSlot in [false, true] {
            if hasFreeSlot {
                let released = persistent.removeLast()
                await released.close()
            }
            let (network, _) = try connectLookup(port: port, purpose: PairingRecoveryFrame.applicationProtocol,
                serverKey: f.transport.publicKey.x963Representation, identity: phoneIdentity)
            defer { network.abort() }
            try await network.start(timeoutMilliseconds: 5_000)
            try await sendRecovery(.lookup(query), to: network)
            if hasFreeSlot {
                guard case .challenge = try await readRecovery(from: network) else { throw Fault.injected }
                try await sendRecovery(.proof(Data(repeating: 1, count: 64)), to: network)
                guard case .refused = try await readRecovery(from: network) else { throw Fault.injected }
            } else {
                let reply = try? await network.receive()
                XCTAssertNil(reply)
            }
            await network.close()
            for link in persistent {
                let trust = try await link.fetchTrust(expectedMacID: f.mac, expectedAccountID: f.account)
                XCTAssertTrue(trust.peers.isEmpty)
            }
        }
        for link in persistent { await link.close() }
        await service.closeAndWait()
    }

    func testNativeRecoveryHasItsOwnAdmissionLimitInsideTheListener() async throws {
        let f = try Fixture(configureTransport: true), phone = P256.Signing.PrivateKey()
        let root = try RecoveryRoot(f, maximumConnections: 9)
        defer { root.registry.close() }
        let service = try recoveryService(f, root: root)
        try await service.start()
        let port = try await waitForService(service), phoneIdentity = try identity(phone)
        let scope = try ChannelScope(macID: f.mac, accountID: f.account,
            phoneID: Data(repeating: 41, count: 16), enrollmentEpoch: Data(repeating: 42, count: 16))
        let query = try PairingRecoveryQuery(setupID: Data(repeating: 43, count: 16),
            transcriptDigest: Data(repeating: 44, count: 32), scope: scope)
        var open: [NetworkByteChannel] = []
        for index in 0..<3 {
            let (network, _) = try connectLookup(port: port, purpose: PairingRecoveryFrame.applicationProtocol,
                serverKey: f.transport.publicKey.x963Representation, identity: phoneIdentity)
            open.append(network)
            if index < 2 {
                try await network.start(timeoutMilliseconds: 3_000)
                try await sendRecovery(.lookup(query), to: network)
                guard case .challenge = try await readRecovery(from: network) else { throw Fault.injected }
            } else {
                let response: PairingRecoveryFrame?
                do {
                    try await network.start(timeoutMilliseconds: 3_000)
                    try await sendRecovery(.lookup(query), to: network)
                    response = try await readRecovery(from: network)
                } catch { response = nil }
                XCTAssertNil(response)
            }
        }
        for channel in open { await channel.close() }
        await service.closeAndWait()
    }

    func testNativeRecoveryAcceptsAnEnrolledCandidateOnlyThroughItsDedicatedPurpose() async throws {
        let f = try Fixture(configureTransport: true), phone = P256.Signing.PrivateKey()
        let (proposal, biometric) = try proposal(f, transportKey: phone.publicKey)
        let attempt = try stage(f, proposal)
        _ = try commit(f, attempt, key: biometric)
        let root = try RecoveryRoot(f)
        defer { root.registry.close() }
        XCTAssertEqual(try root.access.snapshot().peers.count, 1)
        let service = try recoveryService(f, root: root)
        try await service.start()
        let port = try await waitForService(service)
        let response = try await lookupNative(port: port, fixture: f, transcript: attempt.transcript,
            phone: phone, phoneIdentity: identity(phone))
        guard case let .committed(signature) = response else { throw Fault.injected }
        XCTAssertTrue(try attempt.transcript.verify(signature: signature, publicKey: f.authority.publicKey.x963Representation,
            purpose: .macCommit))
        let before = root.connections.withLock { $0 }
        let (wrong, _) = try connectLookup(port: port, purpose: PairingRecoveryFrame.applicationProtocol,
            serverKey: f.transport.publicKey.x963Representation, identity: identity(phone))
        defer { wrong.abort() }
        try await wrong.start(timeoutMilliseconds: 3_000)
        let negotiation = try ChannelNegotiation(local: approvalOffer(scope: attempt.transcript.phone.scope), trustedMinimum: 1)
        defer { negotiation.close() }
        try await sendNativeFrame(negotiation.offer(), to: wrong)
        let reply = try? await wrong.receive()
        XCTAssertNil(reply)
        XCTAssertEqual(root.connections.withLock { $0 }, before)
        await service.closeAndWait()
    }

    func testNativeRecoveryUnavailableOnLegacyTransportOrRoot() async throws {
        let f = try Fixture(configureTransport: true), phone = P256.Signing.PrivateKey()
        for (supported, limit) in [(false, 8), (true, 7)] {
            let root = try RecoveryRoot(f, supported: supported, maximumConnections: limit)
            defer { root.registry.close() }
            let service = try recoveryService(f, root: root)
            try await service.start()
            let state = await service.state
            XCTAssertEqual(state, .noEligiblePhones)
            let ordinary = try root.open(onClose: {})
            try await ordinary.start()
            let trust = try await ordinary.fetchTrust(expectedMacID: f.mac, expectedAccountID: f.account)
            XCTAssertTrue(trust.peers.isEmpty)
            await ordinary.close()
            await service.closeAndWait()
        }

        let enrolled = try DirectApprovalPeer(scope: .init(macID: f.mac, accountID: f.account,
            phoneID: Data(repeating: 53, count: 16), enrollmentEpoch: Data(repeating: 54, count: 16)),
            transportPublicKey: phone.publicKey.derRepresentation, requests: [], auditVersions: [], maximumPayloadBytes: 4096)
        let bound = Box<UInt16?>(nil)
        let legacy = try DirectApprovalListener(identity: identity(f.transport), peers: [enrolled], binding: .loopback,
            timeoutMilliseconds: 1_000, event: { event in if case let .ready(port) = event { bound.value = port } },
            handler: { _, _ in XCTFail("Recovery advanced onto the legacy approval handler") })
        try legacy.start()
        defer { legacy.close() }
        let port = try await waitForPort(bound)
        let (network, _) = try connectLookup(port: port, purpose: PairingRecoveryFrame.applicationProtocol,
            serverKey: f.transport.publicKey.x963Representation, identity: identity(phone))
        defer { network.abort() }
        let received: Data?
        do { try await network.start(timeoutMilliseconds: 2_000); received = try await network.receive() }
        catch { received = nil }
        XCTAssertNil(received)
        await legacy.closeAndWait()
    }

    func testRecoveryQuotaKeepsTheReplacementMarginAtEveryRootCapacity() {
        XCTAssertEqual(AuthorityTransportConnectionCapacity.recoveryQuota(6), 0)
        XCTAssertEqual(AuthorityTransportConnectionCapacity.recoveryQuota(7), 0)
        XCTAssertEqual(AuthorityTransportConnectionCapacity.recoveryQuota(8), 1)
        XCTAssertEqual(AuthorityTransportConnectionCapacity.recoveryQuota(9), 2)
        XCTAssertEqual(AuthorityTransportConnectionCapacity.recoveryQuota(10), 3)
    }

    func testFullDefaultRecoveryQuotaAllowsImmediateAuxiliaryReplacementAndApproval() async throws {
        try await checkFullQuotaAllowsReplacementAndApproval(maximumConnections: 8)
    }

    func testFullTwoSlotRecoveryQuotaAllowsImmediateAuxiliaryReplacementAndApproval() async throws {
        try await checkFullQuotaAllowsReplacementAndApproval(maximumConnections: 9)
    }

    private func checkFullQuotaAllowsReplacementAndApproval(maximumConnections: Int) async throws {
        let f = try Fixture(configureTransport: true), phone = P256.Signing.PrivateKey()
        let (proposal, biometric) = try proposal(f, transportKey: phone.publicKey)
        let attempt = try stage(f, proposal), query = try lookupQuery(attempt.transcript)
        _ = try commit(f, attempt, key: biometric)
        let root = try RecoveryRoot(f, routingSupported: true, maximumConnections: maximumConnections)
        defer { root.registry.close() }
        let feed = AuthorityTrustFeed(macID: f.mac, accountID: f.account, factory: { try root.open(onClose: $0) })
        let service = try recoveryService(f, root: root, feed: feed)
        try await service.start()
        let port = try await waitForService(service)
        let phoneIdentity = try identity(phone)
        var persistent: [AuthorityXPCChannel] = []
        let quota = AuthorityTransportConnectionCapacity.recoveryQuota(maximumConnections)
        while availableRootSlots(root) > quota + 1 {
            let link = try root.open(onClose: {})
            try await link.start()
            persistent.append(link)
        }
        let serverKey = f.transport.publicKey.x963Representation
        var recoveryChannels: [NetworkByteChannel] = []
        defer { for channel in recoveryChannels { channel.abort() } }
        for _ in 0..<quota {
            let (channel, _) = try connectLookup(port: port, purpose: PairingRecoveryFrame.applicationProtocol,
                serverKey: serverKey, identity: phoneIdentity)
            recoveryChannels.append(channel)
            try await channel.start(timeoutMilliseconds: 3_000)
            try await sendRecovery(.lookup(query), to: channel)
            guard case .challenge = try await readRecovery(from: channel) else { throw Fault.injected }
        }
        XCTAssertEqual(availableRootSlots(root), 1)
        let opened = root.connections.withLock { $0 }
        let releaseOld = try root.retireRoutingLinkKeepingReservation()
        defer { releaseOld() }
        try await feed.requirePhoneRoutingSupport()
        XCTAssertEqual(root.connections.withLock { $0 }, opened + 1)
        // The replacement overlaps the retired reservation while recovery consumes its full quota.
        XCTAssertEqual(availableRootSlots(root), 0)
        releaseOld()

        let (approved, _) = try connectLookup(port: port, purpose: EnrolledChannelPurpose.approvals.applicationProtocol,
            serverKey: serverKey, identity: phoneIdentity)
        defer { approved.abort() }
        try await approved.start(timeoutMilliseconds: 3_000)
        let session = try ChannelNegotiation(local: approvalOffer(scope: attempt.transcript.phone.scope), trustedMinimum: 1)
        defer { session.close() }
        try await sendNativeFrame(session.offer(), to: approved)
        let offer = try await readNativeFrame(from: approved, maximum: 65_536)
        try session.receiveOffer(offer)
        try await sendNativeFrame(session.confirmation(), to: approved)
        let confirmation = try await readNativeFrame(from: approved, maximum: 128)
        try session.receiveConfirmation(confirmation)
        let peer = try session.confirmed()
        XCTAssertEqual(peer.peer.scope, attempt.transcript.phone.scope)
        XCTAssertEqual(peer.peer.role, .mac)

        for channel in recoveryChannels { await channel.close() }
        await approved.close()
        for link in persistent { await link.close() }
        await service.closeAndWait()
    }

    func testNativeRecoveryExporterMatchesAcrossTLSAndChangesPerConnection() async throws {
        let f = try Fixture(), phone = P256.Signing.PrivateKey(), port = Box<UInt16?>(nil)
        let serverExporters = Mutex<[Data]>([])
        // Capture the server output in process. No exporter bytes are sent as application data.
        let listener = try DirectApprovalListener(identity: identity(f.transport), peers: [], binding: .loopback,
            event: { event in if case let .ready(value) = event { port.value = value } },
            handler: { _, _ in XCTFail("Recovery entered the approval handler") },
            sharedWorkBudget: .init(maximum: 8), recoveryMacID: f.mac, sharedRecoveryBudget: .init(maximum: 2),
            recovery: { channel, exporter, _, _ in
                serverExporters.withLock { $0.append(exporter) }
                _ = try await channel.receive()
            })
        try listener.start()
        defer { listener.close() }
        let address = try await waitForPort(port), phoneIdentity = try identity(phone)
        var samples: [Data] = []
        for index in 0..<2 {
            let (channel, connection) = try connectLookup(port: address, purpose: PairingRecoveryFrame.applicationProtocol,
                serverKey: f.transport.publicKey.x963Representation, identity: phoneIdentity)
            defer { channel.abort() }
            try await channel.start(timeoutMilliseconds: 3_000)
            let exporter = try PairingRecoveryTLS.exporter(XCTUnwrap(PairingRecoveryTLS.metadata(connection)))
            let deadline = ContinuousClock.now.advanced(by: .seconds(3))
            while serverExporters.withLock({ $0.count }) <= index {
                guard ContinuousClock.now < deadline else { throw Fault.injected }
                try await Task.sleep(for: .milliseconds(5))
            }
            XCTAssertEqual(exporter.count, 32)
            let remote = serverExporters.withLock { $0[index] }
            XCTAssertEqual(remote.count, 32)
            XCTAssertTrue(exporter == remote)
            samples.append(exporter)
            try await channel.send(Data([1]))
            await channel.close()
        }
        XCTAssertTrue(samples[0] != samples[1])
        await listener.closeAndWait()
    }

    func testRecoveryClosesWithoutProofAfterSignerFailureOrTransportPolicyChange() async throws {
        for changePolicy in [false, true] {
            let f = try Fixture(configureTransport: true), phone = P256.Signing.PrivateKey()
            let (proposal, _) = try proposal(f, transportKey: phone.publicKey)
            let attempt = try stage(f, proposal), query = try lookupQuery(attempt.transcript)
            f.environment.time.value = try XCTUnwrap(retained(f, attempt)).deadline
            XCTAssertTrue(try f.access.isExpired(attempt))
            let invoked = Mutex(false)
            let root = try RecoveryRoot(f, signing: { _ in
                invoked.withLock { $0 = true }
                throw Fault.injected
            })
            defer { root.registry.close() }
            let link = try root.open(onClose: {})
            try await link.start()
            let exporter = Data(repeating: 81, count: 32)
            let challenge = try await link.beginPairingLookup(query, exporter: exporter,
                deadline: DispatchTime.now().uptimeNanoseconds + 5_000_000_000)
            let input = try query.signingInput(exporter: exporter, challenge: challenge)
            let proof = try phone.signature(for: input).rawRepresentation
            if changePolicy {
                let current = try XCTUnwrap(f.journal.read { try $0.codePolicy() })
                let policy = try AuthorityCodePolicy(entries: [Fixture.appEntry(), Fixture.transportEntry(active: false)])
                _ = try f.journal.write { try $0.installCodePolicy(policy, expectedRevision: current.revision) }
            }
            do {
                _ = try await link.finishPairingLookup(proof)
                XCTFail("Recovery produced a result after invalidation")
            } catch {}
            XCTAssertEqual(invoked.withLock { $0 }, !changePolicy)
            await link.close()
        }
    }

    func testRecoveryWithholdsProofWhileTheCommitCheckpointIsUncertain() async throws {
        let f = try Fixture(configureTransport: true), phone = P256.Signing.PrivateKey()
        let (proposal, biometric) = try proposal(f, transportKey: phone.publicKey)
        let attempt = try stage(f, proposal), query = try lookupQuery(attempt.transcript)
        let root = try RecoveryRoot(f)
        defer { root.registry.close() }
        let link = try root.open(onClose: {})
        try await link.start()
        let exporter = Data(repeating: 81, count: 32)
        let challenge = try await link.beginPairingLookup(query, exporter: exporter,
            deadline: DispatchTime.now().uptimeNanoseconds + 5_000_000_000)
        let input = try query.signingInput(exporter: exporter, challenge: challenge)
        let proof = try phone.signature(for: input).rawRepresentation
        try sql(f, "CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT, 'fixture'); END", continuity: true)
        XCTAssertThrowsError(try commit(f, attempt, key: biometric))
        XCTAssertNotNil(try f.continuity.read().pending)
        do {
            _ = try await link.finishPairingLookup(proof)
            XCTFail("Recovery produced proof before restart reconciled the checkpoint")
        } catch {}
        await link.close()
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
            let transport = P256.Signing.PrivateKey()
            let (proposal, key) = try proposal(f, transportKey: transport.publicKey), attempt = try stage(f, proposal)
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
            let first: @Sendable () -> Void
            if expiryWins {
                first = expiryWork
            } else {
                first = commitWork
            }
            DispatchQueue.global().async(group: completed, execute: first)
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
                f.environment.time.value = deadline
                let query = try lookupQuery(attempt.transcript)
                let response = try recover(f, query: query, key: transport)
                guard case let .expired(receipt) = try PairingRecoveryFrame.decode(response) else {
                    return XCTFail("Expiry won but recovery returned no expiry proof")
                }
                XCTAssertTrue(try receipt.verify(transcript: attempt.transcript))
                XCTAssertEqual(receipt.reason, .deadlineElapsed)
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
        let f = try Fixture()
        XCTAssertTrue(try f.access.expiredRePairs().records.isEmpty)
        let (proposal, _) = try proposal(f), attempt = try stage(f, proposal)
        let selection = attempt.transcript.setupID + (try attempt.transcript.digest())
        func listed() throws -> [ExpiredRePairRecord] {
            let connection = try endpoint(f), hello = Box<UInt64>(0), reply = Box<Data?>(nil)
            defer { connection.close() }
            connection.pairedPhoneHello { hello.value = $0 }
            XCTAssertEqual(hello.value, 1)
            connection.managePairedPhone(PairedPhoneOperation.listExpiredRePairs.rawValue, selection: Data(),
                authorization: Data()) { reply.value = $0 }
            let scope = attempt.transcript.phone.scope
            return try ExpiredRePairSnapshot.decode(XCTUnwrap(reply.value), macID: scope.macID, accountID: scope.accountID).records
        }
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
        XCTAssertTrue(try listed().isEmpty)
        XCTAssertEqual(try retained(f, attempt)?.state, .pending)
        f.environment.time.value = try attempt.recoveryStage().deadline
        XCTAssertTrue(try listed().isEmpty)
        XCTAssertEqual(try f.continuity.read(), before)
        XCTAssertTrue(try f.access.isExpired(attempt))
        let oldHead = try f.records()
        let terminalCheckpoint = try f.continuity.read()
        let record = try XCTUnwrap(listed().first)
        XCTAssertEqual(record.phoneID, attempt.transcript.phone.scope.phoneID)
        XCTAssertEqual(record.originalExpiryUnixMilliseconds, attempt.transcript.expiresAtUnixMillis)
        XCTAssertEqual(record.reason, .deadlineElapsed)
        XCTAssertEqual(record.selection, selection)
        XCTAssertThrowsError(try f.access.discardExpiredRePair(setupID: record.setupID,
            digest: record.transcriptDigest, authorize: { throw Fault.injected }))
        XCTAssertEqual(try f.continuity.read(), terminalCheckpoint)
        XCTAssertEqual(try listed(), [record])
        XCTAssertEqual(try discard(), Data([1]))
        XCTAssertTrue(try listed().isEmpty)
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

    func testExpiredListReturnsRetiredStageThroughTheEndpointCodec() throws {
        let f = try Fixture(), attempt = try stage(f, proposal(f).0)
        let replacementIncarnation = UUID()
        try writes(f) { try $0.closeRetiredRecoveryStages(incarnation: replacementIncarnation) }
        let before = try f.continuity.read()
        let connection = try endpoint(f), version = Box<UInt64>(0), reply = Box<Data?>(nil)
        defer { connection.close() }
        connection.pairedPhoneHello(maximumVersion: 2) { version.value = $0 }
        XCTAssertEqual(version.value, 2)
        connection.managePairedPhone(PairedPhoneOperation.listExpiredRePairs.rawValue, selection: Data(),
            authorization: Data()) { reply.value = $0 }
        let records = try ExpiredRePairSnapshot.decode(XCTUnwrap(reply.value), macID: f.mac, accountID: f.account).records
        XCTAssertEqual(records.count, 1)
        let record = try XCTUnwrap(records.first)
        XCTAssertEqual(record.phoneID, attempt.transcript.phone.scope.phoneID)
        XCTAssertEqual(record.reason, .retiredIncarnation)
        XCTAssertEqual(record.originalExpiryUnixMilliseconds, attempt.transcript.expiresAtUnixMillis)
        XCTAssertEqual(record.setupID, attempt.transcript.setupID)
        XCTAssertEqual(try f.continuity.read(), before)
    }

    func testDiscardStaleSelectionKeepsReplacementAndAddsNoAuditEvent() throws {
        let f = try Fixture(), candidate = try proposal(f).0
        let old = try stage(f, candidate)
        f.environment.time.value = try old.recoveryStage().deadline
        XCTAssertTrue(try f.access.isExpired(old))
        let stale = try XCTUnwrap(f.access.expiredRePairs().records.first)
        let replacement = try stage(f, candidate)
        XCTAssertNotEqual(stale.setupID, replacement.transcript.setupID)
        let before = try f.continuity.read()
        let connection = try endpoint(f), reply = Box<Data?>(nil)
        defer { connection.close() }
        connection.pairedPhoneHello { _ in }
        connection.managePairedPhone(PairedPhoneOperation.discardExpiredRePair.rawValue, selection: stale.selection,
            authorization: authorization) { reply.value = $0 }
        XCTAssertNil(reply.value)
        XCTAssertEqual(try retained(f, replacement)?.state, .pending)
        XCTAssertEqual(try retained(f, replacement)?.transcriptDigest, try replacement.transcript.digest())
        XCTAssertEqual(try f.continuity.read(), before)
        XCTAssertEqual(try f.access.maintenanceAdmission.stagedReservations(), 0)
    }

    func testDiscardHonorsClosedMaintenanceAdmission() throws {
        let f = try Fixture(), attempt = try stage(f, proposal(f).0)
        f.environment.time.value = try attempt.recoveryStage().deadline
        XCTAssertTrue(try f.access.isExpired(attempt))
        let record = try XCTUnwrap(f.access.expiredRePairs().records.first)
        let before = try f.continuity.read()
        let connection = try endpoint(f), reply = Box<Data?>(nil)
        defer { connection.close() }
        connection.pairedPhoneHello { _ in }
        f.access.maintenanceAdmission.close()
        connection.managePairedPhone(PairedPhoneOperation.discardExpiredRePair.rawValue, selection: record.selection,
            authorization: authorization) { reply.value = $0 }
        XCTAssertNil(reply.value)
        XCTAssertEqual(try retained(f, attempt)?.state, .deadlineElapsed)
        XCTAssertEqual(try f.continuity.read(), before)
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
            let expired = try restarted.read { try $0.expiredRePairStages() }
            XCTAssertEqual(expired.map(\.transcript.setupID), [retired.transcript.setupID])
            XCTAssertEqual(expired.map(\.state.expiryReason), [.retiredIncarnation])
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
