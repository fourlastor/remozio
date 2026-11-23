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
        let gatewayRevocations: AuthorityGatewayRevocationState?
        let policy: XPCPeerPolicy
        let writer: AuditEpochWriter
        let limits = try! CBORLimits(maxBytes: 16384, maxDepth: 12, maxItems: 1024)
        var mac: Data { Data(repeating: 1, count: 16) }
        var account: Data { Data(repeating: 2, count: 16) }
        init(auditVersions: Set<UInt64> = [1], activity: ReleaseActivityBarrier? = nil, configureGateway: Bool = false) throws {
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
                maximumConsumptions: 20, busyMilliseconds: 100, initialize: true,
                gatewayPolicy: configureGateway ? GatewayAuthorityPolicy(payloadLimits: limits, signingLimits: limits,
                    maximumControls: 32, candidateLifetimeMillis: 1000, clockEpoch: environment.epoch) : nil)
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
            journal = AuthorityJournal(requests: requests)
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
