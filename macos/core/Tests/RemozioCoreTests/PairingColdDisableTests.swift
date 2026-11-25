import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class PairingColdDisableTests: XCTestCase {
    private enum StopFailure: Error { case noExitProof, interrupted }

    private struct Fixture {
        let root: URL
        let directory: ProtectedSetupDirectory
        let activation: RuntimeActivationFixture
        let host: InstalledAuthorityCommandConfiguration

        init() throws {
            activation = try RuntimeActivationFixture()
            let original = activation.plan.host
            let presence = original.command.presence
            let pairing = try XCTUnwrap(presence.pairing)
            let scoped = try AuthorityPairingSetupConfiguration(transportPublicKey: pairing.transportPublicKey,
                lifetimeMilliseconds: 52_001, v2ActivationEnabled: true, lanScope: .init(interfaceName: "en0", family: .ipv6))
            let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 6, maxItems: 1024)
            let nextPresence = try Self.replace(presence.canonicalBytes, 10, scoped.canonicalBytes, limits: limits)
            let command = try Self.replace(original.command.canonicalBytes, 1, nextPresence, limits: limits)
            host = try .decode(Self.replace(original.canonicalBytes, 5, command, limits: limits))
            root = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remozio-cold-disable-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Runtime", owner: getuid(), visibility: .privateState)
            _ = try AdministrativeSetupPublication.publish(host.canonicalBytes, file: .commandHost, directory: directory, owner: getuid())
            _ = try AdministrativeSetupPublication.publish(host.command.canonicalBytes, file: .commandConfiguration,
                directory: directory, owner: getuid())
        }

        func enabledActivation() throws -> RuntimeActivationPlan {
            let limits = try CBORLimits(maxBytes: RuntimeRetainedSetupActivationPlan.maximumBytes, maxDepth: 6, maxItems: 1024)
            return try .decode(Self.replace(activation.plan.encoded, 3, host.canonicalBytes, limits: limits))
        }

        private static func replace(_ data: Data, _ key: UInt64, _ bytes: Data, limits: CBORLimits) throws -> Data {
            guard case .map(var fields) = try DeterministicCBOR.decode(data, limits: limits) else { throw StopFailure.interrupted }
            fields[key] = .bytes(bytes)
            return try DeterministicCBOR.encode(.map(fields), limits: limits)
        }

        func read(_ file: AdministrativeSetupPublication.File) throws -> Data {
            try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name, owner: getuid())
        }

        func intent() throws -> PairingColdDisableIntent? {
            try PairingColdDisablePublication.readIntent(directory: directory, owner: getuid())
        }

        func apply(verifyStopped: () throws -> Void = {}, retainTarget: (InstalledAuthorityCommandConfiguration) throws -> Void = { _ in },
                   didPublish: (PairingColdDisablePublication.Stage) throws -> Void = { _ in }) throws -> PairingColdDisableIntent {
            try PairingColdDisablePublication.apply(expectedHost: host, directory: directory, owner: getuid(),
                verifyStopped: verifyStopped, retainTarget: retainTarget, didPublish: didPublish)
        }
    }

    private func withFixture(_ body: (Fixture) throws -> Void) throws {
        try XCTSkipIf(getuid() == 0 || geteuid() == 0, "Ordinary-owner fixture")
        let fixture = try Fixture()
        defer { fixture.directory.close(); XCTAssertNoThrow(try FileManager.default.removeItem(at: fixture.root)) }
        try body(fixture)
    }

    func testRefusalWithoutExactExitEvidenceMakesNoWrites() throws {
        try withFixture { fixture in
            XCTAssertThrowsError(try fixture.apply(verifyStopped: { throw StopFailure.noExitProof },
                                                   didPublish: { _ in XCTFail("Unexpected publication") }))
            XCTAssertNil(try fixture.intent())
            XCTAssertEqual(try fixture.read(.commandHost), fixture.host.canonicalBytes)
            XCTAssertEqual(try fixture.read(.commandConfiguration), fixture.host.command.canonicalBytes)
        }
    }

    func testLostResponseBetweenTheTwoFilesLeavesPairingClosedAndReplayCompletes() throws {
        try withFixture { fixture in
            let target = try PairingColdDisableConfiguration(source: fixture.host).target
            XCTAssertThrowsError(try fixture.apply(didPublish: { if case .runtime = $0 { throw StopFailure.interrupted } }))
            let pending = try XCTUnwrap(fixture.intent())
            XCTAssertFalse(pending.completed)
            XCTAssertEqual(try fixture.read(.commandHost), fixture.host.canonicalBytes)
            XCTAssertEqual(try fixture.read(.commandConfiguration), target.command.canonicalBytes)
            let sourcePairing = try XCTUnwrap(fixture.host.command.presence.pairing)
            let sourceDigest = PairingColdDisableIntent.digest(sourcePairing.canonicalBytes)
            for digest in [sourceDigest, pending.targetPairing] {
                XCTAssertThrowsError(try PairingColdDisableIntent.requirePairingOpen(macID: pending.macID, accountID: pending.accountID,
                    pairingDigest: digest, read: { try fixture.read(.pairingColdDisableIntent) }))
            }

            var reconciled: Data?
            let completed = try fixture.apply(retainTarget: { reconciled = $0.canonicalBytes })
            XCTAssertEqual(reconciled, target.canonicalBytes)
            XCTAssertEqual(completed, try pending.completion())
            XCTAssertEqual(try fixture.read(.commandHost), target.canonicalBytes)
            XCTAssertEqual(try fixture.read(.commandConfiguration), target.command.canonicalBytes)

            XCTAssertEqual(try fixture.apply(didPublish: { _ in XCTFail("Unexpected replay write") }), completed)
            XCTAssertNoThrow(try PairingColdDisableIntent.requirePairingOpen(macID: completed.macID, accountID: completed.accountID,
                pairingDigest: completed.targetPairing, read: { try fixture.read(.pairingColdDisableIntent) }))
            XCTAssertThrowsError(try PairingColdDisableIntent.requirePairingOpen(macID: completed.macID, accountID: completed.accountID,
                pairingDigest: Data(count: 32), read: { try fixture.read(.pairingColdDisableIntent) }))
        }
    }

    func testExplicitFalsePreservesTheRetainedPinAndOtherSettings() throws {
        try withFixture { fixture in
            let original = try XCTUnwrap(fixture.host.command.presence.pairing)
            let updatedHost = try PairingColdDisableConfiguration(source: fixture.host).target
            let pairing = try XCTUnwrap(updatedHost.command.presence.pairing)
            let limits = try CBORLimits(maxBytes: 512, maxDepth: 2, maxItems: 13)
            guard case .map(let fields) = try DeterministicCBOR.decode(pairing.canonicalBytes, limits: limits) else {
                return XCTFail("Expected pairing configuration map")
            }
            XCTAssertEqual(Set(fields.keys), Set(UInt64(0)...3))
            XCTAssertEqual(fields[0], .unsigned(2))
            XCTAssertEqual(fields[3], .boolean(false))
            XCTAssertNil(pairing.lanScope)
            XCTAssertEqual(pairing.transportPublicKey, original.transportPublicKey)
            XCTAssertEqual(pairing.lifetimeMilliseconds, original.lifetimeMilliseconds)
            XCTAssertEqual(updatedHost.command.presence.wake.canonicalBytes, fixture.host.command.presence.wake.canonicalBytes)
            XCTAssertEqual(updatedHost.codePolicy, fixture.host.codePolicy)
            XCTAssertEqual(updatedHost.installationID, fixture.host.installationID)
            XCTAssertEqual(updatedHost.canonicalBytes, try InstalledAuthorityCommandConfiguration.decode(updatedHost.canonicalBytes).canonicalBytes)
        }
    }

    func testForeignRuntimeDigestCannotCompleteAnInterruptedDisable() throws {
        try withFixture { fixture in
            XCTAssertThrowsError(try fixture.apply(didPublish: { if case .intent = $0 { throw StopFailure.interrupted } }))
            let pending = try XCTUnwrap(fixture.intent())
            try AdministrativeSetupPublication.replacePairingColdDisable(Data([1]), expected: fixture.host.command.canonicalBytes,
                file: .commandConfiguration, directory: fixture.directory, owner: getuid(), verify: {})
            XCTAssertThrowsError(try fixture.apply(retainTarget: { _ in XCTFail("Foreign configuration cannot be retained") }))
            XCTAssertEqual(try fixture.intent(), pending)
            XCTAssertEqual(try fixture.read(.commandConfiguration), Data([1]))
            XCTAssertEqual(try fixture.read(.commandHost), fixture.host.canonicalBytes)
        }
    }

    func testRegisteredActivationRetainsItsInventoryAndJobIdentityAcrossReplay() throws {
        try withFixture { fixture in
            let source = try fixture.enabledActivation()
            let store = fixture.activation.machine
            try store.retainRuntimeActivation(source)
            let inventory = try store.enrollRuntimeActivation(source)
            let target = try source.replacingPairingHost(PairingColdDisableConfiguration(source: source.host).target)
            XCTAssertThrowsError(try store.retainColdDisabledPairing(expected: source, target: target))
            try store.markRuntimeJobsRegistered(source)

            let record = try fixture.apply(retainTarget: { next in
                try store.retainColdDisabledPairing(expected: source, target: source.replacingPairingHost(next))
            })
            XCTAssertTrue(record.completed)
            let retained = try store.runtimeActivation(accountID: source.accountID)
            XCTAssertTrue(retained.jobsRegistered)
            XCTAssertEqual(try retained.plan?.encoded, try target.encoded)
            XCTAssertEqual(try store.inventory(), inventory)
            XCTAssertEqual(retained.plan?.authorityJob.bytes, source.authorityJob.bytes)
            XCTAssertEqual(retained.plan?.transportJob.bytes, source.transportJob.bytes)
            XCTAssertNoThrow(try store.retainColdDisabledPairing(expected: source, target: target))
        }
    }

    func testInterruptedHostAndActivationPublicationsCompleteFromTheRetainedTarget() throws {
        for stage in [PairingColdDisablePublication.Stage.host, .activation] {
            try withFixture { fixture in
                let target = try PairingColdDisableConfiguration(source: fixture.host).target
                var retained = fixture.host
                XCTAssertThrowsError(try fixture.apply(retainTarget: { retained = $0 }, didPublish: { observed in
                    if observed == stage { throw StopFailure.interrupted }
                }))
                let pending = try XCTUnwrap(fixture.intent())
                XCTAssertFalse(pending.completed)
                XCTAssertEqual(try fixture.read(.commandHost), target.canonicalBytes)
                XCTAssertEqual(try fixture.read(.commandConfiguration), target.command.canonicalBytes)
                XCTAssertEqual(retained.canonicalBytes, stage == .host ? fixture.host.canonicalBytes : target.canonicalBytes)
                let complete = try PairingColdDisablePublication.apply(expectedHost: retained, directory: fixture.directory, owner: getuid(),
                    verifyStopped: {}, retainTarget: { retained = $0 })
                XCTAssertEqual(complete, try pending.completion())
                XCTAssertEqual(retained.canonicalBytes, target.canonicalBytes)
            }
        }
    }

    func testCompletedRecordCanRetireAfterLostRestartReply() throws {
        try withFixture { fixture in
            let complete = try fixture.apply()
            let target = try PairingColdDisableConfiguration(source: fixture.host).target
            XCTAssertThrowsError(try PairingColdDisablePublication.retire(complete, retainedHost: target, directory: fixture.directory,
                owner: getuid(), verify: { throw StopFailure.interrupted }))
            XCTAssertEqual(try fixture.intent(), complete)
            XCTAssertEqual(try fixture.apply(didPublish: { _ in XCTFail("Unexpected publication during completed replay") }), complete)
            try PairingColdDisablePublication.retire(complete, retainedHost: target, directory: fixture.directory, owner: getuid(), verify: {})
            XCTAssertNil(try fixture.intent())
            XCTAssertEqual(try fixture.read(.commandHost), try PairingColdDisableConfiguration(source: fixture.host).target.canonicalBytes)
        }
    }

    func testRetirementCanVerifyTheAbsentRecordAfterLostReply() throws {
        try withFixture { fixture in
            let complete = try fixture.apply()
            let target = try PairingColdDisableConfiguration(source: fixture.host).target
            XCTAssertThrowsError(try PairingColdDisablePublication.retire(complete, retainedHost: target, directory: fixture.directory,
                owner: getuid(), verify: {}, didRemove: { throw StopFailure.interrupted }))
            XCTAssertNil(try fixture.intent())
            XCTAssertNoThrow(try PairingColdDisablePublication.retire(complete, retainedHost: target, directory: fixture.directory, owner: getuid(), verify: {}))
            XCTAssertEqual(try fixture.read(.commandConfiguration), try PairingColdDisableConfiguration(source: fixture.host).target.command.canonicalBytes)
        }
    }

    func testCompletedRecordRetiresAgainstUpdatedHostWithTheSamePairingValue() throws {
        try withFixture { fixture in
            let complete = try fixture.apply()
            let original = try PairingColdDisableConfiguration(source: fixture.host).target
            let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 6, maxItems: 1024)
            guard case .map(var host) = try DeterministicCBOR.decode(original.canonicalBytes, limits: limits),
                  case .map(var command) = try DeterministicCBOR.decode(original.command.canonicalBytes, limits: limits),
                  case .map(var presence) = try DeterministicCBOR.decode(original.command.presence.canonicalBytes, limits: limits) else {
                return XCTFail("Expected canonical installed configuration")
            }
            presence[8] = .unsigned(original.command.presence.presence.policy.observationLifetimeMilliseconds + 1)
            command[1] = .bytes(try DeterministicCBOR.encode(.map(presence), limits: limits))
            host[5] = .bytes(try DeterministicCBOR.encode(.map(command), limits: limits))
            let updated = try InstalledAuthorityCommandConfiguration.decode(DeterministicCBOR.encode(.map(host), limits: limits))
            XCTAssertThrowsError(try complete.requireTarget(updated))
            XCTAssertNoThrow(try complete.requirePairingTarget(updated))
            XCTAssertThrowsError(try complete.requirePairingTarget(fixture.host))
            try AdministrativeSetupPublication.replacePairingColdDisable(updated.command.canonicalBytes,
                expected: original.command.canonicalBytes, file: .commandConfiguration,
                directory: fixture.directory, owner: getuid(), verify: {})
            try AdministrativeSetupPublication.replacePairingColdDisable(updated.canonicalBytes,
                expected: original.canonicalBytes, file: .commandHost,
                directory: fixture.directory, owner: getuid(), verify: {})
            try PairingColdDisablePublication.retire(complete, retainedHost: updated, directory: fixture.directory,
                owner: getuid(), verify: {})
            XCTAssertNil(try fixture.intent())
            XCTAssertEqual(try fixture.read(.commandHost), updated.canonicalBytes)
            XCTAssertEqual(try fixture.read(.commandConfiguration), updated.command.canonicalBytes)
        }
    }

    func testOriginalRestorationRequiresAbsentIntentExactFilesAndRegisteredPlan() throws {
        for changed in ["intent", "command-runtime", "command-host", "activation"] {
            try withFixture { fixture in
                let source = try fixture.enabledActivation()
                let store = fixture.activation.machine
                try store.retainRuntimeActivation(source)
                _ = try store.enrollRuntimeActivation(source)
                try store.markRuntimeJobsRegistered(source)
                func canRestore() throws -> Bool {
                    try PairingColdDisablePublication.canRestoreOriginal(source, directory: fixture.directory, owner: getuid(),
                        loadActivation: { try store.runtimeActivation(accountID: source.accountID) }, verify: {})
                }
                XCTAssertTrue(try canRestore())
                switch changed {
                case "intent":
                    XCTAssertThrowsError(try fixture.apply(didPublish: { stage in
                        if stage == .intent { throw StopFailure.interrupted }
                    }))
                    XCTAssertFalse(try canRestore())
                case "command-runtime":
                    try AdministrativeSetupPublication.replacePairingColdDisable(Data([1]), expected: source.host.command.canonicalBytes,
                        file: .commandConfiguration, directory: fixture.directory, owner: getuid(), verify: {})
                    XCTAssertThrowsError(try canRestore())
                case "command-host":
                    try AdministrativeSetupPublication.replacePairingColdDisable(Data([1]), expected: source.host.canonicalBytes,
                        file: .commandHost, directory: fixture.directory, owner: getuid(), verify: {})
                    XCTAssertThrowsError(try canRestore())
                default:
                    let target = try source.replacingPairingHost(PairingColdDisableConfiguration(source: source.host).target)
                    try store.retainColdDisabledPairing(expected: source, target: target)
                    XCTAssertThrowsError(try canRestore())
                }
            }
        }
    }

    func testActivationAcceptsOnlyTheMaskedPairingDifference() throws {
        try withFixture { fixture in
            let baseline = fixture.activation.plan.host.command
            let target = try PairingColdDisableConfiguration(source: fixture.host).target.command
            XCTAssertNoThrow(try PairingColdDisableConfiguration.requirePairingOnlyDifference(derived: baseline, retained: target))
            XCTAssertThrowsError(try PairingColdDisableConfiguration.requirePairingOnlyDifference(
                derived: baseline, retained: fixture.host.command))
            let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 6, maxItems: 1024)
            guard case .map(var command) = try DeterministicCBOR.decode(target.canonicalBytes, limits: limits),
                  case .map(var presence) = try DeterministicCBOR.decode(target.presence.canonicalBytes, limits: limits) else {
                return XCTFail("Expected canonical command and presence maps")
            }
            func decodeWithPresence(_ fields: [UInt64: CBORValue]) throws -> AuthorityCommandStartupConfiguration {
                command[1] = .bytes(try DeterministicCBOR.encode(.map(fields), limits: limits))
                return try AuthorityCommandStartupConfiguration.decode(DeterministicCBOR.encode(.map(command), limits: limits))
            }
            let original = try XCTUnwrap(baseline.presence.pairing)
            let legacy = try AuthorityPairingSetupConfiguration(transportPublicKey: original.transportPublicKey,
                lifetimeMilliseconds: original.lifetimeMilliseconds + 1)
            var legacyPresence = presence
            legacyPresence[10] = .bytes(legacy.canonicalBytes)
            XCTAssertThrowsError(try PairingColdDisableConfiguration.requirePairingOnlyDifference(
                derived: baseline, retained: decodeWithPresence(legacyPresence))) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            presence[8] = .unsigned(target.presence.presence.policy.observationLifetimeMilliseconds + 1)
            let other = try decodeWithPresence(presence)
            XCTAssertThrowsError(try PairingColdDisableConfiguration.requirePairingOnlyDifference(derived: baseline, retained: other)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
        }
    }

    private final class FakeJob: RuntimeJobExitWitness {
        let processID: pid_t
        var registered: Bool
        var exited = false
        var delayedExit = false

        init(_ processID: pid_t, registered: Bool = true) {
            self.processID = processID
            self.registered = registered
        }

        func hasExited() throws -> Bool { exited }

        func session(record: @escaping (String) -> Void) -> RuntimeJobStopSession {
            .init(verifyCurrent: {}, inspect: { self.registered ? .matching(self.processID) : .absent },
                capture: { pid in
                    record("capture \(pid)")
                    return self
                }, bootout: {
                    record("bootout \(self.processID)")
                    self.registered = false
                    self.exited = !self.delayedExit
                })
        }
    }

    func testSetupCapturesBothWitnessesBeforeEitherBootout() throws {
        var operations: [String] = []
        let jobs = [FakeJob(7), FakeJob(8)]
        let sessions = jobs.map { $0.session { operations.append($0) } }
        try PairingColdDisableSetup.stopAndPublish(sessions, requireLiveJobs: true, wait: { false },
            restoreIfUnpublished: { XCTFail("Unexpected restoration"); return false }, publish: {
                XCTAssertTrue(jobs.allSatisfy { $0.exited })
                operations.append("publish")
            })
        XCTAssertEqual(operations, ["capture 7", "capture 8", "bootout 7", "bootout 8", "publish"])
    }

    func testSetupRefusesBeforeBootoutWhenOnlyTransportIsAbsent() throws {
        var operations: [String] = []
        let authority = FakeJob(7), transport = FakeJob(8, registered: false)
        let sessions = [authority, transport].map { $0.session { operations.append($0) } }
        XCTAssertThrowsError(try PairingColdDisableSetup.stopAndPublish(sessions, requireLiveJobs: true, wait: { false },
            restoreIfUnpublished: { XCTFail("Unexpected restoration"); return false }, publish: { XCTFail("Unexpected publication") }))
        XCTAssertTrue(authority.registered)
        XCTAssertEqual(operations, ["capture 7"])
    }

    func testSetupRestoresOriginalRegistrationsWhenAnInitialStopTimesOut() throws {
        var operations: [String] = []
        let jobs = [FakeJob(7), FakeJob(8)]
        jobs[1].delayedExit = true
        let sessions = jobs.map { $0.session { operations.append($0) } }
        XCTAssertThrowsError(try PairingColdDisableSetup.stopAndPublish(sessions, requireLiveJobs: true, wait: { false },
            restoreIfUnpublished: {
                for job in jobs {
                    XCTAssertFalse(job.registered)
                    job.registered = true
                    operations.append("restore \(job.processID)")
                }
                return true
            }, publish: { XCTFail("Unexpected publication") })) {
            guard case PairingColdDisableSetup.RecoveryError.originalJobsRestored = $0 else {
                return XCTFail("Expected restored original jobs")
            }
        }
        XCTAssertTrue(jobs.allSatisfy { $0.registered })
        XCTAssertEqual(operations, ["capture 7", "capture 8", "bootout 7", "bootout 8", "restore 7", "restore 8"])
    }

    func testSetupCannotInferAnExitedProcessFromAnAbsentJob() throws {
        var observation = RuntimeJobStopSession.Observation.absent
        var didStop = false
        final class Witness: RuntimeJobExitWitness {
            let processID: pid_t
            init(processID: pid_t) { self.processID = processID }
            func hasExited() throws -> Bool { true }
        }
        let session = RuntimeJobStopSession(verifyCurrent: {}, inspect: { observation },
            capture: { Witness(processID: $0) }, bootout: { didStop = true; observation = .absent })
        XCTAssertThrowsError(try session.requireRunning())
        XCTAssertFalse(didStop)
        observation = .matching(77)
        try session.requireRunning()
        XCTAssertEqual(try session.poll(), .registrationRemoved)
        XCTAssertTrue(didStop)
        XCTAssertNoThrow(try session.requireRemoved())
    }
}
