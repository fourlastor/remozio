import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class SetupGatewayActivationProgressTests: XCTestCase {
    private func setup(_ f: GatewayJournalSetupExchangeTests.Fixture) throws -> SetupGatewayProgress {
        let machine = f.runtime.machine, account = f.runtime.account
        return try .init(account: account, runtime: machine.runtimePreparation(accountID: account.accountID),
            activation: machine.runtimeActivation(accountID: account.accountID), material: machine.gatewayPreparation(accountID: account.accountID), journal: f.state())
    }
    private func ready() throws -> GatewayJournalSetupExchangeTests.Fixture {
        let f = try GatewayJournalSetupExchangeTests.Fixture(); try f.retainCompletion(.decode(f.initialize())); return f
    }
    private func plan(_ f: GatewayJournalSetupExchangeTests.Fixture, _ settings: GatewayRuntimeActivationSettings) throws -> GatewayRuntimeActivationPlan {
        try .init(journal: f.state(), foreground: f.runtime.plan, inventory: XCTUnwrap(f.runtime.machine.inventory()),
            wakePollMilliseconds: settings.wakePollMilliseconds, wakeTimeoutMilliseconds: settings.wakeTimeoutMilliseconds)
    }
    private func edited(_ bytes: Data, _ change: (inout [UInt64: CBORValue]) -> Void) throws -> Data {
        let limits = try CBORLimits(maxBytes: 1280, maxDepth: 1, maxItems: 32)
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw GatewayPreparationError.invalidRecord }
        change(&fields); return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    func testSelectedTimingsRoundTripAndMatchTheOperationalWakeBounds() throws {
        let f = try ready()
        for (poll, timeout): (UInt64, UInt64) in [(100, 1), (1000, 5000), (60000, 60000)] {
            let settings = try GatewayRuntimeActivationSettings(wakePollMilliseconds: poll, wakeTimeoutMilliseconds: timeout)
            XCTAssertEqual(try GatewayRuntimeActivationSettings.decode(settings.bytes), settings)
            let value = try plan(f, settings)
            XCTAssertEqual(value.extensions.transport.wake?.pollMilliseconds, poll)
            XCTAssertEqual(value.extensions.transport.wake?.wake.timeoutMilliseconds, timeout)
        }
        for (poll, timeout): (UInt64, UInt64) in [(99, 1), (60001, 1), (100, 0), (100, 60001)] {
            XCTAssertThrowsError(try GatewayRuntimeActivationSettings(wakePollMilliseconds: poll, wakeTimeoutMilliseconds: timeout))
        }
        let settings = try GatewayRuntimeActivationSettings()
        for edit: (inout [UInt64: CBORValue]) -> Void in [{ $0[0] = .unsigned(2) }, { $0[1] = .text("foreign") }, { $0[4] = .null }] {
            XCTAssertThrowsError(try GatewayRuntimeActivationSettings.decode(edited(settings.bytes, edit)))
        }
    }
    func testEmptyProgressIsAvailableBeforeJournalCompletionWithoutClaimingReadiness() throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture()
        let value = try SetupGatewayActivationProgress(setup: setup(f), state: .init(plan: nil, filesPublished: false, jobRegistered: false))
        XCTAssertFalse(value.setup.journalInitialized); XCTAssertNil(value.planDigest); XCTAssertNil(value.settings)
        XCTAssertFalse(value.filesPublished); XCTAssertFalse(value.jobRegistered)
        XCTAssertEqual(try SetupGatewayActivationProgress.decode(value.bytes), value)
        XCTAssertThrowsError(try SetupGatewayActivationProgress(setup: setup(f), state: .init(plan: nil, filesPublished: true, jobRegistered: false)))
    }
    func testRetainedHistoricalStagesPreserveTheSelectedTimingsAndContainNoPrivateRuntimeIdentity() throws {
        let f = try ready(), settings = try GatewayRuntimeActivationSettings(wakePollMilliseconds: 2000, wakeTimeoutMilliseconds: 6000)
        let plan = try plan(f, settings)
        for (published, registered) in [(false, false), (true, false), (true, true)] {
            let value = try SetupGatewayActivationProgress(setup: setup(f), state: .init(plan: plan, filesPublished: published, jobRegistered: registered))
            XCTAssertEqual(try SetupGatewayActivationProgress.decode(value.bytes), value)
            XCTAssertEqual(value.settings, settings); XCTAssertEqual(value.planDigest, try plan.digest)
            XCTAssertEqual(value.filesPublished, published); XCTAssertEqual(value.jobRegistered, registered)
            XCTAssertNil(try value.bytes.range(of: f.runtime.material.transportIdentity))
        }
    }
    func testAnotherAccountOrDifferentJournalCannotSupplyTheProgressPlan() throws {
        let f = try ready(), other = try ready(), settings = try GatewayRuntimeActivationSettings()
        XCTAssertThrowsError(try SetupGatewayActivationProgress(setup: setup(f), state: .init(plan: plan(other, settings), filesPublished: false, jobRegistered: false)))
        let pending = try GatewayJournalSetupExchangeTests.Fixture()
        XCTAssertThrowsError(try SetupGatewayActivationProgress(setup: setup(pending), state: .init(plan: plan(f, settings), filesPublished: false, jobRegistered: false)))
    }
    func testCompletionRequiresTheSameScopeAndSelectedPlanWithoutAChangedTiming() throws {
        let f = try ready(), settings = try GatewayRuntimeActivationSettings(), selected = try plan(f, settings), scope = try setup(f)
        let empty = try SetupGatewayActivationProgress(setup: scope, state: .init(plan: nil, filesPublished: false, jobRegistered: false))
        let done = try SetupGatewayActivationProgress(setup: scope, state: .init(plan: selected, filesPublished: true, jobRegistered: true))
        try done.validateActivation(of: empty, selectedSettings: settings); try done.validateActivation(of: done, selectedSettings: settings)
        let other = try GatewayRuntimeActivationSettings(wakePollMilliseconds: 2000)
        XCTAssertThrowsError(try done.validateActivation(of: empty, selectedSettings: other))
        let changed = try SetupGatewayActivationProgress(setup: scope, state: .init(plan: plan(f, other), filesPublished: true, jobRegistered: true))
        XCTAssertThrowsError(try changed.validateActivation(of: done, selectedSettings: other))
        XCTAssertThrowsError(try empty.validateActivation(of: done, selectedSettings: settings))
    }
    func testUnknownFieldsWrongTypesAndImpossibleHistoricalMarkersAreRejected() throws {
        let f = try ready(), settings = try GatewayRuntimeActivationSettings(), plan = try plan(f, settings)
        let value = try SetupGatewayActivationProgress(setup: setup(f), state: .init(plan: plan, filesPublished: true, jobRegistered: true))
        for edit: (inout [UInt64: CBORValue]) -> Void in [
            { $0[0] = .unsigned(2) }, { $0[1] = .text("foreign") }, { $0[7] = .null }, { $0[2] = .bytes(Data()) },
            { $0[3] = .bytes(Data()) }, { $0[3] = .null }, { $0[4] = .null }, { $0[5] = .boolean(false) }, { $0[6] = .unsigned(1) }
        ] { XCTAssertThrowsError(try SetupGatewayActivationProgress.decode(edited(value.bytes, edit))) }
        XCTAssertThrowsError(try SetupGatewayActivationProgress.decode(Data(repeating: 0, count: 1281)))
    }
}
