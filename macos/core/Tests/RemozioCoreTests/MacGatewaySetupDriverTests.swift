import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class MacGatewaySetupDriverTests: XCTestCase {
    private func setup(_ f: GatewayJournalSetupExchangeTests.Fixture, journal: GatewayJournalPreparationState? = nil) throws -> SetupGatewayProgress {
        let machine = f.runtime.machine, account = f.runtime.account
        return try .init(account: account, runtime: machine.runtimePreparation(accountID: account.accountID),
            activation: machine.runtimeActivation(accountID: account.accountID), material: machine.gatewayPreparation(accountID: account.accountID),
            journal: journal ?? f.state())
    }
    func testOperationTimeoutIsBoundedBeforeAnyNativeConnection() throws {
        for timeout: UInt64 in [0, 300001] {
            XCTAssertThrowsError(try NativeMacGatewaySetupDriver(operationTimeoutMilliseconds: timeout)) {
                XCTAssertEqual($0 as? AdministrativeSetupChannelError, .invalidConfiguration)
            }
        }
    }
    func testPendingJournalCannotAskTheInstalledServiceToActivate() async throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture(), driver = try NativeMacGatewaySetupDriver()
        let value = try SetupGatewayActivationProgress(setup: setup(f), state: .init(plan: nil, filesPublished: false, jobRegistered: false))
        do { _ = try await driver.activate(value, settings: .init()); XCTFail() }
        catch { XCTAssertEqual(error as? GatewayPreparationError, .incomplete) }
    }
    func testJournalWithoutAnIntentRefusesBeforeNativeConnectionOrConsent() async throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture(), driver = try NativeMacGatewaySetupDriver()
        let value = try setup(f, journal: .init(intent: nil, initialized: false))
        do { _ = try await driver.initializeJournal(value); XCTFail() }
        catch { XCTAssertEqual(error as? GatewayPreparationError, .incomplete) }
    }
    func testChangedRetainedTimingsRefuseBeforeConnectionOrConsent() async throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture(), driver = try NativeMacGatewaySetupDriver()
        try f.retainCompletion(.decode(f.initialize()))
        let plan = try GatewayRuntimeActivationPlan(journal: f.state(), foreground: f.runtime.plan, inventory: XCTUnwrap(f.runtime.machine.inventory()))
        let value = try SetupGatewayActivationProgress(setup: setup(f), state: .init(plan: plan, filesPublished: true, jobRegistered: true))
        do { _ = try await driver.activate(value, settings: .init(wakePollMilliseconds: 2000)); XCTFail() }
        catch { XCTAssertEqual(error as? GatewayPreparationError, .conflictingMaterial) }
    }
    func testAnotherUIDRefusesBeforeConnectionOrConsent() async throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture(), driver = try NativeMacGatewaySetupDriver()
        let limits = try CBORLimits(maxBytes: 1280, maxDepth: 1, maxItems: 32)
        guard case .map(var fields) = try DeterministicCBOR.decode(setup(f).bytes, limits: limits) else { return XCTFail() }
        fields[6] = .unsigned(UInt64(getuid()) + 1)
        let foreign = try SetupGatewayProgress.decode(DeterministicCBOR.encode(.map(fields), limits: limits))
        do { _ = try await driver.initializeJournal(foreign); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .wrongAccount) }
    }
}
