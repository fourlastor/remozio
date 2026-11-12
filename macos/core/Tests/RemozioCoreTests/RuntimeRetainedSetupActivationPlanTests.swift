import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Synthetic archive operands and proposed jobs only. These tests grant no native startup or publication authority.
final class RuntimeRetainedSetupActivationPlanTests: XCTestCase {
    private typealias Fixture = RetainedSetupActivationArchiveTests.Fixture

    func testUsesTheArchiveCodecAndPreservesEveryValueFromTheSameBytes() throws {
        let f = try Fixture(), bytes = try f.bytes()
        let archive = try RuntimeRetainedSetupActivationArchive.decode(bytes)
        let value = try RuntimeRetainedSetupActivationPlan.decode(bytes)
        XCTAssertEqual(try value.encoded, bytes)
        XCTAssertEqual(try value.archive.encoded, try archive.encoded)
        XCTAssertEqual(value.reference, archive.reference); XCTAssertEqual(value.bundlePath, archive.bundlePath)
        XCTAssertEqual(value.host.canonicalBytes, archive.host.canonicalBytes)
        XCTAssertEqual(value.transport.canonicalBytes, archive.transport.canonicalBytes)
        XCTAssertEqual(value.gatewaySettingsHost, archive.gatewaySettingsHost)
        XCTAssertEqual(value.retainedSetupBinding, archive.binding)
        XCTAssertEqual(value.retainedSetupInventory, archive.inventory)
        XCTAssertEqual(value.phoneRoutingVersion, archive.phoneRoutingVersion)
        XCTAssertEqual(value.phoneAuditVersion, archive.phoneAuditVersion)
        XCTAssertEqual(value.phoneUpdateSchedulingVersion, archive.phoneUpdateSchedulingVersion)
        XCTAssertEqual(value.formatVersion, 6)
        XCTAssertEqual(value.description, "RuntimeRetainedSetupActivationPlan(redacted)")
        XCTAssertEqual(value.debugDescription, value.description)
        let rebuilt = try RuntimeRetainedSetupActivationArchive(reference: archive.reference, bundlePath: archive.bundlePath,
            host: archive.host, transport: archive.transport, gatewaySettingsHost: archive.gatewaySettingsHost,
            phoneRoutingVersion: archive.phoneRoutingVersion, phoneAuditVersion: archive.phoneAuditVersion,
            phoneUpdateSchedulingVersion: archive.phoneUpdateSchedulingVersion, binding: archive.binding, inventory: archive.inventory)
        XCTAssertEqual(try RuntimeRetainedSetupActivationPlan(archive: rebuilt).encoded, bytes)
    }

    func testJobValuesAddOnlyRetainedHealthAndPreserveOwnedMetadata() throws {
        let f = try Fixture(), before = try XCTUnwrap(f.source.f.f.machine.inventory()).canonicalBytes
        let value = try RuntimeRetainedSetupActivationPlan.decode(f.bytes())
        let ordinary = try InstalledAccountJobManifest(accountID: value.accountID, role: .authority,
            executionUID: 0, userName: "root", bundlePath: value.bundlePath, gatewaySettingsControlEnabled: true)
        let service = try MachineUpdateRetainedSetupHealthService.authority(accountID: value.accountID)
        XCTAssertEqual(value.authorityJob.machServices, ordinary.machServices.union([service]))
        XCTAssertEqual(value.authorityJob.arguments, ordinary.arguments)
        XCTAssertEqual(value.authorityJob.declaration, ordinary.declaration)
        XCTAssertEqual(value.authorityJob.configurationPath, ordinary.configurationPath)
        XCTAssertEqual(value.transportJob.bytes, try value.consumerHosts.job(.transport).bytes)
        XCTAssertEqual(try XCTUnwrap(f.source.f.f.machine.inventory()).canonicalBytes, before)
    }

    func testAllNullablePhoneSelectionsUseTheSameArchiveGuards() throws {
        let f = try Fixture()
        for mask in 0..<8 {
            var fields = f.fields
            for bit in 0..<3 { fields[UInt64(6 + bit)] = mask & (1 << bit) == 0 ? .null : .unsigned(1) }
            let bytes = try f.bytes(fields), archive = try RuntimeRetainedSetupActivationArchive.decode(bytes)
            let plan = try RuntimeRetainedSetupActivationPlan.decode(bytes)
            XCTAssertEqual(try plan.encoded, bytes)
            XCTAssertEqual(plan.phoneRoutingVersion, archive.phoneRoutingVersion)
            XCTAssertEqual(plan.phoneAuditVersion, archive.phoneAuditVersion)
            XCTAssertEqual(plan.phoneUpdateSchedulingVersion, archive.phoneUpdateSchedulingVersion)
        }
        XCTAssertNoThrow(try RuntimeRetainedSetupActivationPlan.decode(f.bytes()))
        for key in UInt64(6)...8 {
            for invalid in [CBORValue.unsigned(0), .unsigned(2), .text("1"), .bytes(Data())] {
                var fields = f.fields; fields[key] = invalid
                let bytes = try f.bytes(fields)
                XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(bytes))
                XCTAssertThrowsError(try RuntimeRetainedSetupActivationPlan.decode(bytes))
            }
        }
    }

    func testSharedCodecRejectsMissingExtraNoncanonicalAndOversizedBytes() throws {
        let f = try Fixture(), valid = try f.bytes()
        XCTAssertNoThrow(try RuntimeRetainedSetupActivationPlan.decode(valid))
        for key in f.fields.keys {
            var fields = f.fields; fields[key] = nil
            let bytes = try f.bytes(fields)
            XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(bytes))
            XCTAssertThrowsError(try RuntimeRetainedSetupActivationPlan.decode(bytes))
        }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(5)), (0, .unsigned(7)), (9, .null), (10, .null), (11, .null)] {
            var fields = f.fields; fields[key] = value
            let bytes = try f.bytes(fields)
            XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(bytes))
            XCTAssertThrowsError(try RuntimeRetainedSetupActivationPlan.decode(bytes))
        }
        for bytes in [Data(), valid + Data([0]), Data(repeating: 0, count: RuntimeRetainedSetupActivationPlan.maximumBytes + 1)] {
            XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(bytes))
            XCTAssertThrowsError(try RuntimeRetainedSetupActivationPlan.decode(bytes))
        }
    }

    func testOrdinaryPlanStateAndActualNativeDecodersStillRejectV6() throws {
        let f = try Fixture(), bytes = try f.bytes()
        let value = try RuntimeRetainedSetupActivationPlan.decode(bytes)
        XCTAssertEqual(RuntimeActivationPlan.supportedVersions, [1, 2, 3, 4, 5])
        XCTAssertThrowsError(try RuntimeActivationPlan.decode(bytes))
        XCTAssertThrowsError(try RuntimeActivationState.Plan(encoded: bytes))
        XCTAssertThrowsError(try GatewaySettingsConsumerNativeScope.decodeGatewayStartup(
            value.gatewaySettingsHost.encoded, path: value.gatewaySettingsHost.gatewayConfigurationPath)) {
            XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
        }
        let path = try RuntimePreparationPaths(accountID: value.accountID).transportConfiguration
        XCTAssertThrowsError(try GatewaySettingsConsumerNativeScope.decodeTransportStartup(value.transport.canonicalBytes, path: path)) {
            XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
        }
    }

    func testSharedHostChecksRejectAlteredJobNamespacesBeforePlanConstruction() throws {
        let f = try Fixture()
        XCTAssertNoThrow(try RuntimeRetainedSetupActivationPlan.decode(f.bytes()))
        guard case .map(let original) = try DeterministicCBOR.decode(f.host.canonicalBytes, limits: f.limits) else {
            return XCTFail("Expected host map")
        }
        for (key, value): (UInt64, CBORValue) in [(1, .text("/private/tmp/OtherMachine")),
            (6, .text(f.host.label + ".other")), (7, .text(f.host.plistName + ".other.plist"))] {
            var host = original; host[key] = value
            let changedHost = try DeterministicCBOR.encode(.map(host), limits: f.limits)
            var fields = f.fields; fields[3] = .bytes(changedHost)
            let bytes = try f.bytes(fields)
            XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(bytes)) {
                XCTAssertEqual($0 as? InstalledAuthorityCommandError, .invalidConfiguration)
            }
            XCTAssertThrowsError(try RuntimeRetainedSetupActivationPlan.decode(bytes)) {
                XCTAssertEqual($0 as? InstalledAuthorityCommandError, .invalidConfiguration)
            }
        }
    }

    func testEnrollmentProposesExactJobsAndPreservesUnrelatedAccounts() throws {
        let f = try Fixture(), plan = try RuntimeRetainedSetupActivationPlan.decode(f.bytes())
        let otherID = AccountPreparationIntent.randomID()
        let other = try InstallationAccount(accountID: otherID, ownerUID: plan.reference.services.ownerUID + 1)
        let otherJob = try InstallationService(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
            label: "dev.remozio.other.authority", plistName: "dev.remozio.other.authority.plist", accountID: otherID)
        let inventory = try InstallationInventory(macID: f.inventory.macID, installationID: f.inventory.installationID,
            revision: f.inventory.revision, bundlePath: f.inventory.bundlePath, releaseDigest: f.inventory.releaseDigest,
            accounts: [other], services: f.inventory.services + [otherJob], formatVersion: f.inventory.formatVersion)
        let enrolled = try plan.enrolledInventory(inventory)
        XCTAssertTrue(enrolled.accounts.contains(other)); XCTAssertTrue(enrolled.services.contains(otherJob))
        XCTAssertTrue(enrolled.services.contains(plan.authorityJob.declaration))
        XCTAssertTrue(enrolled.services.contains(plan.transportJob.declaration))
        XCTAssertEqual(try plan.enrolledInventory(enrolled), enrolled)
        let declaration = plan.authorityJob.declaration
        let conflict = try InstallationService(role: declaration.role, kind: declaration.kind,
            domainUID: declaration.domainUID, executionUID: declaration.executionUID, label: declaration.label + ".other",
            plistName: declaration.plistName, accountID: declaration.accountID)
        let changed = try InstallationInventory(macID: enrolled.macID, installationID: enrolled.installationID,
            revision: enrolled.revision, bundlePath: enrolled.bundlePath, releaseDigest: enrolled.releaseDigest,
            accounts: enrolled.accounts, services: enrolled.services.map { $0 == declaration ? conflict : $0 },
            formatVersion: enrolled.formatVersion)
        XCTAssertThrowsError(try plan.enrolledInventory(changed)) { XCTAssertEqual($0 as? RuntimeActivationError, .conflictingPlan) }
        XCTAssertTrue(f.inventory.accounts.isEmpty)
    }
}
