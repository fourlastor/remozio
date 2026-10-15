import Darwin
import Foundation
import Observation
import Security
import ServiceManagement

/// Registration describes macOS permission to launch. It is not a service health result.
public enum MacSetupServiceState: Equatable, Sendable {
    case requiresInstallation, notRegistered, requiresApproval, enabled, notFound, unavailable
}
public enum MacSetupServiceOperation: Equatable, Sendable { case inspecting, registering }
public enum MacSetupServiceNotice: Equatable, Sendable { case inspectionFailed, registrationFailed }

protocol MacSetupServiceDriver: Sendable {
    func inspect() async throws -> MacSetupServiceState
    func register() async throws -> MacSetupServiceState
}

enum MacSetupServiceLocation {
    static func matches(bundlePath: String, codePath: String) -> Bool {
        let installed = MachineBootstrap.bundlePath
        return bundlePath == installed && [installed, installed + "/Contents/MacOS/Remozio"].contains(codePath)
    }
}

private actor NativeMacSetupServiceDriver: MacSetupServiceDriver {
    private let service = SMAppService.daemon(plistName: AdministrativeSetupConfiguration.plistName)

    func inspect() throws -> MacSetupServiceState { try perform(registering: false) }
    func register() throws -> MacSetupServiceState { try perform(registering: true) }

    func enrollmentChannel(serviceAccounts: Bool = false, runtime: Bool = false) throws -> AdministrativeSetupChannel {
        var channel: AdministrativeSetupChannel?
        let state = try perform(registering: false) { release in
            guard let component = release.manifest.components.first(where: { $0.role == .setupController }),
                  let team = component.teamID, let hash = release.codeDirectoryHashes[.setupController] else {
                throw SetupRegistrationError.wrongRelease
            }
            let policy = try XPCPeerPolicy(teamID: team, componentIdentifier: component.identifier,
                approvedCodeDirectoryHashes: [hash], expectedUserID: 0)
            channel = try AdministrativeSetupChannel(serviceName: AdministrativeSetupConfiguration.serviceName,
                rootPolicy: policy, ownerUID: getuid(), serviceAccounts: serviceAccounts, runtime: runtime, timeoutMilliseconds: 60_000)
        }
        guard state == .enabled, let channel else { throw SetupRegistrationError.unavailable }
        return channel
    }
    private func perform(registering: Bool, onVerified: ((SignedReleaseEvidence) throws -> Void)? = nil) throws -> MacSetupServiceState {
        guard getuid() > 0, getuid() == geteuid() else { throw SetupRegistrationError.wrongProcess }
        let bundle = URL(fileURLWithPath: MachineBootstrap.bundlePath)
        let ownBundle = Bundle.main.bundleURL.resolvingSymlinksInPath().path
        guard ownBundle == bundle.path else { return .requiresInstallation }
        let ownCode = URL(fileURLWithPath: try DynamicCodeValidation.selfPath()).resolvingSymlinksInPath().path
        guard MacSetupServiceLocation.matches(bundlePath: ownBundle, codePath: ownCode) else { return .requiresInstallation }
        let placement = try ReleaseDestinationLease.readForServiceRegistration(path: bundle.deletingLastPathComponent().path)
        defer { placement.close() }
        _ = try placement.inspectCopiedTree(name: bundle.lastPathComponent)
        let identity = try runningIdentity()
        let release = try SignedReleaseInspection.inspect(bundle, teamID: identity.team, appIdentifier: "dev.remozio.mac")
        guard release.codeDirectoryHashes[.app] == identity.hash,
              release.manifest.components.first(where: { $0.role == .setupController })?.relativePath
                == AdministrativeSetupConfiguration.executablePath else { throw SetupRegistrationError.wrongRelease }
        try validateManifest(bundle)
        try placement.validate()
        if registering {
            switch service.status {
            case .notRegistered: try service.register()
            case .enabled, .requiresApproval: break
            default: throw SetupRegistrationError.unavailable
            }
        }
        let result = Self.state(service.status)
        try placement.validate()
        _ = try placement.inspectCopiedTree(name: bundle.lastPathComponent)
        let current = try SignedReleaseInspection.inspect(bundle, teamID: identity.team, appIdentifier: "dev.remozio.mac")
        guard try InstallationInventory.digest(current) == InstallationInventory.digest(release) else {
            throw SetupRegistrationError.wrongRelease
        }
        try DynamicCodeValidation.validateSelf(requirement: identity.requirement)
        if result == .enabled { try onVerified?(current) }
        return result
    }

    private struct Identity { let team: String; let hash: Data; let requirement: String }
    private func runningIdentity() throws -> Identity {
        // Trust starts with the running process, not the candidate bundle's release declaration.
        var code: SecCode?, staticCode: SecStaticCode?, information: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              values[kSecCodeInfoIdentifier as String] as? String == "dev.remozio.mac",
              let team = values[kSecCodeInfoTeamIdentifier as String] as? String,
              let hash = values[kSecCodeInfoUnique as String] as? Data else { throw SetupRegistrationError.wrongRelease }
        let requirement = try XPCPeerPolicy(teamID: team, componentIdentifier: "dev.remozio.mac",
            approvedCodeDirectoryHashes: [hash], expectedUserID: getuid()).requirement
        try DynamicCodeValidation.validateSelf(requirement: requirement)
        return Identity(team: team, hash: hash, requirement: requirement)
    }
    private func validateManifest(_ bundle: URL) throws {
        let expected: [String: Any] = ["Label": AdministrativeSetupConfiguration.serviceName,
            "BundleProgram": AdministrativeSetupConfiguration.executablePath,
            "ProgramArguments": [AdministrativeSetupConfiguration.executablePath, "--configuration", AdministrativeSetupConfiguration.startupPath],
            "UserName": "root", "RunAtLoad": true, "KeepAlive": true,
            "MachServices": [AdministrativeSetupConfiguration.serviceName: true]]
        let path = bundle.appendingPathComponent("Contents/Library/LaunchDaemons/" + AdministrativeSetupConfiguration.plistName).path
        let bytes = try ProtectedServiceConfiguration.readPublic(path: path)
        guard let actual = try PropertyListSerialization.propertyList(from: bytes, format: nil) as? [String: Any],
              NSDictionary(dictionary: expected).isEqual(to: actual) else { throw SetupRegistrationError.wrongRelease }
    }
    private static func state(_ value: SMAppService.Status) -> MacSetupServiceState {
        switch value {
        case .notRegistered: .notRegistered
        case .requiresApproval: .requiresApproval
        case .enabled: .enabled
        case .notFound: .notFound
        @unknown default: .unavailable
        }
    }
}
private enum SetupRegistrationError: Error { case wrongProcess, wrongRelease, unavailable }

/// Explicit setup registration only. It never registers approval services, grants access or prompts on startup.
@MainActor @Observable
public final class MacSetupServiceControls {
    public private(set) var state: MacSetupServiceState = .unavailable
    public private(set) var operation: MacSetupServiceOperation?
    public private(set) var notice: MacSetupServiceNotice?
    @ObservationIgnored private let driver: any MacSetupServiceDriver
    public convenience init() { self.init(driver: NativeMacSetupServiceDriver()) }
    init(driver: any MacSetupServiceDriver) { self.driver = driver }

    public func refresh() async {
        guard operation == nil else { return }
        operation = .inspecting
        defer { operation = nil }
        do {
            state = try await driver.inspect()
            if state == .enabled || state == .requiresApproval || notice == .inspectionFailed { notice = nil }
        } catch { state = .unavailable; notice = .inspectionFailed }
    }
    public func enable() async {
        guard operation == nil else { return }
        operation = .registering; notice = nil
        defer { operation = nil }
        do {
            state = try await driver.inspect()
            switch state {
            case .enabled, .requiresApproval: return
            case .notRegistered: break
            default: notice = .registrationFailed; return
            }
            state = try await driver.register()
            if state != .enabled && state != .requiresApproval { notice = .registrationFailed }
        } catch {
            // A failed reply does not undo registration. Read current system state; never repeat the mutation.
            state = (try? await driver.inspect()) ?? .unavailable
            notice = state == .enabled || state == .requiresApproval ? nil : .registrationFailed
        }
    }
    public func openSettings() { SMAppService.openSystemSettingsLoginItems() }
}

/// Verifies protected placement and the running app before opening a pinned Root setup connection.
public enum MacAccountSetupConnection {
    public static func open(serviceAccounts: Bool = false, runtime: Bool = false) async throws -> AdministrativeSetupChannel {
        try await NativeMacSetupServiceDriver().enrollmentChannel(serviceAccounts: serviceAccounts, runtime: runtime)
    }
}
