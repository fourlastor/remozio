import Darwin
import Foundation
import RemozioMach
import RemozioProtocol

public enum AuthorityCommandStartupError: Error, Equatable { case invalidConfiguration, wrongPolicyScope }

/// Machine-specific command startup inputs. Decoding does not establish installation or grant execution authority.
public struct AuthorityCommandStartupConfiguration: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public static let supportedVersions: Set<UInt64> = [1]
    public static let captureSchemaVersion: UInt64 = 3
    public let presence: AuthorityPresenceStartupConfiguration
    public let serviceName: String
    public let policyPath: String
    public let environment: [CapturedEnvironmentEntry]
    public let submissionLimits: CBORLimits
    public let captureLimits: CBORLimits
    public let maximumSessions: Int
    public let receiveWaitMilliseconds: UInt32
    public let replyTimeoutMilliseconds: UInt32
    public let maximumAncestryEntries: Int
    public let approvalLifetimeMilliseconds: UInt64
    public let canonicalBytes: Data
    public var description: String { "AuthorityCommandStartupConfiguration(redacted)" }
    public var debugDescription: String { description }
    public var macID: Data { presence.presence.macID }
    public var accountID: Data { presence.presence.accountID }
    public var callerUID: UInt32 { presence.presence.ownerUID }
    /// Both implemented profiles retain mapped stdio and current-job semantics. Historical profiles are not advertised.
    public var capabilities: CommandHandshakeCapabilities { get throws {
        let terminal = CommandHandshakeCapabilities.mappedTerminalCurrentJobExecution
        let pipes = CommandHandshakeCapabilities.mappedPipeCurrentJobExecutionControls
        return try .init(wireVersions: terminal.wireVersions.union(pipes.wireVersions),
            submissionSchemaVersions: terminal.submissionSchemaVersions.intersection(pipes.submissionSchemaVersions),
            inputCarrierVersions: terminal.inputCarrierVersions.intersection(pipes.inputCarrierVersions))
    } }

    public init(presence: AuthorityPresenceStartupConfiguration, serviceName: String, policyPath: String,
                environment: [CapturedEnvironmentEntry], submissionLimits: CBORLimits, captureLimits: CBORLimits,
                maximumSessions: Int = 32, receiveWaitMilliseconds: UInt32 = 250,
                replyTimeoutMilliseconds: UInt32 = 5000, maximumAncestryEntries: Int = 16,
                approvalLifetimeMilliseconds: UInt64 = 60_000) throws {
        let service = presence.wake.request.service
        let parts = policyPath.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        guard GatewayWakeEndpointConfiguration.validServiceName(serviceName),
              serviceName.utf8.count < remozio_frontend_service_name_capacity(),
              ![service.serviceName, presence.endpoint.serviceName, presence.wake.gatewayServiceName].contains(serviceName),
              policyPath.hasPrefix("/"), policyPath.utf8.count < Int(PATH_MAX), !parts.isEmpty,
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }),
              policyPath != presence.wake.request.keyRecordPath,
              submissionLimits.maxBytes <= 16_777_216, submissionLimits.maxDepth >= 3,
              (32...1_048_576).contains(submissionLimits.maxItems),
              captureLimits.maxBytes <= service.maximumRequestBodyBytes,
              captureLimits.maxDepth >= 4, (128...1_048_576).contains(captureLimits.maxItems), (1...1024).contains(maximumSessions),
              (1...60_000).contains(receiveWaitMilliseconds), (1...60_000).contains(replyTimeoutMilliseconds),
              (0...64).contains(maximumAncestryEntries), (1...86_400_000).contains(approvalLifetimeMilliseconds),
              environment.count <= 64 else { throw AuthorityCommandStartupError.invalidConfiguration }
        let environment = environment.sorted { $0.name.lexicographicallyPrecedes($1.name) }
        var previous: Data?, totalBytes = 0
        for entry in environment {
            totalBytes += entry.name.count + entry.value.count
            guard !entry.name.isEmpty, entry.name.count <= 255, !entry.name.contains(0), !entry.name.contains(0x3d),
                  entry.value.count <= 16_384, !entry.value.contains(0), entry.source == .minimal,
                  previous == nil || previous! != entry.name, totalBytes <= 32_768 else {
                throw AuthorityCommandStartupError.invalidConfiguration
            }
            previous = entry.name
        }
        do {
            try Self.validateProtocolBudgets(environment: environment, callerUID: presence.presence.ownerUID,
                submissionLimits: submissionLimits, captureLimits: captureLimits,
                maximumRequestBodyBytes: service.maximumRequestBodyBytes)
        } catch { throw AuthorityCommandStartupError.invalidConfiguration }
        self.presence = presence; self.serviceName = serviceName; self.policyPath = policyPath; self.environment = environment
        self.submissionLimits = submissionLimits; self.captureLimits = captureLimits; self.maximumSessions = maximumSessions
        self.receiveWaitMilliseconds = receiveWaitMilliseconds; self.replyTimeoutMilliseconds = replyTimeoutMilliseconds
        self.maximumAncestryEntries = maximumAncestryEntries; self.approvalLifetimeMilliseconds = approvalLifetimeMilliseconds
        canonicalBytes = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(presence.canonicalBytes), 2: .text(serviceName), 3: .text(policyPath),
            4: .array(environment.map { .map([0: .bytes($0.name), 1: .bytes($0.value)]) }),
            5: Self.encodeLimits(submissionLimits), 6: Self.encodeLimits(captureLimits),
            7: .unsigned(UInt64(maximumSessions)), 8: .unsigned(UInt64(receiveWaitMilliseconds)),
            9: .unsigned(UInt64(replyTimeoutMilliseconds)), 10: .unsigned(UInt64(maximumAncestryEntries)),
            11: .unsigned(approvalLifetimeMilliseconds), 12: .unsigned(Self.captureSchemaVersion)
        ]), limits: Self.limits)
    }

    /// The production loader reads only a Root-private file under protected local ancestors.
    public static func load(path: String) throws -> Self { try decode(ProtectedServiceConfiguration.read(path: path)) }

    /// Verify the current protected policy scope, then retain only its path for fresh admission and execution checks.
    public func currentElevationPolicy() throws -> CurrentCommandElevationPolicy {
        try validatePolicyScope(CommandElevationPolicy.load(path: policyPath))
        return try .init(path: policyPath, macID: macID, accountID: accountID, callerUID: callerUID)
    }
    func validatePolicyScope(_ policy: CommandElevationPolicy) throws {
        guard policy.macID == macID, policy.accountID == accountID, policy.callerUID == callerUID else {
            throw AuthorityCommandStartupError.wrongPolicyScope
        }
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...12), case .unsigned(let version) = fields[0], supportedVersions.contains(version),
              case .bytes(let presence) = fields[1], case .text(let service) = fields[2], case .text(let path) = fields[3],
              case .array(let rawEnvironment) = fields[4], rawEnvironment.count <= 64,
              fields[12] == .unsigned(captureSchemaVersion) else { throw AuthorityCommandStartupError.invalidConfiguration }
        func number(_ key: UInt64) throws -> UInt64 {
            guard case .unsigned(let value) = fields[key] else { throw AuthorityCommandStartupError.invalidConfiguration }; return value
        }
        func integer(_ key: UInt64) throws -> Int {
            guard let value = Int(exactly: try number(key)) else { throw AuthorityCommandStartupError.invalidConfiguration }; return value
        }
        func duration(_ key: UInt64) throws -> UInt32 {
            guard let value = UInt32(exactly: try number(key)) else { throw AuthorityCommandStartupError.invalidConfiguration }; return value
        }
        let environment = try rawEnvironment.map { raw -> CapturedEnvironmentEntry in
            guard case .map(let values) = raw, Set(values.keys) == [0, 1], case .bytes(let name) = values[0],
                  case .bytes(let value) = values[1] else { throw AuthorityCommandStartupError.invalidConfiguration }
            return .init(name: name, value: value, source: .minimal)
        }
        let result = try Self(presence: .decode(presence), serviceName: service, policyPath: path, environment: environment,
            submissionLimits: decodeLimits(fields[5]), captureLimits: decodeLimits(fields[6]), maximumSessions: integer(7),
            receiveWaitMilliseconds: duration(8), replyTimeoutMilliseconds: duration(9), maximumAncestryEntries: integer(10),
            approvalLifetimeMilliseconds: number(11))
        guard result.canonicalBytes == bytes else { throw AuthorityCommandStartupError.invalidConfiguration }; return result
    }
    /// Size checks use the real codecs for both advertised profiles, including the configured environment.
    /// These records are sizing examples only. They carry no OS provenance or execution authority.
    private static func validateProtocolBudgets(environment: [CapturedEnvironmentEntry], callerUID: UInt32,
        submissionLimits: CBORLimits, captureLimits: CBORLimits, maximumRequestBodyBytes: Int) throws {
        let binding = CapturedSubmission(id: Data(repeating: 1, count: 16), nonce: Data(repeating: 2, count: 32),
            callerBinding: Data(repeating: 3, count: 16))
        let file = CapturedFileIdentity(device: 1, inode: 1)
        let path = Data("/usr/bin/true".utf8), arguments = [Data("true".utf8)]
        let requester = CapturedRequester(executablePath: Data("/Applications/Remozio.app/Contents/MacOS/remozio".utf8),
            realUID: callerUID, effectiveUID: callerUID, pid: 1, pidVersion: 1,
            signing: .init(status: .validated, identifier: "dev.remozio.frontend", team: "TEAMID1234",
                cdHash: Data(repeating: 4, count: 20)), sessionID: 1, ttyPath: nil)
        for mode in [CommandIOMode.pipes, .pty] {
            _ = try CommandSubmission(schemaVersion: 1, executablePath: path, arguments: arguments,
                directoryPath: Data("/".utf8), requestedTargetUID: 0, environmentAdditions: [], ioMode: mode,
                disconnectBehavior: .terminate, unverifiedRationale: nil, binding: binding, limits: submissionLimits)
            let source = CapturedCommandInput(kind: mode == .pty ? .pty : .pipe,
                streamBinding: Data(repeating: 5, count: 16), observedPath: nil, identity: file)
            let input = CapturedCommandStream(source: source, access: mode == .pty ? .readWrite : .readOnly, flags: [])
            let output = CapturedCommandStream(source: source, access: mode == .pty ? .readWrite : .writeOnly, flags: [])
            let terminal: CapturedCommandTerminal? = mode == .pty ? .init(stream: input, sessionID: 1, terminalDevice: 1) : nil
            let layout = CapturedCommandStdioLayout(input: input, output: output, error: output,
                terminal: terminal, ptyMask: mode == .pty ? 7 : 0)
            let capture = try CommandCapture(schemaVersion: captureSchemaVersion,
                executable: .init(path: path, identity: file, sha256: Data(repeating: 6, count: 32)), arguments: arguments,
                directory: .init(path: Data("/".utf8), identity: file),
                target: .init(uid: 0, gid: 0, supplementaryGroups: [0], observedName: "root"),
                environment: environment, input: source, ioMode: mode, disconnectBehavior: .terminate,
                requester: requester, ancestry: .init(completeness: .unavailable, entries: [], reason: .unsupported),
                unverifiedRationale: nil, submission: binding, stdioLayout: layout, limits: captureLimits)
            let bodyLimits = try CBORLimits(maxBytes: maximumRequestBodyBytes, maxDepth: 16, maxItems: 4096)
            _ = try IssuedRequestPayload(contract: .init(requestKind: .command, wireVersion: 1, schemaVersion: captureSchemaVersion),
                macID: Data(repeating: 7, count: 16), accountID: Data(repeating: 8, count: 16),
                requestID: Data(repeating: 9, count: 16), challenge: Data(repeating: 10, count: 32),
                requiredFeatures: [], createdUnixMilliseconds: 1, expiresUnixMilliseconds: 2,
                canonicalCapture: capture.canonicalBytes, permittedActions: [.init(choice: .execute, scope: .currentRequest)],
                bodyLimits: bodyLimits, captureLimits: captureLimits)
        }
    }

    private static func encodeLimits(_ limits: CBORLimits) -> CBORValue {
        .map([0: .unsigned(UInt64(limits.maxBytes)), 1: .unsigned(UInt64(limits.maxDepth)), 2: .unsigned(UInt64(limits.maxItems))])
    }
    private static func decodeLimits(_ raw: CBORValue?) throws -> CBORLimits {
        guard case .map(let values) = raw, Set(values.keys) == [0, 1, 2] else { throw AuthorityCommandStartupError.invalidConfiguration }
        func integer(_ key: UInt64) throws -> Int {
            guard case .unsigned(let number) = values[key], let value = Int(exactly: number) else {
                throw AuthorityCommandStartupError.invalidConfiguration
            }
            return value
        }
        return try .init(maxBytes: integer(0), maxDepth: integer(1), maxItems: integer(2))
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: 65_536, maxDepth: 3, maxItems: 512) } }
}
