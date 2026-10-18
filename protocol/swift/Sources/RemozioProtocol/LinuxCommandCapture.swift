import Foundation

public struct CapturedLinuxCredentials: Equatable, Sendable {
    public let realUID: UInt32
    public let effectiveUID: UInt32
    public let savedUID: UInt32
    public let filesystemUID: UInt32
    public let realGID: UInt32
    public let effectiveGID: UInt32
    public let savedGID: UInt32
    public let filesystemGID: UInt32
    public let supplementaryGroups: [UInt32]

    public init(realUID: UInt32, effectiveUID: UInt32, savedUID: UInt32, filesystemUID: UInt32,
                realGID: UInt32, effectiveGID: UInt32, savedGID: UInt32, filesystemGID: UInt32,
                supplementaryGroups: [UInt32]) {
        self.realUID = realUID; self.effectiveUID = effectiveUID; self.savedUID = savedUID; self.filesystemUID = filesystemUID
        self.realGID = realGID; self.effectiveGID = effectiveGID; self.savedGID = savedGID; self.filesystemGID = filesystemGID
        self.supplementaryGroups = supplementaryGroups
    }
}

/// Host assertions about a retained Linux frontend. These values do not independently prove its code or process identity.
public struct CapturedLinuxRequester: Equatable, Sendable {
    public static let supportedProfile = "linux-protected-single-thread-v1"
    public let profile: String
    public let pid: UInt32
    public let processBinding: Data
    public let monitorIncarnation: Data
    public let execEpoch: UInt64
    public let executable: CapturedExecutable
    public let credentials: CapturedLinuxCredentials
    public let sessionID: UInt32?
    public let codePolicyDigest: Data

    public init(profile: String = Self.supportedProfile, pid: UInt32, processBinding: Data, monitorIncarnation: Data,
                execEpoch: UInt64, executable: CapturedExecutable, credentials: CapturedLinuxCredentials,
                sessionID: UInt32?, codePolicyDigest: Data) {
        self.profile = profile; self.pid = pid; self.processBinding = processBinding; self.monitorIncarnation = monitorIncarnation
        self.execEpoch = execEpoch; self.executable = executable; self.credentials = credentials
        self.sessionID = sessionID; self.codePolicyDigest = codePolicyDigest
    }
}

/// Schema 4 claims only. Parsing or encoding never grants Linux caller, enrollment, or dispatch authority.
public struct LinuxCommandCapture: Equatable, Sendable {
    public static let supportedSchemaVersions: Set<UInt64> = [4]
    public let schemaVersion: UInt64
    public let canonicalBytes: Data
    public let executable: CapturedExecutable
    public let arguments: [Data]
    public let directory: CapturedDirectory
    public let target: CommandTarget
    public let environment: [CapturedEnvironmentEntry]
    public let input: CapturedCommandInput
    public let ioMode: CommandIOMode
    public let stdioLayout: CapturedCommandStdioLayout
    public let disconnectBehavior: StartedCommandDisconnect
    public let requester: CapturedLinuxRequester
    public let ancestry: CapturedAncestry
    public let unverifiedRationale: String?
    public let submission: CapturedSubmission

    public init(schemaVersion: UInt64 = 4, executable: CapturedExecutable, arguments: [Data], directory: CapturedDirectory,
                target: CommandTarget, environment: [CapturedEnvironmentEntry], input: CapturedCommandInput,
                ioMode: CommandIOMode = .pipes, disconnectBehavior: StartedCommandDisconnect = .terminate,
                requester: CapturedLinuxRequester,
                ancestry: CapturedAncestry = .init(completeness: .unavailable, entries: [], reason: .unsupported),
                unverifiedRationale: String?, submission: CapturedSubmission, stdioLayout: CapturedCommandStdioLayout,
                limits: CBORLimits) throws {
        guard Self.supportedSchemaVersions.contains(schemaVersion) else { throw CommandCaptureError.version }
        var fields = CommandCaptureCodec.invocationFields(schemaVersion: schemaVersion, executable: executable,
            arguments: arguments, directory: directory, target: target, environment: environment, input: input,
            ioMode: ioMode, disconnectBehavior: disconnectBehavior, unverifiedRationale: unverifiedRationale, submission: submission)
        let credentials = requester.credentials
        let credentialValues: [UInt32] = [credentials.realUID, credentials.effectiveUID, credentials.savedUID, credentials.filesystemUID,
            credentials.realGID, credentials.effectiveGID, credentials.savedGID, credentials.filesystemGID]
        var credentialFields = Dictionary(uniqueKeysWithValues: credentialValues.enumerated().map { (UInt64($0.offset), CBORValue.unsigned(UInt64($0.element))) })
        credentialFields[8] = .array(credentials.supplementaryGroups.map { .unsigned(UInt64($0)) })
        fields[9] = .map([0: .text(requester.profile), 1: .unsigned(UInt64(requester.pid)),
            2: .bytes(requester.processBinding), 3: .bytes(requester.monitorIncarnation), 4: .unsigned(requester.execEpoch),
            5: CommandCaptureCodec.executableValue(requester.executable), 6: .map(credentialFields),
            7: requester.sessionID.map { .unsigned(UInt64($0)) } ?? .null, 8: .bytes(requester.codePolicyDigest)])
        guard ancestry == Self.unavailableAncestry else { throw CommandCaptureError.ancestry }
        fields[10] = Self.ancestryValue
        fields[13] = CommandCaptureCodec.layoutValue(stdioLayout)
        try self.init(canonicalBytes: DeterministicCBOR.encode(.map(fields), limits: limits), limits: limits,
            expectedSchemaVersion: schemaVersion)
    }

    public init(canonicalBytes: Data, limits: CBORLimits, expectedSchemaVersion: UInt64 = 4) throws {
        guard Self.supportedSchemaVersions.contains(expectedSchemaVersion) else { throw CommandCaptureError.version }
        let root = try CaptureFields(DeterministicCBOR.decode(canonicalBytes, limits: limits), count: 14)
        schemaVersion = try root.uint(0)
        guard schemaVersion == expectedSchemaVersion else { throw CommandCaptureError.version }
        let invocation = try CommandCaptureInvocation(root: root, schemaVersion: schemaVersion)
        executable = invocation.executable; arguments = invocation.arguments; directory = invocation.directory
        target = invocation.target; environment = invocation.environment; input = invocation.input
        ioMode = invocation.ioMode; disconnectBehavior = invocation.disconnectBehavior
        guard ioMode == .pipes, disconnectBehavior == .terminate else { throw CommandCaptureError.fields }
        let requester = try CaptureFields(root[9], count: 9)
        guard requester[0] == .text(CapturedLinuxRequester.supportedProfile) else { throw CommandCaptureError.enumeration }
        let execEpoch = try requester.uint(4)
        guard execEpoch > 0 else { throw CommandCaptureError.type }
        let credentials = try CaptureFields(requester[6], count: 9)
        let uids = try (UInt64(0)...3).map { try credentials.uint32($0) }
        let gids = try (UInt64(4)...7).map { try credentials.uint32($0) }
        let groups = try credentials.array(8).map { try CaptureFields.uint32($0) }
        guard uids.allSatisfy({ $0 == uids[0] }), gids.allSatisfy({ $0 == gids[0] }),
              zip(groups, groups.dropFirst()).allSatisfy({ $0.0 < $0.1 }) else { throw CommandCaptureError.fields }
        self.requester = try CapturedLinuxRequester(pid: requester.pid(1), processBinding: requester.bytes(2, count: 16),
            monitorIncarnation: requester.bytes(3, count: 16), execEpoch: execEpoch,
            executable: CommandCaptureCodec.executable(requester[5]),
            credentials: .init(realUID: uids[0], effectiveUID: uids[1], savedUID: uids[2], filesystemUID: uids[3],
                realGID: gids[0], effectiveGID: gids[1], savedGID: gids[2], filesystemGID: gids[3], supplementaryGroups: groups),
            sessionID: requester[7] == .null ? nil : requester.pid(7), codePolicyDigest: requester.bytes(8, count: 32))
        guard root[10] == Self.ancestryValue else { throw CommandCaptureError.ancestry }
        ancestry = Self.unavailableAncestry
        unverifiedRationale = invocation.unverifiedRationale; submission = invocation.submission
        stdioLayout = try CommandCaptureCodec.layout(root[13], schemaVersion: schemaVersion, input: input,
            ioMode: ioMode, requesterSessionID: self.requester.sessionID)
        self.canonicalBytes = canonicalBytes
    }

    private static var ancestryValue: CBORValue { .map([0: .unsigned(2), 1: .array([]), 2: .unsigned(4)]) }
    private static var unavailableAncestry: CapturedAncestry { .init(completeness: .unavailable, entries: [], reason: .unsupported) }
}
