import Foundation

/// Shared invocation fields only. Each host schema parses its own requester and admission profile.
struct CommandCaptureInvocation {
    let executable: CapturedExecutable
    let arguments: [Data]
    let directory: CapturedDirectory
    let target: CommandTarget
    let environment: [CapturedEnvironmentEntry]
    let input: CapturedCommandInput
    let ioMode: CommandIOMode
    let disconnectBehavior: StartedCommandDisconnect
    let unverifiedRationale: String?
    let submission: CapturedSubmission

    init(root: CaptureFields, schemaVersion: UInt64) throws {
        executable = try CommandCaptureCodec.executable(root[1])
        arguments = try root.array(2).map { try CaptureFields.cString($0) }
        guard !arguments.isEmpty else { throw CommandCaptureError.bytes }
        let directory = try CaptureFields(root[3], count: 2)
        self.directory = try CapturedDirectory(path: directory.path(0), identity: directory.identity(1))
        let target = try CaptureFields(root[4], count: 4)
        self.target = try CommandTarget(uid: target.uint32(0), gid: target.uint32(1),
            supplementaryGroups: target.array(2).map { try CaptureFields.uint32($0) }, observedName: target.optionalText(3))
        var entries: [CapturedEnvironmentEntry] = []
        var previous: Data?
        for value in try root.array(5) {
            let entry = try CaptureFields(value, count: 3)
            let name = try CaptureFields.cString(entry[0])
            guard !name.isEmpty, !name.contains(0x3d), previous == nil || previous!.lexicographicallyPrecedes(name) else {
                throw CommandCaptureError.environment
            }
            entries.append(try CapturedEnvironmentEntry(name: name, value: CaptureFields.cString(entry[1]), source: entry.tag(2)))
            previous = name
        }
        environment = entries
        input = try CommandCaptureCodec.source(root[6], schemaVersion: schemaVersion)
        ioMode = try root.tag(7)
        disconnectBehavior = try root.tag(8)
        unverifiedRationale = try root.optionalText(11)
        let submission = try CaptureFields(root[12], count: 3)
        self.submission = try CapturedSubmission(id: submission.bytes(0, count: 16), nonce: submission.bytes(1, count: 32),
            callerBinding: submission.bytes(2, count: 16))
    }
}

enum CommandCaptureCodec {
    static func identityValue(_ value: CapturedFileIdentity) -> CBORValue {
        .map([0: .unsigned(value.device), 1: .unsigned(value.inode)])
    }
    static func executableValue(_ value: CapturedExecutable) -> CBORValue {
        .map([0: .bytes(value.path), 1: identityValue(value.identity), 2: .bytes(value.sha256)])
    }
    static func sourceValue(_ value: CapturedCommandInput) -> CBORValue {
        .map([0: .unsigned(value.kind.rawValue), 1: value.streamBinding.map { .bytes($0) } ?? .null,
            2: value.observedPath.map { .bytes($0) } ?? .null, 3: value.identity.map(identityValue) ?? .null])
    }
    static func streamValue(_ value: CapturedCommandStream) -> CBORValue {
        .map([0: sourceValue(value.source), 1: .unsigned(value.access.rawValue), 2: .unsigned(value.flags.rawValue)])
    }
    static func layoutValue(_ value: CapturedCommandStdioLayout) -> CBORValue {
        .map([0: streamValue(value.input), 1: streamValue(value.output), 2: streamValue(value.error),
            3: value.terminal.map { .map([0: streamValue($0.stream), 1: .unsigned(UInt64($0.sessionID)),
                2: .unsigned(UInt64($0.terminalDevice))]) } ?? .null, 4: .unsigned(UInt64(value.ptyMask))])
    }
    static func invocationFields(schemaVersion: UInt64, executable: CapturedExecutable, arguments: [Data],
                                 directory: CapturedDirectory, target: CommandTarget, environment: [CapturedEnvironmentEntry],
                                 input: CapturedCommandInput, ioMode: CommandIOMode, disconnectBehavior: StartedCommandDisconnect,
                                 unverifiedRationale: String?, submission: CapturedSubmission) -> [UInt64: CBORValue] {
        [0: .unsigned(schemaVersion), 1: executableValue(executable), 2: .array(arguments.map { .bytes($0) }),
            3: .map([0: .bytes(directory.path), 1: identityValue(directory.identity)]),
            4: .map([0: .unsigned(UInt64(target.uid)), 1: .unsigned(UInt64(target.gid)),
                2: .array(target.supplementaryGroups.map { .unsigned(UInt64($0)) }), 3: target.observedName.map { .text($0) } ?? .null]),
            5: .array(environment.map { .map([0: .bytes($0.name), 1: .bytes($0.value), 2: .unsigned($0.source.rawValue)]) }),
            6: sourceValue(input), 7: .unsigned(ioMode.rawValue), 8: .unsigned(disconnectBehavior.rawValue),
            11: unverifiedRationale.map { .text($0) } ?? .null,
            12: .map([0: .bytes(submission.id), 1: .bytes(submission.nonce), 2: .bytes(submission.callerBinding)])]
    }

    static func executable(_ value: CBORValue) throws -> CapturedExecutable {
        let fields = try CaptureFields(value, count: 3)
        return try CapturedExecutable(path: fields.path(0), identity: fields.identity(1), sha256: fields.bytes(2, count: 32))
    }
    static func source(_ value: CBORValue, schemaVersion: UInt64) throws -> CapturedCommandInput {
        let fields = try CaptureFields(value, count: 4)
        let kind: CommandInputKind = try fields.tag(0)
        guard schemaVersion >= kind.minimumSchemaVersion else { throw CommandCaptureError.enumeration }
        let binding = try fields.optionalBytes(1, count: 16), path = try fields.optionalPath(2), identity = try fields.optionalIdentity(3)
        if kind == .null {
            guard binding == nil, path == nil, identity == nil else { throw CommandCaptureError.fields }
        } else { guard binding != nil else { throw CommandCaptureError.bytes } }
        return CapturedCommandInput(kind: kind, streamBinding: binding, observedPath: path, identity: identity)
    }
    static func stream(_ value: CBORValue, schemaVersion: UInt64) throws -> CapturedCommandStream {
        let fields = try CaptureFields(value, count: 3)
        let flags = try fields.uint(2)
        guard flags <= 15 else { throw CommandCaptureError.enumeration }
        return try CapturedCommandStream(source: source(fields[0], schemaVersion: schemaVersion), access: fields.tag(1), flags: .init(rawValue: flags))
    }
    static func layout(_ value: CBORValue, schemaVersion: UInt64, input: CapturedCommandInput,
                       ioMode: CommandIOMode, requesterSessionID: UInt32?) throws -> CapturedCommandStdioLayout {
        let fields = try CaptureFields(value, count: 5)
        let first = try stream(fields[0], schemaVersion: schemaVersion), output = try stream(fields[1], schemaVersion: schemaVersion),
            error = try stream(fields[2], schemaVersion: schemaVersion)
        let terminal: CapturedCommandTerminal?
        if fields[3] == .null { terminal = nil }
        else {
            let value = try CaptureFields(fields[3], count: 3)
            let control = try stream(value[0], schemaVersion: schemaVersion), session = try value.pid(1), device = try value.uint32(2)
            guard control.access == .readWrite, [.tty, .pty].contains(control.source.kind),
                  control.source.identity != nil, device != UInt32.max, requesterSessionID == session else {
                throw CommandCaptureError.fields
            }
            terminal = CapturedCommandTerminal(stream: control, sessionID: session, terminalDevice: device)
        }
        let mask = try fields.uint32(4)
        guard mask <= 7, first.source == input, first.access != .writeOnly,
              output.access != .readOnly, error.access != .readOnly,
              ioMode == .pty || (mask == 0 && terminal == nil), terminal != nil || mask == 0 else {
            throw CommandCaptureError.fields
        }
        for (index, value) in [first, output, error].enumerated() where mask & (1 << index) != 0 {
            guard [.tty, .pty].contains(value.source.kind), let identity = value.source.identity,
                  identity == terminal?.stream.source.identity else { throw CommandCaptureError.fields }
        }
        return CapturedCommandStdioLayout(input: first, output: output, error: error, terminal: terminal, ptyMask: mask)
    }
}
