package dev.remozio.protocol

import java.util.Collections

enum class CommandCaptureFailure { FIELDS, TYPE, VERSION, BYTES, PATH, ENVIRONMENT, ENUMERATION, ANCESTRY }
class CommandCaptureException(val reason: CommandCaptureFailure) : IllegalArgumentException(reason.name)

interface CommandWireTag { val wireValue: ULong }
data class CapturedFileIdentity(val device: ULong, val inode: ULong)
data class CapturedExecutable(val path: CborValue.Bytes, val identity: CapturedFileIdentity, val sha256: CborValue.Bytes)
data class CapturedDirectory(val path: CborValue.Bytes, val identity: CapturedFileIdentity)
data class CommandTarget(val uid: UInt, val gid: UInt, val supplementaryGroups: List<UInt>, val observedName: String?)
enum class EnvironmentSource(override val wireValue: ULong) : CommandWireTag { MINIMAL(0u), REQUESTED(1u) }
data class CapturedEnvironmentEntry(val name: CborValue.Bytes, val value: CborValue.Bytes, val source: EnvironmentSource)
enum class CommandInputKind(override val wireValue: ULong) : CommandWireTag { NULL(0u), PIPE(1u), FILE(2u), TTY(3u), PTY(4u), SOCKET(5u), DIRECTORY(6u), DEVICE(7u), OTHER(8u) }
data class CapturedCommandInput(val kind: CommandInputKind, val streamBinding: CborValue.Bytes?, val observedPath: CborValue.Bytes?, val identity: CapturedFileIdentity?)
enum class CommandStreamAccess(override val wireValue: ULong) : CommandWireTag { READ_ONLY(0u), WRITE_ONLY(1u), READ_WRITE(2u) }
data class CommandStreamFlags(val wireValue: ULong) {
    val append: Boolean get() = wireValue and 1uL != 0uL
    val nonblocking: Boolean get() = wireValue and 2uL != 0uL
    val asynchronous: Boolean get() = wireValue and 4uL != 0uL
    val synchronous: Boolean get() = wireValue and 8uL != 0uL
}
data class CapturedCommandStream(val source: CapturedCommandInput, val access: CommandStreamAccess, val flags: CommandStreamFlags)
data class CapturedCommandTerminal(val stream: CapturedCommandStream, val sessionID: UInt, val terminalDevice: UInt)
data class CapturedCommandStdioLayout(val input: CapturedCommandStream, val output: CapturedCommandStream,
    val error: CapturedCommandStream, val terminal: CapturedCommandTerminal?, val ptyMask: UInt)
enum class CommandIOMode(override val wireValue: ULong) : CommandWireTag { PIPES(0u), PTY(1u) }
enum class StartedCommandDisconnect(override val wireValue: ULong) : CommandWireTag { TERMINATE(0u), CONTINUE_RUNNING(1u) }
enum class CapturedSigningStatus(override val wireValue: ULong) : CommandWireTag { UNSIGNED(0u), AD_HOC(1u), VALIDATED(2u), INVALID(3u), UNAVAILABLE(4u) }
data class CapturedSigningIdentity(val status: CapturedSigningStatus, val identifier: String?, val team: String?, val cdHash: CborValue.Bytes?)
data class CapturedRequester(val executablePath: CborValue.Bytes, val realUID: UInt, val effectiveUID: UInt, val pid: UInt,
    val pidVersion: UInt, val signing: CapturedSigningIdentity, val sessionID: UInt?, val ttyPath: CborValue.Bytes?)
enum class AncestryCompleteness(override val wireValue: ULong) : CommandWireTag { COMPLETE(0u), PARTIAL(1u), UNAVAILABLE(2u) }
enum class AncestryReason(override val wireValue: ULong) : CommandWireTag { NONE(0u), EXITED(1u), PERMISSION(2u), TRUNCATED(3u), UNSUPPORTED(4u) }
data class CapturedAncestor(val pid: UInt, val pidVersion: UInt, val executablePath: CborValue.Bytes?, val uid: UInt)
data class CapturedAncestry(val completeness: AncestryCompleteness, val entries: List<CapturedAncestor>, val reason: AncestryReason)
data class CapturedSubmission(val id: CborValue.Bytes, val nonce: CborValue.Bytes, val callerBinding: CborValue.Bytes)

/** All credential values are host assertions; this model supplies no independent OS attestation. */
class CapturedLinuxCredentials(val realUID: UInt, val effectiveUID: UInt, val savedUID: UInt, val filesystemUID: UInt,
    val realGID: UInt, val effectiveGID: UInt, val savedGID: UInt, val filesystemGID: UInt,
    supplementaryGroups: List<UInt>) {
    val supplementaryGroups: List<UInt> = immutable(supplementaryGroups)
}
data class CapturedLinuxRequester(val profile: String, val pid: UInt, val processBinding: CborValue.Bytes,
    val monitorIncarnation: CborValue.Bytes, val execEpoch: ULong, val executable: CapturedExecutable,
    val credentials: CapturedLinuxCredentials, val sessionID: UInt?, val codePolicyDigest: CborValue.Bytes)

/** Authenticated transport and issuance are separate from these typed host claims. */
sealed interface CommandCapturePayload {
    val schemaVersion: ULong
    val canonicalBytes: ByteArray
    val canonicalByteCount: Int
    val executable: CapturedExecutable
    val arguments: List<CborValue.Bytes>
    val directory: CapturedDirectory
    val target: CommandTarget
    val environment: List<CapturedEnvironmentEntry>
    val input: CapturedCommandInput
    val ioMode: CommandIOMode
    val stdioLayout: CapturedCommandStdioLayout?
    val disconnectBehavior: StartedCommandDisconnect
    val ancestry: CapturedAncestry
    val unverifiedRationale: String?
    val submission: CapturedSubmission

    companion object {
        val supportedSchemaVersions: Set<ULong> = Collections.unmodifiableSet(setOf(1u, 2u, 3u, 4u))
        /** The negotiated outer schema is mandatory; never infer or translate it from capture bytes. */
        fun decode(canonicalBytes: ByteArray, limits: CborLimits, expectedSchemaVersion: ULong): CommandCapturePayload =
            when (expectedSchemaVersion) {
                1uL, 2uL, 3uL -> CommandCapture(canonicalBytes, limits, expectedSchemaVersion)
                4uL -> LinuxCommandCapture(canonicalBytes, limits, expectedSchemaVersion)
                else -> fail(CommandCaptureFailure.VERSION)
            }
    }
}

/** Parses claims only. OS capture, authenticated issuance, and execution are separate responsibilities. */
class CommandCapture(canonicalBytes: ByteArray, limits: CborLimits, expectedSchemaVersion: ULong = 1u) : CommandCapturePayload {
    companion object { val supportedSchemaVersions: Set<ULong> = Collections.unmodifiableSet(setOf(1u, 2u, 3u)) }
    private val parsed = run {
        ensure(expectedSchemaVersion in supportedSchemaVersions, CommandCaptureFailure.VERSION)
        ParsedCommandCapture(canonicalBytes, limits, expectedSchemaVersion, ::parseMacRequester) { it.sessionID }
    }
    override val schemaVersion: ULong get() = parsed.schemaVersion
    override val canonicalBytes: ByteArray get() = parsed.canonicalBytes
    override val canonicalByteCount: Int get() = parsed.canonicalByteCount
    override val executable: CapturedExecutable get() = parsed.executable
    override val arguments: List<CborValue.Bytes> get() = parsed.arguments
    override val directory: CapturedDirectory get() = parsed.directory
    override val target: CommandTarget get() = parsed.target
    override val environment: List<CapturedEnvironmentEntry> get() = parsed.environment
    override val input: CapturedCommandInput get() = parsed.input
    override val ioMode: CommandIOMode get() = parsed.ioMode
    override val stdioLayout: CapturedCommandStdioLayout? get() = parsed.stdioLayout
    override val disconnectBehavior: StartedCommandDisconnect get() = parsed.disconnectBehavior
    override val ancestry: CapturedAncestry get() = parsed.ancestry
    override val unverifiedRationale: String? get() = parsed.unverifiedRationale
    override val submission: CapturedSubmission get() = parsed.submission
    val requester: CapturedRequester get() = parsed.requester
}

/** Parses claims only. OS capture, authenticated issuance, and execution are separate responsibilities. */
class LinuxCommandCapture(canonicalBytes: ByteArray, limits: CborLimits, expectedSchemaVersion: ULong) : CommandCapturePayload {
    companion object { val supportedSchemaVersions: Set<ULong> = Collections.unmodifiableSet(setOf(4u)) }
    private val parsed = run {
        ensure(expectedSchemaVersion in supportedSchemaVersions, CommandCaptureFailure.VERSION)
        ParsedCommandCapture(canonicalBytes, limits, expectedSchemaVersion, ::parseLinuxRequester) { it.sessionID }
    }
    override val schemaVersion: ULong get() = parsed.schemaVersion
    override val canonicalBytes: ByteArray get() = parsed.canonicalBytes
    override val canonicalByteCount: Int get() = parsed.canonicalByteCount
    override val executable: CapturedExecutable get() = parsed.executable
    override val arguments: List<CborValue.Bytes> get() = parsed.arguments
    override val directory: CapturedDirectory get() = parsed.directory
    override val target: CommandTarget get() = parsed.target
    override val environment: List<CapturedEnvironmentEntry> get() = parsed.environment
    override val input: CapturedCommandInput get() = parsed.input
    override val ioMode: CommandIOMode get() = parsed.ioMode
    override val stdioLayout: CapturedCommandStdioLayout? get() = parsed.stdioLayout
    override val disconnectBehavior: StartedCommandDisconnect get() = parsed.disconnectBehavior
    override val ancestry: CapturedAncestry get() = parsed.ancestry
    override val unverifiedRationale: String? get() = parsed.unverifiedRationale
    override val submission: CapturedSubmission get() = parsed.submission
    val requester: CapturedLinuxRequester get() = parsed.requester

    init {
        ensure(ioMode == CommandIOMode.PIPES && disconnectBehavior == StartedCommandDisconnect.TERMINATE,
            CommandCaptureFailure.FIELDS)
        ensure(stdioLayout?.terminal == null && stdioLayout?.ptyMask == 0u, CommandCaptureFailure.FIELDS)
        ensure(ancestry.completeness == AncestryCompleteness.UNAVAILABLE && ancestry.entries.isEmpty() &&
            ancestry.reason == AncestryReason.UNSUPPORTED, CommandCaptureFailure.ANCESTRY)
    }
}

private fun parseMacRequester(requester: CaptureFields): CapturedRequester {
    val signing = CaptureFields(requester[5u], 4)
    return CapturedRequester(requester.path(0u), requester.uint32(1u), requester.uint32(2u), requester.pid(3u), requester.uint32(4u),
        CapturedSigningIdentity(signing.tag(0u, CapturedSigningStatus.entries), signing.optionalText(1u), signing.optionalText(2u), signing.optionalBytes(3u, 20)),
        requester.optionalUInt32(6u), requester.optionalPath(7u))
}

private fun parseLinuxRequester(requester: CaptureFields): CapturedLinuxRequester {
    val profile = requester.text(0u)
    ensure(profile == "linux-protected-single-thread-v1", CommandCaptureFailure.VERSION)
    val epoch = requester.uint(4u)
    ensure(epoch > 0uL, CommandCaptureFailure.TYPE)
    val executable = CaptureFields(requester[5u], 3)
    val credentials = CaptureFields(requester[6u], 9)
    val uid = credentials.uint32(0u)
    val gid = credentials.uint32(4u)
    val ids = (0uL..7uL).map { credentials.uint32(it) }
    ensure(ids.take(4).all { it == uid } && ids.drop(4).all { it == gid }, CommandCaptureFailure.FIELDS)
    val groups = credentials.array(8u).map { CaptureFields.uint32(it) }
    ensure(groups.zipWithNext().all { (previous, next) -> previous < next }, CommandCaptureFailure.FIELDS)
    return CapturedLinuxRequester(profile, requester.pid(1u), requester.bytes(2u, 16), requester.bytes(3u, 16), epoch,
        CapturedExecutable(executable.path(0u), executable.identity(1u), executable.bytes(2u, 32)),
        CapturedLinuxCredentials(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6], ids[7], groups),
        if (requester[7u] == CborValue.Null) null else requester.pid(7u), requester.bytes(8u, 32))
}

private class ParsedCommandCapture<R>(canonicalBytes: ByteArray, limits: CborLimits, expectedSchemaVersion: ULong,
    parseRequester: (CaptureFields) -> R, requesterSession: (R) -> UInt?) {
    val schemaVersion: ULong
    private val original: CborValue.Bytes
    val canonicalBytes: ByteArray get() = original.copyBytes()
    val canonicalByteCount: Int get() = original.size
    val executable: CapturedExecutable
    val arguments: List<CborValue.Bytes>
    val directory: CapturedDirectory
    val target: CommandTarget
    val environment: List<CapturedEnvironmentEntry>
    val input: CapturedCommandInput
    val ioMode: CommandIOMode
    val stdioLayout: CapturedCommandStdioLayout?
    val disconnectBehavior: StartedCommandDisconnect
    val requester: R
    val ancestry: CapturedAncestry
    val unverifiedRationale: String?
    val submission: CapturedSubmission

    init {
        // Bound input before retaining another copy.
        if (canonicalBytes.size > limits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
        original = CborValue.Bytes(canonicalBytes)
        val root = CaptureFields(DeterministicCbor.decode(original.copyBytes(), limits), if (expectedSchemaVersion >= 3uL) 14 else 13)
        schemaVersion = root.uint(0u)
        ensure(schemaVersion == expectedSchemaVersion, CommandCaptureFailure.VERSION)
        val executable = CaptureFields(root[1u], 3)
        this.executable = CapturedExecutable(executable.path(0u), executable.identity(1u), executable.bytes(2u, 32))
        arguments = immutable(root.array(2u).map { CaptureFields.cString(it) })
        ensure(arguments.isNotEmpty(), CommandCaptureFailure.BYTES)
        val directory = CaptureFields(root[3u], 2)
        this.directory = CapturedDirectory(directory.path(0u), directory.identity(1u))
        val target = CaptureFields(root[4u], 4)
        this.target = CommandTarget(target.uint32(0u), target.uint32(1u),
            immutable(target.array(2u).map { CaptureFields.uint32(it) }), target.optionalText(3u))
        var previous: ByteArray? = null
        environment = immutable(root.array(5u).map { value ->
            val entry = CaptureFields(value, 3)
            val name = CaptureFields.cString(entry[0u])
            val bytes = name.copyBytes()
            ensure(bytes.isNotEmpty() && bytes.none { it == 0x3d.toByte() } &&
                (previous == null || lexicographicallyBefore(previous, bytes)), CommandCaptureFailure.ENVIRONMENT)
            previous = bytes
            CapturedEnvironmentEntry(name, CaptureFields.cString(entry[1u]), entry.tag(2u, EnvironmentSource.entries))
        })
        fun source(value: CborValue): CapturedCommandInput {
            val fields = CaptureFields(value, 4)
            val kind = fields.tag(0u, CommandInputKind.entries)
            ensure(schemaVersion >= 2uL || kind.wireValue <= 4uL, CommandCaptureFailure.ENUMERATION)
            val binding = fields.optionalBytes(1u, 16)
            val path = fields.optionalPath(2u)
            val identity = fields.optionalIdentity(3u)
            if (kind == CommandInputKind.NULL) ensure(binding == null && path == null && identity == null, CommandCaptureFailure.FIELDS)
            else ensure(binding != null, CommandCaptureFailure.BYTES)
            return CapturedCommandInput(kind, binding, path, identity)
        }
        input = source(root[6u])
        ioMode = root.tag(7u, CommandIOMode.entries)
        disconnectBehavior = root.tag(8u, StartedCommandDisconnect.entries)
        requester = parseRequester(CaptureFields(root[9u], if (schemaVersion == 4uL) 9 else 8))
        val ancestry = CaptureFields(root[10u], 3)
        val completeness = ancestry.tag(0u, AncestryCompleteness.entries)
        val reason = ancestry.tag(2u, AncestryReason.entries)
        val entries = immutable(ancestry.array(1u).map { value ->
            val entry = CaptureFields(value, 4)
            CapturedAncestor(entry.pid(0u), entry.uint32(1u), entry.optionalPath(2u), entry.uint32(3u))
        })
        ensure((completeness == AncestryCompleteness.COMPLETE) == (reason == AncestryReason.NONE) &&
            (completeness != AncestryCompleteness.UNAVAILABLE || entries.isEmpty()), CommandCaptureFailure.ANCESTRY)
        this.ancestry = CapturedAncestry(completeness, entries, reason)
        unverifiedRationale = root.optionalText(11u)
        val submission = CaptureFields(root[12u], 3)
        this.submission = CapturedSubmission(submission.bytes(0u, 16), submission.bytes(1u, 32), submission.bytes(2u, 16))
        stdioLayout = if (schemaVersion >= 3uL) {
            fun stream(value: CborValue): CapturedCommandStream {
                val fields = CaptureFields(value, 3)
                val flags = fields.uint(2u)
                ensure(flags <= 15uL, CommandCaptureFailure.ENUMERATION)
                return CapturedCommandStream(source(fields[0u]), fields.tag(1u, CommandStreamAccess.entries), CommandStreamFlags(flags))
            }
            val fields = CaptureFields(root[13u], 5)
            val input = stream(fields[0u])
            val output = stream(fields[1u])
            val error = stream(fields[2u])
            val terminal = if (fields[3u] == CborValue.Null) null else {
                val value = CaptureFields(fields[3u], 3)
                val control = stream(value[0u])
                val session = value.pid(1u)
                val device = value.uint32(2u)
                ensure(control.access == CommandStreamAccess.READ_WRITE &&
                    control.source.kind in listOf(CommandInputKind.TTY, CommandInputKind.PTY) && control.source.identity != null &&
                    device != UInt.MAX_VALUE && requesterSession(this.requester) == session, CommandCaptureFailure.FIELDS)
                CapturedCommandTerminal(control, session, device)
            }
            val mask = fields.uint32(4u)
            ensure(mask <= 7u && input.source == this.input && input.access != CommandStreamAccess.WRITE_ONLY &&
                output.access != CommandStreamAccess.READ_ONLY && error.access != CommandStreamAccess.READ_ONLY &&
                (ioMode == CommandIOMode.PTY || (mask == 0u && terminal == null)) &&
                (terminal != null || mask == 0u), CommandCaptureFailure.FIELDS)
            listOf(input, output, error).forEachIndexed { index, value ->
                if (mask and (1u shl index) != 0u) {
                    ensure(value.source.kind in listOf(CommandInputKind.TTY, CommandInputKind.PTY) &&
                        value.source.identity != null && value.source.identity == terminal?.stream?.source?.identity, CommandCaptureFailure.FIELDS)
                }
            }
            CapturedCommandStdioLayout(input, output, error, terminal, mask)
        } else null
    }
}

private fun <T> immutable(values: List<T>): List<T> = Collections.unmodifiableList(ArrayList(values))
private fun ensure(condition: Boolean, reason: CommandCaptureFailure) { if (!condition) throw CommandCaptureException(reason) }
private fun fail(reason: CommandCaptureFailure): Nothing = throw CommandCaptureException(reason)
private fun lexicographicallyBefore(left: ByteArray, right: ByteArray): Boolean {
    for (i in 0 until minOf(left.size, right.size)) {
        val a = left[i].toInt() and 255
        val b = right[i].toInt() and 255
        if (a != b) return a < b
    }
    return left.size < right.size
}
private class CaptureFields(value: CborValue, count: Int) {
    private val values = (value as? CborValue.Fields)?.values ?: fail(CommandCaptureFailure.FIELDS)
    init { ensure(values.keys == (0 until count).map { it.toULong() }.toSet(), CommandCaptureFailure.FIELDS) }
    operator fun get(field: ULong): CborValue = values.getValue(field)
    fun uint(field: ULong): ULong = (get(field) as? CborValue.Unsigned)?.value ?: fail(CommandCaptureFailure.TYPE)
    fun uint32(field: ULong): UInt = uint32(get(field))
    fun pid(field: ULong): UInt = uint32(field).also { ensure(it > 0u && it <= Int.MAX_VALUE.toUInt(), CommandCaptureFailure.TYPE) }
    fun optionalUInt32(field: ULong): UInt? = if (get(field) == CborValue.Null) null else uint32(field)
    fun <T: CommandWireTag> tag(field: ULong, values: List<T>): T = values.firstOrNull { it.wireValue == uint(field) } ?: fail(CommandCaptureFailure.ENUMERATION)
    fun array(field: ULong): List<CborValue> = (get(field) as? CborValue.ArrayValue)?.values ?: fail(CommandCaptureFailure.TYPE)
    fun bytes(field: ULong, count: Int): CborValue.Bytes = ((get(field) as? CborValue.Bytes)?.takeIf { it.size == count }) ?: fail(CommandCaptureFailure.BYTES)
    fun optionalBytes(field: ULong, count: Int): CborValue.Bytes? = if (get(field) == CborValue.Null) null else bytes(field, count)
    fun path(field: ULong): CborValue.Bytes = cString(get(field)).also { ensure(it.copyBytes().firstOrNull() == 0x2f.toByte(), CommandCaptureFailure.PATH) }
    fun optionalPath(field: ULong): CborValue.Bytes? = if (get(field) == CborValue.Null) null else path(field)
    fun text(field: ULong): String = (get(field) as? CborValue.Text)?.value ?: fail(CommandCaptureFailure.TYPE)
    fun optionalText(field: ULong): String? = if (get(field) == CborValue.Null) null else (get(field) as? CborValue.Text)?.value ?: fail(CommandCaptureFailure.TYPE)
    fun identity(field: ULong): CapturedFileIdentity = CaptureFields(get(field), 2).let { CapturedFileIdentity(it.uint(0u), it.uint(1u)) }
    fun optionalIdentity(field: ULong): CapturedFileIdentity? = if (get(field) == CborValue.Null) null else identity(field)
    companion object {
        fun uint32(value: CborValue): UInt {
            val number = (value as? CborValue.Unsigned)?.value ?: fail(CommandCaptureFailure.TYPE)
            ensure(number <= UInt.MAX_VALUE.toULong(), CommandCaptureFailure.TYPE)
            return number.toUInt()
        }
        fun cString(value: CborValue): CborValue.Bytes {
            val bytes = value as? CborValue.Bytes ?: fail(CommandCaptureFailure.BYTES)
            ensure(bytes.copyBytes().none { it == 0.toByte() }, CommandCaptureFailure.BYTES)
            return bytes
        }
    }
}
