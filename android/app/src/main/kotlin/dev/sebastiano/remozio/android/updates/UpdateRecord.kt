package dev.sebastiano.remozio.android.updates

import java.security.SecureRandom

internal enum class UpdatePhase {
    RESERVED, BOUND, INTENT, SUBMITTED, UNKNOWN, AWAITING_USER, SUCCESS, FAILURE, ABANDONED;
    val terminal get() = this == SUCCESS || this == FAILURE || this == ABANDONED
}

internal data class UpdateRecord(
    val nonce: String,
    val packageName: String,
    val versionCode: Long,
    val sessionId: Int?,
    val phase: UpdatePhase,
) {
    init {
        require(nonce.matches(Regex("[0-9a-f]{64}")))
        require(packageName.length in 1..255 && packageName.matches(Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")))
        require(versionCode > 0 && (sessionId == null || sessionId >= 0))
        require(if (phase == UpdatePhase.RESERVED) sessionId == null else phase == UpdatePhase.ABANDONED || sessionId != null)
    }
}

/** Each transaction must commit durably before returning, or throw. Reads and writes share its lock. */
internal interface UpdateRecordDatabase : AutoCloseable {
    fun <T> transaction(block: () -> T): T
    fun execute(sql: String, vararg values: Any?)
    fun rows(sql: String): List<List<Any?>>
}

/** Blocking, app-private update control state. It contains no approval data or credentials. */
internal class UpdateRecordStore(private val db: UpdateRecordDatabase) : AutoCloseable {
    init {
        db.transaction {
            val version = db.rows("PRAGMA user_version").single().single() as Long
            if (version == 0L) {
                check(db.rows("SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1").isEmpty())
                db.execute("CREATE TABLE update_record (slot INTEGER PRIMARY KEY CHECK(slot = 1), nonce TEXT NOT NULL, package_name TEXT NOT NULL, version_code INTEGER NOT NULL, session_id INTEGER, phase TEXT NOT NULL)")
                db.execute("PRAGMA user_version = 1")
            } else check(version == 1L)
            read()
        }
    }

    fun snapshot(): UpdateRecord? = db.transaction { read() }

    fun reserve(packageName: String, versionCode: Long): UpdateRecord = db.transaction {
        val old = read()
        check(old == null || old.phase.terminal) { "An update still needs reconciliation" }
        val bytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val record = UpdateRecord(bytes.joinToString("") { "%02x".format(it) }, packageName, versionCode, null, UpdatePhase.RESERVED)
        write(record)
        record
    }

    fun bind(nonce: String, sessionId: Int) = change(nonce) {
        check(it.phase == UpdatePhase.RESERVED)
        it.copy(sessionId = sessionId, phase = UpdatePhase.BOUND)
    }

    fun recordCommitIntent(nonce: String, attempt: InstallAttempt) = change(nonce) {
        check(it.phase == UpdatePhase.BOUND && it.matches(attempt))
        it.copy(phase = UpdatePhase.INTENT)
    }

    fun submitted(nonce: String, result: InstallSubmission) = change(nonce) {
        check(it.matches(result.attempt))
        check(it.phase != UpdatePhase.RESERVED && it.phase != UpdatePhase.BOUND && it.phase != UpdatePhase.ABANDONED)
        if (it.phase == UpdatePhase.INTENT) it.copy(phase = when (result.state) {
            InstallSubmissionState.REQUESTED -> UpdatePhase.SUBMITTED
            InstallSubmissionState.UNKNOWN -> UpdatePhase.UNKNOWN
        }) else it
    }

    /** Call only after the host has reconciled and abandoned any session created before commit intent. */
    fun abandonBeforeIntent(nonce: String) = change(nonce) {
        check(it.phase == UpdatePhase.RESERVED || it.phase == UpdatePhase.BOUND)
        it.copy(phase = UpdatePhase.ABANDONED)
    }

    /** The private receiver must authenticate the callback capability before invoking this method. */
    fun callback(nonce: String, sessionId: Int, phase: UpdatePhase): Boolean = db.transaction {
        require(phase == UpdatePhase.AWAITING_USER || phase == UpdatePhase.SUCCESS || phase == UpdatePhase.FAILURE)
        val record = read() ?: return@transaction false
        if (record.nonce != nonce || record.sessionId != sessionId || record.phase.terminal ||
            record.phase == UpdatePhase.RESERVED || record.phase == UpdatePhase.BOUND) return@transaction false
        write(record.copy(phase = phase))
        true
    }

    private fun change(nonce: String, transform: (UpdateRecord) -> UpdateRecord): UpdateRecord = db.transaction {
        val record = checkNotNull(read())
        check(record.nonce == nonce)
        transform(record).also { write(it) }
    }

    private fun UpdateRecord.matches(attempt: InstallAttempt) = sessionId == attempt.sessionId &&
        packageName == attempt.packageName && versionCode == attempt.versionCode

    private fun read(): UpdateRecord? {
        val rows = db.rows("SELECT slot, nonce, package_name, version_code, session_id, phase FROM update_record LIMIT 2")
        check(rows.size <= 1)
        val row = rows.singleOrNull() ?: return null
        check(row[0] == 1L)
        val session = row[4]?.let { (it as Long).also { id -> require(id in 0..Int.MAX_VALUE.toLong()) }.toInt() }
        return UpdateRecord(row[1] as String, row[2] as String, row[3] as Long, session, UpdatePhase.valueOf(row[5] as String))
    }

    private fun write(record: UpdateRecord) = db.execute(
        "INSERT OR REPLACE INTO update_record(slot, nonce, package_name, version_code, session_id, phase) VALUES(1, ?, ?, ?, ?, ?)",
        record.nonce, record.packageName, record.versionCode, record.sessionId, record.phase.name,
    )

    override fun close() = db.close()
}
