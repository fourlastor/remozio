package dev.sebastiano.remozio.android.requests

import dev.remozio.phone.requests.RetiredCommandRequests
import java.security.MessageDigest

internal interface RetiredRequestDatabase : AutoCloseable {
    fun <T> transaction(block: () -> T): T
    fun execute(sql: String, vararg values: Any)
    fun row(sql: String, vararg values: String): List<Any>?
}

/** Exact membership on disk. The caller owns the database on failed construction; a successful owner closes it. */
internal class RetiredRequestIndex(private val db: RetiredRequestDatabase) : RetiredCommandRequests {
    private var closed = false
    private var failed = false

    init {
        check(db.row("PRAGMA journal_mode")?.single()?.toString()?.equals("delete", true) == true)
        check((db.row("PRAGMA synchronous")?.single() as? Number)?.toInt() == 3)
        db.transaction {
            val version = (db.row("PRAGMA user_version")?.single() as? Number)?.toInt()
            if (version == 0) {
                check((db.row("SELECT count(*) FROM sqlite_master")?.single() as? Number)?.toLong() == 0L)
                db.execute("CREATE TABLE retired_requests(request_key TEXT PRIMARY KEY NOT NULL, digest BLOB NOT NULL CHECK(length(digest) = 32)) WITHOUT ROWID")
                db.execute("PRAGMA user_version = 1")
            } else check(version == 1)
        }
    }

    @Synchronized override fun lookup(requestID: ByteArray): ByteArray? {
        check(!closed && !failed)
        val row = db.row("SELECT length(digest), typeof(digest), substr(digest, 1, 32) FROM retired_requests WHERE request_key = ?", key(requestID)) ?: return null
        check(row.size == 3 && (row[0] as? Number)?.toInt() == 32 && row[1] == "blob")
        return (row[2] as ByteArray).also { check(it.size == 32) }.copyOf()
    }

    @Synchronized override fun remember(requestID: ByteArray, requestDigest: ByteArray) {
        check(!closed && !failed)
        require(requestDigest.size == 32)
        val identifier = key(requestID)
        try {
            db.transaction {
                val existing = lookup(requestID)
                if (existing == null) db.execute("INSERT INTO retired_requests(request_key, digest) VALUES (?, ?)", identifier, requestDigest.copyOf())
                else check(existing.contentEquals(requestDigest))
            }
        } catch (failure: Throwable) { failed = true; throw failure }
    }

    @Synchronized override fun close() { if (!closed) { closed = true; db.close() } }

    private fun key(requestID: ByteArray): String {
        require(requestID.size == 16)
        return MessageDigest.getInstance("SHA-256").digest(requestID).joinToString("") { "%02x".format(it) }
    }
}
