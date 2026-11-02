package dev.sebastiano.remozio.android.requests

import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteException
import android.system.Os
import android.system.OsConstants
import androidx.annotation.WorkerThread
import androidx.core.database.sqlite.transaction
import dev.sebastiano.remozio.android.storage.ExclusiveFileOwner
import dev.remozio.phone.enrollment.PhoneEnrollment
import java.io.File
import java.security.MessageDigest

/** Stores opaque hashes only. It contains no capture, command text, credential, outcome, or audit record. */
internal object AndroidRetiredCommandRequests {
    @WorkerThread
    fun open(context: Context, enrollment: PhoneEnrollment): RetiredRequestIndex {
        val app = context.applicationContext
        check(!app.isDeviceProtectedStorage)
        val directory = File(app.noBackupFilesDir, "retired-requests")
        if (!directory.isDirectory) {
            check(directory.mkdirs() || directory.isDirectory)
            val parent = Os.open(app.noBackupFilesDir.path, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC, 0)
            try { Os.fsync(parent) } finally { Os.close(parent) }
        }
        val scope = digest(enrollment.recordID.copyBytes() + enrollment.macID.copyBytes() + enrollment.accountID.copyBytes() +
            enrollment.epoch.copyBytes() + enrollment.authorityPublicKey.copyBytes())
        val file = File(directory, "$scope.sqlite")
        val owner = ExclusiveFileOwner.acquire(File(file.path + ".lock"))
        var db: SQLiteDatabase? = null
        try {
            db = SQLiteDatabase.openDatabase(file, SQLiteDatabase.OpenParams.Builder()
                .setOpenFlags(SQLiteDatabase.CREATE_IF_NECESSARY or SQLiteDatabase.NO_LOCALIZED_COLLATORS)
                .setJournalMode(SQLiteDatabase.JOURNAL_MODE_DELETE)
                .setSynchronousMode(SQLiteDatabase.SYNC_MODE_EXTRA)
                .setErrorHandler { throw SQLiteException("Request index is corrupt; preserve it for recovery") }.build())
            return RetiredRequestIndex(AndroidRetiredRequestDatabase(db, owner))
        } catch (failure: Throwable) { try { db?.close() } finally { owner.close() }; throw failure }
    }

    private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}

private class AndroidRetiredRequestDatabase(private val db: SQLiteDatabase, private val owner: AutoCloseable) : RetiredRequestDatabase {
    override fun <T> transaction(block: () -> T): T = db.transaction { block() }
    override fun execute(sql: String, vararg values: Any) = db.execSQL(sql, values)
    override fun row(sql: String, vararg values: String): List<Any>? = db.rawQuery(sql, values).use { cursor ->
        if (!cursor.moveToFirst()) null else {
            val row = List(cursor.columnCount) { column ->
                when (cursor.getType(column)) {
                    Cursor.FIELD_TYPE_INTEGER -> cursor.getLong(column)
                    Cursor.FIELD_TYPE_STRING -> cursor.getString(column)
                    Cursor.FIELD_TYPE_BLOB -> cursor.getBlob(column)
                    else -> error("Invalid retirement index field")
                }
            }
            check(!cursor.moveToNext())
            row
        }
    }
    override fun close() { try { db.close() } finally { owner.close() } }
}
