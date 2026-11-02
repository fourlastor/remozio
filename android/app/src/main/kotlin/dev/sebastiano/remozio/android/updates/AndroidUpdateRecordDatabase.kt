package dev.sebastiano.remozio.android.updates

import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteException
import java.io.File

internal class AndroidUpdateRecordDatabase(context: Context) : UpdateRecordDatabase {
    private val db = SQLiteDatabase.openDatabase(
        File(context.applicationContext.noBackupFilesDir, "update-record.sqlite"),
        SQLiteDatabase.OpenParams.Builder()
            .setOpenFlags(SQLiteDatabase.CREATE_IF_NECESSARY or SQLiteDatabase.NO_LOCALIZED_COLLATORS)
            .setJournalMode(SQLiteDatabase.JOURNAL_MODE_DELETE)
            .setSynchronousMode(SQLiteDatabase.SYNC_MODE_EXTRA)
            .setErrorHandler { throw SQLiteException("Update record is corrupt; preserve it for recovery") }
            .build(),
    ).also { opened ->
        try {
            opened.rawQuery("PRAGMA journal_mode", null).use { check(it.moveToFirst() && it.getString(0).equals("delete", true)) }
            opened.rawQuery("PRAGMA synchronous", null).use { check(it.moveToFirst() && it.getInt(0) == 3) }
        } catch (error: Throwable) {
            opened.close()
            throw error
        }
    }

    @Synchronized override fun <T> transaction(block: () -> T): T {
        db.beginTransaction()
        try {
            val result = block()
            db.setTransactionSuccessful()
            return result
        } finally {
            db.endTransaction()
        }
    }

    override fun execute(sql: String, vararg values: Any?) = db.execSQL(sql, values)

    override fun rows(sql: String): List<List<Any?>> = db.rawQuery(sql, null).use { cursor ->
        buildList {
            while (cursor.moveToNext()) {
                add(List(cursor.columnCount) { column ->
                    when (cursor.getType(column)) {
                        Cursor.FIELD_TYPE_NULL -> null
                        Cursor.FIELD_TYPE_INTEGER -> cursor.getLong(column)
                        Cursor.FIELD_TYPE_STRING -> cursor.getString(column)
                        else -> error("Invalid update record field")
                    }
                })
            }
        }
    }

    @Synchronized override fun close() = db.close()
}
