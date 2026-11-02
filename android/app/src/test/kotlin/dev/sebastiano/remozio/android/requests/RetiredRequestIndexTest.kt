package dev.sebastiano.remozio.android.requests

import java.io.File
import java.nio.file.Files
import java.sql.DriverManager
import org.junit.Test
import kotlin.test.*

class RetiredRequestIndexTest {
    private fun id(value: Int) = ByteArray(16) { value.toByte() }
    private fun digest(value: Int) = ByteArray(32) { value.toByte() }
    private class Database(file: File) : RetiredRequestDatabase {
        private val connection = DriverManager.getConnection("jdbc:sqlite:${file.absolutePath}")
        var failAfterCommit = false
        init { execute("PRAGMA journal_mode = DELETE"); execute("PRAGMA synchronous = EXTRA") }
        override fun <T> transaction(block: () -> T): T {
            connection.autoCommit = false
            try {
                val result = block()
                connection.commit()
                if (failAfterCommit) throw java.io.IOException("Synthetic lost commit result")
                return result
            } catch (failure: Throwable) { connection.rollback(); throw failure }
            finally { connection.autoCommit = true }
        }
        override fun execute(sql: String, vararg values: Any) {
            connection.prepareStatement(sql).use { statement ->
                values.forEachIndexed { index, value -> statement.setObject(index + 1, value) }
                statement.execute()
            }
        }
        override fun row(sql: String, vararg values: String): List<Any>? = connection.prepareStatement(sql).use { statement ->
            values.forEachIndexed { index, value -> statement.setString(index + 1, value) }
            statement.executeQuery().use { result ->
                if (!result.next()) null else {
                    val row = (1..result.metaData.columnCount).map { checkNotNull(result.getObject(it)) }
                    check(!result.next()); row
                }
            }
        }
        override fun close() = connection.close()
    }
    private fun fixture(block: (File) -> Unit) {
        val directory = Files.createTempDirectory("remozio-retired-test-").toFile()
        try { block(File(directory, "index.sqlite")) } finally { directory.deleteRecursively() }
    }

    @Test fun exactMembershipSurvivesReopenAndDoesNotStorePlainRequestIDs() = fixture { file ->
        RetiredRequestIndex(Database(file)).use { index ->
            for (value in 1..200) index.remember(id(value), digest(value))
            index.remember(id(1), digest(1))
            assertNull(index.lookup(id(0)))
        }
        RetiredRequestIndex(Database(file)).use { index ->
            for (value in 1..200) assertContentEquals(digest(value), index.lookup(id(value)))
            val result = checkNotNull(index.lookup(id(1))); result.fill(0)
            assertContentEquals(digest(1), index.lookup(id(1)))
        }
        Database(file).use { db ->
            val row = checkNotNull(db.row("SELECT min(length(request_key)), max(length(request_key)), count(*) FROM retired_requests"))
            assertEquals(listOf(64, 64, 200), row.map { (it as Number).toInt() })
        }
    }

    @Test fun conflictingDigestCannotOverwriteAndQuarantinesOwner() = fixture { file ->
        RetiredRequestIndex(Database(file)).use { index ->
            index.remember(id(1), digest(1))
            assertFails { index.remember(id(1), digest(2)) }
            assertFails { index.lookup(id(1)) }
        }
        RetiredRequestIndex(Database(file)).use { assertContentEquals(digest(1), it.lookup(id(1))) }
    }

    @Test fun uncertainCommitRequiresReopenAndPreservesCommittedMembership() = fixture { file ->
        val db = Database(file)
        RetiredRequestIndex(db).use { index ->
            db.failAfterCommit = true
            assertFails { index.remember(id(1), digest(1)) }
            assertFails { index.lookup(id(1)) }
        }
        RetiredRequestIndex(Database(file)).use { assertContentEquals(digest(1), it.lookup(id(1))) }
    }

    @Test fun malformedRowsAndUnsupportedSchemaFailWithoutReset() = fixture { file ->
        RetiredRequestIndex(Database(file)).use { it.remember(id(1), digest(1)) }
        Database(file).use { it.execute("UPDATE retired_requests SET digest = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'") }
        RetiredRequestIndex(Database(file)).use { assertFails { it.lookup(id(1)) } }
        Database(file).use { db ->
            db.execute("PRAGMA user_version = 2")
            assertFails { RetiredRequestIndex(db) }
            assertEquals(2, (db.row("PRAGMA user_version")!!.single() as Number).toInt())
            assertEquals(1, (db.row("SELECT count(*) FROM retired_requests")!!.single() as Number).toInt())
        }
    }

    @Test fun pristineVersionZeroRecoversAfterCreationOrRolledBackSchema() {
        for (rollback in listOf(false, true)) fixture { file ->
            Database(file).use { db ->
                if (rollback) assertFails {
                    db.transaction {
                        db.execute("CREATE TABLE interrupted(value INTEGER)")
                        error("Synthetic interruption before schema commit")
                    }
                }
                assertEquals(0, (db.row("PRAGMA user_version")!!.single() as Number).toInt())
            }
            RetiredRequestIndex(Database(file)).use { it.remember(id(1), digest(1)) }
            RetiredRequestIndex(Database(file)).use { assertContentEquals(digest(1), it.lookup(id(1))) }
        }
    }

    @Test fun versionZeroWithExistingObjectsIsNeverReinitialized() = fixture { file ->
        Database(file).use { db ->
            db.execute("CREATE TABLE preserved(value INTEGER)")
            db.execute("INSERT INTO preserved(value) VALUES (42)")
            assertFails { RetiredRequestIndex(db) }
            assertEquals(42, (db.row("SELECT value FROM preserved")!!.single() as Number).toInt())
            assertEquals(0, (db.row("PRAGMA user_version")!!.single() as Number).toInt())
            assertEquals(1, (db.row("SELECT count(*) FROM sqlite_master")!!.single() as Number).toInt())
        }
    }
}
