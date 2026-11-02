package dev.sebastiano.remozio.android.updates

import java.sql.DriverManager

internal class UpdateRecordTestDatabase(path: String) : UpdateRecordDatabase {
    private val connection = DriverManager.getConnection("jdbc:sqlite:$path")
    var failCommit = false
    var failAfterCommit = false
    init {
        execute("PRAGMA journal_mode = DELETE")
        execute("PRAGMA synchronous = EXTRA")
        execute("PRAGMA busy_timeout = 5000")
    }
    @Synchronized override fun <T> transaction(block: () -> T): T {
        execute("BEGIN IMMEDIATE")
        var committed = false
        try {
            val result = block()
            if (failCommit) error("Injected commit failure")
            execute("COMMIT")
            committed = true
            if (failAfterCommit) error("Injected lost commit reply")
            return result
        } catch (error: Throwable) {
            if (!committed) execute("ROLLBACK")
            throw error
        }
    }
    override fun execute(sql: String, vararg values: Any?) {
        connection.prepareStatement(sql).use { statement ->
            values.forEachIndexed { index, value -> statement.setObject(index + 1, value) }
            statement.execute()
        }
    }
    override fun rows(sql: String): List<List<Any?>> = connection.createStatement().use { statement ->
        statement.executeQuery(sql).use { result ->
            buildList {
                while (result.next()) add(List(result.metaData.columnCount) { index ->
                    when (val value = result.getObject(index + 1)) {
                        is Int -> value.toLong()
                        else -> value
                    }
                })
            }
        }
    }
    override fun close() = connection.close()
}
