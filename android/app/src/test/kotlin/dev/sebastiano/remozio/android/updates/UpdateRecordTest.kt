package dev.sebastiano.remozio.android.updates

import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.Test

class UpdateRecordTest {
    private val pkg = "dev.sebastiano.remozio.android"
    private val attempt = InstallAttempt(7, pkg, 2)

    private fun withFile(test: (String) -> Unit) {
        val directory = Files.createTempDirectory("update-record-test")
        try { test(directory.resolve("record.sqlite").toString()) }
        finally { directory.toFile().deleteRecursively() }
    }

    @Test fun reopensUnresolvedIntentAndRefusesAnotherAttempt() = withFile { path ->
        val record = UpdateRecordStore(UpdateRecordTestDatabase(path)).use { store ->
            val record = store.reserve(pkg, 2)
            store.bind(record.nonce, 7)
            store.recordCommitIntent(record.nonce, attempt)
        }
        UpdateRecordStore(UpdateRecordTestDatabase(path)).use { store ->
            assertEquals(record, store.snapshot())
            assertEquals(UpdatePhase.INTENT, record.phase)
            assertFails { store.reserve(pkg, 3) }
            assertFails { store.abandonBeforeIntent(record.nonce) }
        }
    }

    @Test fun rejectsUnboundAndStaleCallbacksAndKeepsFirstTerminalResult() = withFile { path ->
        UpdateRecordStore(UpdateRecordTestDatabase(path)).use { store ->
            val first = store.reserve(pkg, 2)
            assertFalse(store.callback(first.nonce, 7, UpdatePhase.SUCCESS))
            store.bind(first.nonce, 7)
            assertFalse(store.callback(first.nonce, 7, UpdatePhase.SUCCESS))
            assertFails { store.recordCommitIntent(first.nonce, attempt.copy(versionCode = 3)) }
            store.recordCommitIntent(first.nonce, attempt)
            assertFalse(store.callback("0".repeat(64), 7, UpdatePhase.SUCCESS))
            assertFalse(store.callback(first.nonce, 8, UpdatePhase.SUCCESS))
            assertTrue(store.callback(first.nonce, 7, UpdatePhase.SUCCESS))
            assertFalse(store.callback(first.nonce, 7, UpdatePhase.FAILURE))
            store.submitted(first.nonce, InstallSubmission(attempt, InstallSubmissionState.UNKNOWN))
            assertEquals(UpdatePhase.SUCCESS, store.snapshot()!!.phase)
            val next = store.reserve(pkg, 3)
            assertNotEquals(first.nonce, next.nonce)
            store.bind(next.nonce, 7)
            store.recordCommitIntent(next.nonce, attempt.copy(versionCode = 3))
            assertFalse(store.callback(first.nonce, 7, UpdatePhase.FAILURE))
            assertEquals(UpdatePhase.INTENT, store.snapshot()!!.phase)
        }
    }

    @Test fun callbackBeforeSubmissionReturnDoesNotRegress() = withFile { path ->
        UpdateRecordStore(UpdateRecordTestDatabase(path)).use { store ->
            val record = store.reserve(pkg, 2)
            store.bind(record.nonce, 7)
            store.recordCommitIntent(record.nonce, attempt)
            assertTrue(store.callback(record.nonce, 7, UpdatePhase.AWAITING_USER))
            store.submitted(record.nonce, InstallSubmission(attempt, InstallSubmissionState.REQUESTED))
            assertEquals(UpdatePhase.AWAITING_USER, store.snapshot()!!.phase)
            assertTrue(store.callback(record.nonce, 7, UpdatePhase.FAILURE))
        }
    }

    @Test fun uncertainSubmissionSurvivesReopenWithoutRetry() = withFile { path ->
        val nonce = UpdateRecordStore(UpdateRecordTestDatabase(path)).use { store ->
            val record = store.reserve(pkg, 2)
            store.bind(record.nonce, 7)
            store.recordCommitIntent(record.nonce, attempt)
            store.submitted(record.nonce, InstallSubmission(attempt, InstallSubmissionState.UNKNOWN))
            record.nonce
        }
        UpdateRecordStore(UpdateRecordTestDatabase(path)).use { store ->
            assertEquals(UpdatePhase.UNKNOWN, store.snapshot()!!.phase)
            assertFails { store.reserve(pkg, 3) }
            assertTrue(store.callback(nonce, 7, UpdatePhase.SUCCESS))
        }
    }

    @Test fun failedCommitRollsBackAndDoesNotReturnPermissionToCommit() = withFile { path ->
        val db = UpdateRecordTestDatabase(path)
        UpdateRecordStore(db).use { store ->
            val record = store.reserve(pkg, 2)
            store.bind(record.nonce, 7)
            db.failCommit = true
            var nativeCommitCalled = false
            assertFails {
                store.recordCommitIntent(record.nonce, attempt)
                nativeCommitCalled = true
            }
            assertFalse(nativeCommitCalled)
            db.failCommit = false
            assertEquals(UpdatePhase.BOUND, store.snapshot()!!.phase)
        }
        UpdateRecordStore(UpdateRecordTestDatabase(path)).use { assertEquals(UpdatePhase.BOUND, it.snapshot()!!.phase) }
    }

    @Test fun lostStorageReplyKeepsIntentButDoesNotAuthorizeNativeCommit() = withFile { path ->
        val db = UpdateRecordTestDatabase(path)
        UpdateRecordStore(db).use { store ->
            val record = store.reserve(pkg, 2)
            store.bind(record.nonce, 7)
            db.failAfterCommit = true
            var nativeCommitCalled = false
            assertFails {
                store.recordCommitIntent(record.nonce, attempt)
                nativeCommitCalled = true
            }
            assertFalse(nativeCommitCalled)
            db.failAfterCommit = false
        }
        UpdateRecordStore(UpdateRecordTestDatabase(path)).use { store ->
            assertEquals(UpdatePhase.INTENT, store.snapshot()!!.phase)
            assertFails { store.reserve(pkg, 3) }
        }
    }

    @Test fun separateConnectionsReserveOnlyOnePendingAttempt() = withFile { path ->
        UpdateRecordStore(UpdateRecordTestDatabase(path)).use { first ->
            UpdateRecordStore(UpdateRecordTestDatabase(path)).use { second ->
                val executor = Executors.newFixedThreadPool(2)
                try {
                    val start = CountDownLatch(1)
                    val results = listOf(first, second).map { store -> executor.submit<Boolean> {
                        start.await()
                        runCatching { store.reserve(pkg, 2) }.isSuccess
                    } }
                    start.countDown()
                    assertEquals(1, results.count { it.get() })
                    assertEquals(first.snapshot(), second.snapshot())
                } finally { executor.shutdownNow() }
            }
        }
    }

    @Test fun refusesUnsupportedSchemaAndPreservesExistingData() = withFile { path ->
        UpdateRecordTestDatabase(path).use { db ->
            db.execute("CREATE TABLE future_state(value TEXT)")
            db.execute("INSERT INTO future_state VALUES('retain')")
            db.execute("PRAGMA user_version = 2")
            assertFails { UpdateRecordStore(db) }
            assertEquals(listOf(listOf("retain")), db.rows("SELECT value FROM future_state"))
        }
    }

    @Test fun refusesUnversionedNonemptyUpdateRecordTestDatabase() = withFile { path ->
        UpdateRecordTestDatabase(path).use { db ->
            db.execute("CREATE TABLE other_state(value TEXT)")
            assertFails { UpdateRecordStore(db) }
            assertEquals(listOf(listOf(0L)), db.rows("PRAGMA user_version"))
        }
    }

    @Test fun refusesCorruptFieldsWithoutReplacingThem() = withFile { path ->
        val mutations = listOf(
            "nonce = 'bad'", "version_code = 'oops'", "version_code = 0",
            "session_id = 2147483648", "phase = 'FUTURE'", "phase = 'SUCCESS'",
        )
        UpdateRecordTestDatabase(path).use { db ->
            val store = UpdateRecordStore(db)
            val record = store.reserve(pkg, 2)
            for (mutation in mutations) {
                db.execute("UPDATE update_record SET $mutation")
                assertFails { store.snapshot() }
                assertFails { UpdateRecordStore(db) }
                db.execute("UPDATE update_record SET nonce = ?, version_code = 2, session_id = NULL, phase = 'RESERVED'", record.nonce)
            }
            assertEquals(record, store.snapshot())
        }
    }

    @Test fun explicitPreIntentAbandonAllowsNewReservation() = withFile { path ->
        UpdateRecordStore(UpdateRecordTestDatabase(path)).use { store ->
            val record = store.reserve(pkg, 2)
            store.abandonBeforeIntent(record.nonce)
            assertEquals(UpdatePhase.ABANDONED, store.snapshot()!!.phase)
            assertNotEquals(record.nonce, store.reserve(pkg, 2).nonce)
        }
    }
}
