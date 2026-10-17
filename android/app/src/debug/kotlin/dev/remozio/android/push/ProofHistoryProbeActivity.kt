package dev.remozio.android.push

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Bundle
import android.util.Log
import dev.remozio.phone.enrollment.*
import dev.remozio.protocol.*
import java.io.File
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

/** Debug-only local file experiment. It creates no pairing, hardware key, provider session or network operation. */
class ProofHistoryProbeActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        check(applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        Thread {
            val passed = mutableListOf<String>()
            val root = File(noBackupFilesDir, "proof-history-probe-" + UUID.randomUUID()).also { check(it.mkdir()) }
            var failed: String? = null
            try {
                val record = record(); val metadata = metadata(record)
                fun case(name: String, body: (Context, File) -> Unit) {
                    val directory = File(root, name).also { check(it.mkdir()) }
                    val context = object : ContextWrapper(applicationContext) {
                        override fun getApplicationContext(): Context = this
                        override fun getNoBackupFilesDir(): File = directory
                    }
                    body(context, File(directory, "push-proof-history/state")); passed += name
                }
                case("claim-reopen") { context, file ->
                    AndroidPushProofs.open(context).use { check(it.claim(record, metadata, offer)) }
                    AndroidPushProofs.open(context).use { check(!it.claim(record, metadata, offer)) }
                    check(!file.readText(Charsets.ISO_8859_1).contains(offer.token))
                }
                case("exclusive-owner") { context, _ ->
                    AndroidPushProofs.open(context).use { owner ->
                        check(owner.claim(record, metadata, offer))
                        check(runCatching { AndroidPushProofs.open(context).close() }.isFailure)
                        check(!owner.claim(record, metadata, offer))
                    }
                    AndroidPushProofs.open(context).use { check(!it.claim(record, metadata, offer)) }
                }
                case("corrupt-archive") { context, file ->
                    AndroidPushProofs.open(context).use { check(it.claim(record, metadata, offer)) }
                    file.appendBytes(byteArrayOf(0)); val corrupt = file.readBytes()
                    check(runCatching { AndroidPushProofs.open(context).close() }.isFailure)
                    check(file.readBytes().contentEquals(corrupt))
                }
                case("partial-new-without-base") { context, file ->
                    AndroidPushProofs.open(context).use { check(it.claim(record, metadata, offer)) }
                    val partial = file.readBytes().take(10).toByteArray(); check(file.delete())
                    val pending = File(file.path + ".new"); pending.writeBytes(partial)
                    check(runCatching { AndroidPushProofs.open(context).close() }.isFailure)
                    check(pending.readBytes().contentEquals(partial)); check(!file.exists())
                }
                case("legacy-backup-recovery") { context, file ->
                    AndroidPushProofs.open(context).use { check(it.claim(record, metadata, offer)) }
                    val original = file.readBytes(); check(file.renameTo(File(file.path + ".bak")))
                    AndroidPushProofs.open(context).use { check(!it.claim(record, metadata, offer)) }
                    check(file.readBytes().contentEquals(original))
                }
            } catch (failure: Throwable) { failed = failure.javaClass.simpleName }
            finally {
                val cleaned = root.deleteRecursively()
                val report = JSONObject().put("experiment", "android-proof-history-files").put("api", Build.VERSION.SDK_INT)
                    .put("status", if (failed == null && cleaned) "passed" else "failed").put("cases", JSONArray(passed))
                    .put("failureType", failed).put("fixtureRemoved", cleaned).put("hardwareKeysCreated", false)
                    .put("providerDeliveryTested", false).put("pairingCreated", false).put("networkUsed", false)
                Log.i("RemozioProofProbe", report.toString())
                runOnUiThread { finish() }
            }
        }.start()
    }
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
    private fun record(): StoredPhoneEnrollment {
        fun local(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val bytes = key()
            return EnrollmentKeyReference(role, id(role.ordinal + 10),
                "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
                if (role == EnrollmentKeyRole.TRANSPORT) bytes else bytes.takeLast(65).toByteArray())
        }
        return StoredPhoneEnrollment(PhoneEnrollment(id(1), id(2), id(3), id(4), id(5), "Synthetic file probe", key().takeLast(65).toByteArray(),
            key(), local(EnrollmentKeyRole.TRANSPORT), local(EnrollmentKeyRole.DECISION), local(EnrollmentKeyRole.BIOMETRIC), ByteArray(32) { 6 }, null), EnrollmentPhase.ACTIVE)
    }
    private val offer = PhonePushTokenOffer("synthetic-proof-file-token", "project", "123", "dev.remozio.android")
    private fun metadata(record: StoredPhoneEnrollment): PhonePushRegistrationMetadata {
        val e = record.enrollment
        val binding = GatewayTokenBinding(id(7), e.macID.copyBytes(), e.accountID.copyBytes(), id(8), id(9), e.phoneID.copyBytes(), e.epoch.copyBytes(),
            id(10), MessageDigest.getInstance("SHA-256").digest(offer.token.toByteArray()), ByteArray(32) { 42 }, e.enrollmentTag.copyBytes())
        return PhonePushRegistrationMetadata(GatewayTokenCandidate(binding, 1u, id(11), 1000u, 2000u))
    }
}
