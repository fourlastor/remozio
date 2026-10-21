package dev.remozio.android.requests

import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.SystemBarStyle
import android.graphics.Color
import androidx.compose.foundation.layout.*
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Density
import androidx.lifecycle.lifecycleScope
import dev.remozio.android.R
import dev.remozio.android.RemozioNavigation
import dev.remozio.android.RemozioTheme
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.*
import dev.remozio.protocol.*
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.*

/** Disposable software signatures and in-memory wires only. No enrollment, Android keys or host connection. */
open class CombinedInboxPreviewActivity : ComponentActivity() {
    protected open val dark = false
    protected open val largeFont = false
    protected open val expanded = false
    protected open val empty = false
    protected open val unavailable = false
    private val connections = mutableListOf<CommandConnection>()
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        check(applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        if (dark) enableEdgeToEdge(statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT))
        else enableEdgeToEdge()
        if (expanded) requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE
        val owners = if (empty || unavailable) emptyList() else listOf(peer(1, 20, 100, "Studio Mac"), peer(2, 21, 100, "Studio Mac"),
            peer(3, 20, 101, "Studio Mac"))
        setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, if (largeFont) 1.3f else density.fontScale)) {
                RemozioTheme(darkTheme = dark) {
                    RemozioNavigation(0, {}) {
                        Column(Modifier.fillMaxSize()) {
                            Text(stringResource(R.string.inbox_preview_notice))
                            Box(Modifier.weight(1f)) {
                                CombinedCommandInboxSurface(if (unavailable) ForegroundCommandState.Unavailable else ForegroundCommandState.Ready(owners), {}, {})
                            }
                        }
                    }
                }
            }
        }
    }
    private fun peer(n: Int, mac: Int, account: Int, label: String): StoredCommandOwner {
        val bounds = CborLimits(32768, 32, 4096)
        fun id(value: Int, length: Int = 16) = ByteArray(length) { value.toByte() }
        fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        fun key(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val public = pair().public.encoded
            return EnrollmentKeyReference(role, id(10 + role.ordinal), "remozio.${role.aliasPart}.v1.${"%032x".format(10 + role.ordinal)}",
                if (role == EnrollmentKeyRole.TRANSPORT) public else public.takeLast(65).toByteArray())
        }
        val authority = pair()
        val enrollment = PhoneEnrollment(id(n), id(mac), id(account), id(101), id(102), label,
            authority.public.encoded.takeLast(65).toByteArray(), pair().public.encoded, key(EnrollmentKeyRole.TRANSPORT),
            key(EnrollmentKeyRole.DECISION), key(EnrollmentKeyRole.BIOMETRIC), id(6, 32), null)
        fun sign(bytes: ByteArray, type: ApprovalMessageType, purpose: SigningPurpose) = P256SignatureEncoding.fromDer(
            Signature.getInstance("SHA256withECDSA").run {
                initSign(authority.private); update(SigningInput.make(1u, type, purpose, bytes, bounds, bounds)); sign()
            })
        val connection = CommandConnection(StoredPhoneEnrollment(enrollment, EnrollmentPhase.ACTIVE), RequestLimits(bounds, bounds, bounds, bounds), { _, requests ->
            val actions = listOf(CapturedAction(ActionChoice.DECLINE, ActionScope.CurrentRequest), CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest))
            val request = IssuedRequestPayload(RequestContract(RequestKind.COMMAND, 1u, 1u), id(mac), id(account), id(7), id(8, 32), emptySet(),
                1u, 60001u, resources.openRawResource(R.raw.sample_command).use { it.readBytes() }, actions, bounds, bounds)
            val body = request.encode(bounds)
            val session = requests.accept(body, sign(body, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST))
            val status = RequestStatusPayload(id(mac), id(account), id(7), request.requestDigest(bounds, bounds), request.challenge, 1u,
                RequestPhase.PRESENTED, RequestStatusReason.NONE, id(20), 1000u, 59000u, null, false, null, null).encode(bounds)
            session.observe(status, sign(status, ApprovalMessageType.STATUS, SigningPurpose.STATUS), RequestElapsedClock.now())
            object : CommandConnectionWire {
                override suspend fun receive() { awaitCancellation() }
                override suspend fun send(bytes: ByteArray) { error("Display fixture cannot deliver a decision") }
                override fun close() = Unit
            }
        }, RequestElapsedClock::now)
        connections += connection
        lifecycleScope.launch { connection.run() }
        return StoredCommandOwner(enrollment.recordID, enrollment.macID, enrollment.accountID, label, connection)
    }
    override fun onDestroy() {
        connections.forEach { it.close() }
        super.onDestroy()
    }
}
class InboxDarkPreviewActivity : CombinedInboxPreviewActivity() { override val dark = true }
class InboxLargeFontPreviewActivity : CombinedInboxPreviewActivity() { override val largeFont = true }
class InboxExpandedPreviewActivity : CombinedInboxPreviewActivity() { override val expanded = true }
class InboxExpandedDarkPreviewActivity : CombinedInboxPreviewActivity() { override val expanded = true; override val dark = true }
class InboxEmptyPreviewActivity : CombinedInboxPreviewActivity() { override val empty = true }
class InboxUnavailablePreviewActivity : CombinedInboxPreviewActivity() { override val unavailable = true }
