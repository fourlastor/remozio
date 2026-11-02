package dev.sebastiano.remozio.android.audit

import android.content.Context
import android.content.res.Configuration
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.graphics.Color
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Density
import dev.sebastiano.remozio.android.R
import dev.sebastiano.remozio.android.RemozioNavigation
import dev.sebastiano.remozio.android.RemozioTheme
import dev.remozio.phone.audit.*
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.*
import kotlinx.coroutines.flow.collect
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** Disposable signed in-memory display data. No enrollment, files, Android Keystore or network operation. */
open class AuditPreviewActivity : ComponentActivity() {
    protected open val dark = false
    protected open val largeFont = false
    protected open val expanded = false
    protected open val previous = false
    protected open val archiveFocus = false
    protected open val archiveFocusIndex = 6
    protected open val details = false
    protected open val unavailable = false
    protected open val missing = false
    protected open val syncPhase: AuditSyncPhase? = null
    protected open val syncUnavailable = false
    protected open val savedTimes = false
    protected open val partialSavedTime = false
    protected open val savedTimeFocusEnd = false
    override fun attachBaseContext(newBase: Context) {
        val configured = if (largeFont) newBase.createConfigurationContext(Configuration(newBase.resources.configuration).apply {
            fontScale = 2f
        }) else newBase
        super.attachBaseContext(configured)
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        check(applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        setTurnScreenOn(true)
        setShowWhenLocked(true)
        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        if (dark) enableEdgeToEdge(statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT)) else enableEdgeToEdge()
        if (expanded) requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE
        val scope = previewScope()
        val ready = StoredAuditState.Ready(listOf(AuditMacOption(scope.scope.macID, scope.label)), listOf(scope))
        setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, if (largeFont) 2f else density.fontScale)) {
                RemozioTheme(darkTheme = dark) {
                    val list = rememberLazyListState()
                    LaunchedEffect(list) {
                        snapshotFlow { list.layoutInfo.totalItemsCount }.collect { count ->
                            if (count > 11 && previous) list.scrollToItem(11)
                            else if (archiveFocus && count > archiveFocusIndex) list.scrollToItem(archiveFocusIndex, if (savedTimeFocusEnd) 600 else 0)
                        }
                    }
                    RemozioNavigation(2, {}) {
                        Column(Modifier.fillMaxSize()) {
                            Text(stringResource(R.string.audit_preview_notice), style = MaterialTheme.typography.bodySmall)
                            val syncing = if (syncPhase == null && !syncUnavailable) null else AuditSyncDisplays.Ready(listOf(
                                AuditSyncDisplay(AuditSyncScope(scope.scope.macID, scope.scope.accountID, scope.archives.first().authorityPublicKey),
                                    if (syncUnavailable) AuditSyncProgress.Unavailable else AuditSyncProgress.Observed(checkNotNull(syncPhase),
                                        if (syncPhase == AuditSyncPhase.FAILED) AuditSyncFailure.TRANSPORT else null,
                                        if (syncPhase == AuditSyncPhase.COMPLETE) ElapsedInstant(1, 3_400_000u) else null,
                                        if (syncPhase == AuditSyncPhase.PAUSED || syncPhase == AuditSyncPhase.COMPLETE) ElapsedInstant(1, 3_400_000u) else null,
                                        null, (scope.archives.first().content as? CachedAuditContent.Loaded)?.localTimes), working = syncPhase == AuditSyncPhase.SYNCING)))
                            Box(Modifier.weight(1f)) { AuditContent(ready, ready.macs, listState = list, sync = syncing, moment = ElapsedInstant(1, 3_600_000u)) }
                        }
                        if (details) {
                            val archive = scope.archives.last()
                            val loaded = archive.content as CachedAuditContent.Loaded
                            val event = loaded.snapshot.epochs.single().records.first()
                            AuditDetails(AuditSelection(scope, archive, loaded, event)) { finish() }
                        }
                    }
                }
            }
        }
    }
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun previewScope(): CachedAuditScope {
        fun archive(retired: Boolean): CachedAuditArchive {
            val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            val publicKey = key.public.encoded.takeLast(65).toByteArray()
            val bound = CborLimits(65536, 8, 2048)
            val events = (1..2).map { sequence -> AuditEventMetadata(id(sequence + 30), id(1), id(2), id(3), sequence.toULong(),
                id(60), (3000 - sequence * 1000).toULong(), null, AuditEventKind.REQUEST_CREATED, AuditCategory.COMMAND,
                null, null, AuditAuthentication.SYSTEM, AuditOutcome.PENDING,
                if (retired) AuditReason.UNKNOWN else AuditReason.NONE, null, null).encode(bound) }
            val body = DeterministicCbor.encode(CborValue.Fields(mapOf(
                0uL to CborValue.Unsigned(1u), 1uL to CborValue.Bytes(id(1)), 2uL to CborValue.Bytes(id(2)),
                3uL to CborValue.Bytes(id(3)), 4uL to CborValue.Unsigned(7u), 5uL to CborValue.Unsigned(0u),
                6uL to CborValue.Unsigned(0u), 7uL to CborValue.Unsigned(4u), 8uL to CborValue.Bytes(ByteArray(32)),
                9uL to CborValue.ArrayValue(events.map(CborValue::Bytes)),
            )), bound)
            val signature = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                initSign(key.private); update(AuditBatchSigningInput.make(1u, body, bound, bound)); sign()
            })
            val store = AuditEvidenceStore(id(1), id(2), publicKey,
                AuditPageLimits(bound, bound, bound, 8, bound, bound), AuditEvidenceLimits(20, 100_000, 20, 10))
            store.importEvidence(AuditEvidenceKind.PAGE, body, signature)
            val snapshot = store.snapshot()
            val content = when {
                !retired && unavailable -> CachedAuditContent.Unavailable
                !retired && missing -> CachedAuditContent.Missing
                else -> {
                    val time = if (savedTimes) AuditLocalSyncTime(1_790_000_000_000L - if (retired) 86_400_000L else 0,
                        CborValue.Bytes(ByteArray(32) { if (retired) 9 else 7 })) else null
                    CachedAuditContent.Loaded(snapshot, AuditHistory.list(listOf(snapshot)).single(),
                        time?.let { AuditLocalSyncTimes(it, if (partialSavedTime) null else it) })
                }
            }
            return CachedAuditArchive(CborValue.Bytes(publicKey), retired, content)
        }
        return CachedAuditScope(AuditHistoryScope(CborValue.Bytes(id(1)), CborValue.Bytes(id(2))),
            getString(R.string.routing_preview_studio), listOf(archive(false), archive(true)))
    }
}
class AuditDarkPreviewActivity : AuditPreviewActivity() { override val dark = true }
class AuditLargeFontPreviewActivity : AuditPreviewActivity() { override val largeFont = true; override val archiveFocus = true }
class AuditFocusPreviewActivity : AuditPreviewActivity() { override val archiveFocus = true }
class AuditFocusDarkPreviewActivity : AuditPreviewActivity() { override val archiveFocus = true; override val dark = true }
class AuditExpandedPreviewActivity : AuditPreviewActivity() { override val expanded = true; override val archiveFocus = true }
class AuditExpandedDarkPreviewActivity : AuditPreviewActivity() { override val expanded = true; override val dark = true; override val archiveFocus = true }
class AuditPreviousPreviewActivity : AuditPreviewActivity() { override val previous = true }
class AuditPreviousDarkPreviewActivity : AuditPreviewActivity() { override val previous = true; override val dark = true }
class AuditPreviousLargeFontPreviewActivity : AuditPreviewActivity() { override val previous = true; override val largeFont = true }
class AuditUnavailablePreviewActivity : AuditPreviewActivity() { override val unavailable = true; override val archiveFocus = true }
class AuditMissingPreviewActivity : AuditPreviewActivity() { override val missing = true; override val archiveFocus = true; override val archiveFocusIndex = 4 }
class AuditDetailsPreviewActivity : AuditPreviewActivity() { override val details = true }
class AuditDetailsLargeFontPreviewActivity : AuditPreviewActivity() { override val details = true; override val largeFont = true }
class AuditDetailsExpandedPreviewActivity : AuditPreviewActivity() { override val details = true; override val expanded = true }
class AuditDetailsExpandedDarkPreviewActivity : AuditPreviewActivity() { override val details = true; override val expanded = true; override val dark = true }

class AuditSyncPreviewActivity : AuditPreviewActivity() { override val syncPhase = AuditSyncPhase.COMPLETE }
class AuditSyncFocusPreviewActivity : AuditPreviewActivity() { override val syncPhase = AuditSyncPhase.COMPLETE; override val archiveFocus = true }
class AuditSyncDarkPreviewActivity : AuditPreviewActivity() { override val syncPhase = AuditSyncPhase.COMPLETE; override val dark = true; override val archiveFocus = true }
class AuditSyncLargeFontPreviewActivity : AuditPreviewActivity() { override val syncPhase = AuditSyncPhase.COMPLETE; override val largeFont = true; override val archiveFocus = true }
class AuditSyncPausedPreviewActivity : AuditPreviewActivity() { override val syncPhase = AuditSyncPhase.PAUSED; override val archiveFocus = true }
class AuditSyncPausedDarkPreviewActivity : AuditPreviewActivity() { override val syncPhase = AuditSyncPhase.PAUSED; override val archiveFocus = true; override val dark = true }
class AuditSyncPausedLargeFontPreviewActivity : AuditPreviewActivity() { override val syncPhase = AuditSyncPhase.PAUSED; override val archiveFocus = true; override val largeFont = true }
class AuditSyncRunningPreviewActivity : AuditPreviewActivity() { override val syncPhase = AuditSyncPhase.SYNCING; override val archiveFocus = true }
class AuditSyncFailedPreviewActivity : AuditPreviewActivity() { override val syncPhase = AuditSyncPhase.FAILED; override val archiveFocus = true }
class AuditSyncUnavailablePreviewActivity : AuditPreviewActivity() { override val syncUnavailable = true; override val archiveFocus = true }
class AuditSyncExpandedPreviewActivity : AuditPreviewActivity() { override val syncPhase = AuditSyncPhase.PAUSED; override val archiveFocus = true; override val expanded = true }
class AuditSyncExpandedDarkPreviewActivity : AuditPreviewActivity() { override val syncPhase = AuditSyncPhase.PAUSED; override val archiveFocus = true; override val expanded = true; override val dark = true }
class AuditSyncPreviousPreviewActivity : AuditPreviewActivity() { override val syncPhase = AuditSyncPhase.COMPLETE; override val previous = true }

class AuditSavedTimesPreviewActivity : AuditPreviewActivity() { override val savedTimes = true; override val syncPhase = AuditSyncPhase.IDLE }
class AuditSavedTimesFocusPreviewActivity : AuditPreviewActivity() { override val savedTimes = true; override val syncPhase = AuditSyncPhase.IDLE; override val archiveFocus = true }
class AuditSavedTimesDarkPreviewActivity : AuditPreviewActivity() { override val savedTimes = true; override val syncPhase = AuditSyncPhase.IDLE; override val archiveFocus = true; override val dark = true }
class AuditSavedTimesLargeFontPreviewActivity : AuditPreviewActivity() { override val savedTimes = true; override val syncPhase = AuditSyncPhase.IDLE; override val archiveFocus = true; override val largeFont = true }
class AuditSavedTimesLargeFontEndPreviewActivity : AuditPreviewActivity() { override val savedTimes = true; override val syncPhase = AuditSyncPhase.IDLE; override val archiveFocus = true; override val largeFont = true; override val savedTimeFocusEnd = true }
class AuditSavedPartialPreviewActivity : AuditPreviewActivity() { override val savedTimes = true; override val partialSavedTime = true; override val syncPhase = AuditSyncPhase.IDLE; override val archiveFocus = true }
class AuditSavedPreviousPreviewActivity : AuditPreviewActivity() { override val savedTimes = true; override val syncPhase = AuditSyncPhase.IDLE; override val previous = true }
class AuditSavedUnavailablePreviewActivity : AuditPreviewActivity() { override val savedTimes = true; override val syncUnavailable = true; override val archiveFocus = true }
class AuditSavedRunningPreviewActivity : AuditPreviewActivity() { override val savedTimes = true; override val syncPhase = AuditSyncPhase.SYNCING; override val archiveFocus = true }
class AuditSavedLiveCompletePreviewActivity : AuditPreviewActivity() { override val savedTimes = true; override val syncPhase = AuditSyncPhase.COMPLETE; override val archiveFocus = true }
class AuditSavedExpandedPreviewActivity : AuditPreviewActivity() { override val savedTimes = true; override val syncPhase = AuditSyncPhase.IDLE; override val archiveFocus = true; override val expanded = true }
class AuditSavedExpandedDarkPreviewActivity : AuditPreviewActivity() { override val savedTimes = true; override val syncPhase = AuditSyncPhase.IDLE; override val archiveFocus = true; override val expanded = true; override val dark = true }
class AuditSavedCacheOnlyPreviewActivity : AuditPreviewActivity() { override val savedTimes = true; override val archiveFocus = true }
class AuditUnknownLocalTimePreviewActivity : AuditPreviewActivity() { override val syncPhase = AuditSyncPhase.IDLE; override val archiveFocus = true }
