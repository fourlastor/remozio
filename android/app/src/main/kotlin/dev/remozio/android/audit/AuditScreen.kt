package dev.remozio.android.audit

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import dev.remozio.android.R
import dev.remozio.android.RemozioApplication
import dev.remozio.phone.audit.*
import dev.remozio.phone.requests.ElapsedInstant
import android.os.SystemClock
import dev.remozio.protocol.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext

internal class AuditSelection(val scope: CachedAuditScope, val archive: CachedAuditArchive,
                             val loaded: CachedAuditContent.Loaded, val event: AuditEventMetadata)

@Composable
internal fun AuditScreen() {
    val app = LocalContext.current.applicationContext as RemozioApplication
    val reader = app.audits
    val foreground = app.foregroundAudits
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var mac by remember { mutableStateOf<CborValue.Bytes?>(null) }
    var macLabel by remember { mutableStateOf<String?>(null) }
    var category by remember { mutableStateOf<AuditCategory?>(null) }
    var outcome by remember { mutableStateOf<AuditOutcome?>(null) }
    var retry by remember { mutableIntStateOf(0) }
    var options by remember { mutableStateOf(emptyList<AuditMacOption>()) }
    var sync by remember { mutableStateOf<AuditSyncDisplays>(AuditSyncDisplays.Loading) }
    val displays = remember(foreground) { foreground.displays() }
    LaunchedEffect(foreground, lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) { foreground.runForeground() }
    }
    val moment by produceState<ElapsedInstant?>(null, lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            try {
                while (isActive) { value = ElapsedInstant(1, SystemClock.elapsedRealtime().toULong()); delay(1000) }
            } finally { value = null }
        }
    }
    val state by produceState<StoredAuditState>(StoredAuditState.Loading, reader, lifecycle, mac, category, outcome, retry) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            value = StoredAuditState.Loading
            try {
                displays.collect { current ->
                    sync = current
                    val result = reader.read(mac, category, outcome)
                    if (result is StoredAuditState.Ready) options = result.macs
                    value = result
                }
            } finally { value = StoredAuditState.Loading; sync = AuditSyncDisplays.Loading }
        }
    }
    AuditContent(state, options, mac, macLabel, category, outcome,
        onMac = { mac = it; macLabel = options.firstOrNull { option -> option.macID == it }?.label },
        onCategory = { category = it }, onOutcome = { outcome = it }, onRetry = { retry++; foreground.enrollmentsChanged() }, sync = sync, moment = moment)
}

/** Display-only content also used by disposable debug previews. The host owns reads and filter changes. */
@Composable
internal fun AuditContent(state: StoredAuditState, options: List<AuditMacOption>, mac: CborValue.Bytes? = null,
                          macLabel: String? = null, category: AuditCategory? = null, outcome: AuditOutcome? = null,
                          onMac: (CborValue.Bytes?) -> Unit = {}, onCategory: (AuditCategory?) -> Unit = {},
                          onOutcome: (AuditOutcome?) -> Unit = {}, onRetry: () -> Unit = {},
                          listState: LazyListState = rememberLazyListState(), sync: AuditSyncDisplays? = null,
                          moment: ElapsedInstant? = null) {
    var selection by remember(mac, category, outcome) { mutableStateOf<AuditSelection?>(null) }
    LaunchedEffect(state) { if (state !is StoredAuditState.Ready) selection = null }
    LazyColumn(Modifier.fillMaxSize(), state = listState, contentPadding = PaddingValues(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        item {
            Text(stringResource(R.string.audit_title), style = MaterialTheme.typography.headlineLarge,
                modifier = Modifier.semantics { heading() })
        }
        item { Text(stringResource(if (sync == null) R.string.audit_cached_notice else R.string.audit_sync_notice)) }
        item { Text(stringResource(R.string.audit_order_notice), style = MaterialTheme.typography.bodyMedium) }
        item {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                AuditFilter(stringResource(R.string.audit_filter_mac), macLabel ?: stringResource(R.string.audit_all_macs),
                    listOf<CborValue.Bytes?>(null).map { it to stringResource(R.string.audit_all_macs) } + options.map { it.macID to stringResource(R.string.audit_mac_choice, it.label, checkNotNull(auditID(it.macID.copyBytes()))) }) {
                    onMac(it)
                }
                AuditFilter(stringResource(R.string.audit_filter_category), category?.let { stringResource(auditLabel(it)) } ?: stringResource(R.string.audit_all_categories),
                    listOf<AuditCategory?>(null).map { it to stringResource(R.string.audit_all_categories) } + AuditCategory.entries.map { it to stringResource(auditLabel(it)) }) { onCategory(it) }
                AuditFilter(stringResource(R.string.audit_filter_outcome), outcome?.let { stringResource(auditLabel(it)) } ?: stringResource(R.string.audit_all_outcomes),
                    listOf<AuditOutcome?>(null).map { it to stringResource(R.string.audit_all_outcomes) } + AuditOutcome.entries.map { it to stringResource(auditLabel(it)) }) { onOutcome(it) }
            }
        }
        when (val current = state) {
            StoredAuditState.Loading -> item { Column(verticalArrangement = Arrangement.spacedBy(8.dp)) { CircularProgressIndicator(); Text(stringResource(R.string.audit_loading)) } }
            StoredAuditState.Unavailable -> item {
                AuditNotice(R.string.audit_unavailable_description)
                TextButton(onClick = onRetry) { Text(stringResource(R.string.audit_retry)) }
            }
            is StoredAuditState.Ready -> {
                if (current.macs.isEmpty()) item { Text(stringResource(R.string.audit_no_macs)) }
                else if (mac != null && current.macs.none { it.macID == mac }) item { Text(stringResource(R.string.audit_selected_mac_missing)) }
                current.scopes.forEach { scope ->
                    item {
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(scope.label, style = MaterialTheme.typography.titleLarge, modifier = Modifier.semantics { heading() })
                            AuditField(R.string.audit_mac_id, auditID(scope.scope.macID.copyBytes()))
                            AuditField(R.string.audit_account_id, auditID(scope.scope.accountID.copyBytes()))
                        }
                    }
                    if (scope.archives.size > 1) item { Text(stringResource(R.string.audit_archive_separation)) }
                    scope.archives.forEach { archive ->
                        item {
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                HorizontalDivider()
                                Text(stringResource(if (archive.retired) R.string.audit_archive_previous else R.string.audit_archive_current),
                                    style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
                                AuditField(R.string.audit_archive_key, archive.shortFingerprint)
                                if (sync != null) AuditSyncStatus(scope, archive, sync, moment, onRetry)
                                else (archive.content as? CachedAuditContent.Loaded)?.localTimes?.let {
                                    AuditSyncTimes(moment, null, null, it)
                                }
                            }
                        }
                        when (val content = archive.content) {
                            CachedAuditContent.Missing -> item { Text(stringResource(R.string.audit_missing)) }
                            CachedAuditContent.Unavailable -> item { AuditNotice(R.string.audit_scope_unavailable) }
                            is CachedAuditContent.Loaded -> auditGroup(content.history) { selection = AuditSelection(scope, archive, content, it) }
                        }
                    }
                }
                item { TextButton(onClick = onRetry) { Text(stringResource(R.string.audit_retry)) } }
            }
        }
    }
    selection?.let { selected -> AuditDetails(selected) { selection = null } }
}

@Composable
private fun AuditSyncStatus(scope: CachedAuditScope, archive: CachedAuditArchive, displays: AuditSyncDisplays,
                            moment: ElapsedInstant?, onRetry: () -> Unit) {
    val entry = (displays as? AuditSyncDisplays.Ready)?.entries?.singleOrNull {
        it.scope == AuditSyncScope(scope.scope.macID, scope.scope.accountID, archive.authorityPublicKey)
    }
    val observed = if (archive.retired) null else entry?.progress as? AuditSyncProgress.Observed
    when {
        archive.retired -> Text(stringResource(R.string.audit_sync_retired), style = MaterialTheme.typography.bodyMedium)
        displays is AuditSyncDisplays.Loading || entry?.progress is AuditSyncProgress.Loading ->
            Text(stringResource(R.string.audit_sync_opening))
        displays is AuditSyncDisplays.Unavailable || entry?.progress is AuditSyncProgress.Unavailable -> {
            AuditNotice(R.string.audit_sync_unavailable)
            TextButton(onClick = onRetry) { Text(stringResource(R.string.audit_retry)) }
        }
        observed != null -> {
            val progress = observed
            val label = when (progress.phase) {
                AuditSyncPhase.IDLE -> R.string.audit_sync_idle
                AuditSyncPhase.SYNCING -> R.string.audit_sync_running
                AuditSyncPhase.PAUSED -> R.string.audit_sync_paused
                AuditSyncPhase.COMPLETE -> R.string.audit_sync_complete
                AuditSyncPhase.CANCELLED, AuditSyncPhase.CLOSED -> R.string.audit_sync_stopped
                AuditSyncPhase.FAILED -> when (progress.failure) {
                    AuditSyncFailure.INVALID_RESPONSE -> R.string.audit_sync_invalid
                    AuditSyncFailure.STORAGE -> R.string.audit_sync_storage
                    AuditSyncFailure.CONFLICT -> R.string.audit_sync_conflict
                    AuditSyncFailure.HISTORY_CHANGED -> R.string.audit_sync_changed
                    else -> R.string.audit_sync_transport
                }
            }
            Text(stringResource(label), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            if (entry?.working == true) LinearProgressIndicator(Modifier.fillMaxWidth())
            AuditSyncTimes(moment, progress.completedAt, progress.responseAt, progress.localTimes)
            TextButton(enabled = entry != null && !entry.working && progress.phase != AuditSyncPhase.CLOSED,
                onClick = { entry?.request?.invoke(progress.phase == AuditSyncPhase.PAUSED) }) {
                Text(stringResource(if (progress.phase == AuditSyncPhase.PAUSED) R.string.audit_sync_continue else R.string.audit_sync_refresh))
            }
        }
        else -> Text(stringResource(R.string.audit_sync_no_active), style = MaterialTheme.typography.bodyMedium)
    }
    if (observed == null) (archive.content as? CachedAuditContent.Loaded)?.localTimes?.let {
        AuditSyncTimes(moment, null, null, it)
    }
}

@Composable
private fun AuditSyncTimes(now: ElapsedInstant?, completed: ElapsedInstant?, response: ElapsedInstant?, saved: AuditLocalSyncTimes?) {
    val completion = auditSyncTimestamp(now, completed, saved?.lastCompleted)
    val received = auditSyncTimestamp(now, response, saved?.lastResponse)
    AuditSyncMoment(R.string.audit_sync_last_complete, completion)
    if (received != completion) AuditSyncMoment(R.string.audit_sync_last_response, received)
}

@Composable
private fun AuditSyncMoment(label: Int, moment: AuditSyncTimestamp) {
    val text = when (moment) {
        AuditSyncTimestamp.Unknown -> stringResource(R.string.audit_sync_age_unknown)
        is AuditSyncTimestamp.PhoneTime -> auditTime(moment.value.unixMilliseconds.toULong())?.let {
            stringResource(R.string.audit_sync_saved_phone_time, it)
        } ?: stringResource(R.string.audit_sync_age_unknown)
        is AuditSyncTimestamp.ElapsedAge -> {
            val seconds = moment.milliseconds / 1000u
            val (resource, amount) = when {
                seconds >= 86400u -> R.plurals.audit_sync_days to seconds / 86400u
                seconds >= 3600u -> R.plurals.audit_sync_hours to seconds / 3600u
                seconds >= 60u -> R.plurals.audit_sync_minutes to seconds / 60u
                else -> R.plurals.audit_sync_seconds to seconds
            }
            pluralStringResource(resource, minOf(amount, Int.MAX_VALUE.toULong()).toInt(), amount.toLong())
        }
    }
    AuditField(label, text)
}

@Composable
private fun <T> AuditFilter(title: String, selected: String, choices: List<Pair<T, String>>, onSelect: (T) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        OutlinedButton(onClick = { expanded = true }) { Text("$title: $selected") }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            choices.forEach { (value, label) -> DropdownMenuItem(text = { Text(label) }, onClick = { expanded = false; onSelect(value) }) }
        }
    }
}

private fun LazyListScope.auditGroup(group: AuditHistoryGroup, onEvent: (AuditEventMetadata) -> Unit) {
    if (group.conflictingProofCount > 0) item { AuditNotice(R.string.audit_conflict) }
    if (group.reports.any { it.status.disposition == AuditHistoryDisposition.UNAVAILABLE || it.status.disposition == AuditHistoryDisposition.CURSOR_AHEAD }) {
        item { AuditNotice(R.string.audit_report_discontinuity) }
    }
    if (group.chains.isEmpty()) item { Text(stringResource(R.string.audit_no_segments)) }
    group.chains.forEach { chain ->
        if (group.chains.size > 1) item { AuditNotice(R.string.audit_independent_chain) }
        chain.epochs.forEach { epoch ->
            item {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    HorizontalDivider()
                    Text(stringResource(R.string.audit_segment), style = MaterialTheme.typography.titleMedium)
                    AuditField(R.string.audit_epoch_id, auditID(epoch.epoch.copyBytes()))
                    AuditEpochCauseField(epoch.descriptor?.cause)
                }
            }
            if (epoch.records.isEmpty()) item { Text(stringResource(if (epoch.retainedRecordCount > 0) R.string.audit_no_matching else R.string.audit_no_events)) }
            items(auditRows(epoch.records, epoch.gaps, newestFirst = true)) { row ->
                when (row) {
                    is AuditRow.Gap -> AuditGapNotice(row.value)
                    is AuditRow.Event -> {
                        val event = row.value
                        Card(onClick = { onEvent(event) }, modifier = Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(stringResource(auditLabel(event.kind)), style = MaterialTheme.typography.titleMedium)
                                Text(stringResource(auditLabel(event.category)))
                                AuditField(R.string.audit_outcome, stringResource(auditLabel(event.outcome)))
                                AuditField(R.string.audit_sequence, event.sequence.toString())
                                AuditField(R.string.audit_event_time, auditTime(event.eventTimeMs))
                                Text(stringResource(R.string.audit_event_details), style = MaterialTheme.typography.labelLarge)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AuditEpochCauseField(cause: AuditEpochCause?) {
    if (cause == null) Text(stringResource(R.string.audit_segment_unknown))
    else AuditField(R.string.audit_epoch_cause, stringResource(auditLabel(cause)))
}

@Composable
private fun AuditGapNotice(gap: AuditHistoryGap) {
    Column {
        Text(stringResource(R.string.audit_gap, gap.after.toString(), gap.through.toString()))
        if (gap.belowRetentionBoundary) Text(stringResource(R.string.audit_retention_gap))
    }
}

@Composable
private fun AuditNotice(resource: Int) {
    Text(stringResource(resource), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
}

@Composable
private fun AuditField(label: Int, value: String?) {
    Column {
        Text(stringResource(label), style = MaterialTheme.typography.labelMedium)
        Text(value ?: stringResource(R.string.audit_not_available), style = MaterialTheme.typography.bodyMedium)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun AuditDetails(selection: AuditSelection, onDismiss: () -> Unit) {
    val width = with(LocalDensity.current) { LocalWindowInfo.current.containerSize.width.toDp() }
    val timeline by produceState<AuditHistoryGroup?>(null, selection) {
        selection.event.requestID?.let { request -> value = withContext(Dispatchers.Default) { AuditHistory.timeline(selection.loaded.snapshot, request) } }
    }
    val content: @Composable () -> Unit = {
        Column(Modifier.fillMaxWidth().heightIn(max = 720.dp).padding(24.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(stringResource(R.string.audit_details), style = MaterialTheme.typography.headlineSmall,
                    modifier = Modifier.weight(1f).semantics { heading() })
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.audit_close)) }
            }
            LazyColumn(Modifier.weight(1f, fill = false), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                item {
                    Text(selection.scope.label, style = MaterialTheme.typography.titleMedium)
                    Text(stringResource(if (selection.archive.retired) R.string.audit_archive_previous else R.string.audit_archive_current))
                    AuditField(R.string.audit_archive_key, selection.archive.fingerprint)
                }
                item { Text(stringResource(R.string.audit_not_retained)) }
                item { Text(stringResource(R.string.audit_time_notice)) }
                item { AuditEventDetails(selection.event) }
                timeline?.let { group ->
                    item {
                        Text(stringResource(R.string.audit_timeline), style = MaterialTheme.typography.titleLarge,
                            modifier = Modifier.semantics { heading() })
                        Text(stringResource(R.string.audit_timeline_order))
                    }
                    if (group.conflictingProofCount > 0) item { AuditNotice(R.string.audit_conflict) }
                    group.chains.forEach { chain ->
                        if (group.chains.size > 1) item { AuditNotice(R.string.audit_independent_chain) }
                        chain.epochs.forEach { epoch ->
                            item {
                                HorizontalDivider()
                                AuditField(R.string.audit_epoch_id, auditID(epoch.epoch.copyBytes()))
                                AuditEpochCauseField(epoch.descriptor?.cause)
                            }
                            items(auditRows(epoch.records, epoch.gaps, newestFirst = false)) { row ->
                                when (row) {
                                    is AuditRow.Gap -> AuditGapNotice(row.value)
                                    is AuditRow.Event -> AuditEventDetails(row.value)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if (width < 600.dp) {
        ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberBottomSheetState(
            initialValue = SheetValue.Hidden, enabledValues = setOf(SheetValue.Hidden, SheetValue.Expanded),
        )) { content() }
    } else {
        Dialog(onDismissRequest = onDismiss) {
            Surface(modifier = Modifier.widthIn(max = 720.dp), shape = MaterialTheme.shapes.extraLarge) { content() }
        }
    }
}

@Composable
private fun AuditEventDetails(event: AuditEventMetadata) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(stringResource(auditLabel(event.kind)), style = MaterialTheme.typography.titleMedium)
        AuditField(R.string.audit_outcome, stringResource(auditLabel(event.outcome)))
        AuditField(R.string.audit_reason, stringResource(auditLabel(event.reason)))
        AuditField(R.string.audit_category, stringResource(auditLabel(event.category)))
        AuditField(R.string.audit_action, event.action?.let { stringResource(auditLabel(it.kind)) })
        AuditField(R.string.audit_lifetime, event.action?.let { stringResource(auditLabel(it.lifetime)) })
        AuditField(R.string.audit_target_scope, event.action?.target?.let { stringResource(auditLabel(it)) })
        AuditField(R.string.audit_authentication, stringResource(auditLabel(event.authentication)))
        AuditField(R.string.audit_event_time, auditTime(event.eventTimeMs))
        AuditField(R.string.audit_receipt_time, auditTime(event.authorityReceiptTimeMs))
        AuditField(R.string.audit_mac_id, auditID(event.macID))
        AuditField(R.string.audit_account_id, auditID(event.accountID))
        AuditField(R.string.audit_request_id, auditID(event.requestID))
        AuditField(R.string.audit_event_id, auditID(event.eventID))
        AuditField(R.string.audit_epoch_id, auditID(event.journalEpoch))
        AuditField(R.string.audit_sequence, event.sequence.toString())
        AuditField(R.string.audit_deciding_phone, auditID(event.decisionPhoneID))
        AuditField(R.string.audit_peer, auditID(event.peerDeviceID))
        AuditField(R.string.audit_dropped_events, event.droppedEventCount?.toString())
    }
}
