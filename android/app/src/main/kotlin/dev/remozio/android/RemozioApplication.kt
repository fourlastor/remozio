package dev.remozio.android

import android.app.Application
import android.os.SystemClock
import dev.remozio.android.routing.*
import dev.remozio.android.decisions.AndroidDecisionIdentities
import dev.remozio.phone.transport.PhoneRoutingChallenge
import dev.remozio.android.push.*
import dev.remozio.android.push.androidPushClient
import dev.remozio.android.push.AndroidWakeNotifications
import dev.remozio.android.push.StoredWakeNotifications
import dev.remozio.android.push.PushDeliveryReports
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.android.audit.androidStoredAuditReader
import dev.remozio.android.audit.androidAuditConnections
import dev.remozio.android.audit.AuditWorkSettings
import dev.remozio.android.audit.ForegroundAuditConnections
import dev.remozio.android.enrollment.AndroidPairingAttempt
import dev.remozio.android.enrollment.AndroidEnrollmentStore
import dev.remozio.android.enrollment.validatePairingKeys
import dev.remozio.android.enrollment.StoredPairingHost
import dev.remozio.android.enrollment.StoredMacReader
import dev.remozio.android.enrollment.PairingReceiptRecovery
import dev.remozio.android.enrollment.androidPairingReceiptWire
import dev.remozio.android.updates.androidUpdateHost
import dev.remozio.android.updates.MacUpdateProgressConnection
import dev.remozio.android.updates.MacUpdateSchedulingConnection
import dev.remozio.android.updates.androidMacUpdateProgressConnections
import dev.remozio.android.updates.androidMacUpdateSchedulingConnections
import dev.remozio.android.updates.applicationMacUpdateScheduling
import dev.remozio.phone.transport.PhoneUpdateSchedulingStatus
import dev.remozio.protocol.UpdateSchedulingAction
import dev.remozio.android.requests.CommandRequestNotifications
import dev.remozio.android.requests.RequestElapsedClock
import dev.remozio.android.requests.ForegroundCommandConnections
import dev.remozio.android.requests.StoredCommandConnections
import dev.remozio.android.requests.androidCommandConnection
import dev.remozio.android.requests.commandRequestLimits
import dev.remozio.phone.requests.CommandMemoryBudget
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.async
import kotlinx.coroutines.launch

class RemozioApplication : Application() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val enrollmentAccess = Mutex()
    internal val pushDelivery by lazy { PushDeliveryReports(this) }
    internal val pushClient by lazy { androidPushClient(this) }
    internal val pushChallenges by lazy {
        ApplicationPushChallenges(pushClient, { AndroidPushChallenges.moment(this) }) { AndroidPushChallenges.open(this) }
    }
    internal val pushRegistrationWorkSettings by lazy { PushRegistrationWorkSettings(this) }
    private val pushProofs by lazy { ApplicationPushProofs(pushClient) { AndroidPushProofs.open(this) } }
    internal val pushRegistrations by lazy {
        StoredPushRegistrations(
            { AndroidEnrollmentStore.openExisting(this, maximumRecords = 1024, maximumPlaintextBytes = 16_777_216) },
            enrollmentAccess, pushClient, pushChallenges, pushProofs,
            { parent, record -> androidPushRecoveryWire(this, parent, record, pushRegistrationWorkSettings.read().operationSeconds * 1000L) },
            { parent, record -> androidPushProofWire(this, parent, record, pushRegistrationWorkSettings.read().operationSeconds * 1000L) },
            { pushRegistrationWorkSettings.read().operationSeconds * 1000L }, maximumConcurrent = 64,
            concurrencyLimit = { pushRegistrationWorkSettings.read().maximumConcurrent },
        )
    }
    internal val pushRegistrationWork by lazy {
        AndroidPushRegistrationWork(this, pushClient, pushRegistrationWorkSettings, pushRegistrations::records)
    }
    internal val wakeWorkSettings by lazy { WakeWorkSettings(this) }
    private val wakeDemand by lazy { ApplicationWakeDemand(pushClient) { AndroidWakeDemand.open(this) } }
    internal val wakeFetches by lazy {
        StoredWakeFetches(
            { AndroidEnrollmentStore.openExisting(this, maximumRecords = 1024, maximumPlaintextBytes = 16_777_216) },
            enrollmentAccess, pushClient, wakeDemand, { commands.acquire(it) },
            { wakeWorkSettings.read().snapshotSeconds * 1000L },
        )
    }
    internal val wakeWork by lazy { AndroidWakeWork(this, pushClient, wakeWorkSettings, wakeFetches) { generation, status ->
        pushClient.withCurrent(generation) { pushDelivery.record(generation, status) }
    } }
    private val notificationPublisher by lazy { AndroidWakeNotifications(this, 60_000) }
    private val commandNotifications by lazy {
        CommandRequestNotifications(RequestElapsedClock::now,
            { target, timeout -> notificationPublisher.postRequest(target, timeout) }, notificationPublisher::cancelRequest)
    }
    internal val wakeNotifications by lazy {
        val notifications = notificationPublisher
        StoredWakeNotifications(
            { AndroidEnrollmentStore.openExisting(this, maximumRecords = 1024, maximumPlaintextBytes = 16_777_216) },
            enrollmentAccess, pushClient, { ElapsedInstant(1, SystemClock.elapsedRealtime().toULong()) },
            notifications::postForRecord, notifications::cancelRecord,
            admit = { generation, selected, active ->
                wakeDemand.admit(generation, selected.enrollment.enrollmentTag, active.map { it.enrollment.enrollmentTag }.toSet())
            },
        )
    }
    override fun onCreate() {
        super.onCreate()
        pushClient.restore()
        wakeWork.start(scope)
        pushRegistrationWork.start(scope)
    }
    internal val macs by lazy {
        StoredMacReader({ AndroidEnrollmentStore.openExisting(this, maximumRecords = 1024, maximumPlaintextBytes = 16_777_216) }, enrollmentAccess = enrollmentAccess)
    }
    private val commandMemory = CommandMemoryBudget(8_388_608, 262_144)
    internal val commands by lazy {
        StoredCommandConnections(
            { AndroidEnrollmentStore.openExisting(this, maximumRecords = 1024, maximumPlaintextBytes = 16_777_216) },
            { androidCommandConnection(this, it, commandRequestLimits(), commandMemory).also { owner ->
                commandNotifications.observe(CoroutineScope(scope.coroutineContext + Dispatchers.IO), owner)
            } }, enrollmentAccess,
        )
    }
    internal val foregroundCommands by lazy { ForegroundCommandConnections(commands::acquireActive) }
    internal val routingWorkSettings by lazy { RoutingWorkSettings(this) }
    internal val routing by lazy {
        StoredRoutingConnections(
            { AndroidEnrollmentStore.openExisting(this, maximumRecords = 1024, maximumPlaintextBytes = 16_777_216) },
            { record, current -> MacRoutingConnection(record,
                open = { parent, active -> androidRoutingWire(this, parent, active, routingWorkSettings.read().operationSeconds * 1000L) },
                loadSigner = { active ->
                    val identity = AndroidDecisionIdentities.load(active)
                    object : RoutingDecisionSigner {
                        override fun sign(challenge: PhoneRoutingChallenge) = identity.signRoutingAway(challenge)
                        override fun close() = identity.close()
                    }
                }, current = current, freshnessMillis = { routingWorkSettings.read().freshnessSeconds * 1000L },
                timeoutMillis = { routingWorkSettings.read().operationSeconds * 1000L }) }, enrollmentAccess,
        )
    }
    internal val foregroundRouting by lazy { ForegroundRoutingConnections(routing::acquireActive) { routingWorkSettings.read().refreshSeconds * 1000L } }

    /** The application owns explicit routing work across navigation and activity replacement. */
    internal fun setRoutingAway(connection: MacRoutingConnection): kotlinx.coroutines.Deferred<Boolean> =
        applicationRoutingAway(scope, connection)

    internal fun refreshRouting(connection: MacRoutingConnection): kotlinx.coroutines.Deferred<Boolean> =
        scope.async(Dispatchers.IO) { connection.refresh() }

    internal val macUpdateScheduling by lazy {
        androidMacUpdateSchedulingConnections(this, enrollmentAccess,
            freshnessMillis = { routingWorkSettings.read().freshnessSeconds * 1000L },
            timeoutMillis = { routingWorkSettings.read().operationSeconds * 1000L })
    }

    internal val macUpdateProgress by lazy {
        androidMacUpdateProgressConnections(this, enrollmentAccess,
            freshnessMillis = { routingWorkSettings.read().freshnessSeconds * 1000L },
            timeoutMillis = { routingWorkSettings.read().operationSeconds * 1000L })
    }

    internal fun refreshMacUpdateProgress(connection: MacUpdateProgressConnection): kotlinx.coroutines.Deferred<Boolean> =
        scope.async(Dispatchers.IO) { connection.refresh() }

    internal fun scheduleMacUpdate(connection: MacUpdateSchedulingConnection, expected: PhoneUpdateSchedulingStatus,
        action: UpdateSchedulingAction): kotlinx.coroutines.Deferred<Boolean> =
        applicationMacUpdateScheduling(scope, connection, expected, action)

    internal fun refreshMacUpdateScheduling(connection: MacUpdateSchedulingConnection): kotlinx.coroutines.Deferred<Boolean> =
        scope.async(Dispatchers.IO) { connection.refresh() }

    internal val pairing by lazy {
        StoredPairingHost(
            { AndroidEnrollmentStore.open(this, maximumRecords = 1024, maximumPlaintextBytes = 16_777_216) },
            { AndroidEnrollmentStore.openExisting(this, maximumRecords = 1024, maximumPlaintextBytes = 16_777_216) },
            enrollmentAccess, { ids ->
                try { macUpdateProgress.invalidateRecordsLocked(ids) }
                finally {
                    try { macUpdateScheduling.invalidateRecordsLocked(ids) }
                    finally { retireEnrollmentConnectionsLocked(ids) }
                }
            }, ::validatePairingKeys, onChanged = {
                foregroundCommands.refresh()
                foregroundRouting.refresh()
                foregroundAudits.enrollmentsChanged()
                scope.launch(Dispatchers.IO) { pushRegistrationWork.changed() }
            },
        )
    }

    private suspend fun retireEnrollmentConnectionsLocked(ids: Set<dev.remozio.protocol.CborValue.Bytes>) {
        try { auditConnections.invalidateRecordsLocked(ids) }
        finally {
            try { routing.invalidateRecordsLocked(ids) }
            finally {
                try { commands.invalidateRecordsLocked(ids) }
                finally {
                    try { wakeFetches.invalidateRecordsLocked(ids) }
                    finally {
                        try { wakeNotifications.invalidateRecordsLocked(ids) }
                        finally { pushRegistrations.invalidateRecordsLocked(ids) }
                    }
                }
            }
        }
    }
    internal val pairingReceipts by lazy {
        PairingReceiptRecovery(pairing, { parent, record -> androidPairingReceiptWire(this, parent, record) })
    }
    internal fun retirePairing(attempt: AndroidPairingAttempt): kotlinx.coroutines.Deferred<Result<Unit>> {
        attempt.close()
        return scope.async { runCatching { attempt.closeAndJoin() } }
    }
    internal val auditWorkSettings by lazy { AuditWorkSettings(this) }
    internal val auditConnections by lazy { androidAuditConnections(this, scope, enrollmentAccess, auditWorkSettings::read) }
    internal val foregroundAudits by lazy { ForegroundAuditConnections(auditConnections::activeRecords, auditConnections::acquire) }
    internal val audits by lazy { androidStoredAuditReader(this, enrollmentAccess, auditConnections::readSnapshot) }
    internal val updates by lazy { androidUpdateHost(this, scope) }
}
