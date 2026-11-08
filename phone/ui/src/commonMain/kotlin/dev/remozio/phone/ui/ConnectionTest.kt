package dev.remozio.phone.ui

import dev.remozio.pairing.PairingSetupChannel
import dev.remozio.pairing.PlatformPairingKeys
import dev.remozio.pairing.connectPlatform
import dev.remozio.protocol.PairingInvitation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** The steps of a connection test. It never pairs: it stops at the comparison code and saves nothing. */
sealed interface ConnectionTestState {
    data object Idle : ConnectionTestState
    data object Connecting : ConnectionTestState
    data class Reached(val code: String) : ConnectionTestState
    data object Failed : ConnectionTestState
}

/**
 * Runs the setup exchange with fresh in-memory keys up to the transcript, then closes the channel.
 * No proof is sent, so the computer enrolls nothing.
 */
suspend fun testConnection(scope: CoroutineScope, invitationText: String, keys: PlatformPairingKeys,
    timeoutMillis: Long = 60_000,
): ConnectionTestState {
    val invitation = try { PairingInvitation.importText(invitationText.trim()) }
    catch (_: IllegalArgumentException) { return ConnectionTestState.Failed }
    catch (_: IllegalStateException) { return ConnectionTestState.Failed }
    val channel = try { PairingSetupChannel.connectPlatform(scope, invitation, keys, timeoutMillis) }
    catch (cancelled: CancellationException) { throw cancelled }
    catch (_: Throwable) { return ConnectionTestState.Failed }
    return try { ConnectionTestState.Reached(channel.transcript.verificationCode()) }
    finally { withContext(NonCancellable) { channel.closeAndJoin() } }
}
