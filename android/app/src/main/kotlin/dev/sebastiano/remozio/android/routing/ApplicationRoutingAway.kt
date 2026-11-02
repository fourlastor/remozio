package dev.sebastiano.remozio.android.routing

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async

/** The application owns this scope. Cancelling a screen waiter must not cancel the explicit operation. */
internal fun applicationRoutingAway(scope: CoroutineScope, connection: MacRoutingConnection): Deferred<Boolean> =
    scope.async { connection.setAway() }
