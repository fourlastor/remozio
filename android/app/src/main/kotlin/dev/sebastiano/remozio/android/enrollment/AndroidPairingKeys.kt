package dev.sebastiano.remozio.android.enrollment

import androidx.annotation.WorkerThread
import dev.sebastiano.remozio.android.biometrics.loadBiometricKey
import dev.sebastiano.remozio.android.decisions.loadDecisionKey
import dev.sebastiano.remozio.android.transport.AndroidTransportIdentities
import dev.remozio.phone.enrollment.PhoneEnrollment

/** Checks existing keys only. Missing or invalidated keys are never silently replaced. */
@WorkerThread
internal fun validatePairingKeys(enrollment: PhoneEnrollment) {
    AndroidTransportIdentities.load(enrollment.transportKey.alias, enrollment.transportKey.publicKey.copyBytes()).use {
        check(!it.requiresUnlockedDevice)
        loadDecisionKey(enrollment.decisionKey)
        loadBiometricKey(enrollment.biometricKey)
    }
}
