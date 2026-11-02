package dev.sebastiano.remozio.android.updates

import android.content.pm.PackageInstaller

internal const val UPDATE_STATUS_ACTION = "dev.remozio.UPDATE_STATUS"
internal const val UPDATE_CONFIRM_ACTION = "dev.remozio.UPDATE_CONFIRM"

internal data class UpdateCallbackBinding(val sessionId: Int, val nonce: String) {
    init {
        require(sessionId >= 0)
        require(nonce.matches(Regex("[0-9a-f]{64}")))
    }
    val uri get() = "remozio-update://session/$sessionId/$nonce"
    fun matches(record: UpdateRecord) = record.sessionId == sessionId && record.nonce == nonce

    companion object {
        fun parse(value: String?): UpdateCallbackBinding? {
            val match = Regex("remozio-update://session/(0|[1-9][0-9]{0,9})/([0-9a-f]{64})").matchEntire(value ?: return null)
                ?: return null
            val id = match.groupValues[1].toIntOrNull() ?: return null
            return UpdateCallbackBinding(id, match.groupValues[2])
        }
    }
}

internal data class UpdateCallback(val binding: UpdateCallbackBinding, val phase: UpdatePhase)

internal fun decodeUpdateCallback(
    action: String?, data: String?, sessionId: Int, status: Int, preApproval: Boolean,
): UpdateCallback? {
    if (action != UPDATE_STATUS_ACTION || preApproval) return null
    val binding = UpdateCallbackBinding.parse(data) ?: return null
    if (binding.sessionId != sessionId) return null
    val phase = when (status) {
        PackageInstaller.STATUS_PENDING_USER_ACTION -> UpdatePhase.AWAITING_USER
        PackageInstaller.STATUS_SUCCESS -> UpdatePhase.SUCCESS
        PackageInstaller.STATUS_FAILURE,
        PackageInstaller.STATUS_FAILURE_BLOCKED,
        PackageInstaller.STATUS_FAILURE_ABORTED,
        PackageInstaller.STATUS_FAILURE_INVALID,
        PackageInstaller.STATUS_FAILURE_CONFLICT,
        PackageInstaller.STATUS_FAILURE_STORAGE,
        PackageInstaller.STATUS_FAILURE_INCOMPATIBLE,
        PackageInstaller.STATUS_FAILURE_TIMEOUT -> UpdatePhase.FAILURE
        else -> return null
    }
    return UpdateCallback(binding, phase)
}
