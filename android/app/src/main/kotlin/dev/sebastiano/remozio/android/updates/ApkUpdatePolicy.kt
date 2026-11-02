package dev.sebastiano.remozio.android.updates

internal class UpdateRejected : Exception("The update could not be verified")

internal class ApkIdentity(
    val packageName: String,
    val versionCode: Long,
    val versionName: String?,
    currentSigners: Set<String>,
    signingHistory: List<String>,
    val minSdk: Int,
    val targetSdk: Int,
    val debuggable: Boolean = false,
    val testOnly: Boolean = false,
    val split: Boolean = false,
) {
    val currentSigners = currentSigners.toSet()
    val signingHistory = signingHistory.toList()
}

internal fun checkUpdate(installed: ApkIdentity, candidate: ApkIdentity, deviceSdk: Int) {
    if (candidate.packageName != installed.packageName || candidate.versionCode <= installed.versionCode ||
        candidate.minSdk < 37 || candidate.minSdk > deviceSdk || candidate.targetSdk < installed.targetSdk ||
        candidate.split || candidate.debuggable && !installed.debuggable || candidate.testOnly && !installed.testOnly ||
        installed.currentSigners.isEmpty() || candidate.currentSigners.isEmpty()) throw UpdateRejected()
    if (installed.currentSigners == candidate.currentSigners) return
    if (installed.currentSigners.size != 1 || candidate.currentSigners.size != 1) throw UpdateRejected()
    val previous = installed.currentSigners.single()
    val next = candidate.currentSigners.single()
    if (next in installed.signingHistory || candidate.signingHistory.lastOrNull() != next ||
        previous !in candidate.signingHistory) throw UpdateRejected()
}
