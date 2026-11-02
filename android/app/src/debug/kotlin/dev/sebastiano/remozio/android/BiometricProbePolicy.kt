package dev.sebastiano.remozio.android

internal data class BiometricProbePolicy(
    val hardwareBacked: Boolean,
    val securityLevel: Int,
    val nonExportable: Boolean,
    val authenticationRequired: Boolean,
    val hardwareAuthentication: Boolean,
    val validitySeconds: Int,
    val authenticationType: Int,
    val strongBiometricType: Int,
    val unlockedDeviceRequired: Boolean,
    val invalidatedByEnrollment: Boolean,
) {
    val accepted: Boolean get() = hardwareBacked && nonExportable && authenticationRequired &&
        hardwareAuthentication && validitySeconds in -1..0 && authenticationType == strongBiometricType &&
        unlockedDeviceRequired

    // Only primitive policy metadata enters this report; no provider messages or key material.
    fun diagnostic(): String = "hardwareBacked=$hardwareBacked; securityLevel=$securityLevel; " +
        "nonExportable=$nonExportable; authenticationRequired=$authenticationRequired; " +
        "hardwareAuthentication=$hardwareAuthentication; validitySeconds=$validitySeconds (expected -1 or 0); " +
        "authenticationType=$authenticationType (expected $strongBiometricType); " +
        "unlockedDeviceRequired=$unlockedDeviceRequired; invalidatedByEnrollment=$invalidatedByEnrollment"
}

internal class BiometricProbePolicyException(val policy: BiometricProbePolicy) : IllegalStateException()
