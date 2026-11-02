package dev.sebastiano.remozio.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BiometricProbePolicyTest {
    private val valid = BiometricProbePolicy(true, 2, true, true, true, -1, 2, 2, true, false)

    @Test fun policyDiagnosticsPreserveEveryRejection() {
        assertTrue(valid.accepted)
        listOf(
            valid.copy(hardwareBacked = false), valid.copy(nonExportable = false),
            valid.copy(authenticationRequired = false), valid.copy(hardwareAuthentication = false),
            valid.copy(validitySeconds = -2), valid.copy(validitySeconds = 30),
            valid.copy(authenticationType = 0), valid.copy(authenticationType = 3),
            valid.copy(unlockedDeviceRequired = false),
        ).forEach { assertFalse(it.accepted) }
    }

    @Test fun perUseRepresentationsPermitOnlyTheSigningExperiment() {
        assertTrue(valid.copy(validitySeconds = -1).accepted)
        assertTrue(valid.copy(validitySeconds = 0, invalidatedByEnrollment = true).accepted)
        assertTrue(valid.copy(invalidatedByEnrollment = true).diagnostic().contains("invalidatedByEnrollment=true"))
    }

    @Test fun reportIncludesUnexpectedMetadataWithoutProviderText() {
        val report = valid.copy(validitySeconds = 0, unlockedDeviceRequired = false).diagnostic()
        assertTrue(report.contains("validitySeconds=0 (expected -1 or 0)"))
        assertTrue(report.contains("unlockedDeviceRequired=false"))
        assertTrue(report.contains("hardwareAuthentication=true"))
        assertFalse(report.contains("remozio.debug.biometric-probe.v1"))
    }
}
