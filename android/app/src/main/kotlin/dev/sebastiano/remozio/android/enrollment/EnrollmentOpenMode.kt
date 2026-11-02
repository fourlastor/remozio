package dev.sebastiano.remozio.android.enrollment

import dev.remozio.phone.enrollment.EnrollmentStoreUnavailable

internal enum class EnrollmentOpenMode { EMPTY, OPEN, CREATE }

internal fun enrollmentOpenMode(hasKey: Boolean, hasArchive: Boolean, createIfAbsent: Boolean): EnrollmentOpenMode {
    if (hasKey != hasArchive) throw EnrollmentStoreUnavailable()
    return when {
        hasKey -> EnrollmentOpenMode.OPEN
        createIfAbsent -> EnrollmentOpenMode.CREATE
        else -> EnrollmentOpenMode.EMPTY
    }
}
