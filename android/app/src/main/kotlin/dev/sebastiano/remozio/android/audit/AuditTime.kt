package dev.sebastiano.remozio.android.audit

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

internal fun auditTime(milliseconds: ULong?, zone: ZoneId = ZoneId.systemDefault()): String? {
    if (milliseconds == null || milliseconds > Long.MAX_VALUE.toULong()) return null
    return try {
        val value = Instant.ofEpochMilli(milliseconds.toLong()).atZone(zone)
        if (value.year !in 1..9999) null else DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM).format(value)
    } catch (_: java.time.DateTimeException) { null }
}

internal fun auditID(bytes: ByteArray?): String? = bytes?.joinToString("") { "%02x".format(it) }
