package dev.sebastiano.remozio.android.audit

import dev.remozio.phone.audit.AuditHistoryGap
import dev.remozio.protocol.AuditEventMetadata

internal sealed interface AuditRow {
    class Event(val value: AuditEventMetadata) : AuditRow
    class Gap(val value: AuditHistoryGap) : AuditRow
}

/** A gap follows its lower sequence boundary. No clock value affects this order. */
internal fun auditRows(records: List<AuditEventMetadata>, gaps: List<AuditHistoryGap>, newestFirst: Boolean): List<AuditRow> {
    val rows: List<AuditRow> = records.map(AuditRow::Event) + gaps.map(AuditRow::Gap)
    val ordered = rows.sortedWith(compareBy<AuditRow> {
        when (it) { is AuditRow.Event -> it.value.sequence; is AuditRow.Gap -> it.value.after }
    }.thenBy { if (it is AuditRow.Event) 0 else 1 })
    return if (newestFirst) ordered.asReversed() else ordered
}
