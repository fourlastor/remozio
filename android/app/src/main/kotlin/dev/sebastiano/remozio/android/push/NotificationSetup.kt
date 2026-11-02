package dev.sebastiano.remozio.android.push

internal enum class NotificationAccess {
    PERMISSION_REQUIRED, APP_DISABLED, CHANNEL_MISSING, CHANNEL_DISABLED, ALLOWED, QUIET, UNAVAILABLE,
}
internal enum class LocalNotificationResult { SUBMITTED, BLOCKED, FAILED, CLEARED }

/** Local permission and channel state cannot establish remote delivery or visibility. */
internal fun notificationAccess(permission: Boolean, appEnabled: Boolean, channelImportance: Int?): NotificationAccess = when {
    !permission -> NotificationAccess.PERMISSION_REQUIRED
    !appEnabled -> NotificationAccess.APP_DISABLED
    channelImportance == null -> NotificationAccess.CHANNEL_MISSING
    channelImportance == 0 -> NotificationAccess.CHANNEL_DISABLED
    channelImportance !in 1..5 -> NotificationAccess.UNAVAILABLE
    channelImportance < 4 -> NotificationAccess.QUIET
    else -> NotificationAccess.ALLOWED
}

internal val NotificationAccess.canTest: Boolean
    get() = this == NotificationAccess.ALLOWED || this == NotificationAccess.QUIET
