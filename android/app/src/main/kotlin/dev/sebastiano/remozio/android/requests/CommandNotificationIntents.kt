package dev.sebastiano.remozio.android.requests

import android.content.Context
import android.content.Intent
import androidx.core.net.toUri
import dev.sebastiano.remozio.android.MainActivity

/** Explicit immutable PendingIntents use distinct data identities; extras never carry authority. */
internal object CommandNotificationIntents {
    const val OPEN_INBOX = "dev.sebastiano.remozio.android.OPEN_INBOX"
    const val OPEN_REQUEST = "dev.sebastiano.remozio.android.OPEN_REQUEST"
    fun inbox(context: Context) = Intent(context, MainActivity::class.java)
        .setAction(OPEN_INBOX).setData("remozio:inbox:v1".toUri())
        .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
    fun request(context: Context, target: CommandNotificationTarget) = inbox(context)
        .setAction(OPEN_REQUEST).setData(target.encode().toUri())
    fun receive(intent: Intent, navigation: CommandInboxNavigation) {
        when (intent.action) {
            OPEN_INBOX -> if (intent.dataString == "remozio:inbox:v1") navigation.request(null)
            OPEN_REQUEST -> CommandNotificationTarget.decode(intent.dataString)?.let(navigation::request)
        }
    }
}
