package dev.remozio.android.requests

import androidx.lifecycle.ViewModel

/** Retains handled intent state across activity recreation, without saving request captures to a Bundle. */
internal class CommandNavigationViewModel : ViewModel() {
    val navigation = CommandInboxNavigation()
    var initialIntentHandled = false
}
