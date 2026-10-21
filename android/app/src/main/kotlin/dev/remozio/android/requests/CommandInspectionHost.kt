package dev.remozio.android.requests

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.remozio.android.R

/** One root placement keeps a new notification or a filter change from replacing biometric state. */
@Composable
internal fun CommandInspectionHost(navigation: CommandInboxNavigation, owners: List<StoredCommandOwner>) {
    val state by navigation.state.collectAsStateWithLifecycle()
    state.selected?.takeIf { it.isCurrent(owners) }?.let { request ->
        val approval = remember(request.connection, request.session) { request.connection.approval(request.session) }
        CommandRequestInspection(request.session, commandMacLabel(request.owner, owners),
            stringResource(R.string.commands_account_suffix, commandAccountSuffix(request.owner, owners)),
            onDismiss = navigation::dismiss, approval = approval)
    }
}
