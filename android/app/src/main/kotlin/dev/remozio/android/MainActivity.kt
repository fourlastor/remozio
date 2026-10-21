package dev.remozio.android

import android.os.Bundle
import android.content.Intent
import dev.remozio.android.requests.*
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.delay
import androidx.compose.runtime.LaunchedEffect
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.ViewModelProvider
import dev.remozio.android.enrollment.PairingViewModel
import dev.remozio.android.enrollment.PairingSetupSheet
import dev.remozio.android.enrollment.PairingPhase
import androidx.compose.material3.Button
import dev.remozio.android.audit.AuditScreen
import dev.remozio.android.push.NotificationSettingsScreen
import dev.remozio.android.enrollment.StoredMacList
import dev.remozio.android.enrollment.StoredMac
import dev.remozio.android.requests.CombinedCommandInboxScreen
import dev.remozio.android.requests.CommandInboxScreen
import androidx.activity.compose.BackHandler
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import dev.remozio.android.updates.UpdateStatusCard
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialExpressiveTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Text
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
    private lateinit var requestNavigation: CommandNavigationViewModel
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        CommandNotificationIntents.receive(intent, requestNavigation.navigation)
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val pairing = ViewModelProvider(this, PairingViewModel.Factory(application as RemozioApplication))[PairingViewModel::class.java]
        requestNavigation = ViewModelProvider(this)[CommandNavigationViewModel::class.java]
        if (!requestNavigation.initialIntentHandled) {
            requestNavigation.initialIntentHandled = true
            CommandNotificationIntents.receive(intent, requestNavigation.navigation)
        }
        setContent { RemozioTheme { RemozioScreen(pairing, this, requestNavigation.navigation) } }
    }
}

@Composable
internal fun RemozioTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    val context = LocalContext.current
    val colors = if (darkTheme) {
        dynamicDarkColorScheme(context)
    } else {
        dynamicLightColorScheme(context)
    }
    MaterialExpressiveTheme(colorScheme = colors, content = content)
}

@Composable
private fun RemozioScreen(pairing: PairingViewModel, activity: ComponentActivity, navigation: CommandInboxNavigation) {
    val commands = (LocalContext.current.applicationContext as RemozioApplication).foregroundCommands
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(commands, lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) { commands.runForeground() }
    }
    var destination by rememberSaveable { mutableIntStateOf(0) }
    val foreground by commands.state.collectAsStateWithLifecycle()
    val owners = (foreground as? ForegroundCommandState.Ready)?.owners.orEmpty()
    val requestFlow = remember(owners) { observeCommandInbox(owners) }
    val requests by requestFlow.collectAsStateWithLifecycle(initialValue = emptyList())
    val route by navigation.state.collectAsStateWithLifecycle()
    val setup by pairing.state.collectAsStateWithLifecycle()
    val pairingOpen = setup.phase != PairingPhase.CLOSED
    LaunchedEffect(owners, requests, route.pending, route.selected, foreground, pairingOpen) {
        navigation.synchronize(owners, requests, foreground is ForegroundCommandState.Ready, canOpen = !pairingOpen)
    }
    LaunchedEffect(route.inboxRequested, route.selected, pairingOpen) {
        if (route.inboxRequested && route.selected == null && !pairingOpen) {
            destination = 0
            navigation.inboxShown()
        }
    }
    LaunchedEffect(route.pending, route.selected, lifecycle, pairingOpen) {
        val pending = route.pending
        if (pending != null && route.selected == null && !pairingOpen) lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            val app = activity.application as RemozioApplication
            delay(app.wakeWorkSettings.read().snapshotSeconds * 1000L)
            navigation.expire(pending.serial)
        }
    }
    RemozioNavigation(destination, { destination = it }) {
        when (destination) {
            1 -> MacsScreen(pairing, navigation)
            2 -> AuditScreen()
            3 -> NotificationSettingsScreen()
            else -> CombinedCommandInboxScreen(pairing::open, navigation)
        }
    }
    CommandInspectionHost(navigation, owners)
    PairingSetupSheet(pairing, activity)
}

/** The same adaptive navigation shell is used by the app and its debug display fixtures. */
@Composable
internal fun RemozioNavigation(destination: Int, onDestination: (Int) -> Unit, content: @Composable () -> Unit) {
    val labels = listOf(R.string.nav_requests, R.string.nav_macs, R.string.nav_audit, R.string.nav_settings)
    val icons = listOf(R.drawable.ic_requests, R.drawable.ic_macs, R.drawable.ic_audit, R.drawable.ic_settings)
    BoxWithConstraints(Modifier.fillMaxSize()) {
        val expanded = maxWidth >= 600.dp
        Scaffold(bottomBar = {
            if (!expanded) NavigationBar {
                labels.indices.forEach { index -> NavigationBarItem(
                    selected = destination == index, onClick = { onDestination(index) },
                    icon = { Icon(painterResource(icons[index]), contentDescription = null) },
                    label = { Text(stringResource(labels[index])) },
                ) }
            }
        }) { insets ->
            Row(Modifier.fillMaxSize().padding(insets)) {
                if (expanded) NavigationRail {
                    labels.indices.forEach { index -> NavigationRailItem(
                        selected = destination == index, onClick = { onDestination(index) },
                        icon = { Icon(painterResource(icons[index]), contentDescription = null) },
                        label = { Text(stringResource(labels[index])) },
                    ) }
                }
                Box(Modifier.weight(1f)) {
                    content()
                }
            }
        }
    }

}

@Composable
private fun MacsScreen(pairing: PairingViewModel, navigation: CommandInboxNavigation) {
    var selected by remember { mutableStateOf<StoredMac?>(null) }
    selected?.let { mac ->
        BackHandler { selected = null }
        CommandInboxScreen(mac, onBack = { selected = null }, navigation = navigation)
        return
    }
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(Modifier.widthIn(max = 720.dp).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(24.dp)) {
            Text(stringResource(R.string.your_macs), style = MaterialTheme.typography.headlineLarge,
                modifier = Modifier.semantics { heading() })
            Button(onClick = pairing::open) { Text(stringResource(R.string.pairing_setup_title)) }
            val setup by pairing.state.collectAsState()
            androidx.compose.runtime.key(setup.phase == PairingPhase.CLOSED) {
                StoredMacList(onOpen = { selected = it })
            }
            UpdateStatusCard()
            DevelopmentTools()
        }
    }
}
