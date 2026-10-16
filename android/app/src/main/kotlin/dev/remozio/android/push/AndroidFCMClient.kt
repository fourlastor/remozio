package dev.remozio.android.push

import android.content.Context
import android.util.AtomicFile
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.messaging.FirebaseMessaging
import java.io.File
import java.io.FileNotFoundException
import android.system.Os
import android.system.OsConstants

internal fun androidPushClient(context: Context): PushClientOwner {
    val app = context.applicationContext
    check(!app.isDeviceProtectedStorage)
    return PushClientOwner(app.packageName, AndroidPushConfigurationStorage(app), AndroidFCMDriver(app))
}

/** Uses the existing HTTP v1 registration-token contract. FID direct-send is a separate protocol migration. */
@Suppress("DEPRECATION")
private class AndroidFCMDriver(private val context: Context) : PushClientDriver {
    private var messaging: FirebaseMessaging? = null
    override fun start(configuration: FCMClientConfiguration, token: (String) -> Unit, failed: () -> Unit) {
        val options = FirebaseOptions.Builder().setApplicationId(configuration.applicationID).setApiKey(configuration.apiKey)
            .setProjectId(configuration.projectID).setGcmSenderId(configuration.senderID).build()
        val existing = FirebaseApp.getApps(context).singleOrNull { it.name == FirebaseApp.DEFAULT_APP_NAME }
        val firebase = existing?.also { check(it.options == options) } ?: FirebaseApp.initializeApp(context, options)
        firebase.isDataCollectionDefaultEnabled = false
        val client = FirebaseMessaging.getInstance()
        client.setDeliveryMetricsExportToBigQuery(false)
        client.isAutoInitEnabled = true
        messaging = client
        client.token.addOnCompleteListener { result ->
            if (result.isSuccessful && result.result != null) token(result.result) else failed()
        }
    }
    override fun stop() { messaging?.isAutoInitEnabled = false }
}

/** Public options live in app-private, non-backup storage. Atomic publication does not change any pairing record. */
private class AndroidPushConfigurationStorage(context: Context) : PushConfigurationStorage {
    private val packageName = context.packageName
    private val parent = context.noBackupFilesDir
    private val file = File(parent, "fcm-client-v1.json")
    private val atomic = AtomicFile(file)
    override fun read(): StoredPushConfiguration? {
        val input = try { atomic.openRead() } catch (failure: FileNotFoundException) {
            check(!file.exists() && !File(file.path + ".bak").exists() && !File(file.path + ".new").exists())
            return null
        }
        return input.use {
            val bytes = it.readNBytes(FCMClientConfiguration.MAXIMUM_BYTES + 1)
            StoredPushConfiguration.decode(bytes, packageName)
        }
    }
    override fun replace(configuration: StoredPushConfiguration) {
        val bytes = configuration.encode()
        require(bytes.size <= FCMClientConfiguration.MAXIMUM_BYTES)
        val output = atomic.startWrite()
        try {
            output.write(bytes); output.fd.sync(); atomic.finishWrite(output)
            val directory = Os.open(parent.path, OsConstants.O_RDONLY, 0)
            try { Os.fsync(directory) } finally { Os.close(directory) }
        } catch (failure: Exception) { atomic.failWrite(output); throw failure }
    }
}
