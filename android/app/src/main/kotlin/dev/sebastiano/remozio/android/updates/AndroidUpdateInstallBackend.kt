package dev.sebastiano.remozio.android.updates

import android.content.Context
import android.content.IntentSender
import android.content.pm.PackageInstaller
import java.io.OutputStream

/** The host supplies a private, session-bound status receiver before any commit can run. */
internal class AndroidUpdateInstallBackend(
    context: Context,
    private val statusReceiver: (Int) -> IntentSender,
) : UpdateInstallBackend {
    private val packages = context.applicationContext.packageManager
    private val installer = packages.packageInstaller
    private val inspector = AndroidApkInspector(context)

    override fun canRequestInstallation() = packages.canRequestPackageInstalls()
    override fun installed() = inspector.installed()

    override fun create(identity: ApkIdentity, size: Long): UpdateInstallSession {
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(identity.packageName)
            setSize(size)
            setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
        }
        val sessionId = installer.createSession(params)
        var session: PackageInstaller.Session? = null
        try {
            val receiver = statusReceiver(sessionId)
            val opened = installer.openSession(sessionId)
            session = opened
            return object : UpdateInstallSession {
                override val id = sessionId
                override fun openWrite(size: Long) = opened.openWrite("base.apk", 0, size)
                override fun fsync(output: OutputStream) = opened.fsync(output)
                override fun commit() = opened.commit(receiver)
                override fun abandon() = opened.abandon()
                override fun close() = opened.close()
            }
        } catch (error: Exception) {
            runCatching { session?.close() }
            runCatching { installer.abandonSession(sessionId) }
            throw error
        }
    }
}
