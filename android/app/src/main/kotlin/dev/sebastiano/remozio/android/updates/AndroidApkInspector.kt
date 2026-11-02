package dev.sebastiano.remozio.android.updates

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.SigningInfo
import android.os.Build
import java.io.File
import java.security.MessageDigest

internal interface ApkInspector {
    fun installed(): ApkIdentity
    fun verify(file: File): ApkIdentity
}

internal class AndroidApkInspector(context: Context) : ApkInspector {
    private val packages = context.applicationContext.packageManager
    private val packageName = context.applicationContext.packageName

    override fun installed(): ApkIdentity {
        val info = packages.getPackageInfo(packageName,
            PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()))
        return identity(info, info.signingInfo ?: throw UpdateRejected())
    }

    override fun verify(file: File): ApkIdentity {
        val signing = PackageManager.getVerifiedSigningInfo(file.path, SigningInfo.VERSION_SIGNING_BLOCK_V2)
        val info = packages.getPackageArchiveInfo(file.path, PackageManager.PackageInfoFlags.of(0))
            ?: throw UpdateRejected()
        return identity(info, signing)
    }

    private fun identity(info: PackageInfo, signing: SigningInfo): ApkIdentity {
        val app = info.applicationInfo ?: throw UpdateRejected()
        fun fingerprint(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
        val current = signing.apkContentsSigners?.map { fingerprint(it.toByteArray()) }?.toSet()
            ?: throw UpdateRejected()
        val history = if (signing.hasMultipleSigners()) emptyList() else
            signing.signingCertificateHistory?.map { fingerprint(it.toByteArray()) } ?: emptyList()
        return ApkIdentity(info.packageName, info.longVersionCode, info.versionName, current, history,
            app.minSdkVersion, app.targetSdkVersion,
            app.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0,
            app.flags and ApplicationInfo.FLAG_TEST_ONLY != 0,
            !info.splitNames.isNullOrEmpty())
    }
}

internal fun apkUpdateVerifier(context: Context, maxBytes: Long = 256L * 1024 * 1024) =
    StagedApkVerifier(context.applicationContext.cacheDir, AndroidApkInspector(context), Build.VERSION.SDK_INT, maxBytes)
