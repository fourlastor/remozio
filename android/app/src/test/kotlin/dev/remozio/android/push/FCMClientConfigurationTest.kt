package dev.remozio.android.push

import java.util.UUID
import kotlinx.serialization.json.*
import org.junit.Test
import kotlin.test.*

internal fun publicFCMConfiguration(packageName: String = "dev.remozio.android.debug", sender: String = "12345", project: String = "remozio-test"): ByteArray =
    buildJsonObject {
        putJsonObject("project_info") { put("project_id", project); put("project_number", sender) }
        putJsonArray("client") {
            add(buildJsonObject {
                putJsonObject("client_info") { put("mobilesdk_app_id", "1:$sender:android:abcdef123456"); putJsonObject("android_client_info") { put("package_name", packageName) } }
                putJsonArray("api_key") { add(buildJsonObject { put("current_key", "A" + "x".repeat(38)) }) }
            })
        }
    }.toString().encodeToByteArray()

class FCMClientConfigurationTest {
    private val packageName = "dev.remozio.android.debug"
    @Test fun importsOnlyTheInstalledPackageAndRoundTripsThePrivateLocalRecord() {
        val config = FCMClientConfiguration.import(publicFCMConfiguration(), packageName)
        assertEquals("12345", config.senderID); assertEquals("remozio-test", config.projectID)
        assertEquals(packageName, config.packageName)
        assertFalse(config.toString().contains(config.apiKey))
        val stored = StoredPushConfiguration(UUID.randomUUID(), config, true)
        val restored = StoredPushConfiguration.decode(stored.encode(), packageName)
        assertTrue(restored.client.sameAs(config)); assertEquals(stored.generation, restored.generation); assertTrue(restored.enabled)
        assertContentEquals(stored.encode(), restored.encode())
        assertEquals("StoredPushConfiguration(redacted)", stored.toString())
    }
    @Test fun selectsOneMatchingClientWithoutUsingAnotherAppsKey() {
        val root = Json.parseToJsonElement(publicFCMConfiguration().decodeToString()).jsonObject
        val other = Json.parseToJsonElement(publicFCMConfiguration("dev.other.app", "67890").decodeToString()).jsonObject["client"]!!.jsonArray.single()
        val clients = root["client"]!!.jsonArray
        val multiple = JsonObject(root + ("client" to JsonArray(listOf(other) + clients)))
        assertEquals("12345", FCMClientConfiguration.import(multiple.toString().encodeToByteArray(), packageName).senderID)
        val duplicate = JsonObject(root + ("client" to JsonArray(clients + clients)))
        assertFails { FCMClientConfiguration.import(duplicate.toString().encodeToByteArray(), packageName) }
        assertFails { FCMClientConfiguration.import(publicFCMConfiguration("dev.other.app"), packageName) }
    }
    @Test fun rejectsProviderSecretsMalformedUtf8OversizedAndDeepInput() {
        val invalid = listOf(
            "{\"type\":\"service_account\",\"private_key\":\"synthetic-secret\"}".encodeToByteArray(),
            byteArrayOf(0xc3.toByte(), 0x28), ByteArray(FCMClientConfiguration.MAXIMUM_BYTES + 1),
            ("[".repeat(17) + "0" + "]".repeat(17)).encodeToByteArray(), byteArrayOf(),
            "{\"project_info\":true}".encodeToByteArray(),
        )
        invalid.forEach { assertFails { FCMClientConfiguration.import(it, packageName) } }
    }
    @Test fun rejectsMismatchedSenderAndInvalidLocalStorageWithoutFallback() {
        val source = publicFCMConfiguration().decodeToString()
        assertFails { FCMClientConfiguration.import(source.replace("1:12345:android:", "1:67890:android:").encodeToByteArray(), packageName) }
        val config = FCMClientConfiguration.import(publicFCMConfiguration(), packageName)
        val stored = StoredPushConfiguration(UUID.randomUUID(), config, false).encode().decodeToString()
        for (invalid in listOf(stored.replace("\"version\":1", "\"version\":2"),
            stored.replace("\"enabled\":false", "\"enabled\":\"false\""),
            stored.dropLast(1) + ",\"unknown\":1}", stored.replace(packageName, "dev.other.app"))) {
            assertFails { StoredPushConfiguration.decode(invalid.encodeToByteArray(), packageName) }
        }
    }
    @Test fun providerNotificationPrefixesCannotReachSdkRendering() {
        assertTrue(acceptsFCMExtras(setOf("wake_v1", "enrollment_v1", "google.message_id", "from")))
        for (key in listOf("gcm.n.e", "gcm.n.body", "gcm.notification.title", "gcm.notification.android_channel_id")) {
            assertFalse(acceptsFCMExtras(setOf("wake_v1", key)))
        }
    }
}
