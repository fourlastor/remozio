package dev.remozio.android.push

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.UUID
import kotlinx.serialization.json.*

/** Public Android client options only. This is never a provider service account or an approval identity. */
internal class FCMClientConfiguration(
    val packageName: String, val projectID: String, val senderID: String, val applicationID: String, val apiKey: String,
) {
    init {
        require(packageName.length in 1..255 && Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+").matches(packageName))
        require(projectID.length in 1..128 && Regex("[A-Za-z0-9][A-Za-z0-9_.:-]*").matches(projectID))
        require(senderID.length in 1..32 && senderID.all { it in '0'..'9' })
        require(applicationID.length <= 256 && Regex("1:" + senderID + ":android:[a-fA-F0-9]+").matches(applicationID))
        require(Regex("A[A-Za-z0-9_-]{38}").matches(apiKey))
    }
    fun sameAs(other: FCMClientConfiguration): Boolean = packageName == other.packageName && projectID == other.projectID &&
        senderID == other.senderID && applicationID == other.applicationID && apiKey == other.apiKey
    override fun toString() = "FCMClientConfiguration(redacted)"

    companion object {
        const val MAXIMUM_BYTES = 65_536
        fun import(bytes: ByteArray, expectedPackage: String): FCMClientConfiguration {
            val root = boundedObject(bytes)
            require(root["type"] != JsonPrimitive("service_account") && "private_key" !in root)
            val project = root.getValue("project_info").jsonObject
            val clients = root.getValue("client").jsonArray
            require(clients.size in 1..128)
            val matching = clients.map { it.jsonObject }.filter {
                it["client_info"]?.jsonObject?.get("android_client_info")?.jsonObject?.get("package_name") == JsonPrimitive(expectedPackage)
            }
            val client = matching.single()
            val info = client.getValue("client_info").jsonObject
            val keys = client.getValue("api_key").jsonArray
            require(keys.size == 1)
            return FCMClientConfiguration(expectedPackage, project.string("project_id"), project.string("project_number"),
                info.string("mobilesdk_app_id"), keys.single().jsonObject.string("current_key"))
        }
    }
}

/** One durable local configuration incarnation. It cannot register a phone with a Mac. */
internal class StoredPushConfiguration(val generation: UUID, val client: FCMClientConfiguration, val enabled: Boolean) {
    override fun toString() = "StoredPushConfiguration(redacted)"
    fun encode(): ByteArray = buildJsonObject {
        put("version", 1); put("generation", generation.toString()); put("enabled", enabled)
        put("package", client.packageName); put("project", client.projectID); put("sender", client.senderID)
        put("application", client.applicationID); put("key", client.apiKey)
    }.toString().encodeToByteArray()
    companion object {
        fun decode(bytes: ByteArray, expectedPackage: String): StoredPushConfiguration {
            val root = boundedObject(bytes)
            require(root.keys == setOf("version", "generation", "enabled", "package", "project", "sender", "application", "key"))
            require(root["version"] == JsonPrimitive(1) && root["enabled"]?.jsonPrimitive?.isString == false)
            val generation = root.string("generation")
            require(UUID.fromString(generation).toString() == generation)
            require(root.string("package") == expectedPackage)
            return StoredPushConfiguration(UUID.fromString(generation), FCMClientConfiguration(expectedPackage,
                root.string("project"), root.string("sender"), root.string("application"), root.string("key")),
                requireNotNull(root["enabled"]?.jsonPrimitive?.booleanOrNull))
        }
    }
}

private fun JsonObject.string(key: String): String = getValue(key).jsonPrimitive.let { require(it.isString); it.content }

/** Limit nesting before the JSON parser allocates or recursively descends through imported input. */
private fun boundedObject(bytes: ByteArray): JsonObject {
    require(bytes.size in 1..FCMClientConfiguration.MAXIMUM_BYTES)
    val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    var quoted = false; var escaped = false; var depth = 0
    for (c in text) {
        if (quoted) {
            if (escaped) escaped = false else if (c == '\\') escaped = true else if (c == '"') quoted = false
        } else when (c) {
            '"' -> quoted = true
            '{', '[' -> { depth++; require(depth <= 16) }
            '}', ']' -> { depth--; require(depth >= 0) }
        }
    }
    require(depth == 0 && !quoted)
    return Json.parseToJsonElement(text).jsonObject
}
