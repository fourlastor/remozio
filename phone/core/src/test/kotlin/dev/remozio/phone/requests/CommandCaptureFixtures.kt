package dev.remozio.phone.requests

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal fun schemaThreeCapture(name: String): ByteArray {
    val file = File(checkNotNull(System.getProperty("remozio.test.commandVectors3")))
    val rows = Json.parseToJsonElement(file.readText()).jsonObject.getValue("valid").jsonArray
    val row = rows.first { it.jsonObject.getValue("name").jsonPrimitive.content == name }.jsonObject
    return row.getValue("hex").jsonPrimitive.content.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

internal fun schemaFourCapture(name: String = "schema4-base"): ByteArray {
    val file = File(checkNotNull(System.getProperty("remozio.test.commandVectors4")))
    val rows = Json.parseToJsonElement(file.readText()).jsonObject.getValue("valid").jsonArray
    val row = rows.first { it.jsonObject.getValue("name").jsonPrimitive.content == name }.jsonObject
    return row.getValue("hex").jsonPrimitive.content.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
