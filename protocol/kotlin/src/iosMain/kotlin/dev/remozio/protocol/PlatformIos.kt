@file:OptIn(ExperimentalForeignApi::class)

package dev.remozio.protocol

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA256_DIGEST_LENGTH
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDictionaryAddValue
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFNumberCreate
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.kCFNumberIntType
import platform.CoreFoundation.kCFTypeDictionaryKeyCallBacks
import platform.CoreFoundation.kCFTypeDictionaryValueCallBacks
import platform.Security.SecKeyCreateWithData
import platform.Security.kSecAttrKeyClass
import platform.Security.kSecAttrKeyClassPublic
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeECSECPrimeRandom
import platform.posix.uint8_tVar

internal actual fun sha256(input: ByteArray): ByteArray {
    val digest = ByteArray(CC_SHA256_DIGEST_LENGTH)
    input.usePinned { source ->
        digest.usePinned { output ->
            CC_SHA256(if (input.isEmpty()) null else source.addressOf(0), input.size.toUInt(),
                output.addressOf(0).reinterpret<uint8_tVar>())
        }
    }
    return digest
}

/** Security imports the point with corecrypto, which rejects coordinates at or above p and off-curve points. */
internal actual fun pairingPoint(bytes: ByteArray) {
    require(bytes.size == 65 && bytes[0] == 4.toByte())
    val accepted = memScoped {
        val data = bytes.usePinned { CFDataCreate(null, it.addressOf(0).reinterpret(), bytes.size.toLong()) }
        val size = alloc<IntVar>().apply { value = 256 }
        val bits = CFNumberCreate(null, kCFNumberIntType, size.ptr)
        val attributes = CFDictionaryCreateMutable(null, 3, kCFTypeDictionaryKeyCallBacks.ptr, kCFTypeDictionaryValueCallBacks.ptr)
        CFDictionaryAddValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
        CFDictionaryAddValue(attributes, kSecAttrKeyClass, kSecAttrKeyClassPublic)
        CFDictionaryAddValue(attributes, kSecAttrKeySizeInBits, bits)
        val key = SecKeyCreateWithData(data, attributes, null)
        key?.let { CFRelease(it) }
        CFRelease(attributes); CFRelease(bits); CFRelease(data)
        key != null
    }
    require(accepted)
}

// Native has no mutable view of these classes, so a MutableList or MutableMap cast fails.
private class ReadOnlyList<T>(private val delegate: List<T>) : List<T> by delegate {
    override fun equals(other: Any?): Boolean = delegate == other
    override fun hashCode(): Int = delegate.hashCode()
    override fun toString(): String = delegate.toString()
}

private class ReadOnlyMap<K, V>(private val delegate: Map<K, V>) : Map<K, V> by delegate {
    override fun equals(other: Any?): Boolean = delegate == other
    override fun hashCode(): Int = delegate.hashCode()
    override fun toString(): String = delegate.toString()
}

internal actual fun <T> readOnlySnapshot(values: List<T>): List<T> = ReadOnlyList(ArrayList(values))
internal actual fun <K, V> readOnlySnapshot(values: Map<K, V>): Map<K, V> = ReadOnlyMap(LinkedHashMap(values))
