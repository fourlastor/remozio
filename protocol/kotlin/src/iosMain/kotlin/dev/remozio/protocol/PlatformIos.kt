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
        // A failed allocation rejects the point instead of passing null to Security or CFRelease.
        val data = bytes.usePinned { CFDataCreate(null, it.addressOf(0).reinterpret(), bytes.size.toLong()) }
        val size = alloc<IntVar>().apply { value = 256 }
        val bits = CFNumberCreate(null, kCFNumberIntType, size.ptr)
        val attributes = CFDictionaryCreateMutable(null, 3, kCFTypeDictionaryKeyCallBacks.ptr, kCFTypeDictionaryValueCallBacks.ptr)
        val key = if (data != null && bits != null && attributes != null) {
            CFDictionaryAddValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
            CFDictionaryAddValue(attributes, kSecAttrKeyClass, kSecAttrKeyClassPublic)
            CFDictionaryAddValue(attributes, kSecAttrKeySizeInBits, bits)
            SecKeyCreateWithData(data, attributes, null)
        } else {
            null
        }
        key?.let { CFRelease(it) }
        attributes?.let { CFRelease(it) }; bits?.let { CFRelease(it) }; data?.let { CFRelease(it) }
        key != null
    }
    require(accepted)
}

// Native has no mutable view of these classes, so a MutableList or MutableMap cast fails. Every view and
// iterator they return is wrapped as well, so no cast reaches the backing copy.
private class ReadOnlyIterator<T>(delegate: Iterator<T>) : Iterator<T> by delegate

private class ReadOnlyListIterator<T>(delegate: ListIterator<T>) : ListIterator<T> by delegate

private class ReadOnlyList<T>(private val delegate: List<T>) : List<T> by delegate {
    override fun iterator(): Iterator<T> = ReadOnlyIterator(delegate.iterator())
    override fun listIterator(): ListIterator<T> = ReadOnlyListIterator(delegate.listIterator())
    override fun listIterator(index: Int): ListIterator<T> = ReadOnlyListIterator(delegate.listIterator(index))
    override fun subList(fromIndex: Int, toIndex: Int): List<T> = ReadOnlyList(delegate.subList(fromIndex, toIndex))
    override fun equals(other: Any?): Boolean = delegate == other
    override fun hashCode(): Int = delegate.hashCode()
    override fun toString(): String = delegate.toString()
}

private class ReadOnlyCollection<T>(private val delegate: Collection<T>) : Collection<T> by delegate {
    override fun iterator(): Iterator<T> = ReadOnlyIterator(delegate.iterator())
    override fun toString(): String = delegate.toString()
}

private class ReadOnlySet<T>(private val delegate: Set<T>) : Set<T> by delegate {
    override fun iterator(): Iterator<T> = ReadOnlyIterator(delegate.iterator())
    override fun equals(other: Any?): Boolean = delegate == other
    override fun hashCode(): Int = delegate.hashCode()
    override fun toString(): String = delegate.toString()
}

private class ReadOnlyEntry<K, V>(override val key: K, override val value: V) : Map.Entry<K, V> {
    override fun equals(other: Any?): Boolean = other is Map.Entry<*, *> && key == other.key && value == other.value
    override fun hashCode(): Int = key.hashCode() xor value.hashCode()
    override fun toString(): String = "$key=$value"
}

private class ReadOnlyMap<K, V>(private val delegate: Map<K, V>) : Map<K, V> by delegate {
    override val keys: Set<K> get() = ReadOnlySet(delegate.keys)
    override val values: Collection<V> get() = ReadOnlyCollection(delegate.values)
    override val entries: Set<Map.Entry<K, V>>
        get() = ReadOnlySet(delegate.entries.mapTo(LinkedHashSet()) { ReadOnlyEntry(it.key, it.value) })
    override fun equals(other: Any?): Boolean = delegate == other
    override fun hashCode(): Int = delegate.hashCode()
    override fun toString(): String = delegate.toString()
}

internal actual fun <T> readOnlySnapshot(values: List<T>): List<T> = ReadOnlyList(ArrayList(values))
internal actual fun <K, V> readOnlySnapshot(values: Map<K, V>): Map<K, V> = ReadOnlyMap(LinkedHashMap(values))
