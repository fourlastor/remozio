package dev.remozio.pairing

import java.security.SecureRandom

private val random = SecureRandom()

internal actual fun secureRandom(count: Int): ByteArray = ByteArray(count).also(random::nextBytes)
