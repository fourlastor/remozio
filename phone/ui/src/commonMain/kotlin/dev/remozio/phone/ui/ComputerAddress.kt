package dev.remozio.phone.ui

/**
 * Where the phone tries to reach a computer when discovery cannot find it, for example over Tailscale.
 * The address is only a route hint: the connection still opens only when TLS 1.3, the pinned key from the
 * invitation and the ALPN match, so a wrong address can only fail.
 */
data class ComputerAddress(val host: String, val port: Int) {
    companion object {
        private const val MAXIMUM_HOST = 253
        // Room for the brackets of an IPv6 literal, the colon and a five-digit port.
        private const val MAXIMUM_TEXT = MAXIMUM_HOST + 8

        /** Reads `host:port`, `[IPv6]:port` or `IPv4:port`. Returns null for anything else, including blank text. */
        fun parse(text: String): ComputerAddress? {
            val value = text.trim()
            if (value.isEmpty() || value.length > MAXIMUM_TEXT || value.any { it.isWhitespace() }) return null
            val host: String
            val portText: String
            if (value.startsWith("[")) {
                val close = value.indexOf(']')
                if (close < 0 || value.getOrNull(close + 1) != ':') return null
                host = value.substring(1, close)
                portText = value.substring(close + 2)
                if (!isIPv6(host)) return null
            } else {
                val colon = value.lastIndexOf(':')
                if (colon < 0) return null
                host = value.substring(0, colon)
                portText = value.substring(colon + 1)
                // An IPv6 literal must be in brackets, or its last group would read as the port.
                if (':' in host || !isHostName(host)) return null
            }
            // ASCII digits only: other Unicode digits pass isDigit but make toInt throw.
            val port = portText.takeIf { it.length in 1..5 && it.all { c -> c in '0'..'9' } }?.toInt() ?: return null
            if (port !in 1..65_535) return null
            return ComputerAddress(host, port)
        }

        private fun isHostName(host: String): Boolean {
            if (host.isEmpty() || host.length > MAXIMUM_HOST) return false
            return host.split('.').all { label ->
                label.length in 1..63 && label.first() != '-' && label.last() != '-' &&
                    label.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' }
            }
        }

        /** Eight groups of one to four hex digits, or fewer with one `::`; the last two may be a dotted IPv4. */
        private fun isIPv6(host: String): Boolean {
            if (host.length !in 2..45) return false
            val halves = host.split("::")
            if (halves.size > 2) return false
            val groups = halves.map { half -> if (half.isEmpty()) emptyList() else half.split(':') }
            val all = groups.flatten()
            var count = 0
            for ((index, group) in all.withIndex()) {
                if (index == all.lastIndex && '.' in group) {
                    if (!isIPv4(group)) return false
                    count += 2
                } else {
                    if (group.length !in 1..4 || !group.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return false
                    count += 1
                }
            }
            return if (halves.size == 2) count <= 7 else count == 8
        }

        private fun isIPv4(text: String): Boolean {
            val parts = text.split('.')
            return parts.size == 4 && parts.all { part ->
                part.length in 1..3 && part.all { it in '0'..'9' } && part.toInt() <= 255
            }
        }
    }
}

/** What Test connection does with the address field. */
sealed interface ConnectionRoute {
    /** The field is empty: search the local network. */
    data object Discover : ConnectionRoute
    data class Direct(val address: ComputerAddress) : ConnectionRoute
    /** The field holds text that is not an address. The test cannot start. */
    data object Invalid : ConnectionRoute

    companion object {
        fun of(addressText: String): ConnectionRoute =
            if (addressText.isBlank()) Discover else ComputerAddress.parse(addressText)?.let(::Direct) ?: Invalid
    }
}
