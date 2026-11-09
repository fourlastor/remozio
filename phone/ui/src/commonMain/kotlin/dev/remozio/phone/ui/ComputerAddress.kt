package dev.remozio.phone.ui

/**
 * Where the phone tries to reach a computer when discovery cannot find it, for example over Tailscale.
 * The address is only a route hint: the connection still opens only when TLS 1.3, the pinned key from the
 * invitation and the ALPN match, so a wrong address can only fail.
 */
data class ComputerAddress(val host: String, val port: Int) {
    companion object {
        private const val MAXIMUM_HOST = 253

        /** Reads `host:port`, `[IPv6]:port` or `IPv4:port`. Returns null for anything else, including blank text. */
        fun parse(text: String): ComputerAddress? {
            val value = text.trim()
            if (value.isEmpty() || value.length > MAXIMUM_HOST + 8 || value.any { it.isWhitespace() }) return null
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
            val port = portText.takeIf { it.length in 1..5 && it.all(Char::isDigit) }?.toInt() ?: return null
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

        private fun isIPv6(host: String): Boolean =
            host.length in 2..45 && host.count { it == ':' } >= 2 &&
                host.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }
    }
}
