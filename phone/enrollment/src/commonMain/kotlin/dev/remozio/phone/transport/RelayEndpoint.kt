package dev.remozio.phone.transport

/** An endpoint from trusted enrollment storage, never a push payload or discovery assertion. */
data class RelayEndpoint(val host: String, val port: Int = 443, val path: String = "/remozio/approval") {
    init {
        require(host.length in 1..253 && host == host.lowercase())
        require(host.split('.').all { it.length in 1..63 && Regex("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?").matches(it) })
        require(port in 1..65_535)
        require(path.length in 1..512 && path.startsWith('/') && Regex("/[A-Za-z0-9/._~-]*").matches(path))
        require(path.split('/').none { it == "." || it == ".." })
    }
    internal val authority: String get() = if (port == 443) host else "$host:$port"
    override fun toString(): String = "RelayEndpoint(redacted)"
}

/** A per-installation Access credential scoped to one exact endpoint. It grants no Remozio authority. */
class RelayAccessCredential(
    internal val endpoint: RelayEndpoint,
    internal val clientId: String,
    internal val clientSecret: String,
) {
    init {
        require(listOf(clientId, clientSecret).all { value -> value.length in 1..2_048 && value.all { it.code in 0x21..0x7e } })
    }
    override fun toString(): String = "RelayAccessCredential(redacted)"
}
