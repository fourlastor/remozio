package dev.remozio.phone.ui

import kotlin.test.*

class ComputerAddressTest {
    @Test fun readsAnIPv4Address(): Unit =
        assertEquals(ComputerAddress("100.64.0.1", 7443), ComputerAddress.parse("100.64.0.1:7443"))

    @Test fun readsAHostName(): Unit =
        assertEquals(ComputerAddress("linux-pc.example.ts.net", 7443), ComputerAddress.parse("  linux-pc.example.ts.net:7443 "))

    @Test fun readsABracketedIPv6Address(): Unit =
        assertEquals(ComputerAddress("fd7a:115c:a1e0::1", 7443), ComputerAddress.parse("[fd7a:115c:a1e0::1]:7443"))

    @Test fun acceptsThePortLimits() {
        assertEquals(1, ComputerAddress.parse("host:1")?.port)
        assertEquals(65_535, ComputerAddress.parse("host:65535")?.port)
    }

    @Test fun rejectsEverythingElse() {
        for (text in listOf(
            "", "   ", "host", "host:", ":7443", "host:0", "host:65536", "host:123456", "host:74a3", "host:-1",
            "fd7a::1:7443", "[fd7a::1]", "[fd7a::1]7443", "[host]:7443", "[]:7443",
            "https://host:7443", "host:7443/path", "user@host:7443", "ho st:7443", "host :7443",
            "-host:7443", "host-:7443", "host..name:7443", ".host:7443", "hö st:7443", "hōst:7443",
            "a".repeat(64) + ".example:7443", ("a".repeat(60) + ".").repeat(5) + "b:7443",
        )) assertNull(ComputerAddress.parse(text), text)
    }
}
