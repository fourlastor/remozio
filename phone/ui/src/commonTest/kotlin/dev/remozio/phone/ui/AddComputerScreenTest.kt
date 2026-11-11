package dev.remozio.phone.ui

import androidx.compose.ui.test.*
// The v2 runner queues coroutines on a StandardTestDispatcher, as production does, instead of running them at once.
import androidx.compose.ui.test.v2.runComposeUiTest
import dev.remozio.pairing.PairingTransport
import dev.remozio.pairing.PlatformPairingKeys
import kotlin.test.*

/** The address typed in Add computer is the one Test connection asks the native shell for. */
@OptIn(ExperimentalTestApi::class)
class AddComputerScreenTest {
    // The "ascii" row of protocol/vectors/pairing-invitation-v1.json, as in ConnectionTestTest.
    private val invitation = "remozio-pairing:v1:pwABAVABAQEBAQEBAQEBAQEBAQEBAlACAgICAgICAgICAgICAgICA2ZTdHVkaW8EWEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li_hp_m47n60p8D54WK84zV2sxXs7LtkBoN79R9QVYQQR88nsYjQNPfopSOAMEtRrDwIlp4nfyGzWmC0j8R2aZeAd3VRDbjtBAKT2axp90MNu6fa3mPOmCKZ4Et50ieHPRBgE"

    /** Records each address the screen asks for. Its keys fail at once, so every test ends as Failed. */
    private inner class Services : PhoneServices {
        val addresses = mutableListOf<ComputerAddress?>()
        override fun scanQrCode(onResult: (String?) -> Unit) = onResult(null)
        override fun pasteText() = invitation
        override fun pairingKeys(address: ComputerAddress?): PlatformPairingKeys {
            addresses += address
            return NoKeys
        }
    }

    private object NoKeys : PlatformPairingKeys {
        override val transportPublicKey: ByteArray get() = error("no keys in this test")
        override val decisionPublicKey: ByteArray get() = error("no keys in this test")
        override val biometricPublicKey: ByteArray get() = error("no keys in this test")
        override fun openTransport(macID: ByteArray, accountID: ByteArray, pin: ByteArray, applicationProtocol: String):
            PairingTransport = error("no network in this test")
    }

    private fun ComposeUiTest.openPastedInvitation(services: Services) {
        setContent { RemozioApp(services) }
        onNodeWithTag("add-computer").performClick()
        onNodeWithTag("paste").performClick()
        onNodeWithTag("parsed").assertExists()
    }

    private fun ComposeUiTest.testConnection() {
        onNodeWithTag("test-connection").performScrollTo().performClick()
        waitUntilExactlyOneExists(hasTestTag("connection-failed"))
    }

    @Test fun aTypedAddressReachesTheNativeShell() = runComposeUiTest {
        val services = Services()
        openPastedInvitation(services)
        onNodeWithTag("computer-address").performScrollTo().performTextInput("192.0.2.10:7443")
        testConnection()
        assertEquals(listOf<ComputerAddress?>(ComputerAddress("192.0.2.10", 7443)), services.addresses)
    }

    @Test fun anEmptyFieldSearchesTheNetwork() = runComposeUiTest {
        val services = Services()
        openPastedInvitation(services)
        testConnection()
        assertEquals(listOf<ComputerAddress?>(null), services.addresses)
    }

    @Test fun textThatIsNotAnAddressStartsNothing() = runComposeUiTest {
        val services = Services()
        openPastedInvitation(services)
        // Without a port the text is not an address. It must never fall back to searching the network.
        onNodeWithTag("computer-address").performScrollTo().performTextInput("192.0.2.10")
        onNodeWithTag("address-invalid").assertExists()
        // The click is a touch at the button's position, so it shows that a real tap does nothing.
        onNodeWithTag("test-connection").assertIsNotEnabled().performClick()
        waitForIdle()
        onNodeWithTag("connecting").assertDoesNotExist()
        assertEquals(emptyList(), services.addresses)
        // Clearing the field makes it empty again, so the next tap searches the network.
        onNodeWithTag("computer-address").performTextClearance()
        onNodeWithTag("address-invalid").assertDoesNotExist()
        testConnection()
        assertEquals(listOf<ComputerAddress?>(null), services.addresses)
    }

    @Test fun aChangedAddressIsUsedOnTheNextTap() = runComposeUiTest {
        val services = Services()
        openPastedInvitation(services)
        onNodeWithTag("computer-address").performScrollTo().performTextInput("192.0.2.10:7443")
        testConnection()
        onNodeWithTag("computer-address").performScrollTo().performTextReplacement("[2001:db8::1]:7443")
        // Editing the address clears the failure; the next result comes only from a new tap.
        onNodeWithTag("connection-failed").assertDoesNotExist()
        testConnection()
        assertEquals(listOf<ComputerAddress?>(ComputerAddress("192.0.2.10", 7443), ComputerAddress("2001:db8::1", 7443)),
            services.addresses)
    }
}
