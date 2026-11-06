package dev.remozio.protocol

/** Consistency only. The host must still verify the complete fresh transcript and peer identity. */
fun PairingInvitation.validateMacClaims(transcript: PairingTranscript) {
    require(transcript.phone.scope.value.values.take(2) == listOf(macID, accountID))
    require(transcript.macAuthorityKey == authorityPublicKey && transcript.macTransportKey == transportPublicKey)
    require(transcript.minimumEnvelopeVersion == minimumEnvelopeVersion)
}
