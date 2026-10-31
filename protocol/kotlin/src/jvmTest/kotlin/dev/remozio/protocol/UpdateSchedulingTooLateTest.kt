package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

private fun tooLateHex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
private fun JsonObject.tooLateText(name: String) = getValue(name).jsonPrimitive.content

class UpdateSchedulingTooLateTest {
  private val limits = CborLimits(16384, 2, 32)
  private fun vectors() = Json.parseToJsonElement(
    File(checkNotNull(System.getProperty("remozio.updateSchedulingTooLateVectors"))).readText(),
  ).jsonObject
  private fun verify(signature: ByteArray, key: ByteArray, payload: ByteArray) =
    UpdateSchedulingTooLateSignature.verify(signature, key, 1u, payload, limits)

  @Test fun sharedVectorsBindTheExactRequestProgressAndRootSignature() {
    val data = vectors()
    val rows = data.getValue("valid").jsonArray
    assertEquals(8, rows.size)
    for (entry in rows) {
      val row = entry.jsonObject
      val payload = tooLateHex(row.tooLateText("hex"))
      val request = PhoneUpdateSchedulingFrame.decode(tooLateHex(row.tooLateText("request")))
      val value = UpdateSchedulingTooLateResponse.decode(payload)
      assertContentEquals(payload, value.encode())
      assertContentEquals(payload, UpdateSchedulingTooLateResponse(request, value.progress).encode())
      assertContentEquals(tooLateHex(row.tooLateText("requestDigest")), UpdateSchedulingTooLateResponse.digest(request))
      assertTrue(value.matches(request, value.progress.status.scope))
      assertContentEquals(tooLateHex(row.tooLateText("signingInput")), UpdateSchedulingTooLateSigningInput.make(1u, payload, limits))
      assertTrue(verify(tooLateHex(row.tooLateText("signature")), tooLateHex(data.tooLateText("publicKey")), payload))
      assertTrue(value.progress.phase.irreversible)
      assertEquals(0uL, value.progress.availableActions)
      assertNull(value.progress.status.controlDigest)
    }
  }

  @Test fun validSignaturesCannotMakeMalformedReversibleOrAcknowledgmentPayloadsValid() {
    val data = vectors()
    val rows = data.getValue("invalid").jsonArray
    assertEquals(19, rows.size)
    for (entry in rows) {
      val row = entry.jsonObject
      val bytes = tooLateHex(row.tooLateText("hex"))
      assertTrue(P256Verification.verify(tooLateHex(row.tooLateText("signature")), tooLateHex(data.tooLateText("publicKey")),
        tooLateHex(row.tooLateText("signingInput"))))
      assertFails(row.tooLateText("name")) { UpdateSchedulingTooLateResponse.decode(bytes) }
      assertFails { verify(tooLateHex(row.tooLateText("signature")), tooLateHex(data.tooLateText("publicKey")), bytes) }
    }
  }

  @Test fun signaturesBindEveryFieldAndCannotCrossExistingSchedulingDomains() {
    val data = vectors()
    val key = tooLateHex(data.tooLateText("publicKey"))
    for (entry in data.getValue("valid").jsonArray) {
      val row = entry.jsonObject
      val bytes = tooLateHex(row.tooLateText("hex"))
      val signature = tooLateHex(row.tooLateText("signature"))
      assertFalse(verify(signature, tooLateHex(data.tooLateText("otherPublicKey")), bytes))
      for (field in listOf("wrongProgressDomainSignature", "wrongStatusDomainSignature", "wrongControlDomainSignature")) {
        assertFalse(verify(tooLateHex(row.tooLateText(field)), key, bytes))
      }
      for (item in row.getValue("mutations").jsonArray) {
        val changed = tooLateHex(item.jsonObject.tooLateText("hex"))
        UpdateSchedulingTooLateResponse.decode(changed)
        assertFalse(verify(signature, key, changed))
      }
    }
  }

  @Test fun anotherScopeNonceActionRevisionOrCandidateCannotReuseTheReply() {
    val row = vectors().getValue("valid").jsonArray.first { it.jsonObject.tooLateText("name").endsWith("challenge") }.jsonObject
    val value = UpdateSchedulingTooLateResponse.decode(tooLateHex(row.tooLateText("hex")))
    val request = PhoneUpdateSchedulingFrame.decode(tooLateHex(row.tooLateText("request"))) as PhoneUpdateSchedulingFrame.Challenge
    val scope = value.progress.status.scope
    val ids = scope.value.values.map { (it as CborValue.Bytes).copyBytes() }
    val other = ChannelScope(ByteArray(16) { 99 }, ids[1], ids[2], ids[3])
    assertFalse(value.matches(request, other))
    val nonce = request.queryNonce.copyBytes()
    val update = request.updateID.copyBytes()
    val changed = listOf(
      PhoneUpdateSchedulingFrame.Challenge(ByteArray(32) { 99 }, update, request.generation, request.revision, request.action),
      PhoneUpdateSchedulingFrame.Challenge(nonce, update, request.generation, request.revision + 1u, request.action),
      PhoneUpdateSchedulingFrame.Challenge(nonce, update, request.generation, request.revision, UpdateSchedulingAction.DEFER_UPDATE),
      PhoneUpdateSchedulingFrame.Challenge(nonce, ByteArray(32) { 99 }, request.generation, request.revision, request.action),
      PhoneUpdateSchedulingFrame.Challenge(nonce, update, request.generation + 1u, request.revision, request.action),
    )
    assertTrue(changed.all { !value.matches(it, scope) })
    assertFails { UpdateSchedulingTooLateResponse(changed.last(), value.progress) }
  }

  @Test fun applySignatureAndCapturedPhoneRemainPartOfTheRejectedRequest() {
    val row = vectors().getValue("valid").jsonArray.first { it.jsonObject.tooLateText("name").endsWith("apply") }.jsonObject
    val value = UpdateSchedulingTooLateResponse.decode(tooLateHex(row.tooLateText("hex")))
    val request = PhoneUpdateSchedulingFrame.decode(tooLateHex(row.tooLateText("request"))) as PhoneUpdateSchedulingFrame.Apply
    val signature = request.signature.copyBytes()
    signature[0] = (signature[0].toInt() xor 1).toByte()
    assertFalse(value.matches(PhoneUpdateSchedulingFrame.Apply(request.queryNonce.copyBytes(),
      request.canonicalControl.copyBytes(), signature), value.progress.status.scope))
    val bounds = CborLimits(1024, 2, 32)
    val fields = (DeterministicCbor.decode(request.canonicalControl.copyBytes(), bounds) as CborValue.Fields).values.toMutableMap()
    fields[3uL] = CborValue.Bytes(ByteArray(16) { 99 })
    val wrong = PhoneUpdateSchedulingFrame.Apply(request.queryNonce.copyBytes(), DeterministicCbor.encode(CborValue.Fields(fields), bounds),
      request.signature.copyBytes())
    assertFails { UpdateSchedulingTooLateResponse(wrong, value.progress) }
  }

  @Test fun statusAndResponseFramesCannotMasqueradeAsRejectedActions() {
    val row = vectors().getValue("valid").jsonArray[0].jsonObject
    val bytes = tooLateHex(row.tooLateText("hex"))
    val value = UpdateSchedulingTooLateResponse.decode(bytes)
    for (frame in listOf(PhoneUpdateSchedulingFrame.Status(value.progress.status.queryNonce.copyBytes()),
      PhoneUpdateSchedulingFrame.Failure(value.progress.status.queryNonce.copyBytes(), PhoneUpdateSchedulingFailure.UNAVAILABLE))) {
      assertFails { UpdateSchedulingTooLateResponse.digest(frame) }
      assertFails { UpdateSchedulingTooLateResponse(frame, value.progress) }
    }
    assertFails { UpdateSchedulingStatusResponse.decode(bytes) }
    assertFails { UpdateSchedulingProgressResponse.decode(bytes) }
  }

  @Test fun versionResourceAndSignatureBoundsRemainStrict() {
    val data = vectors()
    val row = data.getValue("valid").jsonArray[0].jsonObject
    val bytes = tooLateHex(row.tooLateText("hex"))
    val key = tooLateHex(data.tooLateText("publicKey"))
    for (version in listOf(0uL, 2uL, ULong.MAX_VALUE)) {
      assertFails { UpdateSchedulingTooLateSigningInput.make(version, bytes, limits) }
    }
    assertFails { UpdateSchedulingTooLateResponse.decode(ByteArray(8193)) }
    val size = UpdateSchedulingTooLateSigningInput.make(1u, bytes, limits).size
    assertFails { UpdateSchedulingTooLateSigningInput.make(1u, bytes, CborLimits(size - 1, 2, 32)) }
    for (size in listOf(0, 63, 65)) assertFalse(verify(ByteArray(size), key, bytes))
  }

  @Test fun valueCopiesAndDescriptionsDoNotExposeOrReplaceCapturedEvidence() {
    val row = vectors().getValue("valid").jsonArray[0].jsonObject
    val bytes = tooLateHex(row.tooLateText("hex"))
    val value = UpdateSchedulingTooLateResponse.decode(bytes)
    val copy = value.requestDigest.copyBytes()
    copy[0] = (copy[0].toInt() xor 1).toByte()
    assertFalse(copy.contentEquals(value.requestDigest.copyBytes()))
    assertContentEquals(bytes, value.encode())
    assertEquals("UpdateSchedulingTooLateResponse(redacted)", value.toString())
  }
}
