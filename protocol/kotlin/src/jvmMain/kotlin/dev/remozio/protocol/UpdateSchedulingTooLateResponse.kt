package dev.remozio.protocol

import java.security.MessageDigest

/** A signed rejection of one scheduling request. Its progress is an observation, not a control acknowledgment. */
class UpdateSchedulingTooLateResponse private constructor(
  requestDigest: ByteArray,
  val progress: UpdateSchedulingProgressResponse,
) {
  val requestDigest = CborValue.Bytes(requestDigest)

  init {
    require(this.requestDigest.size == 32 && progress.phase.irreversible && progress.availableActions == 0uL)
    require(progress.status.controlDigest == null)
  }

  constructor(request: PhoneUpdateSchedulingFrame, progress: UpdateSchedulingProgressResponse) : this(digest(request), progress) {
    require(requestMatchesProgress(request, progress))
  }

  /** The caller must also verify the Root signature and the original live query deadline. */
  fun matches(request: PhoneUpdateSchedulingFrame, expectedScope: ChannelScope): Boolean =
    progress.status.scope == expectedScope && requestMatchesProgress(request, progress) &&
      digest(request).contentEquals(requestDigest.copyBytes())

  fun encode(): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
    0uL to CborValue.Unsigned(1u), 1uL to CborValue.Unsigned(0u),
    2uL to requestDigest, 3uL to CborValue.Bytes(progress.encode()),
  )), LIMITS)

  override fun toString() = "UpdateSchedulingTooLateResponse(redacted)"

  companion object {
    const val MAXIMUM_BYTES = 8192
    val LIMITS = CborLimits(MAXIMUM_BYTES, 2, 16)

    fun digest(request: PhoneUpdateSchedulingFrame): ByteArray {
      require(request is PhoneUpdateSchedulingFrame.Challenge || request is PhoneUpdateSchedulingFrame.Apply)
      return MessageDigest.getInstance("SHA-256").digest(
        "dev.remozio.update-scheduling-request\u0000".toByteArray(Charsets.UTF_8) + request.encode(),
      )
    }

    private fun requestMatchesProgress(request: PhoneUpdateSchedulingFrame, progress: UpdateSchedulingProgressResponse): Boolean {
      request.encode()
      if (request.queryNonce != progress.status.queryNonce) return false
      return when (request) {
        is PhoneUpdateSchedulingFrame.Challenge ->
          request.updateID == progress.status.updateID && request.generation == progress.status.generation
        is PhoneUpdateSchedulingFrame.Apply -> {
          val control = UpdateSchedulingControl.decode(request.canonicalControl.copyBytes(), CborLimits(1024, 2, 32))
          val ids = progress.status.scope.value.values
          control.macID.contentEquals((ids[0] as CborValue.Bytes).copyBytes()) && control.accountID.contentEquals((ids[1] as CborValue.Bytes).copyBytes()) && control.phoneID.contentEquals((ids[2] as CborValue.Bytes).copyBytes()) && control.enrollmentEpoch.contentEquals((ids[3] as CborValue.Bytes).copyBytes()) &&
            control.updateID.contentEquals(progress.status.updateID.copyBytes()) && control.expectedGeneration == progress.status.generation
        }
        else -> throw IllegalArgumentException("Invalid scheduling request")
      }
    }

    fun decode(bytes: ByteArray): UpdateSchedulingTooLateResponse {
      val fields = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values
        ?: throw IllegalArgumentException("Invalid TooLate response")
      require(fields.keys == (0uL..3uL).toSet() && fields[0u] == CborValue.Unsigned(1u) && fields[1u] == CborValue.Unsigned(0u))
      val digest = (fields[2u] as? CborValue.Bytes)?.copyBytes() ?: throw IllegalArgumentException("Invalid request digest")
      val progress = (fields[3u] as? CborValue.Bytes)?.copyBytes() ?: throw IllegalArgumentException("Invalid progress")
      val result = UpdateSchedulingTooLateResponse(digest, UpdateSchedulingProgressResponse.decode(progress))
      require(result.encode().contentEquals(bytes))
      return result
    }
  }
}

object UpdateSchedulingTooLateSigningInput {
  fun make(wireVersion: ULong, canonicalPayload: ByteArray, inputLimits: CborLimits): ByteArray {
    if (wireVersion != 1uL) throw SigningInputException(SigningInputFailure.UNSUPPORTED_VERSION)
    UpdateSchedulingTooLateResponse.decode(canonicalPayload)
    return DeterministicCbor.encode(CborValue.Fields(mapOf(
      0uL to CborValue.Text("dev.remozio.update-scheduling-too-late"), 1uL to CborValue.Unsigned(1u),
      2uL to CborValue.Unsigned(1u), 3uL to CborValue.Unsigned(1u), 4uL to CborValue.Bytes(canonicalPayload),
    )), inputLimits)
  }
}

object UpdateSchedulingTooLateSignature {
  fun verify(signature: ByteArray, authorityPublicKey: ByteArray, wireVersion: ULong,
             canonicalPayload: ByteArray, inputLimits: CborLimits): Boolean =
    P256Verification.verify(signature, authorityPublicKey,
      UpdateSchedulingTooLateSigningInput.make(wireVersion, canonicalPayload, inputLimits))
}
