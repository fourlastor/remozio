package dev.remozio.protocol

import java.security.MessageDigest
import java.util.Collections

enum class IssuedRequestFailure {
    INVALID_FIELDS, UNSUPPORTED_WRAPPER, UNSUPPORTED_CONTRACT, UNSUPPORTED_FEATURES,
    INVALID_BYTES, INVALID_TIMES, INVALID_FEATURES, INVALID_ACTIONS, INVALID_CAPTURE, CAPTURE_DIGEST_MISMATCH,
}
class IssuedRequestException(val reason: IssuedRequestFailure) : IllegalArgumentException(reason.name)

/** Common wrapper only. Capture semantics, authority identity, and current validity remain separate checks. */
class IssuedRequestPayload(
    val contract: RequestContract,
    macID: ByteArray,
    accountID: ByteArray,
    requestID: ByteArray,
    challenge: ByteArray,
    requiredFeatures: Set<ULong>,
    val createdUnixMilliseconds: ULong,
    val expiresUnixMilliseconds: ULong,
    canonicalCapture: ByteArray,
    permittedActions: List<CapturedAction>,
    bodyLimits: CborLimits,
    captureLimits: CborLimits,
) {
    init {
        ensure(contract.wireVersion == 1uL, IssuedRequestFailure.UNSUPPORTED_CONTRACT)
        ensure(listOf(macID.size, accountID.size, requestID.size, challenge.size) == listOf(16, 16, 16, 32), IssuedRequestFailure.INVALID_BYTES)
        ensure(createdUnixMilliseconds < expiresUnixMilliseconds, IssuedRequestFailure.INVALID_TIMES)
        if (requiredFeatures.size > bodyLimits.maxItems || permittedActions.size > bodyLimits.maxItems) throw CborException(CborFailure.ITEM_LIMIT)
        if (canonicalCapture.size > captureLimits.maxBytes || canonicalCapture.size > bodyLimits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
    }

    private val identities = listOf(macID, accountID, requestID, challenge).map { CborValue.Bytes(it) }
    private val capture = CborValue.Bytes(canonicalCapture)
    private val digest = CborValue.Bytes(sha256(capture.copyBytes()))
    val macID: ByteArray get() = identities[0].copyBytes()
    val accountID: ByteArray get() = identities[1].copyBytes()
    val requestID: ByteArray get() = identities[2].copyBytes()
    val challenge: ByteArray get() = identities[3].copyBytes()
    val canonicalCapture: ByteArray get() = capture.copyBytes()
    val captureDigest: ByteArray get() = digest.copyBytes()
    val requiredFeatures: Set<ULong> = Collections.unmodifiableSet(HashSet(requiredFeatures))
    val permittedActions: List<CapturedAction> = Collections.unmodifiableList(ArrayList(permittedActions))

    init {
        ensure(DeterministicCbor.decode(capture.copyBytes(), captureLimits) is CborValue.Fields, IssuedRequestFailure.INVALID_CAPTURE)
        val actions = this.permittedActions.toSet()
        ensure(actions.isNotEmpty() && actions.size == this.permittedActions.size, IssuedRequestFailure.INVALID_ACTIONS)
        try {
            this.permittedActions.forEach { ActionPolicy.requirement(it, contract.requestKind, actions) }
        } catch (_: ActionPolicyException) { fail(IssuedRequestFailure.INVALID_ACTIONS) }
        encode(bodyLimits)
    }

    fun encode(limits: CborLimits): ByteArray {
        if (requiredFeatures.size > limits.maxItems || permittedActions.size > limits.maxItems) throw CborException(CborFailure.ITEM_LIMIT)
        val kind = when (contract.requestKind) {
            RequestKind.COMMAND -> 0uL
            RequestKind.ONE_PASSWORD_ACCESS -> 1uL
            RequestKind.ONE_PASSWORD_UNLOCK -> 2uL
            RequestKind.LITTLE_SNITCH -> 3uL
        }
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Unsigned(1u), 1uL to identities[0], 2uL to identities[1], 3uL to identities[2], 4uL to identities[3],
            5uL to CborValue.Unsigned(kind), 6uL to CborValue.Unsigned(contract.schemaVersion),
            7uL to CborValue.ArrayValue(requiredFeatures.sorted().map { CborValue.Unsigned(it) }),
            8uL to CborValue.Unsigned(createdUnixMilliseconds), 9uL to CborValue.Unsigned(expiresUnixMilliseconds),
            10uL to capture, 11uL to digest, 12uL to CborValue.ArrayValue(permittedActions.map { ActionWire.encode(it) }),
        )), limits)
    }

    fun requestDigest(bodyLimits: CborLimits, signingLimits: CborLimits): ByteArray = sha256(SigningInput.make(
        contract.wireVersion, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST,
        encode(bodyLimits), bodyLimits, signingLimits,
    ))

    companion object {
        fun decode(bytes: ByteArray, bodyLimits: CborLimits, captureLimits: CborLimits,
                   localCapabilities: ContractCapabilities): IssuedRequestPayload {
            val fields = (DeterministicCbor.decode(bytes, bodyLimits) as? CborValue.Fields)?.values
                ?: fail(IssuedRequestFailure.INVALID_FIELDS)
            ensure(fields.keys == (0uL..12uL).toSet(), IssuedRequestFailure.INVALID_FIELDS)
            ensure(fields[0u] == CborValue.Unsigned(1u), IssuedRequestFailure.UNSUPPORTED_WRAPPER)
            fun uint(key: ULong) = (fields[key] as? CborValue.Unsigned)?.value ?: fail(IssuedRequestFailure.INVALID_FIELDS)
            fun data(key: ULong) = (fields[key] as? CborValue.Bytes)?.copyBytes() ?: fail(IssuedRequestFailure.INVALID_BYTES)
            val kind = when (uint(5u)) {
                0uL -> RequestKind.COMMAND
                1uL -> RequestKind.ONE_PASSWORD_ACCESS
                2uL -> RequestKind.ONE_PASSWORD_UNLOCK
                3uL -> RequestKind.LITTLE_SNITCH
                else -> fail(IssuedRequestFailure.UNSUPPORTED_CONTRACT)
            }
            val schema = uint(6u)
            ensure(schema > 0uL, IssuedRequestFailure.UNSUPPORTED_CONTRACT)
            val contract = RequestContract(kind, 1u, schema)
            val supported = localCapabilities.contracts[contract] ?: fail(IssuedRequestFailure.UNSUPPORTED_CONTRACT)
            val featureValues = (fields[7u] as? CborValue.ArrayValue)?.values ?: fail(IssuedRequestFailure.INVALID_FEATURES)
            val features = mutableSetOf<ULong>()
            var previous: ULong? = null
            for (feature in featureValues) {
                val value = (feature as? CborValue.Unsigned)?.value ?: fail(IssuedRequestFailure.INVALID_FEATURES)
                ensure(previous == null || value > previous, IssuedRequestFailure.INVALID_FEATURES)
                features.add(value)
                previous = value
            }
            ensure(supported.containsAll(features), IssuedRequestFailure.UNSUPPORTED_FEATURES)
            val actionValues = (fields[12u] as? CborValue.ArrayValue)?.values ?: fail(IssuedRequestFailure.INVALID_ACTIONS)
            val actions = try { actionValues.map { ActionWire.decode(it) } }
                catch (_: ActionWireException) { fail(IssuedRequestFailure.INVALID_ACTIONS) }
            val result = IssuedRequestPayload(contract, data(1u), data(2u), data(3u), data(4u), features,
                uint(8u), uint(9u), data(10u), actions, bodyLimits, captureLimits)
            ensure(data(11u).contentEquals(result.captureDigest), IssuedRequestFailure.CAPTURE_DIGEST_MISMATCH)
            return result
        }

        private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun ensure(condition: Boolean, reason: IssuedRequestFailure) { if (!condition) fail(reason) }
        private fun fail(reason: IssuedRequestFailure): Nothing = throw IssuedRequestException(reason)
    }
}
