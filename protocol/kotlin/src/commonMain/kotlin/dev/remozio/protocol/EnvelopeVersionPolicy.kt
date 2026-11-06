package dev.remozio.protocol

enum class CompatibilityFailure { INVALID_POLICY, NO_SAFE_ENVELOPE_VERSION, NO_COMPATIBLE_PHONES }
class CompatibilityException(val reason: CompatibilityFailure) : IllegalArgumentException(reason.name)

/** Highest envelope version both sides offer that is not below the minimum the caller already trusts. */
internal fun selectEnvelopeVersion(local: Set<ULong>, peer: Set<ULong>, trustedMinimum: ULong): ULong {
    if (trustedMinimum == 0uL) throw CompatibilityException(CompatibilityFailure.INVALID_POLICY)
    return local.intersect(peer).filter { it >= trustedMinimum }.maxOrNull()
        ?: throw CompatibilityException(CompatibilityFailure.NO_SAFE_ENVELOPE_VERSION)
}
