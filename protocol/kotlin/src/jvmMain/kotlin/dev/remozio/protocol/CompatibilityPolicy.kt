package dev.remozio.protocol

import java.util.Collections
import java.util.UUID

data class RequestContract(val requestKind: RequestKind, val wireVersion: ULong, val schemaVersion: ULong) {
    init {
        if (wireVersion == 0uL || schemaVersion == 0uL) throw CompatibilityException(CompatibilityFailure.INVALID_POLICY)
    }
}

class ContractCapabilities(contracts: Map<RequestContract, Set<ULong>>) {
    val contracts: Map<RequestContract, Set<ULong>> = Collections.unmodifiableMap(
        contracts.mapValues { (_, features) -> Collections.unmodifiableSet(HashSet(features)) },
    )
}

class ContractSelection(val contract: RequestContract, eligibleEnrollments: Set<UUID>) {
    val eligibleEnrollments: Set<UUID> = Collections.unmodifiableSet(HashSet(eligibleEnrollments))
}

enum class CompatibilityFailure { INVALID_POLICY, NO_SAFE_ENVELOPE_VERSION, NO_COMPATIBLE_PHONES }
class CompatibilityException(val reason: CompatibilityFailure) : IllegalArgumentException(reason.name)

/** Selection over already-authenticated capabilities; this does not authenticate a handshake. */
object CompatibilityPolicy {
    fun envelopeVersion(local: Set<ULong>, peer: Set<ULong>, trustedMinimum: ULong): ULong {
        if (trustedMinimum == 0uL) throw CompatibilityException(CompatibilityFailure.INVALID_POLICY)
        return local.intersect(peer).filter { it >= trustedMinimum }.maxOrNull()
            ?: throw CompatibilityException(CompatibilityFailure.NO_SAFE_ENVELOPE_VERSION)
    }

    fun requestContract(
        requestKind: RequestKind,
        authority: ContractCapabilities,
        authorizedEnrollments: Map<UUID, ContractCapabilities>,
        trustedAllowedContracts: Set<RequestContract>,
        requiredFeatures: Set<ULong>,
    ): ContractSelection {
        var best: ContractSelection? = null
        for ((contract, features) in authority.contracts) {
            if (contract.requestKind != requestKind || contract !in trustedAllowedContracts || !features.containsAll(requiredFeatures)) continue
            val eligible = authorizedEnrollments.filterValues { capabilities ->
                capabilities.contracts[contract]?.containsAll(requiredFeatures) == true
            }.keys
            if (eligible.isEmpty()) continue
            val current = best
            if (current == null || eligible.size > current.eligibleEnrollments.size ||
                (eligible.size == current.eligibleEnrollments.size && (contract.wireVersion > current.contract.wireVersion ||
                    (contract.wireVersion == current.contract.wireVersion && contract.schemaVersion > current.contract.schemaVersion)))
            ) {
                best = ContractSelection(contract, eligible)
            }
        }
        return best ?: throw CompatibilityException(CompatibilityFailure.NO_COMPATIBLE_PHONES)
    }
}
