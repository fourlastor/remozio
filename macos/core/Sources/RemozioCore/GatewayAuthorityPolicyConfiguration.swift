import Foundation
import RemozioProtocol

extension GatewayAuthorityPolicy {
    func sameConfiguration(as other: Self) -> Bool {
        func limits(_ left: CBORLimits, _ right: CBORLimits) -> Bool {
            left.maxBytes == right.maxBytes && left.maxDepth == right.maxDepth && left.maxItems == right.maxItems
        }
        return limits(payloadLimits, other.payloadLimits) && limits(signingLimits, other.signingLimits)
            && maximumControls == other.maximumControls && candidateLifetimeMillis == other.candidateLifetimeMillis && clockEpoch == other.clockEpoch
    }
}
