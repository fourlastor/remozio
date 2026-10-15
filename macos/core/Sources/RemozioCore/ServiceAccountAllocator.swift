import Foundation

/// Candidate IDs are hints. Only the machine transaction reserves them; native creation rechecks every directory index.
enum ServiceAccountAllocator {
    static func plan(account: AccountPreparationIntent, reserved: Set<UInt32>,
                     candidate: () -> UInt32 = { UInt32.random(in: 20_000...60_000) },
                     available: (ServiceAccountClaim) throws -> Bool) throws -> ServiceAccountPlan {
        var used = reserved.union([0, 80, UInt32.max, account.ownerUID]), claims: [ServiceAccountClaim] = []
        for role in ServiceAccountPlan.roles {
            var selected: ServiceAccountClaim?
            // Bounded queries keep an unavailable directory from stalling the setup helper indefinitely.
            for _ in 0..<128 {
                let number = candidate()
                guard (20_000...60_000).contains(number), !used.contains(number) else { continue }
                let claim = try ServiceAccountClaim(accountID: account.accountID, role: role, number: number, userID: UUID(), groupID: UUID())
                if try available(claim) { selected = claim; break }
            }
            guard let selected else { throw ServiceAccountProvisioningError.exhausted }
            used.insert(selected.number); claims.append(selected)
        }
        return try .init(account: account, planID: AccountPreparationIntent.randomID(), claims: claims)
    }
}
