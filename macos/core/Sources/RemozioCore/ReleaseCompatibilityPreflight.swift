import Foundation

public enum ReleaseCompatibilityError: Error, Equatable {
    case invalidRequirements
    case missingRole(AuthorityCodeRole)
    case missingFormat(AuthorityCodeRole, String)
    case missingReader(AuthorityCodeRole, String, UInt64)
    case missingWriter(AuthorityCodeRole, String, UInt64)
    case missingRequest(AuthorityCodeRole, UInt64, UInt64, UInt64)
    case missingActions(AuthorityCodeRole, UInt64, UInt64, UInt64)
    case missingPurposes(AuthorityCodeRole, UInt64, UInt64, UInt64)
    case missingFeatures(AuthorityCodeRole, UInt64, UInt64, UInt64)
}

public struct RetainedReleaseFormat: Sendable {
    public let role: AuthorityCodeRole
    public let name: String
    public let readVersions: Set<UInt64>
    public let writeVersions: Set<UInt64>

    public init(role: AuthorityCodeRole, name: String, readVersions: Set<UInt64>, writeVersions: Set<UInt64> = []) throws {
        guard (1...255).contains(name.utf8.count), name.utf8.allSatisfy({
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 46 || $0 == 45
        }), !readVersions.isEmpty, readVersions.count <= 32, writeVersions.count <= 32,
           !readVersions.contains(0), !writeVersions.contains(0) else { throw ReleaseCompatibilityError.invalidRequirements }
        self.role = role; self.name = name; self.readVersions = readVersions; self.writeVersions = writeVersions
    }
}

public struct RetainedReleaseRequest: Sendable {
    public let role: AuthorityCodeRole
    public let contract: ReleaseRequestContract

    public init(role: AuthorityCodeRole, contract: ReleaseRequestContract) {
        self.role = role; self.contract = contract
    }
}

public struct RetainedReleaseRequirements: Sendable {
    public let formats: [RetainedReleaseFormat]
    public let requests: [RetainedReleaseRequest]

    public init(formats: [RetainedReleaseFormat], requests: [RetainedReleaseRequest]) throws {
        guard formats.count <= 384, requests.count <= 384 else { throw ReleaseCompatibilityError.invalidRequirements }
        for role in AuthorityCodeRole.allCases {
            let roleFormats = formats.filter { $0.role == role }
            let roleRequests = requests.filter { $0.role == role }
            guard roleFormats.count <= 32, roleRequests.count <= 32,
                  Set(roleFormats.map(\.name)).count == roleFormats.count,
                  Set(roleRequests.map { [$0.contract.kind, $0.contract.wireVersion, $0.contract.schemaVersion] }).count == roleRequests.count else {
                throw ReleaseCompatibilityError.invalidRequirements
            }
        }
        self.formats = formats; self.requests = requests
    }
}

public enum ReleaseCompatibilityPreflight {
    /// Compares exact retained requirements. The installation owner must derive and revalidate them from protected state.
    /// This comparison performs no migration and grants no activation authority.
    public static func validate(_ evidence: SignedReleaseEvidence, policy: AuthorityCodePolicy,
                         requirements: RetainedReleaseRequirements) throws {
        try ReleaseGenerationPreflight.validate(evidence, against: policy)
        let components = evidence.manifest.components
        for required in requirements.formats {
            guard let component = components.first(where: { $0.role == required.role }) else {
                throw ReleaseCompatibilityError.missingRole(required.role)
            }
            guard let format = component.formats.first(where: { $0.name == required.name }) else {
                throw ReleaseCompatibilityError.missingFormat(required.role, required.name)
            }
            for version in required.readVersions.sorted() where !format.readers.contains(version) {
                throw ReleaseCompatibilityError.missingReader(required.role, required.name, version)
            }
            for version in required.writeVersions.sorted() where !format.writers.contains(version) {
                throw ReleaseCompatibilityError.missingWriter(required.role, required.name, version)
            }
        }
        for required in requirements.requests {
            let request = required.contract
            guard let component = components.first(where: { $0.role == required.role }) else {
                throw ReleaseCompatibilityError.missingRole(required.role)
            }
            guard let candidate = component.requests.first(where: {
                $0.kind == request.kind && $0.wireVersion == request.wireVersion && $0.schemaVersion == request.schemaVersion
            }) else {
                throw ReleaseCompatibilityError.missingRequest(required.role, request.kind, request.wireVersion, request.schemaVersion)
            }
            guard request.actions.isSubset(of: candidate.actions) else {
                throw ReleaseCompatibilityError.missingActions(required.role, request.kind, request.wireVersion, request.schemaVersion)
            }
            guard request.purposes.isSubset(of: candidate.purposes) else {
                throw ReleaseCompatibilityError.missingPurposes(required.role, request.kind, request.wireVersion, request.schemaVersion)
            }
            guard request.features.isSubset(of: candidate.features) else {
                throw ReleaseCompatibilityError.missingFeatures(required.role, request.kind, request.wireVersion, request.schemaVersion)
            }
        }
    }
}
