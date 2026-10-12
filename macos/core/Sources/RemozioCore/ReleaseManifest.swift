import Foundation
import RemozioProtocol

public enum ReleaseManifestError: Error, Equatable {
    case invalidDeclaration, corruptData, unsupportedSchema, missingMetadata, identityMismatch, unsafePath
    case security(Int32)
}

/// Exact codec declarations. These sets do not enable a service or authorize a migration.
public struct ReleaseFormat: Equatable, Sendable {
    public let name: String
    public let readers: Set<UInt64>
    public let writers: Set<UInt64>
    public let migrations: [UInt64: UInt64]

    public init(name: String, readers: Set<UInt64>, writers: Set<UInt64>, migrations: [UInt64: UInt64] = [:]) throws {
        guard ReleaseManifest.validToken(name), !readers.isEmpty, readers.count <= 32, writers.count <= 32,
              !readers.contains(0), writers.isSubset(of: readers), migrations.count <= 32,
              migrations.allSatisfy({ $0.key > 0 && $0.key < $0.value && writers.contains($0.value) }) else {
            throw ReleaseManifestError.invalidDeclaration
        }
        self.name = name; self.readers = readers; self.writers = writers; self.migrations = migrations
    }
    fileprivate var value: CBORValue {
        .map([0: .text(name), 1: .array(readers.sorted().map(CBORValue.unsigned)),
              2: .array(writers.sorted().map(CBORValue.unsigned)), 3: .map(migrations.mapValues(CBORValue.unsigned))])
    }
}

/// Understood request semantics, separate from live adapter readiness and retained permission.
public struct ReleaseRequestContract: Equatable, Sendable {
    public let kind: UInt64
    public let wireVersion: UInt64
    public let schemaVersion: UInt64
    public let actions: Set<UInt64>
    public let purposes: Set<SigningPurpose>
    public let features: Set<UInt64>

    public init(kind: UInt64, wireVersion: UInt64, schemaVersion: UInt64,
                actions: Set<UInt64>, purposes: Set<SigningPurpose>, features: Set<UInt64> = []) throws {
        guard kind <= 3, wireVersion > 0, schemaVersion > 0, !actions.isEmpty,
              actions.allSatisfy({ $0 <= 9 }), !purposes.isEmpty, features.count <= 32 else { throw ReleaseManifestError.invalidDeclaration }
        self.kind = kind; self.wireVersion = wireVersion; self.schemaVersion = schemaVersion
        self.actions = actions; self.purposes = purposes; self.features = features
    }
    fileprivate var key: [UInt64] { [kind, wireVersion, schemaVersion] }
    fileprivate func value(manifestSchema: UInt64) -> CBORValue {
        var fields: [UInt64: CBORValue] = [0: .unsigned(kind), 1: .unsigned(wireVersion), 2: .unsigned(schemaVersion),
              3: .array(actions.sorted().map(CBORValue.unsigned)),
              4: .array(purposes.map(\.rawValue).sorted().map(CBORValue.unsigned))]
        if manifestSchema >= 3 { fields[5] = .array(features.sorted().map(CBORValue.unsigned)) }
        return .map(fields)
    }
}

/// A declared executable. Registration remains absent until the protected installer records it.
public struct ReleaseComponent: Equatable, Sendable {
    public let role: AuthorityCodeRole
    public let identifier: String
    public let generation: UInt64
    public let relativePath: String
    /// The app has no embedded self hash. Inspection obtains it from the enclosing signature.
    public let codeDirectoryHash: Data?
    public let build: String
    /// Nil denotes an ad-hoc test artifact. Production inspection requires the trusted Team ID.
    public let teamID: String?
    public let formats: [ReleaseFormat]
    public let requests: [ReleaseRequestContract]

    public init(role: AuthorityCodeRole, identifier: String, generation: UInt64, relativePath: String,
                codeDirectoryHash: Data?, build: String, teamID: String?, formats: [ReleaseFormat],
                requests: [ReleaseRequestContract] = []) throws {
        let parts = relativePath.split(separator: "/", omittingEmptySubsequences: false)
        guard ReleaseManifest.validToken(identifier), generation > 0,
              relativePath.utf8.count <= 1024, parts.count >= 3, parts.first == "Contents",
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && $0.utf8.count <= 255 && !$0.utf8.contains(0) }),
              role == .app ? codeDirectoryHash == nil : codeDirectoryHash?.count == 20,
              ReleaseManifest.validToken(build),
              teamID == nil || (teamID!.utf8.count == 10 && teamID!.utf8.allSatisfy({ (65...90).contains($0) || (48...57).contains($0) })),
              formats.count <= 32, Set(formats.map(\.name)).count == formats.count,
              requests.count <= 32, Set(requests.map(\.key)).count == requests.count else {
            throw ReleaseManifestError.invalidDeclaration
        }
        self.role = role; self.identifier = identifier; self.generation = generation; self.relativePath = relativePath
        self.codeDirectoryHash = codeDirectoryHash; self.build = build; self.teamID = teamID
        self.formats = formats.sorted { $0.name < $1.name }
        self.requests = requests.sorted { $0.key.lexicographicallyPrecedes($1.key) }
    }
    fileprivate func value(manifestSchema: UInt64) -> CBORValue {
        .map([0: .unsigned(role.rawValue), 1: .text(identifier), 2: .unsigned(generation), 3: .text(relativePath),
              4: codeDirectoryHash.map(CBORValue.bytes) ?? .null, 5: .text(build), 6: teamID.map(CBORValue.text) ?? .null,
              7: .array(formats.map(\.value)), 8: .array(requests.map { $0.value(manifestSchema: manifestSchema) }),
              9: .unsigned(0)]) // No supported schema contains installed service registration.
    }
}

/// Unauthenticated until read through strict signature inspection. No activation authority is implied.
public struct ReleaseManifest: Equatable, Sendable {
    public static let infoKey = "RemozioReleaseManifest"
    public static let maximumBytes = 65_536
    public let release: String
    public let build: String
    public let components: [ReleaseComponent]
    public let schemaVersion: UInt64
    public let dependencies: [ReleaseDependency]
    public var absentRoles: Set<AuthorityCodeRole> { Set(AuthorityCodeRole.allCases).subtracting(components.map(\.role)) }

    public init(release: String, build: String, components: [ReleaseComponent], dependencies: [ReleaseDependency] = []) throws {
        try self.init(release: release, build: build, components: components, dependencies: dependencies,
                      schemaVersion: components.contains(where: { $0.requests.contains(where: { !$0.features.isEmpty }) }) ? 3 : dependencies.isEmpty ? 1 : 2)
    }

    private init(release: String, build: String, components: [ReleaseComponent], dependencies: [ReleaseDependency],
                 schemaVersion: UInt64) throws {
        guard Self.validToken(release), Self.validToken(build), !components.isEmpty,
              components.count <= AuthorityCodeRole.allCases.count,
              Set(components.map(\.role)).count == components.count,
              Set(components.map(\.identifier)).count == components.count,
              Set(components.map(\.relativePath)).count == components.count,
              components.filter({ $0.role == .app }).count == 1 else { throw ReleaseManifestError.invalidDeclaration }
        guard (1...3).contains(schemaVersion), schemaVersion >= 2 || dependencies.isEmpty,
              schemaVersion >= 3 || components.allSatisfy({ $0.requests.allSatisfy({ $0.features.isEmpty }) }),
              dependencies.count <= 32, Set(dependencies.map(\.executablePath)).count == dependencies.count,
              dependencies.allSatisfy({ dependency in components.contains(where: { $0.role == dependency.owner }) }) else {
            throw ReleaseManifestError.invalidDeclaration
        }
        let identifiers = components.map(\.identifier) + dependencies.map(\.identifier)
        let paths = components.map(\.relativePath) + dependencies.flatMap { [$0.executablePath] + $0.executableAliases.sorted() }
        guard Set(identifiers).count == identifiers.count, paths.count <= 256, Set(paths).count == paths.count else {
            throw ReleaseManifestError.invalidDeclaration
        }
        self.schemaVersion = schemaVersion
        self.dependencies = dependencies.sorted { $0.executablePath < $1.executablePath }
        self.release = release; self.build = build
        self.components = components.sorted { $0.role.rawValue < $1.role.rawValue }
        _ = try canonicalBytes
    }

    public var canonicalBytes: Data {
        get throws {
            var fields: [UInt64: CBORValue] = [0: .unsigned(schemaVersion), 1: .text(release), 2: .text(build),
                3: .text("arm64"), 4: .text("26.0"), 5: .array(components.map { $0.value(manifestSchema: schemaVersion) })]
            if schemaVersion >= 2 { fields[6] = .array(dependencies.map(\.value)) }
            return try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
        }
    }
    static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 8, maxItems: 8192) } }
    static func validToken(_ text: String) -> Bool {
        (1...255).contains(text.utf8.count) && text.utf8.allSatisfy {
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 46 || $0 == 45
        }
    }

    public static func decode(_ bytes: Data) throws -> Self {
        do {
            let raw = try DeterministicCBOR.decode(bytes, limits: limits)
            guard case .map(let header) = raw, case .unsigned(let version) = header[0] else {
                throw ReleaseManifestError.corruptData
            }
            guard (1...3).contains(version) else { throw ReleaseManifestError.unsupportedSchema }
            let fields = try dictionary(raw, keys: version == 1 ? 0...5 : 0...6)
            guard fields[3] == .text("arm64"), fields[4] == .text("26.0") else { throw ReleaseManifestError.corruptData }
            let components = try array(fields[5]).map { item -> ReleaseComponent in
                let fields = try dictionary(item, keys: 0...9)
                guard let role = AuthorityCodeRole(rawValue: try number(fields[0])), fields[9] == .unsigned(0) else {
                    throw ReleaseManifestError.corruptData
                }
                let hash: Data?
                if fields[4] == .null { hash = nil }
                else if case .bytes(let bytes) = fields[4] { hash = bytes }
                else { throw ReleaseManifestError.corruptData }
                let team = fields[6] == .null ? nil : try text(fields[6])
                let formats = try array(fields[7]).map { item -> ReleaseFormat in
                    let f = try dictionary(item, keys: 0...3)
                    guard case .map(let migrations) = f[3] else { throw ReleaseManifestError.corruptData }
                    return try ReleaseFormat(name: text(f[0]), readers: numbers(f[1]), writers: numbers(f[2]),
                        migrations: migrations.mapValues { try number($0) })
                }
                let requests = try array(fields[8]).map { item -> ReleaseRequestContract in
                    let f = try dictionary(item, keys: version >= 3 ? 0...5 : 0...4)
                    let purposes = try numbers(f[4]).map { tag -> SigningPurpose in
                        guard let purpose = SigningPurpose(rawValue: tag) else { throw ReleaseManifestError.corruptData }; return purpose
                    }
                    return try ReleaseRequestContract(kind: number(f[0]), wireVersion: number(f[1]), schemaVersion: number(f[2]),
                        actions: numbers(f[3]), purposes: Set(purposes), features: version >= 3 ? numbers(f[5]) : [])
                }
                return try ReleaseComponent(role: role, identifier: text(fields[1]), generation: number(fields[2]),
                    relativePath: text(fields[3]), codeDirectoryHash: hash, build: text(fields[5]), teamID: team,
                    formats: formats, requests: requests)
            }
            let dependencies = version == 1 ? [] : try array(fields[6]).map { value -> ReleaseDependency in
                let item = try dictionary(value, keys: 0...8)
                guard let owner = AuthorityCodeRole(rawValue: try number(item[0])),
                      let kind = ReleaseDependencyKind(rawValue: try number(item[1])),
                      case .bytes(let hash) = item[5] else { throw ReleaseManifestError.corruptData }
                let aliases = try array(item[8]).map { try text($0) }
                guard aliases.count <= 16, Set(aliases).count == aliases.count else { throw ReleaseManifestError.corruptData }
                return try ReleaseDependency(owner: owner, kind: kind, signaturePath: text(item[2]),
                    executablePath: text(item[3]), identifier: text(item[4]), codeDirectoryHash: hash,
                    teamID: item[6] == .null ? nil : text(item[6]), build: item[7] == .null ? nil : text(item[7]),
                    executableAliases: Set(aliases))
            }
            let result = try Self(release: text(fields[1]), build: text(fields[2]), components: components,
                                  dependencies: dependencies, schemaVersion: version)
            guard try result.canonicalBytes == bytes else { throw ReleaseManifestError.corruptData }
            return result
        } catch ReleaseManifestError.unsupportedSchema { throw ReleaseManifestError.unsupportedSchema }
        catch { throw ReleaseManifestError.corruptData }
    }
    private static func dictionary(_ value: CBORValue, keys: ClosedRange<UInt64>) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = value, Set(fields.keys) == Set(keys) else { throw ReleaseManifestError.corruptData }; return fields
    }
    private static func text(_ value: CBORValue?) throws -> String {
        guard case .text(let text) = value else { throw ReleaseManifestError.corruptData }; return text
    }
    private static func number(_ value: CBORValue?) throws -> UInt64 {
        guard case .unsigned(let number) = value else { throw ReleaseManifestError.corruptData }; return number
    }
    private static func array(_ value: CBORValue?) throws -> [CBORValue] {
        guard case .array(let array) = value else { throw ReleaseManifestError.corruptData }; return array
    }
    private static func numbers(_ value: CBORValue?) throws -> Set<UInt64> {
        let values = try array(value).map { try number($0) }
        guard values.count <= 32, Set(values).count == values.count else { throw ReleaseManifestError.corruptData }
        return Set(values)
    }
}
