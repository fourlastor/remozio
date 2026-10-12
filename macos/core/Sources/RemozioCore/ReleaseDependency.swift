import Foundation
import RemozioProtocol

public enum ReleaseDependencyKind: UInt64, Sendable {
    case framework = 1, application, xpcService, tool
}

/// Candidate declarations only. Dependencies receive no service or authority role.
public struct ReleaseDependency: Equatable, Sendable {
    public let owner: AuthorityCodeRole
    public let kind: ReleaseDependencyKind
    public let signaturePath: String
    public let executablePath: String
    public let identifier: String
    public let codeDirectoryHash: Data
    public let teamID: String?
    public let build: String?
    public let executableAliases: Set<String>

    public init(owner: AuthorityCodeRole, kind: ReleaseDependencyKind, signaturePath: String,
                executablePath: String, identifier: String, codeDirectoryHash: Data,
                teamID: String?, build: String?, executableAliases: Set<String> = []) throws {
        guard Self.validPath(signaturePath), Self.validPath(executablePath), Self.validToken(identifier),
              codeDirectoryHash.count == 20,
              teamID == nil || (teamID!.utf8.count == 10 && teamID!.utf8.allSatisfy({
                  (65...90).contains($0) || (48...57).contains($0)
              })), build == nil || Self.validToken(build!),
              executableAliases.count <= 16, !executableAliases.contains(executablePath),
              executableAliases.allSatisfy(Self.validPath) else { throw ReleaseManifestError.invalidDeclaration }
        switch kind {
        case .framework:
            guard signaturePath.hasSuffix(".framework"), executablePath.hasPrefix(signaturePath + "/"),
                  build != nil else { throw ReleaseManifestError.invalidDeclaration }
        case .application, .xpcService:
            let suffix = kind == .application ? ".app" : ".xpc"
            let prefix = signaturePath + "/Contents/MacOS/"
            guard signaturePath.hasSuffix(suffix), executablePath.hasPrefix(prefix),
                  Self.validToken(String(executablePath.dropFirst(prefix.count))),
                  build != nil else { throw ReleaseManifestError.invalidDeclaration }
        case .tool:
            guard signaturePath == executablePath else { throw ReleaseManifestError.invalidDeclaration }
        }
        self.owner = owner; self.kind = kind; self.signaturePath = signaturePath
        self.executablePath = executablePath; self.identifier = identifier
        self.codeDirectoryHash = codeDirectoryHash; self.teamID = teamID; self.build = build
        self.executableAliases = executableAliases
    }

    var value: CBORValue {
        .map([0: .unsigned(owner.rawValue), 1: .unsigned(kind.rawValue), 2: .text(signaturePath),
              3: .text(executablePath), 4: .text(identifier), 5: .bytes(codeDirectoryHash),
              6: teamID.map(CBORValue.text) ?? .null, 7: build.map(CBORValue.text) ?? .null,
              8: .array(executableAliases.sorted().map(CBORValue.text))])
    }

    static func validPath(_ value: String) -> Bool {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        return value.utf8.count <= 1024 && (3...16).contains(parts.count) && parts.first == "Contents"
            && parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && $0.utf8.count <= 255 && !$0.utf8.contains(0) })
    }
    private static func validToken(_ value: String) -> Bool {
        (1...255).contains(value.utf8.count) && value.utf8.allSatisfy {
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 46 || $0 == 45
        }
    }
}
