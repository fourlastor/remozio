import CryptoKit
import Darwin
import Foundation
import Security

/// Disposable System Keychain items only. No login keychain or production namespace is searched.
enum NativeStage: String, Codable { case disableUI, selectKeychain, trustReader, createAccess, generateRandom, createItem, readItem, deleteItem }
enum ProbeError: Error, Equatable { case arguments, rootRequired, invalidResponse, status(OSStatus), native(NativeStage, OSStatus) }
enum Operation: Equatable {
    case plan
    case create(UUID, reader: String)
    case read(UUID, digest: String)
    case remove(UUID)
    static func parse(_ args: [String]) throws -> Self {
        if args == ["--plan"] || args.isEmpty { return .plan }
        guard args.count >= 2, let id = UUID(uuidString: args[1]), id.uuidString.lowercased() == args[1] else { throw ProbeError.arguments }
        if args[0] == "--create", args.count == 4, args[2] == "--reader" {
            let path = args[3]
            guard path.hasPrefix("/"), !path.utf8.contains(0), path.utf8.count < Int(PATH_MAX),
                  path.split(separator: "/", omittingEmptySubsequences: false).dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { throw ProbeError.arguments }
            return .create(id, reader: path)
        }
        if args[0] == "--read", args.count == 4, args[2] == "--sha256",
           args[3].utf8.count == 64, args[3].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) {
            return .read(id, digest: args[3])
        }
        if args[0] == "--delete", args.count == 2 { return .remove(id) }
        throw ProbeError.arguments
    }
}
struct Report: Codable, Equatable {
    let operation: String
    let outcome: String
    var experimentID: String? = nil
    var secretSHA256: String? = nil
    var status: Int32? = nil
    var nativeStage: NativeStage? = nil
    var actualUID: UInt32? = nil
    var keychainOperationRequested = false
    var lifecycleProven = false
    var readerIsolationProven = false
    static func failure(_ error: Error, requested: Bool, uid: UInt32) -> Report {
        var value = Report(operation: "probe", outcome: "not-proven", actualUID: uid, keychainOperationRequested: requested)
        switch error {
        case ProbeError.native(let stage, let status): value.nativeStage = stage; value.status = status
        case ProbeError.status(let status): value.status = status
        default: break
        }
        return value
    }
}
protocol KeychainBackend {
    func create(id: UUID, reader: String) throws -> String
    func read(id: UUID) throws -> String
    func remove(id: UUID) throws
}
struct Controller<Backend: KeychainBackend> {
    let backend: Backend
    let uid: UInt32
    let effectiveUID: UInt32
    func run(_ operation: Operation) throws -> Report {
        switch operation {
        case .plan:
            return Report(operation: "plan", outcome: "not-run")
        case .create(let id, let reader):
            guard uid == 0, effectiveUID == 0 else { throw ProbeError.rootRequired }
            let digest = try backend.create(id: id, reader: reader)
            return Report(operation: "create", outcome: "created", experimentID: id.uuidString.lowercased(),
                secretSHA256: digest, actualUID: effectiveUID, keychainOperationRequested: true)
        case .read(let id, let expected):
            let digest = try backend.read(id: id)
            guard digest == expected else { throw ProbeError.invalidResponse }
            return Report(operation: "read", outcome: "matched", experimentID: id.uuidString.lowercased(),
                actualUID: effectiveUID, keychainOperationRequested: true)
        case .remove(let id):
            guard uid == 0, effectiveUID == 0 else { throw ProbeError.rootRequired }
            try backend.remove(id: id)
            return Report(operation: "delete", outcome: "removed", experimentID: id.uuidString.lowercased(),
                actualUID: effectiveUID, keychainOperationRequested: true)
        }
    }
}

struct SystemKeychain: KeychainBackend {
    static let service = "dev.remozio.experiment.system-keychain.v1"
    private func check(_ status: OSStatus, _ stage: NativeStage) throws { guard status == errSecSuccess else { throw ProbeError.native(stage, status) } }
    private func selected() throws -> SecKeychain {
        // This is process-local. Never unlock a keychain or allow authentication UI.
        try check(SecKeychainSetUserInteractionAllowed(false), .disableUI)
        var keychain: SecKeychain?
        try check(SecKeychainCopyDomainDefault(.system, &keychain), .selectKeychain)
        guard let keychain else { throw ProbeError.invalidResponse }; return keychain
    }
    static func selection(id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: id.uuidString.lowercased(), kSecUseDataProtectionKeychain as String: false]
    }
    private func query(id: UUID, keychain: SecKeychain) -> [String: Any] {
        var result = Self.selection(id: id)
        result[kSecMatchSearchList as String] = [keychain]
        return result
    }
    func create(id: UUID, reader: String) throws -> String {
        let keychain = try selected()
        var trusted: SecTrustedApplication?
        try check(SecTrustedApplicationCreateFromPath(reader, &trusted), .trustReader)
        guard let trusted else { throw ProbeError.invalidResponse }
        var access: SecAccess?
        try check(SecAccessCreate("Remozio disposable daemon credential probe" as CFString, [trusted] as CFArray, &access), .createAccess)
        guard let access else { throw ProbeError.invalidResponse }
        var secret = Data(count: 32)
        let randomStatus = secret.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        try check(randomStatus, .generateRandom)
        var attributes = Self.selection(id: id)
        attributes[kSecUseKeychain as String] = keychain
        attributes[kSecAttrAccess as String] = access
        attributes[kSecValueData as String] = secret
        // An existing item produces a duplicate error. Never adopt or overwrite it.
        try check(SecItemAdd(attributes as CFDictionary, nil), .createItem)
        return Self.digest(secret)
    }
    func read(id: UUID) throws -> String {
        let keychain = try selected()
        var attributes = query(id: id, keychain: keychain)
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecReturnData as String] = true
        var value: CFTypeRef?
        try check(SecItemCopyMatching(attributes as CFDictionary, &value), .readItem)
        guard let bytes = value as? Data, bytes.count == 32 else { throw ProbeError.invalidResponse }
        return Self.digest(bytes)
    }
    func remove(id: UUID) throws {
        let keychain = try selected()
        try check(SecItemDelete(query(id: id, keychain: keychain) as CFDictionary), .deleteItem)
    }
    private static func digest(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
}
