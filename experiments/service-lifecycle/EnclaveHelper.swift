import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import os
import Security

@main struct EnclaveLifecycleHelper {
    static func emit(_ values: [String: Any], daemonEvidence: Bool = false) {
        guard let data = try? JSONSerialization.data(withJSONObject: values, options: [.sortedKeys]) else { exit(EX_SOFTWARE) }
        if daemonEvidence {
            let logger = Logger(subsystem: ServiceProbeContract.appID, category: "enclave-lifecycle")
            let json = String(decoding: data, as: UTF8.self)
            logger.notice("Enclave lifecycle evidence: \(json, privacy: .public)")
        } else {
            FileHandle.standardOutput.write(data + Data([10]))
        }
    }
    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        if args == ["--describe"] {
            emit(["role": "enclave", "capability": "disposable-key-lifecycle-only"]); return
        }
        let create = args == ["--create-disposable-key", "--confirm-disposable-key-test"]
        let service = args == ["--service-key-probe"]
        guard create || service || args == ["--restore-disposable-key"] else { exit(EX_UNAVAILABLE) }
        guard getuid() == 0, geteuid() == 0 else { exit(EX_NOPERM) }
        var report: [String: Any] = ["experiment": "disposable-enclave-lifecycle", "schemaVersion": 1,
            "osVersion": ProcessInfo.processInfo.operatingSystemVersionString, "authenticationUIAllowed": false,
            "accessibility": "after-first-unlock-this-device-only", "softwareFallback": false,
            "status": "blocked", "stage": "signed-placement", "preLoginProven": false,
            "statePersistence": "notAttempted", "pid": getpid(), "uid": getuid(), "euid": geteuid(),
            "serviceMode": service, "observedAt": ISO8601DateFormatter().string(from: Date())]
        let context = LAContext(); context.interactionNotAllowed = true
        defer { context.invalidate() }
        do {
            var bytes = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
            guard proc_pidpath(getpid(), &bytes, UInt32(bytes.count)) > 0, let end = bytes.firstIndex(of: 0),
                  let path = String(bytes: bytes[..<end].map { UInt8(bitPattern: $0) }, encoding: .utf8) else {
                throw EnclaveProbeError.unsafePlacement
            }
            let app = URL(fileURLWithPath: path).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            let placement = try ServiceProbePlacement(app: app)
            defer { placement.close() }
            try ServiceProbeContract.validateManifests(app)
            try ServiceProbeContract.validateSigning(app, notarized: true)
            try placement.validate()
            var session: SecuritySessionId = 0, attributes = SessionAttributeBits(rawValue: 0)
            let sessionStatus = SessionGetInfo(callerSecuritySession, &session, &attributes)
            report["securitySessionStatus"] = sessionStatus
            if sessionStatus == errSecSuccess {
                report["rootSecuritySession"] = attributes.contains(.sessionIsRoot)
                report["graphicAccess"] = attributes.contains(.sessionHasGraphicAccess)
                report["remoteSession"] = attributes.contains(.sessionIsRemote)
            }
            guard !service || (sessionStatus == errSecSuccess && attributes.contains(.sessionIsRoot)
                && !attributes.contains(.sessionHasGraphicAccess)) else { throw EnclaveProbeError.unavailable }
            report["stage"] = "private-namespace"
            let namespace = try EnclaveProbeNamespace()
            let record: EnclaveProbeRecord
            if create {
                try namespace.requireAbsent()
                report["stage"] = "create-hardware-key"
                guard SecureEnclave.isAvailable else { throw EnclaveProbeError.unavailable }
                var accessError: Unmanaged<CFError>?
                guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                    .privateKeyUsage, &accessError) else { throw EnclaveProbeError.unavailable }
                let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: context)
                record = try EnclaveProbeRecord(publicKey: key.publicKey.x963Representation, wrappedKey: key.dataRepresentation)
                report["publicFingerprint"] = record.publicFingerprint
                report["stage"] = "persist-state"; report["statePersistence"] = "attemptedOutcomeUnknown"
                try namespace.create(record)
                report["statePersistence"] = "confirmed"
            } else {
                report["stage"] = "read-existing-state"
                record = try namespace.read()
                report["publicFingerprint"] = record.publicFingerprint
            }
            report["stage"] = "restore-and-sign"
            let key = try record.restore(context: context)
            let message = Data("Remozio disposable daemon key lifecycle v1".utf8)
            let signature = try key.signature(for: message)
            guard key.publicKey.isValidSignature(signature, for: message), try namespace.read().encode() == record.encode() else {
                throw EnclaveProbeError.invalidState
            }
            try placement.validate()
            report["signatureVerifiedAgainstRetainedPublicKey"] = true
            report["stage"] = "complete"; report["status"] = "passed"
            emit(report, daemonEvidence: service)
        } catch {
            let error = error as NSError
            report["failureDomain"] = error.domain; report["failureCode"] = error.code
            emit(report, daemonEvidence: service); exit(EX_CONFIG)
        }
    }
}
