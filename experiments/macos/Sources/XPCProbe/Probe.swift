import Foundation
import RemozioCore

@objc protocol ProbeProtocol: TransportAuthorityXPCProtocol, AdministrativeSetupXPCProtocol {
    func ping(_ nonce: String, reply: @escaping (String) -> Void)
}

final class ProbeService: NSObject, ProbeProtocol {
    func hello(reply: @escaping @Sendable (UInt64) -> Void) { reply(1) }
    // Synthetic selector checks only. These methods cannot provision accounts or import administrator rights.
    func enrollmentHello(reply: @escaping @Sendable (UInt64) -> Void) { reply(2) }
    func serviceAccountsHello(reply: @escaping @Sendable (UInt64) -> Void) { reply(AdministrativeSetupInterface.serviceAccountsVersion) }
    func activationHello(reply: @escaping @Sendable (UInt64) -> Void) { reply(AdministrativeSetupInterface.activationVersion) }
    func activationProgress(reply: @escaping @Sendable (Data?) -> Void) { reply(Data()) }
    func activateRuntime(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        print("ACTIVATION_RECEIVED \(String(decoding: expected, as: UTF8.self))")
        fflush(stdout)
        switch String(decoding: authorization, as: UTF8.self) {
        case "activation-bytes": reply(expected)
        case "activation-empty": reply(Data())
        default: reply(nil)
        }
    }
    func runtimeHello(reply: @escaping @Sendable (UInt64) -> Void) { reply(AdministrativeSetupInterface.runtimeVersion) }
    func runtimeProgress(reply: @escaping @Sendable (Data?) -> Void) { reply(Data()) }
    func prepareRuntime(_ expected: Data, fileCustodyAccepted: Bool, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        print("RUNTIME_RECEIVED \(String(decoding: expected, as: UTF8.self))")
        fflush(stdout)
        guard fileCustodyAccepted else { reply(nil); return }
        switch String(decoding: authorization, as: UTF8.self) {
        case "runtime-bytes": reply(expected)
        case "runtime-empty": reply(Data())
        default: reply(nil)
        }
    }
    func accountEnrollmentProgress(reply: @escaping @Sendable (Data?) -> Void) { reply(nil) }
    func beginAccountEnrollment(_ request: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) { reply(nil) }
    func resumeAccountEnrollment(_ setupID: Data, expectedRevision: Data, authorization: Data,
                                 reply: @escaping @Sendable (Data?) -> Void) { reply(nil) }
    func accountStorageProgress(_ accountID: Data, reply: @escaping @Sendable (Data?) -> Void) { reply(nil) }
    func resumeAccountStorage(_ accountID: Data, setupID: Data, expectedRevision: Data, authorization: Data,
                              reply: @escaping @Sendable (Data?) -> Void) { reply(nil) }
    func serviceAccountsProgress(reply: @escaping @Sendable (Data?) -> Void) { reply(Data()) }
    func prepareServiceAccounts(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        print("SETUP_RECEIVED \(String(decoding: expected, as: UTF8.self))")
        fflush(stdout)
        switch String(decoding: authorization, as: UTF8.self) {
        case "setup-bytes": reply(expected)
        case "setup-empty": reply(Data())
        default: reply(nil)
        }
    }
    func requestWakeVersion(reply: @escaping @Sendable (UInt64) -> Void) { reply(0) }
    func wakeDeliveryHints(reply: @escaping @Sendable (Data?) -> Void) { reply(nil) }
    func requestDeliveryVersion(reply: @escaping @Sendable (UInt64) -> Void) { reply(1) }
    func requestDiscoveryVersion(reply: @escaping @Sendable (UInt64) -> Void) { reply(1) }
    func pendingRequestIDs(_ binding: Data, reply: @escaping @Sendable (Data?) -> Void) {
        print("DISCOVERY_RECEIVED \(String(decoding: binding, as: UTF8.self))")
        fflush(stdout)
        reply(binding)
    }
    func pairingReceiptVersion(reply: @escaping @Sendable (UInt64) -> Void) { reply(1) }
    func pairingReceipt(_ binding: Data, setupID: Data, reply: @escaping @Sendable (Data?) -> Void) {
        print("RECEIPT_RECEIVED \(String(decoding: setupID, as: UTF8.self))")
        fflush(stdout)
        switch String(decoding: binding, as: UTF8.self) {
        case "receipt": reply(setupID)
        case "receipt-empty": reply(Data())
        default: reply(nil)
        }
    }
    func requestExchangeVersion(reply: @escaping @Sendable (UInt64) -> Void) { reply(1) }
    func exchangeRequest(_ binding: Data, query: Data, reply: @escaping @Sendable (Data?) -> Void) {
        print("EXCHANGE_RECEIVED \(String(decoding: query, as: UTF8.self))")
        fflush(stdout)
        switch String(decoding: binding, as: UTF8.self) {
        case "exchange": reply(query)
        case "exchange-empty": reply(Data())
        default: reply(nil)
        }
    }
    func trustSnapshot(reply: @escaping @Sendable (Data?) -> Void) { reply(nil) }
    func validatePeer(_ binding: Data, reply: @escaping @Sendable (Bool) -> Void) { reply(false) }
    func requestFrame(_ binding: Data, requestID: Data, reply: @escaping @Sendable (Data?) -> Void) {
        // Exercise the production selector and Data bridge using synthetic bytes only.
        print("FRAME_RECEIVED \(String(decoding: requestID, as: UTF8.self))")
        fflush(stdout)
        switch String(decoding: binding, as: UTF8.self) {
        case "frame": reply(requestID)
        case "empty": reply(Data())
        default: reply(nil)
        }
    }

    func ping(_ nonce: String, reply: @escaping (String) -> Void) {
        // These are synthetic test nonces, never request or credential data.
        print("PING_RECEIVED \(nonce)")
        fflush(stdout)
        reply(nonce)
    }
}

final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: ProbeProtocol.self)
        connection.exportedObject = ProbeService()
        connection.activate()
        return true
    }
}

// XPC callbacks can arrive on a different queue. The lock owns all result state.
final class Completion: @unchecked Sendable {
    private let lock = NSLock()
    private var result: String?
    let signal = DispatchSemaphore(value: 0)

    func finish(_ value: String) {
        lock.lock()
        guard result == nil else { lock.unlock(); return }
        result = value
        lock.unlock()
        signal.signal()
    }

    func value() -> String {
        lock.lock()
        defer { lock.unlock() }
        return result ?? "missing-result"
    }
}

@main enum Probe {
    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        guard args.count >= 3, args[1].hasPrefix("dev.remozio.experiments.") else {
            print("Usage: remozio-xpc-probe serve|ping|guarded-ping service-name peer-identifier [nonce]")
            exit(2)
        }
        let peer = args[2]
        guard peer.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "." || $0 == "-") }) else {
            exit(2)
        }
        let requirement = "identifier \"\(peer)\""
        switch args[0] {
        case "serve":
            guard args.count == 3 else { exit(2) }
            let delegate = ListenerDelegate()
            let listener = NSXPCListener(machServiceName: args[1])
            listener.setConnectionCodeSigningRequirement(requirement)
            listener.delegate = delegate
            listener.activate()
            withExtendedLifetime((listener, delegate)) { RunLoop.current.run() }
        case "ping", "guarded-ping", "frame", "empty", "nil", "discovery", "receipt", "receipt-empty", "receipt-nil", "exchange", "exchange-empty", "exchange-nil",
             "setup-progress", "setup-bytes", "setup-empty", "setup-nil",
             "runtime-progress", "runtime-bytes", "runtime-empty", "runtime-nil", "runtime-no-consent",
             "activation-progress", "activation-bytes", "activation-empty", "activation-nil":
            guard args.count == 4 else { exit(2) }
            let nonce = args[3]
            let completion = Completion()
            let connection = NSXPCConnection(machServiceName: args[1])
            connection.remoteObjectInterface = NSXPCInterface(with: ProbeProtocol.self)
            connection.setCodeSigningRequirement(requirement)
            connection.activate()
            defer { connection.invalidate() }
            if args[0] != "ping" {
                let handshake = Completion()
                guard let helloProxy = connection.remoteObjectProxyWithErrorHandler({ @Sendable error in
                    let error = error as NSError
                    handshake.finish("rejected:\(error.domain):\(error.code)")
                }) as? ProbeProtocol else { exit(2) }
                if args[0].hasPrefix("activation-") {
                    helloProxy.activationHello { @Sendable accepted in
                        handshake.finish(accepted == AdministrativeSetupInterface.activationVersion ? "accepted" : "wrong-reply")
                    }
                } else if args[0].hasPrefix("runtime-") {
                    helloProxy.runtimeHello { @Sendable accepted in
                        handshake.finish(accepted == AdministrativeSetupInterface.runtimeVersion ? "accepted" : "wrong-reply")
                    }
                } else if args[0].hasPrefix("setup-") {
                    helloProxy.serviceAccountsHello { @Sendable accepted in
                        handshake.finish(accepted == AdministrativeSetupInterface.serviceAccountsVersion ? "accepted" : "wrong-reply")
                    }
                } else {
                    helloProxy.hello { @Sendable accepted in
                        handshake.finish(accepted == 1 ? "accepted" : "wrong-reply")
                    }
                }
                guard handshake.signal.wait(timeout: .now() + 10) == .success else {
                    print("timeout")
                    exit(4)
                }
                guard handshake.value() == "accepted" else {
                    print(handshake.value())
                    exit(3)
                }
            }
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ @Sendable error in
                let error = error as NSError
                completion.finish("rejected:\(error.domain):\(error.code)")
            }) as? ProbeProtocol else { exit(2) }
            if args[0] == "ping" || args[0] == "guarded-ping" {
                proxy.ping(nonce) { @Sendable returned in
                    completion.finish(returned == nonce ? "accepted" : "wrong-reply")
                }
            } else if args[0] == "activation-progress" {
                proxy.activationProgress { @Sendable returned in
                    completion.finish(returned == Data() ? "accepted" : "wrong-reply")
                }
            } else if args[0].hasPrefix("activation-") {
                let mode = args[0], bytes = Data(nonce.utf8)
                let expected: Data? = mode == "activation-bytes" ? bytes : mode == "activation-empty" ? Data() : nil
                proxy.activateRuntime(bytes, authorization: Data(mode.utf8)) { @Sendable returned in
                    completion.finish(returned == expected ? "accepted" : "wrong-reply")
                }
            } else if args[0] == "runtime-progress" {
                proxy.runtimeProgress { @Sendable returned in
                    completion.finish(returned == Data() ? "accepted" : "wrong-reply")
                }
            } else if args[0].hasPrefix("runtime-") {
                let mode = args[0], bytes = Data(nonce.utf8)
                let expected: Data? = mode == "runtime-bytes" ? bytes : mode == "runtime-empty" ? Data() : nil
                proxy.prepareRuntime(bytes, fileCustodyAccepted: mode != "runtime-no-consent", authorization: Data(mode.utf8)) { @Sendable returned in
                    completion.finish(returned == expected ? "accepted" : "wrong-reply")
                }
            } else if args[0] == "setup-progress" {
                proxy.serviceAccountsProgress { @Sendable returned in
                    completion.finish(returned == Data() ? "accepted" : "wrong-reply")
                }
            } else if args[0].hasPrefix("setup-") {
                let mode = args[0], bytes = Data(nonce.utf8)
                let expected: Data? = mode == "setup-bytes" ? bytes : mode == "setup-empty" ? Data() : nil
                proxy.prepareServiceAccounts(bytes, authorization: Data(mode.utf8)) { @Sendable returned in
                    completion.finish(returned == expected ? "accepted" : "wrong-reply")
                }
            } else if args[0].hasPrefix("receipt") {
                let version = Completion()
                proxy.pairingReceiptVersion { @Sendable value in version.finish(value == 1 ? "accepted" : "wrong-version") }
                guard version.signal.wait(timeout: .now() + 10) == .success,
                      version.value() == "accepted" else { print("version-failed"); exit(4) }
                let mode = args[0], setupID = Data(nonce.utf8)
                let expected: Data? = mode == "receipt" ? setupID : mode == "receipt-empty" ? Data() : nil
                proxy.pairingReceipt(Data(mode.utf8), setupID: setupID) { @Sendable returned in
                    completion.finish(returned == expected ? "accepted" : "wrong-reply")
                }
            } else if args[0].hasPrefix("exchange") {
                let version = Completion()
                proxy.requestExchangeVersion { @Sendable value in version.finish(value == 1 ? "accepted" : "wrong-version") }
                guard version.signal.wait(timeout: .now() + 10) == .success,
                      version.value() == "accepted" else { print("version-failed"); exit(4) }
                let mode = args[0], query = Data(nonce.utf8)
                let expected: Data? = mode == "exchange" ? query : mode == "exchange-empty" ? Data() : nil
                proxy.exchangeRequest(Data(mode.utf8), query: query) { @Sendable returned in
                    completion.finish(returned == expected ? "accepted" : "wrong-reply")
                }
            } else if args[0] == "discovery" {
                let version = Completion()
                proxy.requestDiscoveryVersion { @Sendable value in version.finish(value == 1 ? "accepted" : "wrong-version") }
                guard version.signal.wait(timeout: .now() + 10) == .success,
                      version.value() == "accepted" else { print("version-failed"); exit(4) }
                let expected = Data(nonce.utf8)
                proxy.pendingRequestIDs(expected) { @Sendable returned in
                    completion.finish(returned == expected ? "accepted" : "wrong-reply")
                }
            } else {
                let version = Completion()
                proxy.requestDeliveryVersion { @Sendable value in
                    version.finish(value == 1 ? "accepted" : "wrong-version")
                }
                guard version.signal.wait(timeout: .now() + 10) == .success,
                      version.value() == "accepted" else { print("version-failed"); exit(4) }
                let mode = args[0], requestID = Data(nonce.utf8)
                let expected: Data? = mode == "frame" ? requestID : mode == "empty" ? Data() : nil
                proxy.requestFrame(Data(mode.utf8), requestID: requestID) { @Sendable returned in
                    completion.finish(returned == expected ? "accepted" : "wrong-reply")
                }
            }
            guard completion.signal.wait(timeout: .now() + 10) == .success else {
                print("timeout")
                exit(4)
            }
            let result = completion.value()
            print(result)
            exit(result == "accepted" ? 0 : (result.hasPrefix("rejected:") ? 3 : 5))
        default:
            exit(2)
        }
    }
}
