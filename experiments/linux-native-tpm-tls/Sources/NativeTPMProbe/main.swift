import CNativeTPMProbe
import Foundation
import Glibc

let arguments = CommandLine.arguments
let result: RemozioNativeProbeResult
if arguments.count == 3, arguments[1] == "sign", ["authority", "healthy"].contains(arguments[2]) {
    result = remozio_probe_sign(arguments[2] == "healthy" ? 1 : 0)
} else if arguments.count == 3, arguments[1] == "tls", let fd = Int32(arguments[2]), fd >= 3 {
    result = remozio_probe_tls(fd)
} else {
    result = RemozioNativeProbeResult(status: Int32(REMOZIO_PROBE_ARGUMENT), key_provider_tpm2: 0,
        signature_provider_tpm2: 0, client_verification_rejected: 0, alpn_rejected: 0,
        application_received: 0, application_sent: 0, signature_bytes: 0)
}
let names = ["ok", "environment", "provider", "key_load", "wrong_provider", "public_key",
    "sign", "io", "timeout", "client_verification", "alpn", "peer_closed", "payload", "tls", "argument", "certificate"]
let status = names.indices.contains(Int(result.status)) ? names[Int(result.status)] : "internal"
let metadata: [String: Any] = ["status": status, "keyProviderTPM2": result.key_provider_tpm2 == 1,
    "signatureProviderTPM2": result.signature_provider_tpm2 == 1,
    "clientVerificationRejected": result.client_verification_rejected == 1,
    "alpnRejected": result.alpn_rejected == 1, "applicationBytesReceived": result.application_received,
    "applicationBytesSent": result.application_sent, "signatureBytes": result.signature_bytes]
if let encoded = try? JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys]),
   let line = String(data: encoded, encoding: .utf8) { print(line) }
else { print("{\"status\":\"internal\"}") }
exit(Int(result.status) == REMOZIO_PROBE_OK ? 0 : 77)
