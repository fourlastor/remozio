import Foundation
import Network
import RemozioProtocol
import Security

enum PairingRecoveryTLS {
    static func isRecovery(_ metadata: sec_protocol_metadata_t) -> Bool {
        guard let name = sec_protocol_metadata_copy_negotiated_protocol(metadata) else { return false }
        defer { free(UnsafeMutableRawPointer(mutating: name)) }
        return String(cString: name) == PairingRecoveryFrame.applicationProtocol
    }

    static func metadata(_ connection: NWConnection) -> sec_protocol_metadata_t? {
        guard let tls = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
            return nil
        }
        let metadata = tls.securityProtocolMetadata
        guard isRecovery(metadata), sec_protocol_metadata_get_negotiated_tls_protocol_version(metadata) == .TLSv13,
              !sec_protocol_metadata_get_early_data_accepted(metadata),
              PairingSetupListener.candidatePoint(metadata: metadata) != nil else { return nil }
        return metadata
    }

    static func exporter(_ metadata: sec_protocol_metadata_t) throws -> Data {
        let label = PairingRecoveryFrame.exporterLabel
        guard let bytes = sec_protocol_metadata_create_secret(metadata, label.utf8.count, label, 32),
              dispatch_data_get_size(bytes) == 32 else { throw DirectListenerError.invalidIdentity }
        var exporter = Data()
        exporter.reserveCapacity(32)
        let copied = dispatch_data_apply(bytes) { _, _, buffer, size in
            exporter.append(buffer.assumingMemoryBound(to: UInt8.self), count: size)
            return true
        }
        guard copied, exporter.count == 32 else { throw DirectListenerError.invalidIdentity }
        return exporter
    }
}
