import dnssd
import Foundation

/// A single scoped Bonjour registration. Start, callbacks and withdrawal share the listener queue.
final class PairingLANAdvertisement: @unchecked Sendable {
    struct HostRecord: Sendable {
        let name = "remozio-pairing-" + UUID().uuidString.lowercased() + ".local."
        let recordType: UInt16
        let data: Data

        init(address: PairingLANRoute.Address) {
            switch address {
            case .ipv4(let ip):
                recordType = UInt16(kDNSServiceType_A)
                data = ip.rawValue
            case .ipv6(let ip):
                recordType = UInt16(kDNSServiceType_AAAA)
                data = ip.rawValue
            }
        }
    }

    typealias Register = @Sendable (String, UInt32, UInt16, HostRecord, DispatchQueue, @escaping @Sendable (Bool) -> Void)
        throws -> @Sendable () -> Void
    private enum State { case idle, starting, announced, withdrawn, closed }
    private let queue: DispatchQueue
    private let register: Register
    private var state = State.idle
    private var unregister: (@Sendable () -> Void)?
    private var monitor: DispatchSourceTimer?

    init(queue: DispatchQueue, register: @escaping Register = PairingLANAdvertisement.nativeRegister) {
        self.queue = queue
        self.register = register
    }

    func start(name: String, index: UInt32, port: UInt16, address: PairingLANRoute.Address,
               isCurrent: @escaping @Sendable () -> Bool, report: @escaping @Sendable (DirectListenerEvent) -> Void) {
        dispatchPrecondition(condition: .onQueue(queue))
        guard state == .idle else { return }
        guard index != 0, port != 0, isCurrent() else { close(); report(.failed); return }
        state = .starting
        do {
            let cancel = try register(name, index, port, HostRecord(address: address), queue) { [weak self] ready in
                guard let self, self.state == .starting || self.state == .announced else { return }
                if !ready || !isCurrent() {
                    self.close()
                    report(.failed)
                } else if self.state == .starting {
                    self.state = .announced
                    report(.ready(port: port))
                }
            }
            guard state == .starting || state == .announced else { cancel(); return }
            unregister = cancel
        } catch {
            close()
            report(.failed)
            return
        }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .milliseconds(500), repeating: .milliseconds(500))
        timer.setEventHandler { [weak self] in
            guard let self, self.state != .closed, !isCurrent() else { return }
            self.close()
            report(.failed)
        }
        monitor = timer
        timer.resume()
    }

    func withdraw() {
        dispatchPrecondition(condition: .onQueue(queue))
        guard state != .closed, state != .withdrawn else { return }
        state = .withdrawn
        unregister?(); unregister = nil
    }

    func close() {
        dispatchPrecondition(condition: .onQueue(queue))
        guard state != .closed else { return }
        withdraw()
        state = .closed
        monitor?.cancel(); monitor = nil
    }

    private final class Registration: @unchecked Sendable {
        private let name: String
        private let index: UInt32
        private let port: UInt16
        private let host: HostRecord
        private let queue: DispatchQueue
        private let report: @Sendable (Bool) -> Void
        private var recordConnection: DNSServiceRef?
        private var service: DNSServiceRef?

        init(name: String, index: UInt32, port: UInt16, host: HostRecord, queue: DispatchQueue,
             report: @escaping @Sendable (Bool) -> Void) {
            self.name = name; self.index = index; self.port = port; self.host = host
            self.queue = queue; self.report = report
        }

        func start() throws {
            guard DNSServiceCreateConnection(&recordConnection) == kDNSServiceErr_NoError, let recordConnection else {
                throw TransportPairingControlError.unavailableInterface
            }
            var record: DNSRecordRef?
            let status = host.data.withUnsafeBytes {
                DNSServiceRegisterRecord(recordConnection, &record, DNSServiceFlags(kDNSServiceFlagsUnique), index,
                    host.name, host.recordType, UInt16(kDNSServiceClass_IN), UInt16($0.count), $0.baseAddress, 0,
                    { _, _, _, error, context in
                        guard let context else { return }
                        let registration = Unmanaged<Registration>.fromOpaque(context).takeUnretainedValue()
                        if error == kDNSServiceErr_NoError { registration.publishService() }
                        else { registration.report(false) }
                    }, Unmanaged.passUnretained(self).toOpaque())
            }
            guard status == kDNSServiceErr_NoError, DNSServiceSetDispatchQueue(recordConnection, queue) == kDNSServiceErr_NoError else {
                throw TransportPairingControlError.unavailableInterface
            }
        }

        private func publishService() {
            guard recordConnection != nil, service == nil else { return }
            let status = DNSServiceRegister(&service, DNSServiceFlags(kDNSServiceFlagsNoAutoRename), index,
                name, "_remozio-pairing._tcp", "local.", host.name, port.bigEndian, 0, nil, { _, flags, error, _, _, _, context in
                    guard let context else { return }
                    let registration = Unmanaged<Registration>.fromOpaque(context).takeUnretainedValue()
                    registration.report(error == kDNSServiceErr_NoError && flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0)
                }, Unmanaged.passUnretained(self).toOpaque())
            guard status == kDNSServiceErr_NoError, let service, DNSServiceSetDispatchQueue(service, queue) == kDNSServiceErr_NoError else {
                report(false)
                return
            }
        }

        func close() {
            if let service { DNSServiceRefDeallocate(service); self.service = nil }
            if let recordConnection { DNSServiceRefDeallocate(recordConnection); self.recordConnection = nil }
        }
    }

    private static func nativeRegister(name: String, index: UInt32, port: UInt16, host: HostRecord, queue: DispatchQueue,
                                       report: @escaping @Sendable (Bool) -> Void) throws -> @Sendable () -> Void {
        let registration = Registration(name: name, index: index, port: port, host: host, queue: queue, report: report)
        do { try registration.start() }
        catch { registration.close(); throw error }
        return { registration.close() }
    }
}
