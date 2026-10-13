import CryptoKit
import Darwin
import Foundation
import os
import RemozioMach
import RemozioProtocol
import Security
import SQLite3
import Synchronization
import XCTest
@testable import RemozioCore

final class MachCommandCallerReceiverTests: XCTestCase {
    private final class Endpoint {
        var port: mach_port_t = 0
        private var ownsReceive = true
        init(borrowingSendRight: mach_port_t) throws {
            guard mach_port_mod_refs(mach_task_self_, borrowingSendRight, MACH_PORT_RIGHT_SEND, 1) == KERN_SUCCESS else { throw MachCommandCallerError.configuration }
            port = borrowingSendRight; ownsReceive = false
        }
        func transferReceiveRight() -> mach_port_t { precondition(ownsReceive); ownsReceive = false; return port }
        func closeReceiveRight() throws {
            guard ownsReceive else { return }
            let status = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1)
            guard status == KERN_SUCCESS else { throw MachCommandCallerError.mach(status) }
            ownsReceive = false
        }
        init() throws {
            guard mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &port) == KERN_SUCCESS,
                  mach_port_insert_right(mach_task_self_, port, port, UInt32(MACH_MSG_TYPE_MAKE_SEND)) == KERN_SUCCESS else {
                throw MachCommandCallerError.configuration
            }
        }
        deinit {
            if ownsReceive { _ = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1) }
            _ = mach_port_deallocate(mach_task_self_, port)
        }
        func send(_ payload: Data, version: UInt32 = 1, claimedLength: UInt32? = nil,
                  identifier: mach_msg_id_t = MachCommandCallerReceiver.messageID, badPadding: Bool = false) throws {
            let prefix = MemoryLayout<mach_msg_header_t>.size
            let size = (prefix + 8 + payload.count + 3) & ~3
            let storage = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: MemoryLayout<mach_msg_header_t>.alignment)
            defer { storage.deallocate() }
            storage.initializeMemory(as: UInt8.self, repeating: 0, count: size)
            let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
            header.pointee.msgh_bits = UInt32(MACH_MSG_TYPE_COPY_SEND)
            header.pointee.msgh_size = UInt32(size)
            header.pointee.msgh_remote_port = port
            header.pointee.msgh_id = identifier
            storage.storeBytes(of: version.bigEndian, toByteOffset: prefix, as: UInt32.self)
            storage.storeBytes(of: (claimedLength ?? UInt32(payload.count)).bigEndian, toByteOffset: prefix + 4, as: UInt32.self)
            payload.withUnsafeBytes { bytes in
                if let base = bytes.baseAddress { storage.advanced(by: prefix + 8).copyMemory(from: base, byteCount: bytes.count) }
            }
            if badPadding { storage.storeBytes(of: UInt8(1), toByteOffset: size - 1, as: UInt8.self) }
            let result = mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, UInt32(size), 0, 0, 1000, 0)
            guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        }
        func sendPort(_ carried: mach_port_t, outOfLineBytes: Int = 0) throws {
            let size = MemoryLayout<mach_msg_header_t>.size + MemoryLayout<mach_msg_body_t>.size + MemoryLayout<mach_msg_port_descriptor_t>.size +
                (outOfLineBytes > 0 ? MemoryLayout<mach_msg_ool_descriptor_t>.size : 0)
            let storage = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: MemoryLayout<mach_msg_header_t>.alignment)
            defer { storage.deallocate() }
            storage.initializeMemory(as: UInt8.self, repeating: 0, count: size)
            let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
            header.pointee.msgh_bits = UInt32(MACH_MSG_TYPE_COPY_SEND) | MACH_MSGH_BITS_COMPLEX
            header.pointee.msgh_size = UInt32(size)
            header.pointee.msgh_remote_port = port
            header.pointee.msgh_id = MachCommandCallerReceiver.messageID
            storage.storeBytes(of: mach_msg_body_t(msgh_descriptor_count: outOfLineBytes > 0 ? 2 : 1), toByteOffset: MemoryLayout<mach_msg_header_t>.size, as: mach_msg_body_t.self)
            var descriptor = mach_msg_port_descriptor_t()
            descriptor.name = carried
            descriptor.disposition = UInt32(MACH_MSG_TYPE_COPY_SEND)
            descriptor.type = UInt32(MACH_MSG_PORT_DESCRIPTOR)
            storage.storeBytes(of: descriptor, toByteOffset: MemoryLayout<mach_msg_header_t>.size + MemoryLayout<mach_msg_body_t>.size, as: mach_msg_port_descriptor_t.self)
            let bytes = UnsafeMutableRawPointer.allocate(byteCount: max(1, outOfLineBytes), alignment: 8)
            defer { bytes.deallocate() }
            bytes.initializeMemory(as: UInt8.self, repeating: 0x5a, count: max(1, outOfLineBytes))
            if outOfLineBytes > 0 {
                var outOfLine = mach_msg_ool_descriptor_t()
                outOfLine.address = bytes
                outOfLine.size = UInt32(outOfLineBytes)
                outOfLine.copy = UInt32(MACH_MSG_VIRTUAL_COPY)
                outOfLine.type = UInt32(MACH_MSG_OOL_DESCRIPTOR)
                storage.storeBytes(of: outOfLine, toByteOffset: MemoryLayout<mach_msg_header_t>.size +
                    MemoryLayout<mach_msg_body_t>.size + MemoryLayout<mach_msg_port_descriptor_t>.size,
                    as: mach_msg_ool_descriptor_t.self)
            }
            let result = mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, UInt32(size), 0, 0, 1000, 0)
            guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        }

        func sendInput(_ payload: Data, fileport: mach_port_t, version: UInt32 = 2, descriptorCount: Int = 1,
                       identifier: mach_msg_id_t = MachCommandCallerReceiver.inputMessageID, replyPort: mach_port_t? = nil, badPadding: Bool = false) throws {
            let headerBytes = MemoryLayout<mach_msg_header_t>.size
            let bodyBytes = MemoryLayout<mach_msg_body_t>.size
            let descriptorBytes = MemoryLayout<mach_msg_port_descriptor_t>.size
            let metadata = headerBytes + bodyBytes + descriptorCount * descriptorBytes
            let size = (metadata + 8 + payload.count + 3) & ~3
            let storage = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: 8)
            defer { storage.deallocate() }
            storage.initializeMemory(as: UInt8.self, repeating: 0, count: size)
            let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
            header.pointee.msgh_bits = UInt32(MACH_MSG_TYPE_COPY_SEND) | MACH_MSGH_BITS_COMPLEX
            header.pointee.msgh_size = UInt32(size)
            header.pointee.msgh_remote_port = port
            header.pointee.msgh_id = identifier
            storage.storeBytes(of: mach_msg_body_t(msgh_descriptor_count: UInt32(descriptorCount)),
                toByteOffset: headerBytes, as: mach_msg_body_t.self)
            for index in 0..<descriptorCount {
                var descriptor = mach_msg_port_descriptor_t()
                descriptor.name = index == 1 ? (replyPort ?? fileport) : fileport
                descriptor.disposition = UInt32(MACH_MSG_TYPE_COPY_SEND)
                descriptor.type = UInt32(MACH_MSG_PORT_DESCRIPTOR)
                storage.storeBytes(of: descriptor, toByteOffset: headerBytes + bodyBytes + index * descriptorBytes,
                    as: mach_msg_port_descriptor_t.self)
            }
            storage.storeBytes(of: version.bigEndian, toByteOffset: metadata, as: UInt32.self)
            storage.storeBytes(of: UInt32(payload.count).bigEndian, toByteOffset: metadata + 4, as: UInt32.self)
            payload.withUnsafeBytes { bytes in
                if let base = bytes.baseAddress { storage.advanced(by: metadata + 8).copyMemory(from: base, byteCount: bytes.count) }
            }
            if badPadding { storage.storeBytes(of: UInt8(1), toByteOffset: size - 1, as: UInt8.self) }
            let result = mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, UInt32(size), 0, 0, 1000, 0)
            guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        }

        func sendOutOfLineInput() throws {
            let headerBytes = MemoryLayout<mach_msg_header_t>.size, bodyBytes = MemoryLayout<mach_msg_body_t>.size
            let metadata = headerBytes + bodyBytes + MemoryLayout<mach_msg_ool_descriptor_t>.size
            let size = metadata + 12
            let storage = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: 8)
            let bytes = UnsafeMutableRawPointer.allocate(byteCount: 65536, alignment: 8)
            defer { storage.deallocate(); bytes.deallocate() }
            bytes.initializeMemory(as: UInt8.self, repeating: 0x5a, count: 65536)
            storage.initializeMemory(as: UInt8.self, repeating: 0, count: size)
            let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
            header.pointee.msgh_bits = UInt32(MACH_MSG_TYPE_COPY_SEND) | MACH_MSGH_BITS_COMPLEX
            header.pointee.msgh_size = UInt32(size)
            header.pointee.msgh_remote_port = port
            header.pointee.msgh_id = MachCommandCallerReceiver.inputMessageID
            storage.storeBytes(of: mach_msg_body_t(msgh_descriptor_count: 1), toByteOffset: headerBytes, as: mach_msg_body_t.self)
            var descriptor = mach_msg_ool_descriptor_t()
            descriptor.address = bytes
            descriptor.size = 65536
            descriptor.copy = UInt32(MACH_MSG_VIRTUAL_COPY)
            descriptor.type = UInt32(MACH_MSG_OOL_DESCRIPTOR)
            storage.storeBytes(of: descriptor, toByteOffset: headerBytes + bodyBytes, as: mach_msg_ool_descriptor_t.self)
            storage.storeBytes(of: UInt32(2).bigEndian, toByteOffset: metadata, as: UInt32.self)
            storage.storeBytes(of: UInt32(1).bigEndian, toByteOffset: metadata + 4, as: UInt32.self)
            let result = mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, UInt32(size), 0, 0, 1000, 0)
            guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        }

        func sendBareHeader() throws {
            var header = mach_msg_header_t()
            header.msgh_bits = UInt32(MACH_MSG_TYPE_COPY_SEND)
            header.msgh_size = UInt32(MemoryLayout<mach_msg_header_t>.size)
            header.msgh_remote_port = port
            header.msgh_id = MachCommandCallerReceiver.messageID
            let result = mach_msg(&header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, header.msgh_size, 0, 0, 1000, 0)
            guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        }
    }

    private func admissionInput(_ endpoint: Endpoint, reply: Endpoint, descriptor: Int32, payload: Data) throws -> ReceivedMachCommandInputSubmission {
        try MachCommandAdmissionWire.send(payload, inputDescriptor: descriptor, destination: endpoint.port,
            replyPort: reply.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        return try receiver(endpoint, maximum: 8192).receiveAdmissionInput(timeoutMilliseconds: 1000)
    }
    private func admissionClientFixture(_ destination: mach_port_t, input: UInt64 = 3, wire: UInt64 = 1, mac: Data? = nil, account: Data? = nil) throws -> sending VerifiedCommandHandshake {
        let endpoint = try Endpoint()
        try endpoint.send(Data([1]))
        let sender = try receiver(endpoint).receive(timeoutMilliseconds: 1000)
        return VerifiedCommandHandshake(profile: .init(wireVersion: wire, submissionSchemaVersion: 1, inputCarrierVersion: input,
            callerBinding: assemblyBinding, macID: mac ?? handshakeMac, accountID: account ?? handshakeAccount), authority: sender.caller,
            destination: try MachCommandAuthorityPort(copying: destination))
    }

    func testAdmissionReplyCarrierPreservesOriginalInputAndRepliesOnce() throws {
        let endpoint = try Endpoint(), reply = try Endpoint()
        var pipeFDs: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&pipeFDs), 0)
        defer { for fd in pipeFDs { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(pipeFDs[1], "queued", 6), 6)
        let flags = fcntl(pipeFDs[0], F_GETFL), baseline = try sendReferences(reply.port)
        let input = try admissionInput(endpoint, reply: reply, descriptor: pipeFDs[0], payload: Data([0xa0]))
        defer { input.closeIfUnclaimed() }
        XCTAssertEqual(input.carrierVersion, 3); XCTAssertEqual(input.payload, Data([0xa0]))
        XCTAssertEqual(try sendReferences(reply.port), baseline + 1)
        try input.sendAdmissionReply(Data([0xa0]))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        XCTAssertThrowsError(try input.sendAdmissionReply(Data([0xa0])))
        let response = try receiver(reply).receiveAdmissionReply(timeoutMilliseconds: 1000)
        defer { response.caller.close() }
        XCTAssertEqual(response.payload, Data([0xa0])); XCTAssertEqual(response.caller.requester.pid, UInt32(getpid()))
        XCTAssertEqual(fcntl(pipeFDs[0], F_GETFL), flags)
        var bytes = [UInt8](repeating: 0, count: 6)
        XCTAssertEqual(Darwin.read(pipeFDs[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("queued".utf8))
    }

    func testAdmissionReplyCarrierKeepsLegacyMeaningAndMixedReceiveQueue() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        let baseline = try sendReferences(reply.port)
        try MachCommandAdmissionWire.send(Data([1]), inputDescriptor: fd, destination: endpoint.port,
            replyPort: reply.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        XCTAssertThrowsError(try receiver(endpoint).receiveInput(timeoutMilliseconds: 1000))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        var fileport: mach_port_t = 0
        XCTAssertEqual(fileport_makeport(fd, &fileport), 0); defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        try endpoint.sendInput(Data([2]), fileport: fileport)
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 1000))
        try endpoint.sendInput(Data([3]), fileport: fileport)
        try MachCommandAdmissionWire.send(Data([4]), inputDescriptor: fd, destination: endpoint.port,
            replyPort: reply.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        for (payload, version) in [(UInt8(3), UInt32(2)), (4, 3)] {
            guard case .input(let input) = try receiver(endpoint).receiveNext(timeoutMilliseconds: 1000) else { return XCTFail("Input missing") }
            XCTAssertEqual(input.payload, Data([payload])); XCTAssertEqual(input.carrierVersion, version)
            input.closeIfUnclaimed()
        }
        XCTAssertEqual(try sendReferences(reply.port), baseline)
    }

    func testAdmissionReplyCarrierRejectsWrongSenderAndMalformedRightsWithoutLeaks() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        var fileport: mach_port_t = 0
        XCTAssertEqual(fileport_makeport(fd, &fileport), 0); defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        let baseline = try sendReferences(reply.port), inputBaseline = try sendReferences(fileport)
        try endpoint.sendInput(Data([1]), fileport: fileport, version: 3, descriptorCount: 2,
            identifier: MachCommandCallerReceiver.admissionInputMessageID, replyPort: reply.port)
        XCTAssertThrowsError(try receiver(endpoint, user: geteuid() ^ 1).receiveAdmissionInput(timeoutMilliseconds: 1000))
        for (count, version, padding) in [(0, UInt32(3), false), (1, 3, false), (3, 3, false), (2, 2, false), (2, 3, true)] {
            try endpoint.sendInput(Data([1]), fileport: fileport, version: version, descriptorCount: count,
                identifier: MachCommandCallerReceiver.admissionInputMessageID, replyPort: reply.port, badPadding: padding)
            XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 1000))
            XCTAssertEqual(try sendReferences(reply.port), baseline); XCTAssertEqual(try sendReferences(fileport), inputBaseline)
        }
        try endpoint.sendInput(Data([1]), fileport: reply.port, version: 3, descriptorCount: 2,
            identifier: MachCommandCallerReceiver.admissionInputMessageID, replyPort: reply.port)
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? RetainedCommandInputError, .system(EINVAL))
        }
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        let next = try admissionInput(endpoint, reply: reply, descriptor: fd, payload: Data([2]))
        next.closeIfUnclaimed(); XCTAssertEqual(try sendReferences(reply.port), baseline)
    }

    func testAdmissionReplyControlCarrierRejectsWrongVersionOversizeAndWrongKind() throws {
        let endpoint = try Endpoint()
        let control = try receiver(endpoint, maximum: 8192)
        for (version, identifier, bytes) in [(UInt32(2), MachCommandCallerReceiver.admissionReplyMessageID, Data([1])),
            (1, MachCommandCallerReceiver.helloReplyMessageID, Data([1])),
            (1, MachCommandCallerReceiver.admissionReplyMessageID, Data(repeating: 1, count: 4097))] {
            try endpoint.send(bytes, version: version, identifier: identifier)
            XCTAssertThrowsError(try control.receiveAdmissionReply(timeoutMilliseconds: 1000))
        }
        try endpoint.send(Data([2]), identifier: MachCommandCallerReceiver.admissionReplyMessageID, badPadding: true)
        XCTAssertThrowsError(try control.receiveAdmissionReply(timeoutMilliseconds: 1000))
        try endpoint.send(Data([3]), identifier: MachCommandCallerReceiver.admissionReplyMessageID)
        let reply = try control.receiveAdmissionReply(timeoutMilliseconds: 1000)
        reply.caller.close(); XCTAssertEqual(reply.payload, Data([3]))
    }

    func testCaptureRetainsAdmissionReplyAcrossOwnershipAndClosesItOnRetirement() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        let baseline = try sendReferences(reply.port), payload = try commandSubmission().canonicalBytes
        let received = try admissionInput(endpoint, reply: reply, descriptor: fd, payload: payload)
        let command = try assemble(received)
        defer { command.close() }
        XCTAssertThrowsError(try received.sendAdmissionReply(Data([0xa0])))
        XCTAssertThrowsError(try assemble(received)) { XCTAssertEqual($0 as? RetainedCommandCaptureError, .alreadyOwned) }
        received.closeIfUnclaimed()
        XCTAssertEqual(try sendReferences(reply.port), baseline + 1)
        try command.sendAdmissionReply(Data([0xa0]))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        let response = try receiver(reply).receiveAdmissionReply(timeoutMilliseconds: 1000)
        response.caller.close(); XCTAssertEqual(response.payload, Data([0xa0]))
        let secondReply = try Endpoint(), second = try admissionInput(endpoint, reply: secondReply, descriptor: fd, payload: payload)
        let owned = try assemble(second)
        XCTAssertEqual(try sendReferences(secondReply.port), 2)
        owned.close(); XCTAssertEqual(try sendReferences(secondReply.port), 1)
        XCTAssertThrowsError(try owned.sendAdmissionReply(Data([0xa0])))
        let failed = try admissionInput(endpoint, reply: reply, descriptor: fd, payload: Data([0]))
        XCTAssertThrowsError(try assemble(failed))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        try expectAssemblyResourcesRetired(failed)
    }

    func testNegotiatedAdmissionCarrierCannotUseLegacyInputAndPreservesReplyOnCapture() throws {
        let endpoint = try Endpoint(), helloReply = try Endpoint(), reply = try Endpoint()
        let session = try RetainedCommandHandshake(hello: hello(endpoint, reply: helloReply, capabilities: .admissionReplies),
            capabilities: .admissionReplies, macID: handshakeMac, accountID: handshakeAccount,
            expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        defer { session.close() }
        XCTAssertEqual(session.profile.inputCarrierVersion, 3)
        let payload = try commandSubmission(binding: .init(id: Data(repeating: 2, count: 16), nonce: Data(repeating: 3, count: 32),
            callerBinding: session.profile.callerBinding)).canonicalBytes
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        let legacy = try inputSubmission(fd, payload: payload)
        XCTAssertThrowsError(try session.assemble(received: TestInputInspection(received: legacy).received,
            expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            captureSchemaVersion: 2, resolvedTarget: assemblyTarget, minimalEnvironment: assemblyEnvironment,
            streamBinding: Data(repeating: 4, count: 16), submissionLimits: assemblyLimits, captureLimits: assemblyLimits)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible)
        }
        try expectAssemblyResourcesRetired(legacy)
        let incoming = try admissionInput(endpoint, reply: reply, descriptor: fd, payload: payload)
        let command = try session.assemble(received: TestInputInspection(received: incoming).received,
            expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            captureSchemaVersion: 2, resolvedTarget: assemblyTarget, minimalEnvironment: assemblyEnvironment,
            streamBinding: Data(repeating: 4, count: 16), submissionLimits: assemblyLimits, captureLimits: assemblyLimits)
        defer { command.close() }
        try command.sendAdmissionReply(Data([0xa0]))
        let response = try receiver(reply).receiveAdmissionReply(timeoutMilliseconds: 1000)
        response.caller.close(); XCTAssertEqual(response.payload, Data([0xa0]))
    }

    func testTypedAdmissionClientRequiresNewWireBeforeExposingInput() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port)
        defer { handshake.close() }
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: -1,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            maximumPayloadBytes: 8192, typedResult: true)) {
            XCTAssertEqual($0 as? CommandAdmissionResultError, .incompatible)
        }
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testTypedAdmissionClientAuthenticatesKnownResultsAndRejectsChangedCommand() throws {
        for altered in [false, true] {
            let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, wire: 2)
            defer { handshake.close() }
            let submission = try commandSubmission(), replySubmission = altered ? try commandSubmission(executablePath: "/usr/bin/false") : submission
            let payload = CommandAdmissionResultPayload(profile: handshake.profile, submission: submission.binding,
                submissionDigest: Data(SHA256.hash(data: replySubmission.canonicalBytes)), outcome: .notAdmitted(.updateWaiting, .updateWaiting))
            let server = try serveAdmission(endpoint.port, response: payload.canonicalBytes)
            let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
            func submit() throws -> AuthenticatedCommandReply {
                try MachCommandAdmissionClient.submit(submission, inputDescriptor: fd, handshake: handshake,
                    expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192, typedResult: true)
            }
            if altered { XCTAssertThrowsError(try submit()) { XCTAssertEqual($0 as? CommandAdmissionResultError, .wrongBinding) } }
            else {
                let result = try XCTUnwrap(submit().verifiedResult)
                XCTAssertEqual(result.outcome, .notAdmitted(.updateWaiting, .updateWaiting)); XCTAssertEqual(result.retryClass, .updateWaiting)
            }
            XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
        }
    }

    func testTypedAdmissionClientValidatesBeforeTheFinalDeadlineAndRejectsMalformedResults() throws {
        for expired in [false, true] {
            let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, wire: 2)
            defer { handshake.close() }
            let submission = try commandSubmission()
            let payload = CommandAdmissionResultPayload(profile: handshake.profile, submission: submission.binding,
                submissionDigest: Data(SHA256.hash(data: submission.canonicalBytes)), outcome: .uncertain(.admissionRejected))
            let server = try serveAdmission(endpoint.port, response: expired ? payload.canonicalBytes : Data([0xa0]))
            let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
            var samples = 0
            XCTAssertThrowsError(try MachCommandAdmissionClient.submit(submission, inputDescriptor: fd, handshake: handshake,
                expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192,
                timeoutMilliseconds: 1000, clock: { samples += 1; return expired && samples >= 5 ? 1000 : 0 }, typedResult: true)) {
                if expired { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
                else { XCTAssertEqual($0 as? CommandAdmissionResultError, .malformed) }
            }
            XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
        }
    }

    private func typedRequestCommand(reply: Endpoint, binding: CapturedSubmission? = nil, macID: Data? = nil) throws -> (RetainedCommandCapture, CommandSubmission, CommandHandshakeProfile) {
        let endpoint = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw MachCommandCallerError.unavailable }
        defer { _ = Darwin.close(fd) }
        let submission = try commandSubmission(binding: binding)
        let profile = CommandHandshakeProfile(wireVersion: 2, submissionSchemaVersion: 1, inputCarrierVersion: 3,
            callerBinding: submission.binding.callerBinding, macID: macID ?? Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16))
        let received = try admissionInput(endpoint, reply: reply, descriptor: fd, payload: submission.canonicalBytes)
        return (try assemble(received, admissionProfile: profile), submission, profile)
    }

    func testTypedAdmissionAcknowledgmentMatchesCommittedRequestAndLostDeliveryPreservesIt() throws {
        for checkpointed in [false, true] {
            for lost in [false, true] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
                let (command, submission, profile) = try typedRequestCommand(reply: reply)
                if lost {
                    let owned = reply.transferReceiveRight()
                    XCTAssertEqual(mach_port_mod_refs(mach_task_self_, owned, MACH_PORT_RIGHT_RECEIVE, -1), KERN_SUCCESS)
                }
                let request = try admitOwnedCommand(command, fixture: fixture)
                XCTAssertNotNil(try fixture.reservation(submission.binding.id))
                XCTAssertEqual(try XCTUnwrap(fixture.authority).withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
                try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
                if !lost {
                    let raw = try receiver(reply, maximum: 4096).receiveAdmissionReply(timeoutMilliseconds: 1000)
                    defer { raw.caller.close() }
                    let result = try CommandAdmissionResultPayload.decode(raw.payload, profile: profile, original: submission)
                    XCTAssertEqual(result.outcome, .admitted(.init(requestID: request.requestID,
                        requestDigest: try request.requestDigest(bodyLimits: fixture.limits, signingLimits: fixture.limits), challenge: request.challenge)))
                    XCTAssertEqual(result.retryClass, .never)
                }
            }
        }
    }

    func testTypedDuplicateReplyIsUncertainAndPreservesTheOriginalRequest() throws {
        let fixture = try CommandRequestFixture(checkpointed: true), firstReply = try Endpoint()
        let (first, submission, _) = try typedRequestCommand(reply: firstReply)
        let request = try admitCommand(first, fixture: fixture), secondReply = try Endpoint()
        let (second, replay, profile) = try typedRequestCommand(reply: secondReply, binding: submission.binding)
        XCTAssertThrowsError(try admitCommand(second, fixture: fixture)) { XCTAssertEqual($0 as? CommandSubmissionReplayError, .alreadyReserved) }
        let raw = try receiver(secondReply, maximum: 4096).receiveAdmissionReply(timeoutMilliseconds: 1000)
        defer { raw.caller.close() }
        let result = try CommandAdmissionResultPayload.decode(raw.payload, profile: profile, original: replay)
        XCTAssertEqual(result.outcome, .uncertain(.duplicateSubmission)); XCTAssertEqual(result.retryClass, .never)
        XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .queued)
        try first.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        XCTAssertThrowsError(try second.withBorrowedInputDescriptor { _ in () })
    }

    func testTypedForeignScopeFailsBeforeRequestCreation() throws {
        let fixture = try CommandRequestFixture(), reply = try Endpoint()
        let (command, submission, _) = try typedRequestCommand(reply: reply, macID: Data(repeating: 99, count: 16))
        let before = try fixture.auditRecordCount
        XCTAssertThrowsError(try admitCommand(command, fixture: fixture)) { XCTAssertEqual($0 as? ApprovalCoordinatorError, .invalidDraft) }
        XCTAssertEqual(try fixture.auditRecordCount, before); XCTAssertNil(try fixture.reservation(submission.binding.id))
        XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
        XCTAssertThrowsError(try receiver(reply, maximum: 4096).receiveAdmissionReply(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testMixedWireCapabilitiesSelectTheHighestUnderstoodPair() throws {
        let server = try CommandHandshakeCapabilities(wireVersions: [1, 2], submissionSchemaVersions: [1], inputCarrierVersions: [2, 3])
        for offered in [try CommandHandshakeCapabilities(wireVersions: [1, 2], submissionSchemaVersions: [1], inputCarrierVersions: [2]), server] {
            let endpoint = try Endpoint(), reply = try Endpoint()
            let session = try RetainedCommandHandshake(hello: hello(endpoint, reply: reply, capabilities: offered), capabilities: server,
                macID: handshakeMac, accountID: handshakeAccount, expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
            defer { session.close() }
            let response = try receiver(reply, maximum: 4096).receiveHelloReply(timeoutMilliseconds: 1000)
            defer { response.caller.close() }
            XCTAssertEqual(session.profile.wireVersion, offered.inputCarrierVersions.contains(3) ? 2 : 1)
            XCTAssertEqual(session.profile.inputCarrierVersion, offered.inputCarrierVersions.contains(3) ? 3 : 2)
            XCTAssertEqual(try CommandHandshakeReply.decode(response.payload,
                offer: CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: offered), macID: handshakeMac, accountID: handshakeAccount), session.profile)
        }
        let endpoint = try Endpoint(), reply = try Endpoint()
        let impossible = try CommandHandshakeCapabilities(wireVersions: [2], submissionSchemaVersions: [1], inputCarrierVersions: [2])
        XCTAssertThrowsError(try RetainedCommandHandshake(hello: hello(endpoint, reply: reply, capabilities: impossible), capabilities: server,
            macID: handshakeMac, accountID: handshakeAccount, expression: selfExpression(), userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible)
        }
        let response = try receiver(reply, maximum: 4096).receiveHelloReply(timeoutMilliseconds: 1000)
        defer { response.caller.close() }
        XCTAssertThrowsError(try CommandHandshakeReply.decode(response.payload,
            offer: CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: impossible), macID: handshakeMac, accountID: handshakeAccount)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible)
        }
    }

    private func typedOutcome(_ reply: Endpoint, submission: CommandSubmission, profile: CommandHandshakeProfile) throws -> CommandAdmissionOutcome {
        let raw = try receiver(reply, maximum: 4096).receiveAdmissionReply(timeoutMilliseconds: 1000)
        defer { raw.caller.close() }
        return try CommandAdmissionResultPayload.decode(raw.payload, profile: profile, original: submission).outcome
    }

    private func admissionAttempt(reply: Endpoint, executable: String = "/usr/bin/true", binding: CapturedSubmission? = nil,
                                  descriptor: Int32? = nil) throws -> (RetainedCommandAdmissionAttempt, CommandSubmission, CommandHandshakeProfile) {
        let endpoint = try Endpoint(), helloReply = try Endpoint()
        let session = try RetainedCommandHandshake(hello: hello(endpoint, reply: helloReply, capabilities: .admissionResults),
            capabilities: .admissionResults, macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        defer { session.close() }
        let fresh = binding ?? CapturedSubmission(id: Data(repeating: 0xb2, count: 16), nonce: Data(repeating: 0xb3, count: 32),
            callerBinding: session.profile.callerBinding)
        let submission = try commandSubmission(executablePath: executable, binding: .init(id: fresh.id, nonce: fresh.nonce,
            callerBinding: session.profile.callerBinding))
        let fd = descriptor ?? Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw MachCommandCallerError.unavailable }
        defer { if descriptor == nil { _ = Darwin.close(fd) } }
        let received = try admissionInput(endpoint, reply: reply, descriptor: fd, payload: submission.canonicalBytes)
        return (try session.prepareAdmission(received: TestInputInspection(received: received).received, expression: selfExpression(), userID: geteuid(),
            auditSessionID: nil, submissionLimits: assemblyLimits), submission, session.profile)
    }
    private func admissionContext() throws -> CommandAdmissionCaptureContext {
        .init(schemaVersion: 1, target: assemblyTarget, minimalEnvironment: assemblyEnvironment,
            streamBinding: Data(repeating: 0xe4, count: 16), limits: try assemblyLimits, maximumAncestryEntries: 1)
    }
    private func admissionDraft(_ capture: CommandCapture, fixture: CommandRequestFixture) -> ApprovalRequestDraft {
        .init(contract: fixture.contract, requiredFeatures: [], capture: capture.canonicalBytes,
            actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
            firstObservedAt: fixture.now(100), deadlineMilliseconds: 200, createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1100)
    }
    private func admitAttempt(_ attempt: RetainedCommandAdmissionAttempt, fixture: CommandRequestFixture,
                              resolution: CommandAdmissionResolution? = nil,
                              checkCancellation: @escaping @Sendable () throws -> Void = {}) throws -> IssuedRequestPayload {
        let resolved = try resolution ?? .capture(admissionContext())
        return try XCTUnwrap(fixture.authority).admitCommandAttempt(attempt, expression: selfExpression(), resolve: { _ in resolved },
            draft: { self.admissionDraft($0, fixture: fixture) }, now: { fixture.now() }, receiptTimeMs: nil,
            checkCancellation: checkCancellation)
    }

    func testAdmissionAttemptAuthenticatesBeforeCaptureAndPreservesUnreadInputOnAdmission() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
            var fds: [Int32] = [-1, -1]
            XCTAssertEqual(pipe(&fds), 0); defer { for fd in fds { _ = Darwin.close(fd) } }
            XCTAssertEqual(Darwin.write(fds[1], "unread", 6), 6)
            let (attempt, submission, profile) = try admissionAttempt(reply: reply, descriptor: fds[0])
            let request = try admitAttempt(attempt, fixture: fixture)
            guard case .admitted(let identity) = try typedOutcome(reply, submission: submission, profile: profile) else {
                return XCTFail("Attempt was not admitted")
            }
            XCTAssertEqual(identity.requestID, request.requestID)
            XCTAssertNotNil(try fixture.reservation(submission.binding.id)); XCTAssertEqual(try sendReferences(reply.port), 1)
            var bytes = [UInt8](repeating: 0, count: 6)
            XCTAssertEqual(Darwin.read(fds[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("unread".utf8))
            XCTAssertThrowsError(try admitAttempt(attempt, fixture: fixture)) {
                XCTAssertEqual($0 as? CommandAdmissionAttemptError, .closed)
            }
            XCTAssertEqual(try XCTUnwrap(fixture.authority).withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
        }
    }

    func testAdmissionAttemptReportsAllTrustedBusyAndPermanentRefusalsOnlyAfterFreshAbsenceRead() throws {
        for checkpointed in [false, true] {
            for reason in [CommandAdmissionRejectionReason.updateInstalling, .authorityStarting, .updateWaiting, .storageUnavailable,
                           .policyRejected, .invalidRequest, .unsupported, .capacityExceeded] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
                let (attempt, submission, profile) = try admissionAttempt(reply: reply, executable: "/missing-before-capture")
                let before = try fixture.auditRecordCount
                XCTAssertThrowsError(try admitAttempt(attempt, fixture: fixture, resolution: .refuse(reason))) {
                    XCTAssertEqual($0 as? CommandAdmissionControllerError, .refused(reason))
                }
                let retry = CommandAdmissionRetryClass(rawValue: reason.rawValue) ?? .never
                XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .notAdmitted(reason, retry))
                XCTAssertNil(try fixture.reservation(submission.binding.id)); XCTAssertEqual(try fixture.auditRecordCount, before)
                XCTAssertEqual(try sendReferences(reply.port), 1)
            }
        }
    }

    func testAdmissionAttemptUsesActualUnpreparedJournalStateWithoutCallingResolverOrDraft() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true, ready: false), reply = try Endpoint()
            let (attempt, submission, profile) = try admissionAttempt(reply: reply)
            XCTAssertThrowsError(try XCTUnwrap(fixture.authority).admitCommandAttempt(attempt, expression: selfExpression(),
                resolve: { _ in XCTFail("Startup must refuse before policy resolution"); return .refuse(.policyRejected) },
                draft: { _ in XCTFail("Startup must refuse before capture"); throw ApprovalCoordinatorError.invalidDraft },
                now: { fixture.now() }, receiptTimeMs: nil))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .notAdmitted(.authorityStarting, .authorityStarting))
            XCTAssertNil(try fixture.reservation(submission.binding.id))
        }
    }

    func testAdmissionAttemptCaptureFailureKeepsPrivateReplyAfterInputCleanup() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
            let (attempt, submission, profile) = try admissionAttempt(reply: reply, executable: "/missing-before-capture")
            XCTAssertThrowsError(try admitAttempt(attempt, fixture: fixture)) { XCTAssertTrue($0 is CommandFilesystemCaptureError) }
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .notAdmitted(.invalidRequest, .never))
            XCTAssertNil(try fixture.reservation(submission.binding.id)); XCTAssertEqual(try sendReferences(reply.port), 1)
        }
    }

    func testAdmissionCaptureClassifierNeverTreatsHostResourceOrUnknownFailuresAsInvalidCommands() {
        for code in [EMFILE, ENFILE, EIO, ENOMEM, ENOSPC, EAGAIN, EINTR, EACCES, EPERM, ESTALE, Int32.max] {
            XCTAssertNil(AuthorityJournal.commandCaptureRefusal(CommandFilesystemCaptureError.system(code)))
        }
        for error in [CommandFilesystemCaptureError.changed, .closed] {
            XCTAssertNil(AuthorityJournal.commandCaptureRefusal(error))
        }
        for code in [ENOENT, ENOTDIR, ELOOP, ENAMETOOLONG] {
            XCTAssertEqual(AuthorityJournal.commandCaptureRefusal(CommandFilesystemCaptureError.system(code)), .invalidRequest)
        }
        XCTAssertNil(AuthorityJournal.commandCaptureRefusal(ApprovalCoordinatorError.capacityExceeded))
    }

    func testAdmissionAttemptChangedExecutableDuringCaptureRemainsUncertainAndKeepsItsReply() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
            let executable = fixture.root.appendingPathComponent("capture-tool")
            try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: executable)
            let writer = Darwin.open(executable.path, O_WRONLY | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(writer, 0); defer { _ = Darwin.close(writer) }
            let (attempt, submission, profile) = try admissionAttempt(reply: reply, executable: executable.path)
            let checks = OSAllocatedUnfairLock(initialState: 0)
            XCTAssertThrowsError(try admitAttempt(attempt, fixture: fixture, checkCancellation: {
                let count = checks.withLock { $0 += 1; return $0 }
                if count == 4 {
                    var byte: UInt8 = 0
                    XCTAssertEqual(pwrite(writer, &byte, 1, 0), 1)
                }
            })) { XCTAssertEqual($0 as? CommandFilesystemCaptureError, .changed) }
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.admissionRejected))
            XCTAssertNil(try fixture.reservation(submission.binding.id)); XCTAssertEqual(try sendReferences(reply.port), 1)
        }
    }

    func testAdmissionAttemptCallbackErrorsCannotSpoofCaptureRefusalAndCannotReenterJournal() throws {
        for stage in 0..<3 {
            let fixture = try CommandRequestFixture(checkpointed: true, owned: true), reply = try Endpoint()
            let (attempt, submission, profile) = try admissionAttempt(reply: reply)
            let authority = try XCTUnwrap(fixture.authority), context = try admissionContext()
            let count = OSAllocatedUnfairLock(initialState: 0)
            XCTAssertThrowsError(try authority.admitCommandAttempt(attempt, expression: selfExpression(), resolve: { _ in
                XCTAssertThrowsError(try authority.read { _ in 0 }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive) }
                if stage == 0 { throw CommandFilesystemCaptureError.invalidPath }
                return .capture(context)
            }, draft: {
                if stage == 1 { throw IssuedRequestError.unsupportedContract }
                return self.admissionDraft($0, fixture: fixture)
            }, now: { fixture.now() }, receiptTimeMs: nil, checkCancellation: {
                let checks = count.withLock { $0 += 1; return $0 }
                if stage == 2 && checks >= 2 { throw CommandFilesystemCaptureError.invalidPath }
            }))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.admissionRejected))
            XCTAssertNil(try fixture.reservation(submission.binding.id)); XCTAssertEqual(try sendReferences(reply.port), 1)
        }
    }

    func testAdmissionAttemptBusyRefusalCannotContradictHistoricalIdentifierOrNonce() throws {
        for checkpointed in [false, true] {
            for nonce in [false, true] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
                let (first, original, _) = try admissionAttempt(reply: reply), request = try admitAttempt(first, fixture: fixture)
                let retiredAt = fixture.now(120)
                _ = try XCTUnwrap(fixture.authority).withRequests { try $0.retirePending(requestID: request.requestID,
                    reason: .cancelled, now: retiredAt, receiptTimeMs: nil) }
                let binding = CapturedSubmission(id: nonce ? Data(repeating: 88, count: 16) : original.binding.id,
                    nonce: nonce ? original.binding.nonce : Data(repeating: 89, count: 32), callerBinding: original.binding.callerBinding)
                let secondReply = try Endpoint(), (second, submission, profile) = try admissionAttempt(reply: secondReply, binding: binding)
                XCTAssertThrowsError(try admitAttempt(second, fixture: fixture, resolution: .refuse(.updateWaiting)))
                XCTAssertEqual(try typedOutcome(secondReply, submission: submission, profile: profile), .uncertain(.duplicateSubmission))
            }
        }
    }

    func testAdmissionAttemptProtectedReadFailureCannotGrantAutomaticRetry() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
            let (attempt, submission, profile) = try admissionAttempt(reply: reply)
            if checkpointed { try fixture.sql("UPDATE audit_epochs_v1 SET head=X'0000000000000002'") }
            else { try XCTUnwrap(fixture.authority).close() }
            XCTAssertThrowsError(try admitAttempt(attempt, fixture: fixture, resolution: .refuse(.updateWaiting)))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.storageFailure))
            XCTAssertEqual(try sendReferences(reply.port), 1)
        }
    }

    func testAdmissionAttemptRefusalRevalidatesCheckpointAfterTrustedResolution() throws {
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), reply = try Endpoint()
        let (attempt, submission, profile) = try admissionAttempt(reply: reply)
        XCTAssertThrowsError(try XCTUnwrap(fixture.authority).admitCommandAttempt(attempt, expression: selfExpression(), resolve: { _ in
            try fixture.sql("UPDATE audit_epochs_v1 SET head=X'0000000000000002'")
            return .refuse(.updateWaiting)
        }, draft: { _ in throw ApprovalCoordinatorError.invalidDraft }, now: { fixture.now() }, receiptTimeMs: nil))
        XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.storageFailure))
        XCTAssertEqual(try sendReferences(reply.port), 1)
    }

    func testAdmissionAttemptLostAcknowledgmentPreservesCommittedRequest() throws {
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), reply = try Endpoint()
        let (attempt, submission, _) = try admissionAttempt(reply: reply)
        let port = reply.transferReceiveRight()
        XCTAssertEqual(mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1), KERN_SUCCESS)
        let request = try admitAttempt(attempt, fixture: fixture)
        XCTAssertNotNil(try fixture.reservation(submission.binding.id))
        XCTAssertEqual(try XCTUnwrap(fixture.authority).withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
    }

    func testAdmissionAttemptPublicJournalRequiresRootIdentityBeforePolicyCallbacks() throws {
        guard geteuid() != 0 else { throw XCTSkip("Normal-user fixture") }
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), reply = try Endpoint()
        let (attempt, submission, profile) = try admissionAttempt(reply: reply)
        XCTAssertThrowsError(try XCTUnwrap(fixture.authority).admitCommandAttempt(TestAttemptInspection(attempt: attempt).attempt, resolve: { _ in
            XCTFail("Unprivileged host must not resolve elevation policy"); return .refuse(.policyRejected)
        }, draft: { _ in throw ApprovalCoordinatorError.invalidDraft }, now: { fixture.now() }, receiptTimeMs: nil)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.storageFailure))
    }

    func testTypedDraftRejectionProvesBothIdentifiersAbsent() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed), reply = try Endpoint()
            let (command, submission, profile) = try typedRequestCommand(reply: reply)
            let before = try fixture.auditRecordCount, baseline = try sendReferences(reply.port)
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture, draft: fixture.draft(command, capture: Data([0xa0]))))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .notAdmitted(.invalidRequest, .never))
            XCTAssertEqual(try sendReferences(reply.port), baseline - 1)
            XCTAssertEqual(try fixture.auditRecordCount, before); XCTAssertNil(try fixture.reservation(submission.binding.id))
            XCTAssertFalse(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
            XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
        }
    }

    func testTypedOwnedJournalRefusalKeepsItsReplyAndAllowsIndependentFreshAdmission() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
            let (command, submission, profile) = try typedRequestCommand(reply: reply)
            XCTAssertThrowsError(try admitOwnedCommand(command, fixture: fixture, draft: fixture.draft(command, capture: Data([0xa0]))))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .notAdmitted(.invalidRequest, .never))
            XCTAssertNil(try fixture.reservation(submission.binding.id))
            XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
            XCTAssertEqual(try sendReferences(reply.port), 1)
            let freshReply = try Endpoint()
            let binding = CapturedSubmission(id: Data(repeating: 88, count: 16), nonce: Data(repeating: 89, count: 32), callerBinding: assemblyBinding)
            let (fresh, original, selected) = try typedRequestCommand(reply: freshReply, binding: binding)
            let request = try admitOwnedCommand(fresh, fixture: fixture)
            XCTAssertNotNil(try fixture.reservation(original.binding.id))
            guard case .admitted(let identity) = try typedOutcome(freshReply, submission: original, profile: selected) else {
                return XCTFail("Fresh request was not admitted")
            }
            XCTAssertEqual(identity.requestID, request.requestID)
            try fresh.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        }
    }

    func testTypedCapacityRefusalPreservesExistingRequestAndStorage() throws {
        for checkpointed in [false, true] {
            for journalCapacity in [false, true] {
                let fixture = try CommandRequestFixture(maximumRequests: journalCapacity ? 8 : 1,
                    checkpointed: checkpointed, maximumSubmissions: journalCapacity ? 1 : 30)
                let firstReply = try Endpoint(), (first, _, _) = try typedRequestCommand(reply: firstReply)
                let request = try admitCommand(first, fixture: fixture), before = try fixture.auditRecordCount
                let secondReply = try Endpoint()
                let binding = CapturedSubmission(id: Data(repeating: 88, count: 16), nonce: Data(repeating: 89, count: 32), callerBinding: assemblyBinding)
                let (second, submission, profile) = try typedRequestCommand(reply: secondReply, binding: binding)
                XCTAssertThrowsError(try admitCommand(second, fixture: fixture))
                XCTAssertEqual(try typedOutcome(secondReply, submission: submission, profile: profile), .notAdmitted(.capacityExceeded, .never))
                XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .queued)
                try first.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
                XCTAssertEqual(try fixture.auditRecordCount, before)
                XCTAssertFalse(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
            }
        }
    }

    func testTypedRolledBackStorageFailureCanProveNoAdmission() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed), reply = try Endpoint()
            let (command, submission, profile) = try typedRequestCommand(reply: reply), before = try fixture.auditRecordCount
            try fixture.sql("CREATE TRIGGER fail_command_insert BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'fixture write failure'); END")
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .notAdmitted(.storageUnavailable, .storageUnavailable))
            XCTAssertEqual(try fixture.auditRecordCount, before)
            XCTAssertFalse(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
            XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
        }
    }

    func testTypedCheckpointFailureNeverClaimsNoAdmissionEvenAfterJournalCommit() throws {
        for prepare in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: true), reply = try Endpoint()
            let (command, submission, profile) = try typedRequestCommand(reply: reply), before = try fixture.auditRecordCount
            let condition = prepare ? "NEW.pending IS NOT NULL" : "NEW.pending IS NULL"
            try fixture.sql("CREATE TRIGGER fail_command_checkpoint BEFORE UPDATE ON continuity_v1 WHEN \(condition) BEGIN SELECT RAISE(ABORT,'fixture checkpoint failure'); END", continuity: true)
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.storageFailure))
            XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
            XCTAssertEqual(try sendReferences(reply.port), 1)
            XCTAssertEqual(try fixture.auditRecordCount, before + (prepare ? 0 : 1))
            XCTAssertTrue(try XCTUnwrap(fixture.continuity).read().pending != nil || prepare)
        }
    }

    func testTypedProtocolDraftRefusalsRequireAbsenceBeforeReportingTheirExactReason() throws {
        for checkpointed in [false, true] {
            for kind in 0..<3 {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed), reply = try Endpoint()
                let (command, submission, profile) = try typedRequestCommand(reply: reply), base = fixture.draft(command)
                let contract = try kind == 0 ? RequestContract(requestKind: .command, wireVersion: 2, schemaVersion: base.contract.schemaVersion) : base.contract
                let draft = ApprovalRequestDraft(contract: contract, requiredFeatures: base.requiredFeatures, capture: base.capture, actions: base.actions,
                    firstObservedAt: base.firstObservedAt, deadlineMilliseconds: base.deadlineMilliseconds,
                    createdUnixMilliseconds: kind == 0 ? base.createdUnixMilliseconds : base.expiresUnixMilliseconds + UInt64(kind - 1),
                    expiresUnixMilliseconds: base.expiresUnixMilliseconds)
                let before = try fixture.auditRecordCount
                XCTAssertThrowsError(try admitCommand(command, fixture: fixture, draft: draft)) {
                    XCTAssertEqual($0 as? IssuedRequestError, kind == 0 ? .unsupportedContract : .invalidTimes)
                }
                XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile),
                    .notAdmitted(kind == 0 ? .unsupported : .invalidRequest, .never))
                XCTAssertEqual(try fixture.auditRecordCount, before)
                XCTAssertFalse(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
                XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
            }
        }
    }

    func testTypedProtocolErrorsFromCallbacksStillCannotClaimNoAdmission() throws {
        for checkpointed in [false, true] {
            for failure: IssuedRequestError in [.unsupportedContract, .invalidTimes] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed), reply = try Endpoint()
                let (command, submission, profile) = try typedRequestCommand(reply: reply)
                XCTAssertThrowsError(try admitCommand(command, fixture: fixture, checkCancellation: { throw failure })) {
                    XCTAssertEqual($0 as? IssuedRequestError, failure)
                }
                XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.admissionRejected))
                XCTAssertFalse(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
            }
        }
    }

    func testTypedUnsupportedContractRefusalUsesVerifiedRollback() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed), reply = try Endpoint()
            let (command, submission, profile) = try typedRequestCommand(reply: reply), base = fixture.draft(command)
            let draft = ApprovalRequestDraft(contract: base.contract, requiredFeatures: [999], capture: base.capture, actions: base.actions,
                firstObservedAt: base.firstObservedAt, deadlineMilliseconds: base.deadlineMilliseconds,
                createdUnixMilliseconds: base.createdUnixMilliseconds, expiresUnixMilliseconds: base.expiresUnixMilliseconds)
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture, draft: draft)) {
                XCTAssertEqual($0 as? DecisionVerificationError, .unsupportedContract)
            }
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .notAdmitted(.unsupported, .never))
            XCTAssertFalse(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
        }
    }

    func testTypedAbsenceProofCoversHistoricalNonceAndSubmissionSeparately() throws {
        for checkpointed in [false, true] {
            for reuseNonce in [false, true] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed), firstReply = try Endpoint()
                let (first, original, _) = try typedRequestCommand(reply: firstReply)
                let request = try admitCommand(first, fixture: fixture)
                _ = try fixture.requests.retirePending(requestID: request.requestID, reason: .cancelled, now: fixture.now(120), receiptTimeMs: nil)
                let binding = CapturedSubmission(id: reuseNonce ? Data(repeating: 88, count: 16) : original.binding.id,
                    nonce: reuseNonce ? original.binding.nonce : Data(repeating: 89, count: 32), callerBinding: assemblyBinding)
                let reply = try Endpoint(), (command, submission, profile) = try typedRequestCommand(reply: reply, binding: binding)
                XCTAssertThrowsError(try admitCommand(command, fixture: fixture, draft: fixture.draft(command, capture: Data([0xa0]))))
                XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.duplicateSubmission))
                XCTAssertTrue(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
                if reuseNonce { XCTAssertNil(try fixture.reservation(submission.binding.id)) }
            }
        }
    }

    func testTypedCallbackErrorsCannotForgeAnOwnerRefusalAndRetainReplyAfterCleanup() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed), reply = try Endpoint()
            let (command, submission, profile) = try typedRequestCommand(reply: reply)
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture, checkCancellation: { throw ApprovalCoordinatorError.capacityExceeded }))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.admissionRejected))
            XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
            XCTAssertEqual(try sendReferences(reply.port), 1)
            XCTAssertFalse(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
        }
    }

    func testTypedFailedAbsenceReadRemainsUncertainAndClosesAllResources() throws {
        for failure in 0..<3 {
            let fixture = try CommandRequestFixture(checkpointed: true), reply = try Endpoint()
            let (command, submission, profile) = try typedRequestCommand(reply: reply)
            if failure == 0 { try fixture.db.close() }
            if failure == 1 { try fixture.sql("UPDATE audit_epochs_v1 SET head=X'0000000000000002'") }
            if failure == 2 { XCTAssertEqual(chmod(fixture.root.appendingPathComponent("store/journal.sqlite").path, 0o644), 0) }
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture, draft: fixture.draft(command, capture: Data([0xa0]))))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.storageFailure))
            XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
            XCTAssertEqual(try sendReferences(reply.port), 1)
        }
    }

    func testTypedAdmissionNegotiatesTheNewWireAndMatchesItsOriginalSubmission() throws {
        let endpoint = try Endpoint(), port = endpoint.port, expression = try selfExpression(), user = geteuid()
        let mac = handshakeMac, account = handshakeAccount
        let completed = DispatchSemaphore(value: 0), result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        DispatchQueue.global().async {
            defer { completed.signal() }
            result.withLock { output in output = Result {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user,
                    auditSessionID: nil, maxPayloadBytes: 8192)
                let session = try RetainedCommandHandshake(hello: receiver.receiveHello(timeoutMilliseconds: 5000),
                    capabilities: .admissionResults, macID: mac, accountID: account, expression: expression, userID: user, auditSessionID: nil)
                defer { session.close() }
                let input = try receiver.receiveAdmissionInput(timeoutMilliseconds: 5000)
                defer { input.closeIfUnclaimed() }
                let submission = try CommandSubmission(canonicalBytes: input.payload,
                    limits: CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024), expectedSchemaVersion: 1)
                let payload = CommandAdmissionResultPayload(profile: session.profile, submission: submission.binding,
                    submissionDigest: Data(SHA256.hash(data: submission.canonicalBytes)), outcome: .uncertain(.admissionRejected))
                try input.sendAdmissionReply(payload.canonicalBytes)
            } }
        }
        let handshake = try MachCommandHandshakeClient.negotiate(authorityPort: port, expression: expression, userID: user,
            auditSessionID: nil, macID: mac, accountID: account, capabilities: .admissionResults)
        defer { handshake.close() }
        var pipeFDs: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&pipeFDs), 0); defer { for fd in pipeFDs { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(pipeFDs[1], "queued", 6), 6)
        let submission = try commandSubmission(binding: .init(id: Data(repeating: 2, count: 16), nonce: Data(repeating: 3, count: 32),
            callerBinding: handshake.profile.callerBinding))
        let response = try MachCommandAdmissionClient.submit(submission, inputDescriptor: pipeFDs[0],
            handshake: handshake, expression: expression, userID: user, auditSessionID: nil, maximumPayloadBytes: 8192, typedResult: true)
        XCTAssertEqual(response.profile, handshake.profile)
        let verified = try XCTUnwrap(response.verifiedResult)
        XCTAssertEqual(verified.outcome, .uncertain(.admissionRejected)); XCTAssertEqual(verified.retryClass, .never)
        XCTAssertEqual(verified.submission, submission.binding)
        XCTAssertEqual(completed.wait(timeout: .now() + 5), .success); try result.withLock { try $0?.get() }
        var bytes = [UInt8](repeating: 0, count: 6)
        XCTAssertEqual(Darwin.read(pipeFDs[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("queued".utf8))
    }

    func testAdmissionClientNegotiatesAndAuthenticatesReplyWithoutReadingInput() throws {
        let endpoint = try Endpoint(), port = endpoint.port, expression = try selfExpression(), user = geteuid()
        let mac = handshakeMac, account = handshakeAccount
        let completed = DispatchSemaphore(value: 0), result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        DispatchQueue.global().async {
            defer { completed.signal() }
            result.withLock { output in output = Result {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user,
                    auditSessionID: nil, maxPayloadBytes: 8192)
                let session = try RetainedCommandHandshake(hello: receiver.receiveHello(timeoutMilliseconds: 5000),
                    capabilities: .admissionReplies, macID: mac, accountID: account, expression: expression, userID: user, auditSessionID: nil)
                defer { session.close() }
                let input = try receiver.receiveAdmissionInput(timeoutMilliseconds: 5000)
                defer { input.closeIfUnclaimed() }
                _ = try CommandSubmission(canonicalBytes: input.payload,
                    limits: CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024), expectedSchemaVersion: 1)
                try input.sendAdmissionReply(Data([0xa0]))
            } }
        }
        let handshake = try MachCommandHandshakeClient.negotiate(authorityPort: port, expression: expression, userID: user,
            auditSessionID: nil, macID: mac, accountID: account, capabilities: .admissionReplies)
        defer { handshake.close() }
        var pipeFDs: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&pipeFDs), 0); defer { for fd in pipeFDs { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(pipeFDs[1], "queued", 6), 6)
        let submission = try commandSubmission(binding: .init(id: Data(repeating: 2, count: 16), nonce: Data(repeating: 3, count: 32),
            callerBinding: handshake.profile.callerBinding))
        let response = try MachCommandAdmissionClient.submit(submission, inputDescriptor: pipeFDs[0],
            handshake: handshake, expression: expression, userID: user, auditSessionID: nil, maximumPayloadBytes: 8192)
        XCTAssertEqual(response.payload, Data([0xa0])); XCTAssertEqual(response.profile, handshake.profile)
        XCTAssertEqual(completed.wait(timeout: .now() + 5), .success); try result.withLock { try $0?.get() }
        var bytes = [UInt8](repeating: 0, count: 6)
        XCTAssertEqual(Darwin.read(pipeFDs[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("queued".utf8))
    }

    func testAdmissionClientRejectsLegacyBindingAndCurrentAuthorityFailureBeforeExposure() throws {
        let endpoint = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        let old = try admissionClientFixture(endpoint.port, input: 2), current = try admissionClientFixture(endpoint.port)
        defer { old.close(); current.close() }
        for handshake in [old, current] {
            let submission = try commandSubmission(binding: .init(id: Data(repeating: 2, count: 16), nonce: Data(repeating: 3, count: 32),
                callerBinding: Data(repeating: 9, count: 16)))
            XCTAssertThrowsError(try MachCommandAdmissionClient.submit(submission, inputDescriptor: fd,
                handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192))
        }
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: fd,
            handshake: current, expression: selfExpression(), userID: geteuid() ^ 1, auditSessionID: nil, maximumPayloadBytes: 8192))
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testAdmissionReplyMustMatchTheRetainedAuthorityIncarnation() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port), peer = try Peer(endpoint: endpoint)
        defer { handshake.close() }
        let reply = try receiver(endpoint, expression: "true").receive(timeoutMilliseconds: 5000)
        defer { reply.caller.close() }
        XCTAssertThrowsError(try handshake.authenticateReply(reply.caller, expression: "true", userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .wrongBinding)
        }
        try peer.advance()
        let replacement = try receiver(endpoint, expression: "true").receive(timeoutMilliseconds: 5000)
        replacement.caller.close()
        try peer.stop()
    }

    private func serveAdmission(_ port: mach_port_t, response: Data?) throws -> (DispatchSemaphore, OSAllocatedUnfairLock<Result<Void, Error>?>) {
        let expression = try selfExpression(), user = geteuid(), completed = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        DispatchQueue.global().async {
            defer { completed.signal() }
            result.withLock { output in output = Result {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user,
                    auditSessionID: nil, maxPayloadBytes: 8192)
                let input = try receiver.receiveAdmissionInput(timeoutMilliseconds: 5000)
                defer { input.closeIfUnclaimed() }
                if let response { try input.sendAdmissionReply(response) }
            } }
        }
        return (completed, result)
    }

    func testAdmissionClientLostReplyKeepsInputAndBorrowedAuthorityRight() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port)
        defer { handshake.close() }
        var pipeFDs: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&pipeFDs), 0); defer { for fd in pipeFDs { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(pipeFDs[1], "queued", 6), 6)
        let baseline = try sendReferences(endpoint.port), server = try serveAdmission(endpoint.port, response: nil)
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: pipeFDs[0],
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
        XCTAssertEqual(try sendReferences(endpoint.port), baseline)
        var bytes = [UInt8](repeating: 0, count: 6)
        XCTAssertEqual(Darwin.read(pipeFDs[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("queued".utf8))
    }

    func testAdmissionClientContinuousDeadlineAndCancellationDoNotExposeInputEarly() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port), fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { handshake.close(); _ = Darwin.close(fd) }
        var tick: UInt64 = 0
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: fd,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            maximumPayloadBytes: 8192, timeoutMilliseconds: 10, clock: { defer { tick += 10 }; return tick })) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: fd,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192,
            checkCancellation: { throw MachCommandHandshakeError.retired }))
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testAdmissionClientCancellationDuringReplyWaitPreservesTheSingleSubmission() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port)
        defer { handshake.close() }
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        let server = try serveAdmission(endpoint.port, response: nil)
        var checks = 0
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: fd,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            maximumPayloadBytes: 8192, timeoutMilliseconds: 5000, checkCancellation: {
                checks += 1
                if checks == 4 { throw MachCommandHandshakeError.retired }
            })) { XCTAssertEqual($0 as? MachCommandHandshakeError, .retired) }
        XCTAssertEqual(checks, 4)
        XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testAdmissionClientRejectsAnAuthenticatedReplyAtTheFinalDeadline() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port)
        defer { handshake.close() }
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        let server = try serveAdmission(endpoint.port, response: Data([0xa0]))
        var samples = 0
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: fd,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            maximumPayloadBytes: 8192, timeoutMilliseconds: 1000, clock: {
                samples += 1
                return samples < 5 ? 0 : 1000
            })) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        XCTAssertEqual(samples, 5)
        XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
    }

    func testAdmissionClientRetainsNegotiatedDestinationAndClosurePreventsSubmission() throws {
        let endpoint = try Endpoint(), baseline = try sendReferences(endpoint.port)
        let handshake = try admissionClientFixture(endpoint.port)
        XCTAssertEqual(try sendReferences(endpoint.port), baseline + 1)
        XCTAssertEqual(try handshake.borrowedAuthorityPort(), endpoint.port)
        handshake.close(); handshake.close()
        XCTAssertEqual(try sendReferences(endpoint.port), baseline)
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: fd,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192))
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testPublicAdmissionClientRequiresRootReleasePolicyBeforeSubmission() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port)
        defer { handshake.close() }
        let policy = try XPCPeerPolicy(teamID: "TEAMID1234", componentIdentifier: "dev.remozio.fixture",
            approvedCodeDirectoryHashes: [Data(repeating: 1, count: 20)], expectedUserID: 1)
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: -1,
            handshake: handshake, authorityPolicy: policy, maximumPayloadBytes: 8192)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testAdmissionWireFullQueueCleanupPreservesBorrowedRightsAndInput() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        var attributes = mach_port_limits_t(mpl_qlimit: 1)
        XCTAssertEqual(withUnsafeMutablePointer(to: &attributes) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: 1) {
                mach_port_set_attributes(mach_task_self_, endpoint.port, MACH_PORT_LIMITS_INFO, $0, mach_msg_type_number_t(MemoryLayout<mach_port_limits_t>.size / MemoryLayout<natural_t>.size))
            }
        }, KERN_SUCCESS)
        try endpoint.send(Data([1]))
        let baseline = try sendReferences(reply.port), authorityBaseline = try sendReferences(endpoint.port), flags = fcntl(fd, F_GETFL)
        XCTAssertThrowsError(try MachCommandAdmissionWire.send(Data([1]), inputDescriptor: fd, destination: endpoint.port,
            replyPort: reply.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 10)) {
            guard case .mach(let result) = $0 as? MachCommandCallerError else { return XCTFail("Wrong failure") }
            XCTAssertEqual(result & ~MACH_MSG_MASK, MACH_SEND_TIMED_OUT)
        }
        XCTAssertEqual(try sendReferences(reply.port), baseline); XCTAssertEqual(try sendReferences(endpoint.port), authorityBaseline)
        XCTAssertEqual(fcntl(fd, F_GETFL), flags)
        let filler = try receiver(endpoint).receive(timeoutMilliseconds: 1000); filler.caller.close()
        let input = try admissionInput(endpoint, reply: reply, descriptor: fd, payload: Data([2])); input.closeIfUnclaimed()
        XCTAssertEqual(try sendReferences(reply.port), baseline)
    }

    func testRejectedComplexPacketReleasesImportedSendRight() throws {
        let endpoint = try Endpoint(), carried = try Endpoint(), receiver = try receiver(endpoint)
        var baseline: mach_port_urefs_t = 0
        XCTAssertEqual(mach_port_get_refs(mach_task_self_, carried.port, MACH_PORT_RIGHT_SEND, &baseline), KERN_SUCCESS)
        try endpoint.sendPort(carried.port)
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .malformed)
        }
        var final: mach_port_urefs_t = 0
        XCTAssertEqual(mach_port_get_refs(mach_task_self_, carried.port, MACH_PORT_RIGHT_SEND, &final), KERN_SUCCESS)
        XCTAssertEqual(final, baseline)
        try endpoint.send(Data([1]))
        XCTAssertEqual(try receiver.receive(timeoutMilliseconds: 1000).payload, Data([1]))
    }

    private func sendReferences(_ port: mach_port_t) throws -> mach_port_urefs_t {
        var count: mach_port_urefs_t = 0
        let result = mach_port_get_refs(mach_task_self_, port, MACH_PORT_RIGHT_SEND, &count)
        guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        return count
    }

    func testPreviewRetainsQueueHeadAndDoesNotImportSendRights() throws {
        let endpoint = try Endpoint(), carried = try Endpoint()
        let baseline = try sendReferences(carried.port)
        try endpoint.sendPort(carried.port, outOfLineBytes: 65536)
        var first = remozio_mach_preview_t(), second = remozio_mach_preview_t()
        XCTAssertEqual(remozio_preview_audit(endpoint.port, 1000, &first), KERN_SUCCESS)
        XCTAssertEqual(remozio_preview_audit(endpoint.port, 1000, &second), KERN_SUCCESS)
        XCTAssertEqual(first.sequence, second.sequence)
        XCTAssertEqual(first.identifier, MachCommandCallerReceiver.messageID)
        XCTAssertEqual(audit_token_to_pid(first.token), getpid())
        XCTAssertEqual(audit_token_to_euid(first.token), geteuid())
        XCTAssertEqual(try sendReferences(carried.port), baseline)
        let capacity = Int(first.size) + MemoryLayout<mach_msg_audit_trailer_t>.size
        let storage = UnsafeMutableRawPointer.allocate(byteCount: capacity, alignment: 8)
        defer { storage.deallocate() }
        storage.initializeMemory(as: UInt8.self, repeating: 0, count: capacity)
        let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
        let result = remozio_receive_audit(header, UInt32(capacity), endpoint.port, 1000)
        XCTAssertEqual(result, KERN_SUCCESS)
        guard result == KERN_SUCCESS else { return }
        XCTAssertEqual(try sendReferences(carried.port), baseline + 1)
        let trailer = storage.loadUnaligned(fromByteOffset: Int(first.size), as: mach_msg_audit_trailer_t.self)
        XCTAssertEqual(trailer.msgh_seqno, first.sequence)
        var receivedToken = trailer.msgh_audit, previewToken = first.token
        XCTAssertTrue(withUnsafeBytes(of: &receivedToken) { a in
            withUnsafeBytes(of: &previewToken) { b in a.elementsEqual(b) }
        })
        let outOfLine = storage.loadUnaligned(fromByteOffset: MemoryLayout<mach_msg_header_t>.size +
            MemoryLayout<mach_msg_body_t>.size + MemoryLayout<mach_msg_port_descriptor_t>.size,
            as: mach_msg_ool_descriptor_t.self)
        XCTAssertEqual(outOfLine.size, 65536)
        XCTAssertEqual(outOfLine.type, UInt32(MACH_MSG_OOL_DESCRIPTOR))
        if let address = outOfLine.address {
            XCTAssertEqual(Data(bytes: address, count: Int(outOfLine.size)), Data(repeating: 0x5a, count: 65536))
        } else { XCTFail("The received out-of-line buffer is missing") }
        mach_msg_destroy(header)
        XCTAssertEqual(try sendReferences(carried.port), baseline)
    }

    func testWrongSenderPolicyDiscardsComplexPacketBeforeImport() throws {
        let endpoint = try Endpoint(), carried = try Endpoint()
        let baseline = try sendReferences(carried.port)
        let rejected = try receiver(endpoint, user: geteuid() ^ 1)
        try endpoint.sendPort(carried.port, outOfLineBytes: 65536)
        XCTAssertThrowsError(try rejected.receive(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .wrongPeer)
        }
        XCTAssertEqual(try sendReferences(carried.port), baseline)
        try endpoint.send(Data([4]))
        XCTAssertEqual(try receiver(endpoint).receive(timeoutMilliseconds: 1000).payload, Data([4]))
    }

    func testDiscardConsumesOnlyThePreviewedQueueHead() throws {
        let endpoint = try Endpoint(), carried = try Endpoint()
        let baseline = try sendReferences(carried.port)
        try endpoint.sendPort(carried.port, outOfLineBytes: 65536)
        try endpoint.send(Data([5]))
        var first = remozio_mach_preview_t(), second = remozio_mach_preview_t()
        XCTAssertEqual(remozio_preview_audit(endpoint.port, 1000, &first), KERN_SUCCESS)
        XCTAssertEqual(remozio_discard_message(endpoint.port), MACH_RCV_TOO_LARGE)
        XCTAssertEqual(try sendReferences(carried.port), baseline)
        XCTAssertEqual(remozio_preview_audit(endpoint.port, 1000, &second), KERN_SUCCESS)
        XCTAssertEqual(second.sequence, first.sequence + 1)
        XCTAssertEqual(try receiver(endpoint).receive(timeoutMilliseconds: 1000).payload, Data([5]))
    }

    func testBareHeaderRemainsQueuedUntilExplicitDiscard() throws {
        let endpoint = try Endpoint()
        try endpoint.sendBareHeader()
        var preview = remozio_mach_preview_t()
        XCTAssertEqual(remozio_preview_audit(endpoint.port, 1000, &preview), KERN_SUCCESS)
        XCTAssertEqual(preview.size, UInt32(MemoryLayout<mach_msg_header_t>.size))
        XCTAssertThrowsError(try receiver(endpoint).receive(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .malformed)
        }
        try endpoint.send(Data([6]))
        XCTAssertEqual(try receiver(endpoint).receive(timeoutMilliseconds: 1000).payload, Data([6]))
    }

    func testInputCarrierRetainsActualPipeAfterSenderClosesItsHandles() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        var descriptors: [Int32] = [-1, -1]
        guard pipe(&descriptors) == 0 else { throw MachCommandCallerError.unavailable }
        defer { for fd in descriptors where fd >= 0 { _ = Darwin.close(fd) } }
        let initialFlags = fcntl(descriptors[0], F_GETFL)
        XCTAssertEqual(fcntl(descriptors[0], F_SETFL, initialFlags | O_NONBLOCK), 0)
        let queued = Data("queued".utf8)
        XCTAssertEqual(queued.withUnsafeBytes { Darwin.write(descriptors[1], $0.baseAddress, $0.count) }, queued.count)
        var fileport: mach_port_t = UInt32(MACH_PORT_NULL)
        XCTAssertEqual(fileport_makeport(descriptors[0], &fileport), 0)
        defer { if fileport != MACH_PORT_NULL { _ = mach_port_deallocate(mach_task_self_, fileport) } }
        let payload = Data([0xff, 0, 3])
        try endpoint.sendInput(payload, fileport: fileport)
        XCTAssertEqual(mach_port_deallocate(mach_task_self_, fileport), KERN_SUCCESS)
        fileport = UInt32(MACH_PORT_NULL)
        XCTAssertEqual(Darwin.close(descriptors[0]), 0)
        descriptors[0] = -1
        let submission = try receiver.receiveInput(timeoutMilliseconds: 1000)
        XCTAssertEqual(submission.payload, payload)
        XCTAssertEqual(submission.caller.requester.pid, UInt32(getpid()))
        let capture = try submission.input.capture(streamBinding: Data(repeating: 0xa1, count: 16))
        XCTAssertEqual(capture.kind, .pipe)
        XCTAssertEqual(capture.kind.minimumSchemaVersion, 1)
        XCTAssertEqual(capture.streamBinding, Data(repeating: 0xa1, count: 16))
        XCTAssertNil(capture.observedPath)
        let later = Data("later".utf8)
        XCTAssertEqual(later.withUnsafeBytes { Darwin.write(descriptors[1], $0.baseAddress, $0.count) }, later.count)
        var imported: Int32 = -1
        try submission.input.withBorrowedDescriptor { fd in
            imported = fd
            XCTAssertNotEqual(fcntl(fd, F_GETFD) & FD_CLOEXEC, 0)
            XCTAssertEqual(fcntl(fd, F_GETFL), initialFlags | O_NONBLOCK)
            var bytes = [UInt8](repeating: 0, count: queued.count + later.count)
            XCTAssertEqual(Darwin.read(fd, &bytes, bytes.count), bytes.count)
            XCTAssertEqual(Data(bytes), queued + later)
        }
        submission.input.close(); submission.input.close()
        XCTAssertEqual(fcntl(imported, F_GETFD), -1)
        XCTAssertEqual(errno, EBADF)
        XCTAssertThrowsError(try submission.input.withBorrowedDescriptor { _ in XCTFail("A retired descriptor was borrowed") }) {
            XCTAssertEqual($0 as? RetainedCommandInputError, .closed)
        }
    }

    func testOrdinaryMachRightCannotBecomeInputAndNextPacketWorks() throws {
        let endpoint = try Endpoint(), carried = try Endpoint(), receiver = try receiver(endpoint)
        let baseline = try sendReferences(carried.port)
        try endpoint.sendInput(Data([1]), fileport: carried.port)
        XCTAssertThrowsError(try receiver.receiveInput(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? RetainedCommandInputError, .system(EINVAL))
        }
        XCTAssertEqual(try sendReferences(carried.port), baseline)
        try endpoint.send(Data([2]))
        XCTAssertEqual(try receiver.receive(timeoutMilliseconds: 1000).payload, Data([2]))
    }

    func testInputCarrierRejectsCountsVersionsAndWrongPeerWithoutPoisoningQueue() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw MachCommandCallerError.unavailable }
        defer { _ = Darwin.close(fd) }
        var fileport: mach_port_t = UInt32(MACH_PORT_NULL)
        XCTAssertEqual(fileport_makeport(fd, &fileport), 0)
        defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        let baseline = try sendReferences(fileport)
        for count in [0, 2] {
            try endpoint.sendInput(Data([1]), fileport: fileport, descriptorCount: count)
            XCTAssertThrowsError(try receiver.receiveInput(timeoutMilliseconds: 1000))
            XCTAssertEqual(try sendReferences(fileport), baseline)
        }
        try endpoint.sendInput(Data([1]), fileport: fileport, version: 3)
        XCTAssertThrowsError(try receiver.receiveInput(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .version)
        }
        try endpoint.sendInput(Data([1]), fileport: fileport)
        XCTAssertThrowsError(try self.receiver(endpoint, user: geteuid() ^ 1).receiveInput(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .wrongPeer)
        }
        XCTAssertEqual(try sendReferences(fileport), baseline)
        try endpoint.sendInput(Data([2]), fileport: fileport)
        let submission = try receiver.receiveInput(timeoutMilliseconds: 1000)
        XCTAssertEqual(submission.payload, Data([2]))
        XCTAssertEqual(try sendReferences(fileport), baseline)
        try submission.input.withBorrowedDescriptor { fd in
            var byte: UInt8 = 0
            XCTAssertEqual(Darwin.read(fd, &byte, 1), 0)
        }
    }

    func testCarrierVersionsCannotSilentlyDowngradeEachOther() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw MachCommandCallerError.unavailable }
        defer { _ = Darwin.close(fd) }
        var fileport: mach_port_t = UInt32(MACH_PORT_NULL)
        XCTAssertEqual(fileport_makeport(fd, &fileport), 0)
        defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        try endpoint.sendInput(Data([1]), fileport: fileport)
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000))
        try endpoint.send(Data([1]))
        XCTAssertThrowsError(try receiver.receiveInput(timeoutMilliseconds: 1000))
        try endpoint.sendInput(Data([2]), fileport: fileport)
        XCTAssertEqual(try receiver.receiveInput(timeoutMilliseconds: 1000).payload, Data([2]))
    }

    func testInputCarrierPreservesRegularFileIdentityAndOffset() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        let fd = Darwin.open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw MachCommandCallerError.unavailable }
        defer { _ = Darwin.close(fd); _ = Darwin.unlink(path) }
        let contents = Data("012345".utf8)
        XCTAssertEqual(contents.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }, contents.count)
        XCTAssertEqual(lseek(fd, 2, SEEK_SET), 2)
        var original = stat()
        XCTAssertEqual(fstat(fd, &original), 0)
        var fileport: mach_port_t = UInt32(MACH_PORT_NULL)
        XCTAssertEqual(fileport_makeport(fd, &fileport), 0)
        defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        try endpoint.sendInput(Data([7]), fileport: fileport)
        let submission = try receiver.receiveInput(timeoutMilliseconds: 1000)
        let capture = try submission.input.capture(streamBinding: Data(repeating: 0xa2, count: 16))
        XCTAssertEqual(capture.kind, .file)
        XCTAssertEqual(capture.kind.minimumSchemaVersion, 1)
        XCTAssertEqual(capture.identity, CapturedFileIdentity(device: UInt64(UInt32(bitPattern: original.st_dev)), inode: original.st_ino))
        XCTAssertNotNil(capture.observedPath)
        try submission.input.withBorrowedDescriptor { imported in
            var observed = stat()
            XCTAssertEqual(fstat(imported, &observed), 0)
            XCTAssertEqual(observed.st_dev, original.st_dev)
            XCTAssertEqual(observed.st_ino, original.st_ino)
            XCTAssertEqual(observed.st_mode, original.st_mode)
            XCTAssertEqual(lseek(imported, 0, SEEK_CUR), 2)
            XCTAssertEqual(lseek(fd, 0, SEEK_CUR), 2)
            var bytes = [UInt8](repeating: 0, count: 4)
            XCTAssertEqual(Darwin.read(imported, &bytes, 4), 4)
            XCTAssertEqual(Data(bytes), Data("2345".utf8))
            XCTAssertEqual(lseek(fd, 0, SEEK_CUR), 6)
        }
    }

    func testInputCarrierRejectsOutOfLineDescriptorBeforeParsingPayload() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        try endpoint.sendOutOfLineInput()
        XCTAssertThrowsError(try receiver.receiveInput(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .malformed)
        }
        try endpoint.send(Data([8]))
        XCTAssertEqual(try receiver.receive(timeoutMilliseconds: 1000).payload, Data([8]))
    }

    private func inputSubmission(_ fd: Int32, payload: Data = Data([1])) throws -> ReceivedMachCommandInputSubmission {
        let endpoint = try Endpoint()
        var fileport: mach_port_t = UInt32(MACH_PORT_NULL)
        guard fileport_makeport(fd, &fileport) == 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        try endpoint.sendInput(payload, fileport: fileport)
        return try receiver(endpoint, maximum: 8192).receiveInput(timeoutMilliseconds: 1000)
    }

    func testSocketCapturePreservesQueuedInputAndSharedFlags() throws {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw RetainedCommandInputError.system(errno) }
        defer { for fd in pair { _ = Darwin.close(fd) } }
        let flags = fcntl(pair[0], F_GETFL)
        XCTAssertEqual(fcntl(pair[0], F_SETFL, flags | O_NONBLOCK), 0)
        let queued = Data("socket".utf8)
        XCTAssertEqual(queued.withUnsafeBytes { Darwin.write(pair[1], $0.baseAddress, $0.count) }, queued.count)
        let submission = try inputSubmission(pair[0])
        defer { submission.input.close(); submission.caller.close() }
        let capture = try submission.input.capture(streamBinding: Data(repeating: 0xa3, count: 16))
        XCTAssertEqual(capture.kind, .socket)
        XCTAssertEqual(capture.kind.minimumSchemaVersion, 2)
        XCTAssertNil(capture.observedPath)
        XCTAssertNotNil(capture.identity)
        XCTAssertEqual(fcntl(pair[0], F_GETFL), flags | O_NONBLOCK)
        try submission.input.withBorrowedDescriptor { fd in
            var bytes = [UInt8](repeating: 0, count: queued.count)
            XCTAssertEqual(Darwin.read(fd, &bytes, bytes.count), bytes.count)
            XCTAssertEqual(Data(bytes), queued)
        }
    }

    func testDirectoryAndDeviceCaptureKeepDistinctKinds() throws {
        let resources: [(String, Int32, CommandInputKind)] = [
            (FileManager.default.temporaryDirectory.path, O_RDONLY | O_DIRECTORY, .directory),
            ("/dev/zero", O_RDONLY, .device), ("/dev/null", O_RDONLY, .null),
        ]
        for (path, flags, kind) in resources {
            let fd = Darwin.open(path, flags | O_CLOEXEC)
            guard fd >= 0 else { throw RetainedCommandInputError.system(errno) }
            defer { _ = Darwin.close(fd) }
            let submission = try inputSubmission(fd)
            defer { submission.input.close(); submission.caller.close() }
            let capture = try submission.input.capture(streamBinding: Data(repeating: 0xa4, count: 16))
            XCTAssertEqual(capture.kind, kind)
            if kind == .null {
                XCTAssertNil(capture.streamBinding); XCTAssertNil(capture.observedPath); XCTAssertNil(capture.identity)
            } else {
                var original = stat()
                XCTAssertEqual(fstat(fd, &original), 0)
                XCTAssertEqual(capture.identity, CapturedFileIdentity(device: UInt64(UInt32(bitPattern: original.st_dev)), inode: original.st_ino))
                XCTAssertNotNil(capture.observedPath)
                XCTAssertEqual(capture.kind.minimumSchemaVersion, 2)
            }
            XCTAssertEqual(fcntl(fd, F_GETFL) & O_ACCMODE, O_RDONLY)
        }
    }

    func testTerminalCaptureUsesKernelTerminalObservationWithoutReadingInput() throws {
        var master: Int32 = -1, slave: Int32 = -1
        guard openpty(&master, &slave, nil, nil, nil) == 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = Darwin.close(master); _ = Darwin.close(slave) }
        let flags = fcntl(slave, F_GETFL)
        let bytes = Data("terminal\n".utf8)
        XCTAssertEqual(bytes.withUnsafeBytes { Darwin.write(master, $0.baseAddress, $0.count) }, bytes.count)
        let submission = try inputSubmission(slave)
        defer { submission.input.close(); submission.caller.close() }
        let capture = try submission.input.capture(streamBinding: Data(repeating: 0xa5, count: 16))
        XCTAssertEqual(capture.kind, .tty)
        XCTAssertEqual(capture.kind.minimumSchemaVersion, 1)
        XCTAssertNotNil(capture.observedPath)
        XCTAssertEqual(fcntl(slave, F_GETFL), flags)
        try submission.input.withBorrowedDescriptor { fd in
            // A bounded readiness wait keeps a failed observation from blocking the test on an empty terminal.
            var ready = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            XCTAssertEqual(poll(&ready, 1, 1000), 1)
            guard ready.revents & Int16(POLLIN) != 0 else { return }
            var actual = [UInt8](repeating: 0, count: bytes.count)
            XCTAssertEqual(Darwin.read(fd, &actual, actual.count), actual.count)
            XCTAssertEqual(Data(actual), bytes)
        }
    }

    func testCaptureRejectsWriteOnlyInputAndInvalidBindingsAndRetiredOwner() throws {
        let fd = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        guard fd >= 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = Darwin.close(fd) }
        let submission = try inputSubmission(fd)
        defer { submission.input.close(); submission.caller.close() }
        for count in [0, 15, 17] {
            XCTAssertThrowsError(try submission.input.capture(streamBinding: Data(repeating: 1, count: count))) {
                XCTAssertEqual($0 as? RetainedCommandInputError, .invalidBinding)
            }
        }
        XCTAssertThrowsError(try submission.input.capture(streamBinding: Data(repeating: 1, count: 16))) {
            XCTAssertEqual($0 as? RetainedCommandInputError, .notReadable)
        }
        XCTAssertEqual(fcntl(fd, F_GETFL) & O_ACCMODE, O_WRONLY)
        submission.input.close()
        XCTAssertThrowsError(try submission.input.capture(streamBinding: Data(repeating: 1, count: 16))) {
            XCTAssertEqual($0 as? RetainedCommandInputError, .closed)
        }
    }

    func testEventOnlyInputIsNotAdvertisedAsReadable() throws {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        let created = Darwin.open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0o600)
        guard created >= 0 else { throw RetainedCommandInputError.system(errno) }
        XCTAssertEqual(Darwin.close(created), 0)
        defer { _ = Darwin.unlink(path) }
        let fd = Darwin.open(path, O_EVTONLY | O_CLOEXEC)
        guard fd >= 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = Darwin.close(fd) }
        let submission = try inputSubmission(fd)
        defer { submission.input.close(); submission.caller.close() }
        XCTAssertThrowsError(try submission.input.capture(streamBinding: Data(repeating: 1, count: 16))) {
            XCTAssertEqual($0 as? RetainedCommandInputError, .notReadable)
        }
        XCTAssertNotEqual(fcntl(fd, F_GETFL) & O_EVTONLY, 0)
    }

    func testPathReplacementCannotReplaceTheCapturedInputObject() throws {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        let original = Darwin.open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0o600)
        guard original >= 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = Darwin.close(original); _ = Darwin.unlink(path) }
        let bytes = Data("original".utf8)
        XCTAssertEqual(bytes.withUnsafeBytes { Darwin.write(original, $0.baseAddress, $0.count) }, bytes.count)
        XCTAssertEqual(lseek(original, 0, SEEK_SET), 0)
        let submission = try inputSubmission(original)
        defer { submission.input.close(); submission.caller.close() }
        let first = try submission.input.capture(streamBinding: Data(repeating: 0xa6, count: 16))
        XCTAssertEqual(Darwin.unlink(path), 0)
        let replacement = Darwin.open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0o600)
        guard replacement >= 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = Darwin.close(replacement) }
        var fresh = stat()
        XCTAssertEqual(fstat(replacement, &fresh), 0)
        XCTAssertNotEqual(first.identity?.inode, fresh.st_ino)
        let observed = try submission.input.capture(streamBinding: Data(repeating: 0xa6, count: 16))
        XCTAssertEqual(observed.identity, first.identity)
        try submission.input.withBorrowedDescriptor { fd in
            var actual = [UInt8](repeating: 0, count: bytes.count)
            XCTAssertEqual(Darwin.read(fd, &actual, actual.count), actual.count)
            XCTAssertEqual(Data(actual), bytes)
        }
    }

    private final class Peer {
        let directory: URL
        let expression: String
        private var child: pid_t = -1
        private var control: Int32 = -1
        var pid: pid_t { child }

        init(endpoint: Endpoint, submission: Data? = nil, controlFrame: Data? = nil, terminalRole: Int? = nil, bindTerminal: Bool = false, mappedTerminalMask: Int? = nil, rawMappedTerminal: Bool = false, mappedHasTerminal: Bool = true, mappedForeignTerminalRole: Int? = nil) throws {
            directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            do {
                let binary = directory.appendingPathComponent("peer")
                let source = try XCTUnwrap(Bundle.module.url(forResource: "MachCommandCallerPeer", withExtension: "c", subdirectory: "Fixtures"))
                let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
                let native = core.appendingPathComponent("Sources/RemozioMach")
                try Self.run("/usr/bin/xcrun", ["clang", "-arch", "arm64", "-mmacosx-version-min=26.0",
                    "-Wall", "-Wextra", "-Werror", "-I", native.appendingPathComponent("include").path,
                    source.path, native.appendingPathComponent("CommandStreamSource.c").path, "-o", binary.path])
                try Self.run("/usr/bin/codesign", ["--force", "--sign", "-", "--options", "runtime",
                    "--identifier", "dev.remozio.command-caller.fixture", binary.path])
                var code: SecStaticCode?, information: CFDictionary?
                guard SecStaticCodeCreateWithPath(binary as CFURL, [], &code) == errSecSuccess,
                      let code, SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
                      let values = information as? [String: Any], let hash = values[kSecCodeInfoUnique as String] as? Data else {
                    throw MachCommandCallerError.unavailable
                }
                expression = "identifier \"dev.remozio.command-caller.fixture\" and cdhash H\"" +
                    hash.map { String(format: "%02x", $0) }.joined() + "\""
                var pipeFDs: [Int32] = [-1, -1]
                guard pipe(&pipeFDs) == 0 else { throw MachCommandCallerError.unavailable }
                defer { Darwin.close(pipeFDs[0]); if control < 0 { Darwin.close(pipeFDs[1]) } }
                var attributes: posix_spawnattr_t?, actions: posix_spawn_file_actions_t?
                guard posix_spawnattr_init(&attributes) == 0 else { throw MachCommandCallerError.unavailable }
                defer { posix_spawnattr_destroy(&attributes) }
                guard posix_spawn_file_actions_init(&actions) == 0 else { throw MachCommandCallerError.unavailable }
                defer { posix_spawn_file_actions_destroy(&actions) }
                guard posix_spawnattr_setspecialport_np(&attributes, endpoint.port, TASK_BOOTSTRAP_PORT) == 0,
                      posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0,
                      posix_spawn_file_actions_adddup2(&actions, pipeFDs[0], STDIN_FILENO) == 0,
                      posix_spawn_file_actions_addclose(&actions, pipeFDs[1]) == 0,
                      posix_spawn_file_actions_addclose(&actions, pipeFDs[0]) == 0 else {
                    throw MachCommandCallerError.unavailable
                }
                var launchArguments = [binary.path, "first"]
                if let controlFrame {
                    let payload = directory.appendingPathComponent("control-frame")
                    try controlFrame.write(to: payload)
                    launchArguments.append(contentsOf: [payload.path, "control"])
                } else if let submission {
                    let payload = directory.appendingPathComponent("submission")
                    try submission.write(to: payload)
                    launchArguments.append(payload.path)
                    if let mappedForeignTerminalRole { launchArguments.append("mapped-foreign-terminal-\(mappedForeignTerminalRole)") }
                    else if let mappedTerminalMask {
                        launchArguments.append(mappedHasTerminal ? "mapped-\(rawMappedTerminal ? "raw-" : "")terminal-\(mappedTerminalMask)" : "mapped-no-terminal-0")
                    }
                    else if let terminalRole { launchArguments.append("\(bindTerminal ? "bound" : "raw")-terminal-\(terminalRole)") }
                }
                let words = launchArguments.map { strdup($0) }
                defer { words.forEach { free($0) } }
                var arguments = words + [nil], environment: [UnsafeMutablePointer<CChar>?] = [nil]
                let result = arguments.withUnsafeMutableBufferPointer { arguments in
                    environment.withUnsafeMutableBufferPointer { environment in
                        posix_spawn(&child, binary.path, &actions, &attributes, arguments.baseAddress!, environment.baseAddress!)
                    }
                }
                guard result == 0 else { throw MachCommandCallerError.unavailable }
                control = pipeFDs[1]
            } catch {
                try? FileManager.default.removeItem(at: directory)
                throw error
            }
        }

        private static func run(_ program: String, _ arguments: [String]) throws {
            let process = Process(), output = Pipe()
            process.executableURL = URL(fileURLWithPath: program); process.arguments = arguments
            process.environment = ["PATH": "/usr/bin:/bin"]
            if let developer = ProcessInfo.processInfo.environment["DEVELOPER_DIR"] { process.environment?["DEVELOPER_DIR"] = developer }
            process.standardOutput = output; process.standardError = output
            try process.run()
            let deadline = ProcessInfo.processInfo.systemUptime + 60
            while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline { usleep(10000) }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                XCTFail(String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
                throw MachCommandCallerError.unavailable
            }
        }

        func revokeOwnTerminal() throws {
            var byte: UInt8 = 0x72
            guard write(control, &byte, 1) == 1 else { throw MachCommandCallerError.unavailable }
        }

        func advance() throws {
            var byte: UInt8 = 0x78
            guard write(control, &byte, 1) == 1 else { throw MachCommandCallerError.unavailable }
        }

        func stop() throws {
            if control >= 0 { Darwin.close(control); control = -1 }
            let deadline = ProcessInfo.processInfo.systemUptime + 5
            var status: Int32 = 0
            while ProcessInfo.processInfo.systemUptime < deadline {
                let result = waitpid(child, &status, WNOHANG)
                if result == child {
                    child = -1
                    guard status == 0 else { throw MachCommandCallerError.unavailable }
                    return
                }
                if result < 0 && errno != EINTR { throw MachCommandCallerError.unavailable }
                usleep(10000)
            }
            throw MachCommandCallerError.timeout
        }

        deinit {
            if control >= 0 { Darwin.close(control) }
            if child > 0 { kill(child, SIGKILL); while waitpid(child, nil, 0) < 0 && errno == EINTR {} }
            try? FileManager.default.removeItem(at: directory)
        }
    }

    func testRawTerminalAliasesAreRejectedInEveryRoleAndTheReceiverKeepsWorking() throws {
        for role in 0..<3 {
            let endpoint = try Endpoint(), reply = try Endpoint(), result = try Endpoint()
            let peer = try Peer(endpoint: endpoint, submission: Data([0xa0]), terminalRole: role)
            let expression = "(\(try selfExpression())) or (\(peer.expression))"
            let context = try registryContext(expression: expression)
            let host = try host(endpoint, wait: 5000, context: { context })
            defer { host.close() }
            XCTAssertEqual(try host.poll { $0.closeIfUnclaimed(); XCTFail("Raw alias reached the handler") }, .rejected(.malformed))
            try peer.stop()
            let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
            defer { _ = Darwin.close(input); _ = Darwin.close(output) }
            try MachCommandIOWire.send(Data([0xa1]), inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
                destination: endpoint.port, admissionReply: reply.port, terminalReply: result.port,
                maximumPayloadBytes: 64, timeoutMilliseconds: 1000)
            XCTAssertEqual(try host.poll { next in
                XCTAssertEqual(next.payload, Data([0xa1]))
                next.closeIfUnclaimed()
            }, .inputHandled)
        }
    }

    func testBoundTerminalAliasesAreAcceptedInEveryRoleWithTheOriginalCallerSession() throws {
        for role in 0..<3 {
            let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint, submission: Data([0xa0]), terminalRole: role, bindTerminal: true)
            let received = try receiver(endpoint, expression: peer.expression).receiveIOInput(timeoutMilliseconds: 5000)
            defer { received.closeIfUnclaimed() }
            let check: (Int32) throws -> Void = { descriptor in
                XCTAssertEqual(tcgetsid(descriptor), peer.pid)
                var alias = true
                XCTAssertEqual(remozio_command_stream_source_is_terminal_alias(descriptor, &alias), 0)
                XCTAssertFalse(alias)
            }
            if role == 0 {
                try received.input.withBorrowedDescriptor(check)
                XCTAssertEqual(try received.input.capture(streamBinding: Data(repeating: 1, count: 16)).kind, .tty)
            } else {
                let channels = try XCTUnwrap(received.outputs)
                try (role == 1 ? channels.output : channels.error).withBorrowedDescriptor(check)
            }
            received.closeIfUnclaimed()
            try peer.stop()
        }
    }

    func testRealPeerExecAndExitRetireOldIncarnations() throws {
        let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint)
        let receiver = try receiver(endpoint, expression: peer.expression)
        let first = try receiver.receive(timeoutMilliseconds: 5000)
        XCTAssertEqual(first.payload, Data("pid=123".utf8))
        XCTAssertEqual(first.caller.requester.pid, UInt32(peer.pid))
        XCTAssertEqual(first.caller.requester.signing.status, .adHoc)
        XCTAssertEqual(first.caller.requester.signing.identifier, "dev.remozio.command-caller.fixture")
        try first.caller.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil)
        try peer.advance()
        let second = try receiver.receive(timeoutMilliseconds: 5000)
        XCTAssertEqual(second.payload, Data("next".utf8))
        XCTAssertEqual(second.caller.requester.pid, first.caller.requester.pid)
        XCTAssertNotEqual(second.caller.requester.pidVersion, first.caller.requester.pidVersion)
        XCTAssertThrowsError(try first.caller.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil))
        XCTAssertThrowsError(try first.caller.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .retired)
        }
        try second.caller.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil)
        try peer.stop()
        XCTAssertThrowsError(try second.caller.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil))
        XCTAssertThrowsError(try second.caller.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .retired)
        }
    }

    func testAncestryUsesActualParentIncarnationAndKeepsItsBoundedPrefix() throws {
        let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint)
        let submission = try receiver(endpoint, expression: peer.expression).receive(timeoutMilliseconds: 5000)
        defer { submission.caller.close() }
        var selfToken = audit_token_t(), missing = false
        XCTAssertEqual(remozio_pid_audit_token(getpid(), &selfToken, &missing), KERN_SUCCESS)
        let capture = try submission.caller.captureAncestry(expression: peer.expression, userID: geteuid(),
            auditSessionID: nil, maximumEntries: 1)
        XCTAssertEqual(capture.entries.count, 1)
        XCTAssertEqual(capture.entries.first?.pid, UInt32(getpid()))
        XCTAssertEqual(capture.entries.first?.pidVersion, UInt32(bitPattern: audit_token_to_pidversion(selfToken)))
        XCTAssertEqual(capture.entries.first?.uid, geteuid())
        XCTAssertNotNil(capture.entries.first?.executablePath)
        XCTAssertEqual(capture.completeness, .partial)
        XCTAssertEqual(capture.reason, .truncated)
        let disabled = try submission.caller.captureAncestry(expression: peer.expression, userID: geteuid(),
            auditSessionID: nil, maximumEntries: 0)
        XCTAssertEqual(disabled.completeness, .unavailable)
        XCTAssertEqual(disabled.reason, .truncated)
        XCTAssertTrue(disabled.entries.isEmpty)
        try peer.advance()
        let next = try receiver(endpoint, expression: peer.expression).receive(timeoutMilliseconds: 5000)
        defer { next.caller.close() }
        XCTAssertEqual(next.caller.requester.pid, submission.caller.requester.pid)
        XCTAssertNotEqual(next.caller.requester.pidVersion, submission.caller.requester.pidVersion)
        XCTAssertThrowsError(try submission.caller.captureAncestry(expression: peer.expression, userID: geteuid(), auditSessionID: nil))
        XCTAssertThrowsError(try submission.caller.captureAncestry(expression: peer.expression, userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .retired)
        }
        try peer.stop()
        XCTAssertThrowsError(try next.caller.captureAncestry(expression: peer.expression, userID: geteuid(), auditSessionID: nil))
        XCTAssertThrowsError(try next.caller.captureAncestry(expression: peer.expression, userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .retired)
        }
    }

    func testAncestryRechecksCurrentPolicyAndPropagatesCancellation() throws {
        enum Cancelled: Error { case test }
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        try endpoint.send(Data([1]))
        let submission = try receiver.receive(timeoutMilliseconds: 1000)
        for limit in [-1, 65] {
            XCTAssertThrowsError(try submission.caller.captureAncestry(expression: selfExpression(), userID: geteuid(),
                auditSessionID: nil, maximumEntries: limit)) { XCTAssertEqual($0 as? MachCommandCallerError, .configuration) }
        }
        XCTAssertThrowsError(try submission.caller.captureAncestry(expression: selfExpression(), userID: geteuid(),
            auditSessionID: nil, checkCancellation: { throw Cancelled.test })) { XCTAssertTrue($0 is Cancelled) }
        try submission.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        XCTAssertThrowsError(try submission.caller.captureAncestry(expression: selfExpression(), userID: geteuid() ^ 1,
            auditSessionID: nil)) { XCTAssertEqual($0 as? MachCommandCallerError, .wrongPeer) }
        XCTAssertThrowsError(try submission.caller.captureAncestry(expression: selfExpression(), userID: geteuid(),
            auditSessionID: nil)) { XCTAssertEqual($0 as? MachCommandCallerError, .retired) }
    }

    private var assemblyLimits: CBORLimits { get throws { try CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024) } }
    private var assemblyBinding: Data { Data(repeating: 0xb1, count: 16) }
    private var assemblyTarget: CommandTarget {
        .init(uid: geteuid(), gid: getegid(), supplementaryGroups: [getegid()], observedName: nil)
    }
    private var assemblyEnvironment: [CapturedEnvironmentEntry] {
        [.init(name: Data("PATH".utf8), value: Data("/synthetic/baseline".utf8), source: .minimal),
         .init(name: Data("HOME".utf8), value: Data("/synthetic/home".utf8), source: .minimal)]
    }
    private func commandSubmission(executablePath: String = "/usr/bin/true", arguments: [Data]? = nil, binding: CapturedSubmission? = nil,
                                   disconnect: StartedCommandDisconnect = .terminate, ioMode: CommandIOMode = .pipes) throws -> CommandSubmission {
        try CommandSubmission(schemaVersion: 1, executablePath: Data(executablePath.utf8),
            arguments: arguments ?? [Data("custom argv0".utf8), Data(), Data([0xff, 0x0a, 0x22])],
            directoryPath: Data(FileManager.default.temporaryDirectory.path.utf8), requestedTargetUID: geteuid(),
            environmentAdditions: [.init(name: Data("HOME".utf8), value: Data("/synthetic/requested".utf8)),
                .init(name: Data("RAW".utf8), value: Data([0xfe, 0x0a]))],
            ioMode: ioMode, disconnectBehavior: disconnect, unverifiedRationale: "pid=123, caller claim",
            binding: binding ?? .init(id: Data(repeating: 0xb2, count: 16), nonce: Data(repeating: 0xb3, count: 32), callerBinding: assemblyBinding),
            limits: assemblyLimits)
    }
    private func assemble(_ received: ReceivedMachCommandInputSubmission, binding: Data? = nil, schema: UInt64 = 1,
                          submissionSchema: UInt64 = 1, target: CommandTarget? = nil, minimal: [CapturedEnvironmentEntry]? = nil,
                          limits: CBORLimits? = nil, checkCancellation: @Sendable () throws -> Void = {},
                           admissionProfile: CommandHandshakeProfile? = nil, callerExpression: String? = nil) throws -> RetainedCommandCapture {
        try RetainedCommandCapture(received: TestInputInspection(received: received).received, expectedCallerBinding: binding ?? assemblyBinding,
            submissionSchemaVersion: submissionSchema, captureSchemaVersion: schema, expression: callerExpression ?? selfExpression(),
            userID: geteuid(), auditSessionID: nil, resolvedTarget: target ?? assemblyTarget,
            minimalEnvironment: minimal ?? assemblyEnvironment, streamBinding: Data(repeating: 0xb4, count: 16),
            submissionLimits: assemblyLimits, captureLimits: limits ?? assemblyLimits, maximumAncestryEntries: 1,
            checkCancellation: checkCancellation, admissionProfile: admissionProfile)
    }
    private func expectAssemblyResourcesRetired(_ received: ReceivedMachCommandInputSubmission) throws {
        XCTAssertThrowsError(try received.input.withBorrowedDescriptor { _ in () }) {
            XCTAssertEqual($0 as? RetainedCommandInputError, .closed)
        }
        XCTAssertThrowsError(try received.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .retired)
        }
    }

    func testAssembledCommandPreservesInvocationAndUnreadOriginalInput() throws {
        var pipeFDs: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&pipeFDs), 0)
        defer { for fd in pipeFDs { _ = Darwin.close(fd) } }
        let queued = Data("unconsumed source".utf8)
        XCTAssertEqual(queued.withUnsafeBytes { Darwin.write(pipeFDs[1], $0.baseAddress, $0.count) }, queued.count)
        let claims = try commandSubmission(), received = try inputSubmission(pipeFDs[0], payload: claims.canonicalBytes)
        let owner = try assemble(received)
        defer { owner.close() }
        let value = owner.capture
        XCTAssertEqual(value.arguments, claims.arguments)
        XCTAssertEqual(value.target, assemblyTarget)
        XCTAssertEqual(value.requester, received.caller.requester)
        XCTAssertEqual(value.requester.pid, UInt32(getpid()))
        XCTAssertEqual(value.unverifiedRationale, claims.unverifiedRationale)
        XCTAssertEqual(value.submission, claims.binding)
        XCTAssertEqual(value.input.kind, .pipe)
        XCTAssertEqual(value.input.streamBinding, Data(repeating: 0xb4, count: 16))
        XCTAssertEqual(value.environment.map(\.name), ["HOME", "PATH", "RAW"].map { Data($0.utf8) })
        XCTAssertEqual(value.environment.map(\.source), [.requested, .minimal, .requested])
        XCTAssertEqual(value.environment.map(\.value), [Data("/synthetic/requested".utf8), Data("/synthetic/baseline".utf8), Data([0xfe, 0x0a])])
        let decoded = try CommandCapture(canonicalBytes: value.canonicalBytes, limits: assemblyLimits)
        XCTAssertEqual(decoded, value)
        try owner.withBorrowedDirectoryDescriptor { fd in
            var directory = stat()
            XCTAssertEqual(fstat(fd, &directory), 0)
            XCTAssertEqual(directory.st_ino, value.directory.identity.inode)
            XCTAssertEqual(UInt64(UInt32(bitPattern: directory.st_dev)), value.directory.identity.device)
        }
        let issued = try IssuedRequestPayload(contract: RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1),
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16), requestID: Data(repeating: 3, count: 16),
            challenge: Data(repeating: 4, count: 32), requiredFeatures: [], createdUnixMilliseconds: 10, expiresUnixMilliseconds: 20,
            canonicalCapture: value.canonicalBytes, permittedActions: [.init(choice: .execute, scope: .currentRequest)],
            bodyLimits: assemblyLimits, captureLimits: assemblyLimits)
        let issuedAgain = try IssuedRequestPayload.decode(issued.encode(limits: assemblyLimits), bodyLimits: assemblyLimits,
            captureLimits: assemblyLimits, localCapabilities: ContractCapabilities(contracts: [issued.contract: []]))
        XCTAssertEqual(issuedAgain.canonicalCapture, value.canonicalBytes)
        try owner.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        try owner.withBorrowedInputDescriptor { fd in
            var bytes = [UInt8](repeating: 0, count: queued.count)
            XCTAssertEqual(Darwin.read(fd, &bytes, bytes.count), bytes.count)
            XCTAssertEqual(Data(bytes), queued)
        }
        owner.close(); owner.close()
        XCTAssertThrowsError(try owner.withBorrowedInputDescriptor { _ in () }) {
            XCTAssertEqual($0 as? RetainedCommandCaptureError, .closed)
        }
        XCTAssertThrowsError(try owner.withBorrowedDirectoryDescriptor { _ in () }) {
            XCTAssertEqual($0 as? RetainedCommandCaptureError, .closed)
        }
        try expectAssemblyResourcesRetired(received)
    }

    func testAssemblyRejectsWrongBindingsSchemasTargetsAndInvalidMinimalEnvironment() throws {
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { _ = Darwin.close(fd) }
        let claims = try commandSubmission()
        let cases: [(ReceivedMachCommandInputSubmission) throws -> RetainedCommandCapture] = [
            { try self.assemble($0, binding: Data(repeating: 0xcc, count: 16)) },
            { try self.assemble($0, binding: Data()) }, { try self.assemble($0, schema: 3) },
            { try self.assemble($0, submissionSchema: 2) },
            { try self.assemble($0, target: .init(uid: self.assemblyTarget.uid ^ 1, gid: 0, supplementaryGroups: [], observedName: nil)) },
            { try self.assemble($0, minimal: self.assemblyEnvironment + self.assemblyEnvironment) },
            { try self.assemble($0, minimal: [.init(name: Data("PATH".utf8), value: Data(), source: .requested)]) },
            { try self.assemble($0, minimal: [.init(name: Data("INVALID=NAME".utf8), value: Data(), source: .minimal)]) }
        ]
        for build in cases {
            let received = try inputSubmission(fd, payload: claims.canonicalBytes)
            XCTAssertThrowsError(try build(received))
            try expectAssemblyResourcesRetired(received)
        }
        let malformed = try inputSubmission(fd, payload: Data([1]))
        XCTAssertThrowsError(try assemble(malformed))
        try expectAssemblyResourcesRetired(malformed)
    }

    func testAssemblyDoesNotDowngradeSocketInputToSchemaOne() throws {
        var pair: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer { for fd in pair { _ = Darwin.close(fd) } }
        let claims = try commandSubmission()
        let old = try inputSubmission(pair[0], payload: claims.canonicalBytes)
        XCTAssertThrowsError(try assemble(old)) { XCTAssertEqual($0 as? CommandCaptureError, .enumeration) }
        try expectAssemblyResourcesRetired(old)
        let received = try inputSubmission(pair[0], payload: claims.canonicalBytes)
        let owner = try assemble(received, schema: 2)
        defer { owner.close() }
        XCTAssertEqual(owner.capture.schemaVersion, 2)
        XCTAssertEqual(owner.capture.input.kind, .socket)
        XCTAssertNil(owner.capture.input.observedPath)
        XCTAssertEqual(try CommandCapture(canonicalBytes: owner.capture.canonicalBytes, limits: assemblyLimits, expectedSchemaVersion: 2), owner.capture)
    }

    func testAssemblyOverflowAndCancellationRetireResourcesWithoutReadingInput() throws {
        enum Cancelled: Error { case test }
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { _ = Darwin.close(fd) }
        let claims = try commandSubmission()
        let oversized = try inputSubmission(fd, payload: claims.canonicalBytes)
        XCTAssertThrowsError(try assemble(oversized, limits: CBORLimits(maxBytes: 20, maxDepth: 16, maxItems: 1024))) {
            XCTAssertEqual($0 as? CBORError, .limitExceeded(.bytes))
        }
        try expectAssemblyResourcesRetired(oversized)
        let cancelled = try inputSubmission(fd, payload: claims.canonicalBytes)
        let checks = OSAllocatedUnfairLock(initialState: 0)
        XCTAssertThrowsError(try assemble(cancelled, checkCancellation: {
            if checks.withLock({ $0 += 1; return $0 }) == 2 { throw Cancelled.test }
        })) {
            XCTAssertTrue($0 is Cancelled)
        }
        try expectAssemblyResourcesRetired(cancelled)
    }

    func testAssemblyRecheckRetiresOwnerAfterExecutableReplacementOrPolicyFailure() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let program = directory.appendingPathComponent("program")
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: program)
        XCTAssertEqual(chmod(program.path, 0o755), 0)
        let claims = try commandSubmission(executablePath: program.path)
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { _ = Darwin.close(fd) }
        let received = try inputSubmission(fd, payload: claims.canonicalBytes), owner = try assemble(received)
        let captured = owner.capture
        try FileManager.default.removeItem(at: program)
        try Data("#!/bin/sh\nexit 1\n".utf8).write(to: program)
        XCTAssertEqual(chmod(program.path, 0o755), 0)
        XCTAssertThrowsError(try owner.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil))
        XCTAssertEqual(owner.capture, captured)
        try expectAssemblyResourcesRetired(received)
        XCTAssertThrowsError(try owner.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? RetainedCommandCaptureError, .closed)
        }
        let nextReceived = try inputSubmission(fd, payload: claims.canonicalBytes), next = try assemble(nextReceived)
        XCTAssertThrowsError(try next.recheck(expression: selfExpression(), userID: geteuid() ^ 1, auditSessionID: nil))
        try expectAssemblyResourcesRetired(nextReceived)
    }

    private final class CommandRequestFixture {
        let root: URL
        let db: JournalDatabase
        let writer: AuditEpochWriter
        private let standaloneRequests: ApprovalRequestCoordinator?
        var requests: ApprovalRequestCoordinator { standaloneRequests! }
        let authority: AuthorityJournal?
        let clock = UUID()
        let biometric = P256.Signing.PrivateKey()
        let decision = P256.Signing.PrivateKey()
        let limits: CBORLimits
        let contract: RequestContract
        var continuity: ContinuityStore?
        init(maximumRequests: Int = 8, checkpointed: Bool = false, owned: Bool = false, ready: Bool = true, commandSchema: UInt64 = 1,
             installReplay: Bool = true, maximumSubmissions: Int = 30, retiredEnrollmentEpoch: UInt8? = nil) throws {
            limits = try CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024)
            contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: commandSchema)
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw MachCommandCallerError.unavailable }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            let directory = root.appendingPathComponent("store")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory.appendingPathComponent(name).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw MachCommandCallerError.unavailable }; _ = Darwin.close(fd)
            }
            let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16), epoch = Data(repeating: 3, count: 16)
            db = try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()),
                macID: mac, accountID: account, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 30, busyMilliseconds: 100, initialize: true, maximumCommandSubmissions: maximumSubmissions)
            if installReplay {
                let policy = try AuthorityCodePolicy(entries: [AuthorityCodeEntry(role: .commandFrontend, teamID: "TEAMID1234",
                    identifier: "dev.remozio.test.frontend", installedGeneration: 1, minimumGeneration: 1,
                    codeDirectoryHash: Data(repeating: 1, count: 20), active: true)])
                try db.write { transaction in
                    _ = try transaction.installCodePolicy(policy, expectedRevision: nil)
                    try transaction.installCommandSubmissionReplay()
                }
            }
            let contract = self.contract
            let capabilities = ContractCapabilities(contracts: [contract: []])
            let revision = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account), 3: .bytes(epoch), 4: .unsigned(1),
                5: .unsigned(1), 6: .null, 7: .null, 8: .null,
            ]), limits: limits), limits: limits)
            let writer = try db.write { try $0.createEpoch(descriptor) }
            self.writer = writer
            let enrollment = try StoredApprovalEnrollment(epoch: Data(repeating: 9, count: 16), notificationTag: Data(repeating: 10, count: 32),
                identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                approval: ApprovalEnrollment(phoneID: Data(repeating: 5, count: 16), active: true, capabilities: capabilities, keys: [
                    EnrolledApprovalKey(id: Data(repeating: 6, count: 16), keyClass: .biometric, publicKey: biometric.publicKey.x963Representation),
                    EnrolledApprovalKey(id: Data(repeating: 7, count: 16), keyClass: .decision, publicKey: decision.publicKey.x963Representation),
                ]))
            var enrollmentRevision = revision
            var enrollmentHead: UInt64 = 0
            if let retiredEnrollmentEpoch {
                let historical = try StoredApprovalEnrollment(epoch: Data(repeating: retiredEnrollmentEpoch, count: 16),
                    notificationTag: Data(repeating: 11, count: 32),
                    identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                    approval: ApprovalEnrollment(phoneID: enrollment.approval.phoneID, active: true,
                        capabilities: capabilities, keys: [
                            EnrolledApprovalKey(id: Data(repeating: 12, count: 16), keyClass: .biometric,
                                publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                            EnrolledApprovalKey(id: Data(repeating: 13, count: 16), keyClass: .decision,
                                publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                        ]))
                enrollmentRevision = try db.write { try $0.addApprovalEnrollment(historical, expectedTrustRevision: enrollmentRevision,
                    eventID: Data(repeating: 28, count: 16), receiptTimeMs: nil, writer: writer, expectedAuditHead: 0) }
                enrollmentRevision = try db.write { try $0.revokeApprovalEnrollment(phoneID: historical.approval.phoneID,
                    epoch: historical.epoch, expectedTrustRevision: enrollmentRevision, eventID: Data(repeating: 29, count: 16),
                    receiptTimeMs: nil, writer: writer, expectedAuditHead: 1).revision }
                enrollmentHead = 2
            }
            _ = try db.write { try $0.addApprovalEnrollment(enrollment, expectedTrustRevision: enrollmentRevision,
                eventID: Data(repeating: 30, count: 16), receiptTimeMs: nil, writer: writer, expectedAuditHead: enrollmentHead) }
            if checkpointed {
                let directory = root.appendingPathComponent("continuity")
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
                for name in ["writer.lock", "continuity.sqlite"] {
                    let fd = Darwin.open(directory.appendingPathComponent(name).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                    guard fd >= 0 else { throw MachCommandCallerError.unavailable }; _ = Darwin.close(fd)
                }
                let initial = try db.read { try CheckpointedJournal.checkpoint(transaction: $0, epoch: writer.epoch,
                    generation: 1, authorityGeneration: 1) }
                let store = try ContinuityStore(lease: ProtectedContinuityLease(anchor: root.path, relativeDirectory: "continuity", owner: getuid()),
                    macID: mac, accountID: account, initialize: initial)
                continuity = store
                if owned {
                    try db.close(); store.close()
                    let anchor = root.path, limits = self.limits
                    let storage = try AuthorityStorage(openJournal: {
                        try JournalDatabase(lease: ProtectedJournalLease(anchor: anchor, relativeDirectory: "store", owner: getuid()),
                            macID: mac, accountID: account, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                            maximumConsumptions: 30, busyMilliseconds: 100, initialize: false, maximumCommandSubmissions: maximumSubmissions)
                    }, openContinuity: { _ in
                        try ContinuityStore(lease: ProtectedContinuityLease(anchor: anchor, relativeDirectory: "continuity", owner: getuid()),
                            macID: mac, accountID: account, initialize: nil)
                    })
                    let authority = try AuthorityJournal(storage: storage)
                    if ready { try authority.prepareRequests(clockEpoch: clock, maximumPayloadBytes: 16384) }
                    self.authority = authority
                    standaloneRequests = nil
                } else {
                    authority = nil
                    standaloneRequests = try ApprovalRequestCoordinator(database: db, continuity: store, writer: writer, clockEpoch: clock,
                        maximumRequests: maximumRequests, maximumRetainedBytes: 65536, requestLimits: limits, captureLimits: limits,
                        decisionLimits: limits, signingLimits: limits, auditLimits: limits)
                }
            } else {
                if owned {
                    try db.close()
                    let ownedDatabase = try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()),
                        macID: mac, accountID: account, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                        maximumConsumptions: 30, busyMilliseconds: 100, initialize: false, maximumCommandSubmissions: maximumSubmissions)
                    let ownedDescriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                        0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account), 3: .bytes(Data(repeating: 4, count: 16)),
                        4: .unsigned(1), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
                    ]), limits: limits), limits: limits)
                    if ready {
                        let ownedWriter = try ownedDatabase.write { try $0.createEpoch(ownedDescriptor) }
                        let requests = try ApprovalRequestCoordinator(database: ownedDatabase, writer: ownedWriter, clockEpoch: clock,
                            maximumRequests: maximumRequests, maximumRetainedBytes: 65536, requestLimits: limits, captureLimits: limits,
                            decisionLimits: limits, signingLimits: limits, auditLimits: limits)
                        authority = AuthorityJournal(requests: requests)
                    } else {
                        authority = AuthorityJournal(database: ownedDatabase)
                    }
                    standaloneRequests = nil
                } else {
                    authority = nil
                    standaloneRequests = try ApprovalRequestCoordinator(database: db, writer: writer, clockEpoch: clock,
                        maximumRequests: maximumRequests, maximumRetainedBytes: 65536, requestLimits: limits, captureLimits: limits,
                        decisionLimits: limits, signingLimits: limits, auditLimits: limits)
                }
            }
        }
        deinit { try? authority?.close(); try? db.close(); continuity?.close(); try? FileManager.default.removeItem(at: root) }
        func now(_ milliseconds: UInt64 = 110) -> AuthorityMoment { .init(epoch: clock, milliseconds: milliseconds) }
        func draft(_ command: RetainedCommandCapture, capture: Data? = nil, contract: RequestContract? = nil,
                   actions: [CapturedAction]? = nil) -> ApprovalRequestDraft {
            .init(contract: contract ?? self.contract, requiredFeatures: [], capture: capture ?? command.capture.canonicalBytes,
                actions: actions ?? [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
                firstObservedAt: now(100), deadlineMilliseconds: 200, createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1100)
        }
        func consume(_ request: IssuedRequestPayload, decline: Bool = false) throws -> ConsumptionReceipt {
            let body = try DecisionPayload(macID: request.macID, accountID: request.accountID, requestID: request.requestID,
                requestDigest: request.requestDigest(bodyLimits: limits, signingLimits: limits), challenge: request.challenge,
                phoneID: Data(repeating: 5, count: 16), keyID: Data(repeating: decline ? 7 : 6, count: 16),
                action: request.permittedActions.first { $0.choice == (decline ? .decline : .execute) }!).encode(limits: limits)
            let signature = try (decline ? decision : biometric).signature(for: SigningInput.make(wireVersion: 1, messageType: .decision,
                purpose: decline ? .cancellation : .biometricAuthorization, canonicalPayload: body, payloadLimits: limits, inputLimits: limits)).rawRepresentation
            return try requests.consume(canonicalDecision: body, signature: signature, authenticatedPhoneID: Data(repeating: 5, count: 16),
                authenticatedEnrollmentEpoch: Data(repeating: 9, count: 16), now: now(120), receiptTimeMs: nil)
        }
        var auditHead: UInt64 { get throws { try db.read { try XCTUnwrap($0.epoch(writer.epoch)).head } } }
        var auditRecordCount: Int64 {
            get throws {
                var connection: OpaquePointer?, row: OpaquePointer?
                guard sqlite3_open_v2(root.appendingPathComponent("store/journal.sqlite").path, &connection, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
                      let connection else { throw MachCommandCallerError.unavailable }
                defer { sqlite3_close(connection) }
                guard sqlite3_prepare_v2(connection, "SELECT count(*) FROM audit_records_v1", -1, &row, nil) == SQLITE_OK,
                      let row else { throw MachCommandCallerError.unavailable }
                defer { sqlite3_finalize(row) }
                guard sqlite3_step(row) == SQLITE_ROW else { throw MachCommandCallerError.unavailable }
                return sqlite3_column_int64(row, 0)
            }
        }
        func reservation(_ submissionID: Data) throws -> CommandSubmissionReservation? {
            if let authority { return try authority.read { try $0.commandSubmissionReservation(submissionID: submissionID) } }
            return try db.read { try $0.commandSubmissionReservation(submissionID: submissionID) }
        }
        func sql(_ statement: String, continuity: Bool = false) throws {
            var connection: OpaquePointer?
            guard sqlite3_open(root.appendingPathComponent(continuity ? "continuity/continuity.sqlite" : "store/journal.sqlite").path, &connection) == SQLITE_OK,
                  let connection else { throw MachCommandCallerError.unavailable }
            defer { sqlite3_close(connection) }
            guard sqlite3_exec(connection, statement, nil, nil, nil) == SQLITE_OK else { throw MachCommandCallerError.unavailable }
        }
    }
    private func admitCommand(_ command: RetainedCommandCapture, fixture: CommandRequestFixture,
                              draft: ApprovalRequestDraft? = nil, userID: uid_t? = nil, nowMilliseconds: UInt64 = 110,
                              checkCancellation: () throws -> Void = {}) throws -> IssuedRequestPayload {
        try fixture.requests.admitCommand(command, draft: draft ?? fixture.draft(command), expression: selfExpression(),
            userID: userID ?? geteuid(), auditSessionID: nil, now: { fixture.now(nowMilliseconds) }, receiptTimeMs: nil, checkCancellation: checkCancellation)
    }
    private func requestCommand(binding: CapturedSubmission? = nil, inputFD: Int32? = nil) throws -> (ReceivedMachCommandInputSubmission, RetainedCommandCapture) {
        let fd = inputFD ?? Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw MachCommandCallerError.unavailable }
        defer { if inputFD == nil { _ = Darwin.close(fd) } }
        let received = try inputSubmission(fd, payload: commandSubmission(binding: binding).canonicalBytes)
        return (received, try assemble(received))
    }

    func testCommandReplayAdmissionCommitsOriginalBindingAndCaptureDigest() throws {
        for checkpointed in [false, true] {
            for owned in [false, true] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: owned)
                let (_, command) = try requestCommand(), capture = command.capture, head = try fixture.auditRecordCount
                let request = try owned ? admitOwnedCommand(command, fixture: fixture) : admitCommand(command, fixture: fixture)
                let reserved = try XCTUnwrap(fixture.reservation(capture.submission.id))
                XCTAssertEqual(reserved.macID, request.macID); XCTAssertEqual(reserved.accountID, request.accountID)
                XCTAssertEqual(reserved.submission, capture.submission)
                XCTAssertEqual(reserved.captureDigest, Data(SHA256.hash(data: capture.canonicalBytes)))
                XCTAssertEqual(try fixture.auditRecordCount, head + 1)
                if let store = fixture.continuity, !owned {
                    let checkpoint = try store.read()
                    XCTAssertNil(checkpoint.pending)
                    XCTAssertEqual(checkpoint.committed.journalHead, UInt64(head + 1))
                }
                try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            }
        }
    }

    func testCommandReplayAdmissionRejectsIndependentIDAndNonceReuseWithoutRetiringFirstRequest() throws {
        for checkpointed in [false, true] {
            for owned in [false, true] {
                for reusedID in [false, true] {
                    let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: owned)
                    var descriptors: [Int32] = [-1, -1]
                    XCTAssertEqual(pipe(&descriptors), 0)
                    defer { for fd in descriptors { _ = Darwin.close(fd) } }
                    let queued = Data("original unread input".utf8)
                    XCTAssertEqual(queued.withUnsafeBytes { Darwin.write(descriptors[1], $0.baseAddress, $0.count) }, queued.count)
                    let (received, first) = try requestCommand(inputFD: descriptors[0]), binding = first.capture.submission
                    let request = try owned ? admitOwnedCommand(first, fixture: fixture) : admitCommand(first, fixture: fixture)
                    let before = try fixture.reservation(binding.id), head = try fixture.auditRecordCount
                    let replay = CapturedSubmission(id: reusedID ? binding.id : Data(repeating: 0xc2, count: 16),
                        nonce: reusedID ? Data(repeating: 0xc3, count: 32) : binding.nonce, callerBinding: binding.callerBinding)
                    let (incoming, second) = try requestCommand(binding: replay)
                    XCTAssertThrowsError(try owned ? admitOwnedCommand(second, fixture: fixture) : admitCommand(second, fixture: fixture)) {
                        XCTAssertEqual($0 as? CommandSubmissionReplayError, .alreadyReserved)
                    }
                    try expectAssemblyResourcesRetired(incoming)
                    XCTAssertEqual(try fixture.auditRecordCount, head)
                    XCTAssertEqual(try fixture.reservation(binding.id), before)
                    if !reusedID { XCTAssertNil(try fixture.reservation(replay.id)) }
                    let state: ApprovalRequestState
                    if let authority = fixture.authority {
                        state = try authority.withRequests { try $0.state(requestID: request.requestID) }
                    } else { state = try fixture.requests.state(requestID: request.requestID) }
                    XCTAssertEqual(state.phase, .queued)
                    try received.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
                    try first.withBorrowedInputDescriptor { fd in
                        var bytes = [UInt8](repeating: 0, count: queued.count)
                        XCTAssertEqual(Darwin.read(fd, &bytes, bytes.count), queued.count)
                        XCTAssertEqual(Data(bytes), queued)
                    }
                }
            }
        }
    }

    func testCommandReplayAdmissionAuditFailureRollsBackReservationAndAllowsFreshCapture() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed), (received, command) = try requestCommand()
            let binding = command.capture.submission, head = try fixture.auditRecordCount
            let boundary = try fixture.continuity?.read()
            try fixture.sql("CREATE TRIGGER reject_replay_admission BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture))
            try expectAssemblyResourcesRetired(received)
            XCTAssertNil(try fixture.reservation(binding.id)); XCTAssertEqual(try fixture.auditRecordCount, head)
            if let boundary { XCTAssertEqual(try fixture.continuity?.read(), boundary) }
            try fixture.sql("DROP TRIGGER reject_replay_admission")
            let (_, fresh) = try requestCommand(binding: binding)
            _ = try admitCommand(fresh, fixture: fixture)
            XCTAssertNotNil(try fixture.reservation(binding.id)); XCTAssertEqual(try fixture.auditRecordCount, head + 1)
        }
    }

    func testCommandReplayAdmissionCapacityDoesNotEvictEvidenceOrCloseEarlierCommand() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, maximumSubmissions: 1)
            let (_, first) = try requestCommand(), original = first.capture.submission
            let request = try admitCommand(first, fixture: fixture), head = try fixture.auditRecordCount
            let binding = CapturedSubmission(id: Data(repeating: 0xc2, count: 16), nonce: Data(repeating: 0xc3, count: 32),
                callerBinding: original.callerBinding)
            let (incoming, second) = try requestCommand(binding: binding)
            XCTAssertThrowsError(try admitCommand(second, fixture: fixture)) {
                XCTAssertEqual($0 as? CommandSubmissionReplayError, .capacityExceeded)
            }
            try expectAssemblyResourcesRetired(incoming)
            XCTAssertEqual(try fixture.auditRecordCount, head); XCTAssertNil(try fixture.reservation(binding.id))
            XCTAssertNotNil(try fixture.reservation(original.id))
            XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .queued)
            try first.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        }
    }

    func testCommandReplayAdmissionRequiresExplicitInstalledStoreBeforePublication() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, installReplay: false)
            let (received, command) = try requestCommand(), head = try fixture.auditRecordCount
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture)) {
                XCTAssertEqual($0 as? CommandSubmissionReplayError, .unavailable)
            }
            try expectAssemblyResourcesRetired(received)
            XCTAssertEqual(try fixture.auditRecordCount, head)
            XCTAssertNil(try fixture.db.read { try $0.codePolicy() })
        }
    }

    func testCommandReplayAdmissionPendingRetirementNeverFreesIDOrNonce() throws {
        for checkpointed in [false, true] {
            for decline in [false, true] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed), (_, command) = try requestCommand()
                let binding = command.capture.submission, request = try admitCommand(command, fixture: fixture)
                if decline { _ = try fixture.consume(request, decline: true) }
                else { _ = try fixture.requests.retirePending(requestID: request.requestID, reason: .cancelled, now: fixture.now(120), receiptTimeMs: nil) }
                let reserved = try fixture.reservation(binding.id), head = try fixture.auditRecordCount
                let (received, replay) = try requestCommand(binding: binding)
                XCTAssertThrowsError(try admitCommand(replay, fixture: fixture, nowMilliseconds: 120)) {
                    XCTAssertEqual($0 as? CommandSubmissionReplayError, .alreadyReserved)
                }
                try expectAssemblyResourcesRetired(received)
                XCTAssertEqual(try fixture.reservation(binding.id), reserved); XCTAssertNotNil(reserved)
                XCTAssertEqual(try fixture.auditRecordCount, head)
            }
        }
    }

    func testCommandReplayAdmissionRestartReconcilesAuditAndReservationTogether() throws {
        for stage in 0..<3 {
            let fixture = try CommandRequestFixture(checkpointed: true), (received, command) = try requestCommand()
            let binding = command.capture.submission, captureDigest = Data(SHA256.hash(data: command.capture.canonicalBytes))
            let originalStore = try XCTUnwrap(fixture.continuity), before = try originalStore.read().committed
            let count = try fixture.auditRecordCount
            var issued: IssuedRequestPayload?
            if stage == 0 {
                issued = try admitCommand(command, fixture: fixture)
            } else {
                let condition = stage == 1 ? "NEW.pending IS NOT NULL" : "NEW.pending IS NULL"
                try fixture.sql("CREATE TRIGGER reject_admission_checkpoint BEFORE UPDATE ON continuity_v1 WHEN \(condition) BEGIN SELECT RAISE(ABORT,'injected'); END", continuity: true)
                XCTAssertThrowsError(try issued = admitCommand(command, fixture: fixture))
                XCTAssertNil(issued)
                try expectAssemblyResourcesRetired(received)
                try fixture.sql("DROP TRIGGER reject_admission_checkpoint", continuity: true)
            }
            let state = try originalStore.read()
            XCTAssertEqual(state.pending != nil, stage == 2)
            fixture.requests.close()
            try expectAssemblyResourcesRetired(received)
            try fixture.db.close(); originalStore.close()
            let journal = try JournalDatabase(lease: ProtectedJournalLease(anchor: fixture.root.path, relativeDirectory: "store", owner: getuid()),
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16), recordLimits: fixture.limits,
                descriptorLimits: fixture.limits, decisionLimits: fixture.limits, maximumConsumptions: 30, busyMilliseconds: 100, initialize: false)
            let store = try ContinuityStore(lease: ProtectedContinuityLease(anchor: fixture.root.path, relativeDirectory: "continuity", owner: getuid()),
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16), initialize: nil)
            defer { try? journal.close(); store.close() }
            let recovered = try JournalCheckpointRecovery.reconcile(journal: journal, continuity: store)
            if stage == 2 { XCTAssertEqual(recovered, .finalized(try XCTUnwrap(state.pending))) }
            else { XCTAssertEqual(recovered, .unchanged(stage == 0 ? state.committed : before)) }
            let reservation = try journal.read { try $0.commandSubmissionReservation(submissionID: binding.id) }
            XCTAssertEqual(reservation != nil, stage != 1)
            XCTAssertEqual(try fixture.auditRecordCount, count + (stage == 1 ? 0 : 1))
            if let reservation {
                XCTAssertEqual(reservation.submission, binding); XCTAssertEqual(reservation.captureDigest, captureDigest)
                let commits = CheckpointedJournal(journal: journal, continuity: store)
                XCTAssertThrowsError(try commits.write(epoch: fixture.writer.epoch, recoverRejectedBody: true) { try $0.reserveCommandSubmission(reservation) }) {
                    XCTAssertEqual($0 as? CommandSubmissionReplayError, .alreadyReserved)
                }
                XCTAssertFalse(commits.retired)
            }
        }
    }

    func testCommandAdmissionRetainsExactCaptureThroughBiometricConsumptionAndTerminalOutcome() throws {
        let fixture = try CommandRequestFixture(), (received, command) = try requestCommand()
        let request = try admitCommand(command, fixture: fixture)
        XCTAssertEqual(request.canonicalCapture, command.capture.canonicalBytes)
        XCTAssertEqual(try fixture.requests.pendingRequest(requestID: request.requestID, now: fixture.now(), receiptTimeMs: nil).payload, request)
        try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        _ = try fixture.requests.markPresented(requestID: request.requestID, now: fixture.now(), receiptTimeMs: nil)
        let receipt = try fixture.consume(request)
        XCTAssertEqual(receipt.decision.requestDigest, try request.requestDigest(bodyLimits: fixture.limits, signingLimits: fixture.limits))
        XCTAssertEqual(try fixture.requests.consumedRequest(requestID: request.requestID, now: fixture.now(120)).payload.canonicalCapture,
            command.capture.canonicalBytes)
        try received.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        _ = try fixture.requests.recordOutcome(requestID: request.requestID, expectedRevision: 0, event: .beginDispatch,
            now: fixture.now(120), receiptTimeMs: nil)
        try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        _ = try fixture.requests.recordOutcome(requestID: request.requestID, expectedRevision: 1, event: .verifySuccess,
            now: fixture.now(130), receiptTimeMs: nil)
        try expectAssemblyResourcesRetired(received)
        XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
        XCTAssertEqual(try fixture.requests.historicalOutcome(requestID: request.requestID)?.phase, .succeeded)
        XCTAssertNotNil(try fixture.reservation(command.capture.submission.id))
    }

    func testCommandDeclineAndPendingRetirementCloseOriginalObjects() throws {
        for reason in [PendingRequestRetirement.cancelled, .deadlineElapsed, .targetTimedOut, .targetDisappeared, .authorityRestart] {
            let fixture = try CommandRequestFixture(), (received, command) = try requestCommand()
            let request = try admitCommand(command, fixture: fixture)
            _ = try fixture.requests.retirePending(requestID: request.requestID, reason: reason,
                now: fixture.now(reason == .deadlineElapsed ? 200 : 120), receiptTimeMs: nil)
            try expectAssemblyResourcesRetired(received)
            XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
        }
        let fixture = try CommandRequestFixture(), (received, command) = try requestCommand()
        let request = try admitCommand(command, fixture: fixture)
        _ = try fixture.consume(request, decline: true)
        XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .declined)
        try expectAssemblyResourcesRetired(received)
    }

    func testCommandExpirySweepAndExplicitCloseRetireResources() throws {
        for sweep in [true, false] {
            let fixture = try CommandRequestFixture(), (received, command) = try requestCommand()
            let request = try admitCommand(command, fixture: fixture)
            if sweep { XCTAssertEqual(try fixture.requests.expirePending(now: fixture.now(200), receiptTimeMs: nil).first?.requestID, request.requestID) }
            else {
                fixture.requests.close(); fixture.requests.close()
                XCTAssertThrowsError(try fixture.requests.state(requestID: request.requestID))
            }
            try expectAssemblyResourcesRetired(received)
            XCTAssertNotNil(try fixture.reservation(command.capture.submission.id))
        }
    }

    func testCommandAdmissionRejectsCaptureActionSchemaAndPeerChangesWithoutAudit() throws {
        enum Cancelled: Error { case test }
        for variant in 0..<6 {
            let fixture = try CommandRequestFixture(), (received, command) = try requestCommand(), head = try fixture.auditHead
            let draft: ApprovalRequestDraft
            switch variant {
            case 0: draft = fixture.draft(command, capture: Data([0xa0]))
            case 1: draft = try fixture.draft(command, contract: RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 2))
            case 2: draft = fixture.draft(command, actions: [.init(choice: .execute, scope: .currentRequest)])
            case 3: draft = fixture.draft(command, actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .execute, scope: .currentRequest)])
            default: draft = fixture.draft(command)
            }
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture, draft: draft,
                userID: variant == 4 ? geteuid() ^ 1 : nil, checkCancellation: { if variant == 5 { throw Cancelled.test } }))
            XCTAssertEqual(try fixture.auditHead, head)
            XCTAssertNil(try fixture.reservation(command.capture.submission.id))
            try expectAssemblyResourcesRetired(received)
        }
    }

    func testCommandDuplicateOwnershipAndCapacityFailureKeepFirstRequestIntact() throws {
        let fixture = try CommandRequestFixture(maximumRequests: 1), (firstReceived, first) = try requestCommand()
        let request = try admitCommand(first, fixture: fixture), head = try fixture.auditHead
        XCTAssertThrowsError(try admitCommand(first, fixture: fixture)) { XCTAssertEqual($0 as? RetainedCommandCaptureError, .alreadyOwned) }
        XCTAssertEqual(try fixture.auditHead, head)
        try first.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        let (secondReceived, second) = try requestCommand()
        XCTAssertThrowsError(try admitCommand(second, fixture: fixture)) { XCTAssertEqual($0 as? ApprovalCoordinatorError, .capacityExceeded) }
        try expectAssemblyResourcesRetired(secondReceived)
        XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .queued)
        try firstReceived.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        fixture.requests.close()
        try expectAssemblyResourcesRetired(firstReceived)
    }

    func testCommandAdmissionSamplesClockAfterRecheckAndRejectsElapsedDeadline() throws {
        let fixture = try CommandRequestFixture(), (received, command) = try requestCommand(), head = try fixture.auditHead
        var rechecked = false, clockSampled = false
        XCTAssertThrowsError(try fixture.requests.admitCommand(command, draft: fixture.draft(command), expression: selfExpression(),
            userID: geteuid(), auditSessionID: nil, now: {
                XCTAssertTrue(rechecked); clockSampled = true
                return fixture.now(200)
            }, receiptTimeMs: nil, checkCancellation: { rechecked = true })) {
            XCTAssertEqual($0 as? ApprovalCoordinatorError, .invalidDraft)
        }
        XCTAssertTrue(clockSampled)
        XCTAssertEqual(try fixture.auditHead, head)
        try expectAssemblyResourcesRetired(received)
    }

    func testCommandCheckpointFailureClosesResourcesBeforeTheFailingOperationReturns() throws {
        for read in [true, false] {
            let fixture = try CommandRequestFixture(checkpointed: true), (received, command) = try requestCommand()
            let request = try admitCommand(command, fixture: fixture)
            try XCTUnwrap(fixture.continuity).close()
            if read { XCTAssertThrowsError(try fixture.requests.state(requestID: request.requestID)) }
            else {
                XCTAssertThrowsError(try fixture.requests.retirePending(requestID: request.requestID, reason: .cancelled,
                    now: fixture.now(120), receiptTimeMs: nil))
            }
            // No additional coordinator call can trigger deferred cleanup before these assertions.
            try expectAssemblyResourcesRetired(received)
            XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
        }
    }

    func testCommandFatalJournalOperationsCloseResourcesWithoutAnotherCoordinatorCall() throws {
        for checkpointed in [true, false] {
            for closed in [true, false] {
                for read in [true, false] {
                    let fixture = try CommandRequestFixture(checkpointed: checkpointed), (received, command) = try requestCommand()
                    let request = try admitCommand(command, fixture: fixture)
                    if closed { try fixture.db.close() }
                    else { XCTAssertEqual(chmod(fixture.root.appendingPathComponent("store/journal.sqlite").path, 0o644), 0) }
                    if read { XCTAssertThrowsError(try fixture.requests.state(requestID: request.requestID)) }
                    else {
                        XCTAssertThrowsError(try fixture.requests.retirePending(requestID: request.requestID, reason: .cancelled,
                            now: fixture.now(120), receiptTimeMs: nil))
                    }
                    try expectAssemblyResourcesRetired(received)
                    XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
                }
            }
        }
    }

    func testCommandOrdinaryJournalReadCallbackFailurePreservesLiveResources() throws {
        for checkpointed in [true, false] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed), (received, command) = try requestCommand()
            let request = try admitCommand(command, fixture: fixture)
            XCTAssertThrowsError(try fixture.requests.historicalOutcome(requestID: Data())) {
                XCTAssertEqual($0 as? ConsumptionJournalError, .wrongScope)
            }
            try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try received.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
            XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .queued)
        }
    }

    // Deliberate aliases let invalid callback tests inspect cleanup. Normal journal admission needs no wrapper.
    private struct TestCommandInspection: @unchecked Sendable { let command: RetainedCommandCapture }
    private func admitOwnedCommand(_ command: RetainedCommandCapture, fixture: CommandRequestFixture,
                                   draft: ApprovalRequestDraft? = nil, now: (() throws -> AuthorityMoment)? = nil,
                                   checkCancellation: () throws -> Void = {}, callerExpression: String? = nil) throws -> IssuedRequestPayload {
        let authority = try XCTUnwrap(fixture.authority)
        return try authority.admitCommand(command, draft: draft ?? fixture.draft(command), expression: callerExpression ?? selfExpression(), userID: geteuid(),
            auditSessionID: nil, now: now ?? { fixture.now() }, receiptTimeMs: nil, checkCancellation: checkCancellation)
    }

    func testJournalCommandTransferRetainsExactRequestUntilCommittedCancellation() throws {
        for checkpointed in [true, false] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
            let request = try admitOwnedCommand(command, fixture: fixture)
            XCTAssertEqual(request.canonicalCapture, command.capture.canonicalBytes)
            XCTAssertEqual(try authority.withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
            try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            let now = fixture.now(120)
            _ = try authority.withRequests { try $0.retirePending(requestID: request.requestID, reason: .cancelled, now: now, receiptTimeMs: nil) }
            try expectAssemblyResourcesRetired(received)
            XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
        }
    }

    func testJournalCommandPreflightFailureReleasesFirstTransfer() throws {
        for checkpointed in [true, false] {
            for failure in 0..<3 {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true, ready: failure != 0)
                let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
                if failure == 1 { try authority.close() }
                if failure == 2 { XCTAssertEqual(chmod(fixture.root.appendingPathComponent("store/journal.sqlite").path, 0o644), 0) }
                XCTAssertThrowsError(try admitOwnedCommand(command, fixture: fixture)) {
                    if failure == 0 { XCTAssertEqual($0 as? ApprovalCoordinatorError, .unavailable) }
                }
                try expectAssemblyResourcesRetired(received)
                XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
            }
        }
    }

    func testJournalCommandDuplicateAndCallbackReentryPreserveExistingOwner() throws {
        for checkpointed in [true, false] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
            let request = try admitOwnedCommand(command, fixture: fixture)
            XCTAssertThrowsError(try admitOwnedCommand(command, fixture: fixture)) {
                XCTAssertEqual($0 as? RetainedCommandCaptureError, .alreadyOwned)
            }
            let inspection = TestCommandInspection(command: command)
            let draft = fixture.draft(command), expression = try selfExpression(), uid = geteuid(), now = fixture.now()
            try authority.withRequests { _ in
                XCTAssertThrowsError(try authority.admitCommand(inspection.command, draft: draft, expression: expression,
                    userID: uid, auditSessionID: nil, now: { now }, receiptTimeMs: nil)) {
                    XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
                }
            }
            try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try received.caller.recheck(expression: expression, userID: uid, auditSessionID: nil)
            XCTAssertEqual(try authority.withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
        }
    }

    func testJournalCommandTransactionReentryClosesOnlyRejectedTransfer() throws {
        for checkpointed in [true, false] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), (originalReceived, original) = try requestCommand()
            let request = try admitOwnedCommand(original, fixture: fixture)
            let (received, command) = try requestCommand(), inspection = TestCommandInspection(command: command)
            let draft = fixture.draft(command), expression = try selfExpression(), uid = geteuid(), now = fixture.now()
            try authority.read { _ in
                XCTAssertThrowsError(try authority.admitCommand(inspection.command, draft: draft, expression: expression,
                    userID: uid, auditSessionID: nil, now: { now }, receiptTimeMs: nil)) {
                    XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
                }
            }
            try expectAssemblyResourcesRetired(received)
            XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
            try original.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try originalReceived.caller.recheck(expression: expression, userID: uid, auditSessionID: nil)
            XCTAssertEqual(try authority.withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
        }
    }

    func testJournalCommandClockCallbackCannotReenterAndFailureResetsAdmission() throws {
        for checkpointed in [true, false] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
            XCTAssertThrowsError(try admitOwnedCommand(command, fixture: fixture, now: {
                try authority.read { _ in () }
                return fixture.now()
            })) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive) }
            try expectAssemblyResourcesRetired(received)
            let (nextReceived, next) = try requestCommand()
            _ = try admitOwnedCommand(next, fixture: fixture)
            try next.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try nextReceived.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        }
    }

    func testCommandOwnerStorageFailureClosesResourcesBeforeReturning() throws {
        for checkpointed in [true, false] {
            for replaced in [true, false] {
                for operation in checkpointed ? [0, 1, 3] : [0, 1, 2] {
                    let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
                    let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
                    _ = try admitOwnedCommand(command, fixture: fixture)
                    let path = fixture.root.appendingPathComponent("store/journal.sqlite").path
                    if replaced { XCTAssertEqual(Darwin.rename(path, path + ".removed"), 0) }
                    else { XCTAssertEqual(chmod(path, 0o644), 0) }
                    switch operation {
                    case 0: XCTAssertThrowsError(try authority.read { _ in () })
                    case 1: XCTAssertThrowsError(try authority.withRequests { _ in XCTFail("fatal storage entered callback") })
                    case 2: XCTAssertThrowsError(try authority.write { _ in () })
                    default: XCTAssertThrowsError(try authority.prepareRequests(clockEpoch: UUID(), maximumPayloadBytes: 16384))
                    }
                    try expectAssemblyResourcesRetired(received)
                    XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
                }
            }
        }
    }

    func testCommandOwnerContinuityFailureClosesResourcesBeforeReturning() throws {
        for failure in 0..<4 {
            let fixture = try CommandRequestFixture(checkpointed: true, owned: true)
            let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
            _ = try admitOwnedCommand(command, fixture: fixture)
            let path = fixture.root.appendingPathComponent("continuity/continuity.sqlite").path
            switch failure {
            case 0: XCTAssertEqual(Darwin.rename(path, path + ".removed"), 0)
            case 1: XCTAssertEqual(chmod(path, 0o644), 0)
            case 2: try fixture.sql("UPDATE continuity_v1 SET repair=1 WHERE id=1", continuity: true)
            default: try fixture.sql("UPDATE audit_epochs_v1 SET head=X'0000000000000002'")
            }
            XCTAssertThrowsError(try authority.read { _ in () })
            try expectAssemblyResourcesRetired(received)
            XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
        }
    }

    func testCommandOwnerTemporaryStorageContentionPreservesResources() throws {
        for checkpointed in [true, false] {
            for continuity in checkpointed ? [true, false] : [false] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
                let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
                let request = try admitOwnedCommand(command, fixture: fixture)
                var connection: OpaquePointer?
                let path = fixture.root.appendingPathComponent(continuity ? "continuity/continuity.sqlite" : "store/journal.sqlite").path
                guard sqlite3_open(path, &connection) == SQLITE_OK, let connection else { throw MachCommandCallerError.unavailable }
                do {
                    defer { sqlite3_exec(connection, "ROLLBACK", nil, nil, nil); sqlite3_close(connection) }
                    XCTAssertEqual(sqlite3_exec(connection, "BEGIN EXCLUSIVE", nil, nil, nil), SQLITE_OK)
                    XCTAssertThrowsError(try authority.read { _ = try $0.approvalTrustSnapshot() })
                }
                try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
                try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
                try received.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
                XCTAssertEqual(try authority.withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
            }
        }
    }

    func testCommandOwnerCallbackRejectionAndReentryPreserveResources() throws {
        for checkpointed in [true, false] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
            let request = try admitOwnedCommand(command, fixture: fixture)
            XCTAssertThrowsError(try authority.read { _ in throw JournalDatabaseError.unavailable }) {
                XCTAssertEqual($0 as? JournalDatabaseError, .unavailable)
            }
            if !checkpointed {
                XCTAssertThrowsError(try authority.write { _ in throw JournalDatabaseError.unavailable })
            }
            XCTAssertThrowsError(try authority.withRequests { _ in throw JournalDatabaseError.unavailable })
            try authority.read { _ in
                XCTAssertThrowsError(try authority.withRequests { _ in () }) {
                    XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
                }
            }
            try authority.withRequests { _ in
                XCTAssertThrowsError(try authority.read { _ in () }) {
                    XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
                }
            }
            try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try received.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
            XCTAssertEqual(try authority.withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
        }
    }

    func testCommandCoordinatorDestructionClosesAnExternallyRetainedCapture() throws {
        let (received, command) = try requestCommand()
        do {
            let fixture = try CommandRequestFixture()
            _ = try admitCommand(command, fixture: fixture)
            try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        }
        try expectAssemblyResourcesRetired(received)
        XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
    }

    func testCommandClockFailureClosesOriginalObjects() throws {
        let fixture = try CommandRequestFixture(), (received, command) = try requestCommand()
        let request = try admitCommand(command, fixture: fixture)
        XCTAssertThrowsError(try fixture.requests.markPresented(requestID: request.requestID, now: fixture.now(109), receiptTimeMs: nil)) {
            XCTAssertEqual($0 as? ApprovalCoordinatorError, .invalidClock)
        }
        try expectAssemblyResourcesRetired(received)
    }

    func testCommandAdmissionAuditFailureReleasesObjectsAndRetirementRollbackKeepsThem() throws {
        for variant in 0..<4 {
            let admissionFailure = variant % 2 == 0
            let fixture = try CommandRequestFixture(checkpointed: variant >= 2), (received, command) = try requestCommand()
            let request = try admissionFailure ? nil : admitCommand(command, fixture: fixture)
            let head = try fixture.auditHead
            try fixture.sql("CREATE TRIGGER reject_command_event BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
            if admissionFailure {
                XCTAssertThrowsError(try admitCommand(command, fixture: fixture))
                try expectAssemblyResourcesRetired(received)
            } else {
                let request = try XCTUnwrap(request)
                XCTAssertThrowsError(try fixture.requests.retirePending(requestID: request.requestID, reason: .cancelled,
                    now: fixture.now(120), receiptTimeMs: nil))
                XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .queued)
                try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
                try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
                try fixture.sql("DROP TRIGGER reject_command_event")
                _ = try fixture.requests.retirePending(requestID: request.requestID, reason: .cancelled,
                    now: fixture.now(120), receiptTimeMs: nil)
                try expectAssemblyResourcesRetired(received)
            }
            if admissionFailure { XCTAssertEqual(try fixture.auditHead, head) }
            else { XCTAssertEqual(try fixture.auditHead, head + 1) }
        }
    }

    func testIOCarrierRetainsOriginalOutputPipesAndClosesOnlyImportedDescriptors() throws {
        let endpoint = try Endpoint(), admission = try Endpoint(), terminal = try Endpoint()
        var input: [Int32] = [-1, -1], output: [Int32] = [-1, -1], error: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&input), 0); XCTAssertEqual(pipe(&output), 0); XCTAssertEqual(pipe(&error), 0)
        defer { for fd in input + output + error { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(input[1], "unread", 6), 6)
        let flags = [input[0], output[1], error[1]].map { fcntl($0, F_GETFL) }
        try MachCommandIOWire.send(Data([0xa0]), inputDescriptor: input[0], outputDescriptor: output[1], errorDescriptor: error[1],
            destination: endpoint.port, admissionReply: admission.port, terminalReply: terminal.port,
            maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        let received = try receiver(endpoint, maximum: 8192).receiveIOInput(timeoutMilliseconds: 1000)
        let channels = try XCTUnwrap(received.outputs)
        XCTAssertEqual([input[0], output[1], error[1]].map { fcntl($0, F_GETFL) }, flags)
        XCTAssertEqual(received.carrierVersion, 4); XCTAssertEqual(received.payload, Data([0xa0]))
        try channels.recheck()
        try channels.output.withBorrowedDescriptor { XCTAssertEqual(Darwin.write($0, "out", 3), 3) }
        try channels.error.withBorrowedDescriptor { XCTAssertEqual(Darwin.write($0, "err", 3), 3) }
        received.closeIfUnclaimed()
        XCTAssertThrowsError(try channels.recheck())
        var control: [Int32] = [-1, -1]; XCTAssertEqual(pipe(&control), 0)
        defer { for fd in control { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(control[1], "out", 3), 3)
        XCTAssertEqual(fcntl(input[0], F_GETFL), flags[0])
        XCTAssertEqual(fcntl(output[1], F_GETFL), fcntl(control[1], F_GETFL))
        XCTAssertEqual(fcntl(error[1], F_GETFL), fcntl(control[1], F_GETFL))
        for (fd, expected) in [(input[0], "unread"), (output[0], "out"), (error[0], "err")] {
            var bytes = [UInt8](repeating: 0, count: expected.utf8.count)
            XCTAssertEqual(Darwin.read(fd, &bytes, bytes.count), bytes.count); XCTAssertEqual(Data(bytes), Data(expected.utf8))
        }
        XCTAssertEqual(try sendReferences(admission.port), 1); XCTAssertEqual(try sendReferences(terminal.port), 1)
    }

    func testMappedIOCarrierKeepsSeparateTerminalWithAllStdioRedirectedAndOptionalAbsence() throws {
        for hasTerminal in [false, true] {
            let endpoint = try Endpoint(), admission = try Endpoint(), result = try Endpoint()
            var input: [Int32] = [-1, -1], output: [Int32] = [-1, -1], error: [Int32] = [-1, -1]
            XCTAssertEqual(pipe(&input), 0); XCTAssertEqual(pipe(&output), 0); XCTAssertEqual(pipe(&error), 0)
            defer { for fd in input + output + error { _ = Darwin.close(fd) } }
            var master: Int32 = -1, slave: Int32 = -1
            if hasTerminal { XCTAssertEqual(openpty(&master, &slave, nil, nil, nil), 0) }
            defer { if hasTerminal { _ = Darwin.close(master); _ = Darwin.close(slave) } }
            let descriptors = [input[0], output[1], error[1]] + (hasTerminal ? [slave] : [])
            let flags = descriptors.map { fcntl($0, F_GETFL) }
            XCTAssertEqual(Darwin.write(input[1], "pending", 7), 7)
            if hasTerminal { XCTAssertEqual(Darwin.write(master, "queued\n", 7), 7) }
            try MachCommandIOWire.sendMapped(Data([0xa0]), inputDescriptor: input[0], outputDescriptor: output[1], errorDescriptor: error[1],
                controlTerminalDescriptor: hasTerminal ? slave : nil, destination: endpoint.port, admissionReply: admission.port,
                terminalReply: result.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
            let received = try receiver(endpoint, maximum: 8192).receiveMappedIOInput(timeoutMilliseconds: 1000)
            XCTAssertEqual(received.carrierVersion, 5)
            XCTAssertEqual(received.payload, Data([0xa0]))
            let outputs = try XCTUnwrap(received.outputs)
            XCTAssertEqual(descriptors.map { fcntl($0, F_GETFL) }, flags)
            try outputs.output.withBorrowedDescriptor { XCTAssertEqual(Darwin.write($0, "out", 3), 3) }
            try outputs.error.withBorrowedDescriptor { XCTAssertEqual(Darwin.write($0, "err", 3), 3) }
            let afterWrites = descriptors.map { fcntl($0, F_GETFL) }
            if hasTerminal {
                let terminal = try XCTUnwrap(received.controlTerminal)
                try terminal.withBorrowedDescriptor { retained in
                    XCTAssertNotEqual(retained, slave)
                    var imported = stat(), original = stat()
                    XCTAssertEqual(fstat(retained, &imported), 0); XCTAssertEqual(fstat(slave, &original), 0)
                    XCTAssertEqual(imported.st_rdev, original.st_rdev)
                    XCTAssertEqual(imported.st_ino, original.st_ino)
                    XCTAssertEqual(isatty(retained), 1)
                    XCTAssertEqual(fcntl(retained, F_GETFL), flags.last)
                }
                received.closeIfUnclaimed()
                XCTAssertThrowsError(try terminal.withBorrowedDescriptor { _ in () })
                var bytes = [UInt8](repeating: 0, count: 7)
                XCTAssertEqual(Darwin.read(slave, &bytes, bytes.count), bytes.count)
                XCTAssertEqual(Data(bytes), Data("queued\n".utf8))
            } else {
                XCTAssertNil(received.controlTerminal)
                received.closeIfUnclaimed()
            }
            XCTAssertEqual(descriptors.map { fcntl($0, F_GETFL) }, afterWrites)
            for (fd, expected) in [(input[0], "pending"), (output[0], "out"), (error[0], "err")] {
                var bytes = [UInt8](repeating: 0, count: expected.utf8.count)
                XCTAssertEqual(Darwin.read(fd, &bytes, bytes.count), bytes.count)
                XCTAssertEqual(Data(bytes), Data(expected.utf8))
            }
            XCTAssertEqual(try sendReferences(admission.port), 1)
            XCTAssertEqual(try sendReferences(result.port), 1)
        }
    }

    func testFrontendPipeSelectionWithAvailableTerminalPassesRootCaptureWithoutConsumingStreams() throws {
        let invocation = try CommandFrontendInvocation(arguments: ["remozio", "run", "--pipes", "--", "/usr/bin/true"].map { Data($0.utf8) },
            defaultIOMode: .pty, defaultDisconnectBehavior: .terminate, limits: assemblyLimits)
        var input: [Int32] = [-1, -1], output: [Int32] = [-1, -1], error: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&input), 0); XCTAssertEqual(pipe(&output), 0); XCTAssertEqual(pipe(&error), 0)
        var master: Int32 = -1, slave: Int32 = -1
        XCTAssertEqual(openpty(&master, &slave, nil, nil, nil), 0)
        defer { for fd in input + output + error + [master, slave] { _ = Darwin.close(fd) } }
        let descriptors = [input[0], output[1], error[1], slave], flags = descriptors.map { fcntl($0, F_GETFL) }
        XCTAssertEqual(Darwin.write(input[1], "pending", 7), 7)
        XCTAssertEqual(Darwin.write(master, "queued\n", 7), 7)
        for malformed in [true, false] {
            let endpoint = try Endpoint(), admission = try Endpoint(), result = try Endpoint()
            let submission = try commandSubmission(ioMode: invocation.ioMode)
            let profile = CommandHandshakeProfile(wireVersion: 11, submissionSchemaVersion: 1, inputCarrierVersion: 5,
                callerBinding: submission.binding.callerBinding, macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16))
            try MachCommandIOWire.sendMapped(submission.canonicalBytes, inputDescriptor: input[0], outputDescriptor: output[1], errorDescriptor: error[1],
                controlTerminalDescriptor: malformed ? slave : invocation.submissionControlTerminal(slave), destination: endpoint.port,
                admissionReply: admission.port, terminalReply: result.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
            let received = try receiver(endpoint, maximum: 8192).receiveMappedIOInput(timeoutMilliseconds: 1000)
            if malformed {
                XCTAssertThrowsError(try assemble(received, schema: 3, admissionProfile: profile)) {
                    XCTAssertEqual($0 as? RetainedCommandCaptureError, .invalidContext)
                }
            } else {
                let capture = try assemble(received, schema: 3, admissionProfile: profile)
                defer { capture.close() }
                XCTAssertNil(capture.capture.stdioLayout?.terminal)
                XCTAssertEqual(capture.capture.stdioLayout?.ptyMask, 0)
            }
            try expectAssemblyResourcesRetired(received)
            XCTAssertEqual(descriptors.map { fcntl($0, F_GETFL) }, flags)
        }
        for (fd, expected) in [(input[0], "pending"), (slave, "queued\n")] {
            var bytes = [UInt8](repeating: 0, count: expected.utf8.count)
            XCTAssertEqual(Darwin.read(fd, &bytes, bytes.count), bytes.count)
            XCTAssertEqual(Data(bytes), Data(expected.utf8))
        }
    }

    func testMappedIOCarrierTransfersTerminalClaimOnlyOnceAndRetiresItsImportedDescriptor() throws {
        let endpoint = try Endpoint(), admission = try Endpoint(), result = try Endpoint()
        let null = Darwin.open("/dev/null", O_RDWR)
        var master: Int32 = -1, slave: Int32 = -1
        XCTAssertEqual(openpty(&master, &slave, nil, nil, nil), 0)
        defer { _ = Darwin.close(null); _ = Darwin.close(master); _ = Darwin.close(slave) }
        try MachCommandIOWire.sendMapped(Data([0xa0]), inputDescriptor: null, outputDescriptor: null, errorDescriptor: null,
            controlTerminalDescriptor: slave, destination: endpoint.port, admissionReply: admission.port,
            terminalReply: result.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        guard case let .input(original) = try receiver(endpoint, maximum: 8192).receiveNext(timeoutMilliseconds: 1000) else {
            return XCTFail("Expected the mapped input carrier")
        }
        let terminal = try XCTUnwrap(original.controlTerminal)
        let (owned, reply) = try original.takeForAdmissionAttempt()
        defer { reply.close() }
        original.closeIfUnclaimed()
        try terminal.withBorrowedDescriptor { XCTAssertEqual(isatty($0), 1) }
        XCTAssertThrowsError(try original.takeForAdmissionAttempt()) {
            XCTAssertEqual($0 as? RetainedCommandCaptureError, .alreadyOwned)
        }
        owned.closeIfUnclaimed()
        XCTAssertThrowsError(try terminal.withBorrowedDescriptor { _ in () })
        XCTAssertEqual(isatty(slave), 1)
    }

    func testMappedIOCarrierRejectsRawControlAliasAndRecoversForTheNextSubmission() throws {
        let endpoint = try Endpoint()
        let peer = try Peer(endpoint: endpoint, submission: Data([0xa0]), mappedTerminalMask: 0, rawMappedTerminal: true)
        let expression = "(" + peer.expression + ") or (" + (try selfExpression()) + ")"
        let receive = try receiver(endpoint, expression: expression, maximum: 8192)
        XCTAssertThrowsError(try receive.receiveNext(timeoutMilliseconds: 5000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .malformed)
        }
        try peer.stop()
        let admission = try Endpoint(), result = try Endpoint()
        let null = Darwin.open("/dev/null", O_RDWR)
        defer { _ = Darwin.close(null) }
        try MachCommandIOWire.sendMapped(Data([0xa1]), inputDescriptor: null, outputDescriptor: null, errorDescriptor: null,
            controlTerminalDescriptor: nil, destination: endpoint.port, admissionReply: admission.port,
            terminalReply: result.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        guard case let .input(received) = try receive.receiveNext(timeoutMilliseconds: 1000) else {
            return XCTFail("Expected the next mapped submission")
        }
        defer { received.closeIfUnclaimed() }
        XCTAssertEqual(received.payload, Data([0xa1]))
        XCTAssertEqual(received.carrierVersion, 5)
        XCTAssertNil(received.controlTerminal)
    }

    func testSchemaThreeCaptureUsesAuthenticatedCallerTerminalForEveryRoutingMask() throws {
        for mask: UInt32 in 0...7 {
            let endpoint = try Endpoint()
            let submission = try commandSubmission(ioMode: .pty)
            let peer = try Peer(endpoint: endpoint, submission: submission.canonicalBytes, mappedTerminalMask: Int(mask))
            let received = try receiver(endpoint, expression: peer.expression, maximum: 8192).receiveMappedIOInput(timeoutMilliseconds: 5000)
            let owner = try assemble(received, schema: 3, callerExpression: peer.expression)
            defer { owner.close() }
            let capture = owner.capture
            let layout = try XCTUnwrap(capture.stdioLayout)
            let terminal = try XCTUnwrap(layout.terminal)
            XCTAssertEqual(layout.ptyMask, mask)
            XCTAssertEqual(terminal.sessionID, UInt32(peer.pid))
            XCTAssertEqual(capture.requester.sessionID, terminal.sessionID)
            XCTAssertEqual(capture.requester.pid, UInt32(peer.pid))
            XCTAssertEqual(layout.input.source, capture.input)
            XCTAssertEqual(terminal.stream.access, .readWrite)
            XCTAssertEqual(terminal.stream.source.kind, .tty)
            for (index, stream) in [layout.input, layout.output, layout.error].enumerated() {
                if mask & (1 << index) != 0 {
                    XCTAssertEqual(stream.source.identity, terminal.stream.source.identity)
                    XCTAssertEqual(stream.source.kind, .tty)
                    XCTAssertEqual(stream.access, .readWrite)
                } else {
                    XCTAssertEqual(stream.source.kind, index == 0 ? .pipe : .null)
                    XCTAssertEqual(stream.access, index == 0 ? .readOnly : .writeOnly)
                }
            }
            let reparsed = try CommandCapture(canonicalBytes: capture.canonicalBytes, limits: assemblyLimits, expectedSchemaVersion: 3)
            XCTAssertEqual(reparsed, capture)
            try owner.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil)
            owner.close()
            if let control = received.controlTerminal {
                XCTAssertThrowsError(try control.withBorrowedDescriptor { _ in () })
            }
            try peer.stop()
        }
    }

    func testSchemaThreeCaptureKeepsForeignTerminalsUnselectedInEveryStreamRole() throws {
        for role in 0...2 {
            let endpoint = try Endpoint(), submission = try commandSubmission(ioMode: .pty)
            let peer = try Peer(endpoint: endpoint, submission: submission.canonicalBytes, mappedForeignTerminalRole: role)
            let received = try receiver(endpoint, expression: peer.expression, maximum: 8192).receiveMappedIOInput(timeoutMilliseconds: 5000)
            let owner = try assemble(received, schema: 3, callerExpression: peer.expression)
            defer { owner.close() }
            let layout = try XCTUnwrap(owner.capture.stdioLayout), terminal = try XCTUnwrap(layout.terminal)
            XCTAssertEqual(layout.ptyMask, 7 & ~(1 << UInt32(role)))
            for (index, stream) in [layout.input, layout.output, layout.error].enumerated() {
                XCTAssertEqual(stream.source.kind, .tty)
                if index == role { XCTAssertNotEqual(stream.source.identity, terminal.stream.source.identity) }
                else { XCTAssertEqual(stream.source.identity, terminal.stream.source.identity) }
            }
            try owner.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil)
            owner.close()
            try peer.stop()
        }
    }

    func testSchemaThreeCapturePreservesPTYModeWithoutAnOriginalCallerTerminal() throws {
        let endpoint = try Endpoint(), submission = try commandSubmission(ioMode: .pty)
        let peer = try Peer(endpoint: endpoint, submission: submission.canonicalBytes, mappedTerminalMask: 0, mappedHasTerminal: false)
        let received = try receiver(endpoint, expression: peer.expression, maximum: 8192).receiveMappedIOInput(timeoutMilliseconds: 5000)
        let context = try received.caller.captureTerminalContext(expression: peer.expression, userID: geteuid(), auditSessionID: nil)
        XCTAssertNil(context.terminalDevice)
        XCTAssertEqual(context.sessionID, peer.pid)
        let owner = try assemble(received, schema: 3, callerExpression: peer.expression)
        defer { owner.close() }
        let layout = try XCTUnwrap(owner.capture.stdioLayout)
        XCTAssertEqual(owner.capture.ioMode, .pty)
        XCTAssertEqual(layout.ptyMask, 0)
        XCTAssertNil(layout.terminal)
        XCTAssertEqual(layout.input.source.kind, .pipe)
        XCTAssertEqual(layout.output.source.kind, .null)
        XCTAssertEqual(layout.error.source.kind, .null)
        try owner.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil)
        owner.close()
        try peer.stop()
    }

    func testMappedIOCarrierCannotBeSilentlyCapturedUnderLegacySchemas() throws {
        for schema: UInt64 in [1, 2] {
            let endpoint = try Endpoint(), admission = try Endpoint(), result = try Endpoint()
            let null = Darwin.open("/dev/null", O_RDWR)
            defer { _ = Darwin.close(null) }
            let submission = try commandSubmission()
            try MachCommandIOWire.sendMapped(submission.canonicalBytes, inputDescriptor: null, outputDescriptor: null, errorDescriptor: null,
                controlTerminalDescriptor: nil, destination: endpoint.port, admissionReply: admission.port,
                terminalReply: result.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
            let received = try receiver(endpoint, maximum: 8192).receiveMappedIOInput(timeoutMilliseconds: 1000)
            XCTAssertThrowsError(try assemble(received, schema: schema)) {
                XCTAssertEqual($0 as? RetainedCommandCaptureError, .invalidContext)
            }
            XCTAssertThrowsError(try received.input.withBorrowedDescriptor { _ in () })
            XCTAssertThrowsError(try received.outputs?.recheck())
            XCTAssertEqual(fcntl(null, F_GETFL) & O_ACCMODE, O_RDWR)
            XCTAssertEqual(try sendReferences(admission.port), 1)
            XCTAssertEqual(try sendReferences(result.port), 1)
        }
    }

    func testSchemaThreeCaptureRejectsRevokedCallerTerminalEvenWithAllStdioRedirected() throws {
        for mask in [0, 7] {
            let endpoint = try Endpoint(), submission = try commandSubmission(ioMode: .pty)
            let peer = try Peer(endpoint: endpoint, submission: submission.canonicalBytes, mappedTerminalMask: mask)
            let receive = try receiver(endpoint, expression: peer.expression, maximum: 8192)
            let received = try receive.receiveMappedIOInput(timeoutMilliseconds: 5000)
            let owner = try assemble(received, schema: 3, callerExpression: peer.expression)
            defer { owner.close() }
            XCTAssertEqual(owner.capture.stdioLayout?.ptyMask, UInt32(mask))
            try owner.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil)
            let pid = peer.pid
            try peer.revokeOwnTerminal()
            let notice = try receive.receive(timeoutMilliseconds: 5000)
            defer { notice.caller.close() }
            XCTAssertEqual(notice.payload, Data("revoked".utf8))
            XCTAssertEqual(notice.caller.requester.pid, UInt32(pid))
            XCTAssertEqual(notice.caller.requester.pidVersion, owner.capture.requester.pidVersion)
            XCTAssertEqual(notice.caller.requester.sessionID, owner.capture.requester.sessionID)
            let afterRevocation = try notice.caller.captureTerminalContext(expression: peer.expression, userID: geteuid(), auditSessionID: nil)
            XCTAssertNil(afterRevocation.terminalDevice)
            XCTAssertNotNil(owner.capture.stdioLayout?.terminal)
            XCTAssertThrowsError(try owner.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil)) {
                switch $0 {
                case CommandStreamObservationError.changed, RetainedCommandInputError.system(EBADF): break
                default: XCTFail("Unexpected revocation error: \($0)")
                }
            }
            XCTAssertThrowsError(try received.controlTerminal?.withBorrowedDescriptor { _ in () })
            XCTAssertThrowsError(try received.input.withBorrowedDescriptor { _ in () })
            XCTAssertThrowsError(try received.outputs?.recheck())
            try peer.stop()
        }
    }

    func testSchemaThreeCaptureRechecksRedirectFlagsAndRetiresAllOwnedStreams() throws {
        let endpoint = try Endpoint(), admission = try Endpoint(), result = try Endpoint()
        let input = Darwin.open("/dev/null", O_RDONLY), output = Darwin.open("/dev/null", O_WRONLY)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        let submission = try commandSubmission()
        try MachCommandIOWire.sendMapped(submission.canonicalBytes, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
            controlTerminalDescriptor: nil, destination: endpoint.port, admissionReply: admission.port,
            terminalReply: result.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        let received = try receiver(endpoint, maximum: 8192).receiveMappedIOInput(timeoutMilliseconds: 1000)
        let owner = try assemble(received, schema: 3)
        defer { owner.close() }
        let layout = try XCTUnwrap(owner.capture.stdioLayout)
        XCTAssertEqual(layout.ptyMask, 0)
        XCTAssertNil(layout.terminal)
        XCTAssertEqual(layout.output.access, .writeOnly)
        XCTAssertEqual(layout.input.access, .readOnly)
        try owner.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        let flags = fcntl(output, F_GETFL)
        XCTAssertEqual(fcntl(output, F_SETFL, flags | O_APPEND), 0)
        XCTAssertThrowsError(try owner.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? CommandStreamObservationError, .changed)
        }
        XCTAssertThrowsError(try received.input.withBorrowedDescriptor { _ in () })
        XCTAssertThrowsError(try received.outputs?.recheck())
        XCTAssertEqual(fcntl(output, F_GETFL), flags | O_APPEND)
    }

    func testSchemaThreeCaptureRejectsLegacyCarrierAndForeignControlTerminalAndClosesCopies() throws {
        for mapped in [false, true] {
            let endpoint = try Endpoint(), admission = try Endpoint(), result = try Endpoint()
            let null = Darwin.open("/dev/null", O_RDWR)
            var master: Int32 = -1, slave: Int32 = -1
            XCTAssertEqual(openpty(&master, &slave, nil, nil, nil), 0)
            defer { _ = Darwin.close(null); _ = Darwin.close(master); _ = Darwin.close(slave) }
            let submission = try commandSubmission(ioMode: .pty)
            if mapped {
                try MachCommandIOWire.sendMapped(submission.canonicalBytes, inputDescriptor: null, outputDescriptor: null, errorDescriptor: null,
                    controlTerminalDescriptor: slave, destination: endpoint.port, admissionReply: admission.port,
                    terminalReply: result.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
            } else {
                try MachCommandIOWire.send(submission.canonicalBytes, inputDescriptor: null, outputDescriptor: null, errorDescriptor: null,
                    destination: endpoint.port, admissionReply: admission.port, terminalReply: result.port,
                    maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
            }
            let receive = try receiver(endpoint, maximum: 8192)
            let received = mapped ? try receive.receiveMappedIOInput(timeoutMilliseconds: 1000) : try receive.receiveIOInput(timeoutMilliseconds: 1000)
            XCTAssertThrowsError(try assemble(received, schema: 3)) {
                XCTAssertEqual($0 as? RetainedCommandCaptureError, .invalidContext)
            }
            XCTAssertThrowsError(try received.input.withBorrowedDescriptor { _ in () })
            if let terminal = received.controlTerminal { XCTAssertThrowsError(try terminal.withBorrowedDescriptor { _ in () }) }
            XCTAssertEqual(isatty(slave), 1)
            XCTAssertEqual(fcntl(null, F_GETFL) & O_ACCMODE, O_RDWR)
            XCTAssertEqual(try sendReferences(admission.port), 1)
            XCTAssertEqual(try sendReferences(result.port), 1)
        }
    }

    func testMappedIOCarrierRejectsNonterminalControlWithoutSending() throws {
        let endpoint = try Endpoint(), admission = try Endpoint(), result = try Endpoint()
        let null = Darwin.open("/dev/null", O_RDWR)
        defer { _ = Darwin.close(null) }
        XCTAssertThrowsError(try MachCommandIOWire.sendMapped(Data([0xa0]), inputDescriptor: null, outputDescriptor: null, errorDescriptor: null,
            controlTerminalDescriptor: null, destination: endpoint.port, admissionReply: admission.port,
            terminalReply: result.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .malformed)
        }
        XCTAssertThrowsError(try receiver(endpoint).receiveNext(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
        XCTAssertEqual(try sendReferences(admission.port), 1)
        XCTAssertEqual(try sendReferences(result.port), 1)
    }

    func testIOCarrierRejectsReadOnlyOutputsWithoutSendingOrChangingInput() throws {
        let endpoint = try Endpoint(), admission = try Endpoint(), terminal = try Endpoint()
        let input = Darwin.open("/dev/null", O_RDONLY), output = Darwin.open("/dev/null", O_WRONLY)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        for descriptor in [input, -1] {
            XCTAssertThrowsError(try MachCommandIOWire.send(Data([0xa0]), inputDescriptor: input, outputDescriptor: output,
                errorDescriptor: descriptor, destination: endpoint.port, admissionReply: admission.port,
                terminalReply: terminal.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000))
            XCTAssertThrowsError(try receiver(endpoint).receiveNext(timeoutMilliseconds: 10)) {
                XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
            }
        }
        XCTAssertEqual(fcntl(input, F_GETFL) & O_ACCMODE, O_RDONLY)
        XCTAssertEqual(fcntl(output, F_GETFL) & O_ACCMODE, O_WRONLY)
    }

    private func selfExpression() throws -> String {
        var code: SecCode?, information: CFDictionary?
        XCTAssertEqual(SecCodeCopySelf([], &code), errSecSuccess)
        XCTAssertEqual(remozio_copy_dynamic_signing_information(try XCTUnwrap(code), &information), errSecSuccess)
        let values = try XCTUnwrap(information as? [String: Any])
        let hash = try XCTUnwrap(values[kSecCodeInfoUnique as String] as? Data)
        return "cdhash H\"" + hash.map { String(format: "%02x", $0) }.joined() + "\""
    }

    private func receiver(_ endpoint: Endpoint, expression: String? = nil, user: uid_t? = nil,
                          session: au_asid_t? = nil, maximum: Int = 64) throws -> MachCommandCallerReceiver {
        try MachCommandCallerReceiver(receivePort: endpoint.port, expression: expression ?? selfExpression(),
            userID: user ?? geteuid(), auditSessionID: session, maxPayloadBytes: maximum)
    }

    func testTerminalContextUsesTheOriginalAuthenticatedCallerAndRejectsRetiredRecords() throws {
        let endpoint = try Endpoint(), expression = try selfExpression()
        try endpoint.send(Data([1]))
        let received = try receiver(endpoint, expression: expression).receive(timeoutMilliseconds: 1000)
        defer { received.caller.close() }
        let context = try received.caller.captureTerminalContext(expression: expression, userID: geteuid(), auditSessionID: nil)
        XCTAssertEqual(context.sessionID, getsid(0))
        try received.caller.recheckTerminalContext(context, expression: expression, userID: geteuid(), auditSessionID: nil)
        received.caller.close()
        XCTAssertThrowsError(try received.caller.recheckTerminalContext(context, expression: expression, userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .retired)
        }
        XCTAssertThrowsError(try received.caller.captureTerminalContext(expression: expression, userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .retired)
        }
    }

    func testKernelIdentityIgnoresPayloadClaimsAndPreservesRawBytes() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        let bytes = Data([0xff, 0x00, 0x31, 0x32, 0x33])
        try endpoint.send(bytes)
        let value = try receiver.receive(timeoutMilliseconds: 1000)
        XCTAssertEqual(value.payload, bytes)
        XCTAssertEqual(value.caller.requester.pid, UInt32(getpid()))
        XCTAssertEqual(value.caller.requester.realUID, getuid())
        XCTAssertEqual(value.caller.requester.effectiveUID, geteuid())
        XCTAssertEqual(value.caller.requester.sessionID, UInt32(getsid(getpid())))
        XCTAssertNil(value.caller.requester.ttyPath)
        try value.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: value.caller.auditSessionID)
        value.caller.close(); value.caller.close()
        XCTAssertThrowsError(try value.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .retired)
        }
    }

    func testAccountSessionAndCodePolicyRejectBeforeReturningCaller() throws {
        for kind in 0..<3 {
            let endpoint = try Endpoint()
            let wrong = "cdhash H\"" + String(repeating: "0", count: 40) + "\""
            var wrongSession: au_asid_t?
            if kind == 1 {
                let baseline = try receiver(endpoint)
                try endpoint.send(Data([1]))
                wrongSession = try baseline.receive(timeoutMilliseconds: 1000).caller.auditSessionID ^ 1
            }
            let receiver = try receiver(endpoint, expression: kind == 2 ? wrong : nil,
                user: kind == 0 ? geteuid() ^ 1 : nil, session: wrongSession)
            try endpoint.send(Data([1]))
            XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000))
        }
    }

    func testPublicReleasePolicyRejectsTheTestHost() throws {
        let endpoint = try Endpoint()
        let policy = try XPCPeerPolicy(teamID: "AB12345678", componentIdentifier: "dev.remozio.command",
            approvedCodeDirectoryHashes: [Data(repeating: 0, count: 20)], expectedUserID: geteuid())
        let receiver = try MachCommandCallerReceiver(receivePort: endpoint.port, policy: policy, maxPayloadBytes: 64)
        try endpoint.send(Data([1]))
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000))
    }

    func testChangedDispatchPolicyRetiresTheCapturedCaller() throws {
        for wrongUser in [false, true] {
            let endpoint = try Endpoint(), receiver = try receiver(endpoint)
            try endpoint.send(Data([1]))
            let value = try receiver.receive(timeoutMilliseconds: 1000)
            let expression = wrongUser ? try selfExpression() : "cdhash H\"" + String(repeating: "0", count: 40) + "\""
            XCTAssertThrowsError(try value.caller.recheck(expression: expression, userID: wrongUser ? geteuid() ^ 1 : geteuid(), auditSessionID: nil))
            XCTAssertThrowsError(try value.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)) {
                XCTAssertEqual($0 as? MachCommandCallerError, .retired)
            }
        }
    }

    func testMalformedVersionLengthPaddingAndIDDoNotPoisonNextReceive() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        try endpoint.send(Data([1]), version: 2)
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000)) { XCTAssertEqual($0 as? MachCommandCallerError, .version) }
        try endpoint.send(Data([1]), claimedLength: 100)
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000))
        try endpoint.send(Data([1]), badPadding: true)
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000))
        try endpoint.send(Data([1]), identifier: 0)
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000))
        try endpoint.send(Data([2]))
        XCTAssertEqual(try receiver.receive(timeoutMilliseconds: 1000).payload, Data([2]))
    }

    func testOversizedPacketFailsWithoutTruncationAndNextPacketWorks() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint, maximum: 4)
        for length in [5, 200] {
            try endpoint.send(Data(repeating: 1, count: length))
            XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000))
        }
        try endpoint.send(Data([3]))
        XCTAssertEqual(try receiver.receive(timeoutMilliseconds: 1000).payload, Data([3]))
    }

    func testTimeoutAndInvalidConfigurationFail() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 0))
        for maximum in [0, -1, Int(UInt32.max)] { XCTAssertThrowsError(try self.receiver(endpoint, maximum: maximum)) }
        XCTAssertThrowsError(try MachCommandCallerReceiver(receivePort: 0, expression: selfExpression(),
            userID: geteuid(), auditSessionID: nil, maxPayloadBytes: 64))
    }
    private var handshakeMac: Data { Data(repeating: 0xd1, count: 16) }
    private var handshakeAccount: Data { Data(repeating: 0xd2, count: 16) }
    private func hello(_ endpoint: Endpoint, reply: Endpoint, capabilities: CommandHandshakeCapabilities = .current) throws -> sending MachCommandHello {
        let offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: capabilities)
        try MachCommandWire.send(offer.canonicalBytes, destination: endpoint.port, replyPort: reply.port,
            identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
        return try receiver(endpoint, maximum: 8192).receiveHello(timeoutMilliseconds: 1000)
    }
    private func serverHandshake(_ hello: MachCommandHello, expression: String? = nil) throws -> RetainedCommandHandshake {
        try RetainedCommandHandshake(hello: hello, macID: handshakeMac, accountID: handshakeAccount,
            expression: expression ?? selfExpression(), userID: geteuid(), auditSessionID: nil)
    }
    // The worker completes before tests borrow the retained session. This is not a product transfer wrapper.
    private final class HandshakeResult: @unchecked Sendable {
        let completed = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var result: Result<RetainedCommandHandshake, Error>?
        func finish(_ result: Result<RetainedCommandHandshake, Error>) { lock.withLock { self.result = result }; completed.signal() }
        func take() throws -> RetainedCommandHandshake {
            guard completed.wait(timeout: .now() + 6) == .success else { throw MachCommandCallerError.timeout }
            return try lock.withLock { try XCTUnwrap(result).get() }
        }
    }

    func testRealMachHandshakeAuthenticatesBothSendersAndCreatesFreshBindings() throws {
        var previous: Data?
        for _ in 0..<2 {
            let endpoint = try Endpoint(), port = endpoint.port, expression = try selfExpression(), uid = geteuid()
            let mac = handshakeMac, account = handshakeAccount, result = HandshakeResult()
            DispatchQueue.global().async {
                result.finish(Result {
                    let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression,
                        userID: uid, auditSessionID: nil, maxPayloadBytes: 4096)
                    let hello = try receiver.receiveHello(timeoutMilliseconds: 5000)
                    return try RetainedCommandHandshake(hello: hello, macID: mac, accountID: account,
                        expression: expression, userID: uid, auditSessionID: nil)
                })
            }
            let client = try MachCommandHandshakeClient.negotiate(authorityPort: port, expression: expression, userID: uid,
                auditSessionID: nil, macID: mac, accountID: account)
            let server = try result.take()
            defer { client.close(); server.close() }
            XCTAssertEqual(client.profile, server.profile)
            XCTAssertEqual(server.profile.wireVersion, 1)
            XCTAssertEqual(server.profile.submissionSchemaVersion, 1)
            XCTAssertEqual(server.profile.inputCarrierVersion, 2)
            XCTAssertEqual(server.profile.callerBinding.count, 16)
            if let previous { XCTAssertNotEqual(previous, server.profile.callerBinding) }
            previous = server.profile.callerBinding
        }
    }

    func testRealMappedHandshakeNegotiatesBothProfilesAndTheHighestUnderstoodPair() throws {
        let mixed = try CommandHandshakeCapabilities(wireVersions: [6, 7, 8, 9], submissionSchemaVersions: [1], inputCarrierVersions: [4, 5])
        for (wire, capabilities): (UInt64, CommandHandshakeCapabilities) in [
            (8, .mappedTerminalJobExecution), (9, .mappedPipeJobExecutionControls), (9, mixed),
        ] {
            let endpoint = try Endpoint(), port = endpoint.port, expression = try selfExpression(), uid = geteuid()
            let mac = handshakeMac, account = handshakeAccount, result = HandshakeResult()
            DispatchQueue.global().async {
                result.finish(Result {
                    let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression,
                        userID: uid, auditSessionID: nil, maxPayloadBytes: 4096)
                    return try RetainedCommandHandshake(hello: receiver.receiveHello(timeoutMilliseconds: 5000),
                        capabilities: mixed, macID: mac, accountID: account, expression: expression, userID: uid, auditSessionID: nil)
                })
            }
            let client = try MachCommandHandshakeClient.negotiate(authorityPort: port, expression: expression, userID: uid,
                auditSessionID: nil, macID: mac, accountID: account, capabilities: capabilities)
            let server = try result.take()
            defer { client.close(); server.close() }
            XCTAssertEqual(client.profile, server.profile)
            XCTAssertEqual(server.profile.wireVersion, wire)
            XCTAssertEqual(server.profile.submissionSchemaVersion, 1)
            XCTAssertEqual(server.profile.inputCarrierVersion, 5)
            XCTAssertTrue(server.profile.supportsMappedLayout)
        }
    }

    func testMappedHandshakeRejectsWrongCarriersAndLegacyOnlyPeers() throws {
        for mapped: CommandHandshakeCapabilities in [.mappedTerminalJobExecution, .mappedPipeJobExecutionControls] {
            let wrongCarrier = try CommandHandshakeCapabilities(wireVersions: mapped.wireVersions,
                submissionSchemaVersions: [1], inputCarrierVersions: [4])
            for (offered, server) in [(wrongCarrier, mapped), (mapped, wrongCarrier),
                (mapped, CommandHandshakeCapabilities.streamingJobExecution),
                (CommandHandshakeCapabilities.pipeJobExecutionControls, mapped)] {
                let endpoint = try Endpoint(), reply = try Endpoint()
                XCTAssertThrowsError(try RetainedCommandHandshake(hello: hello(endpoint, reply: reply, capabilities: offered),
                    capabilities: server, macID: handshakeMac, accountID: handshakeAccount,
                    expression: selfExpression(), userID: geteuid(), auditSessionID: nil)) {
                    XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible)
                }
                let response = try receiver(reply, maximum: 4096).receiveHelloReply(timeoutMilliseconds: 1000)
                defer { response.caller.close() }
                XCTAssertThrowsError(try CommandHandshakeReply.decode(response.payload,
                    offer: CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: offered),
                    macID: handshakeMac, accountID: handshakeAccount)) {
                    XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible)
                }
            }
        }
    }

    func testHandshakeReplyRightOwnershipClosesOnDiscardAndNegotiationFailure() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), baseline = try sendReferences(reply.port)
        var packet: MachCommandHello? = try hello(endpoint, reply: reply)
        XCTAssertEqual(try sendReferences(reply.port), baseline + 1)
        packet?.close(); packet = nil
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        let invalid = try hello(endpoint, reply: reply)
        XCTAssertThrowsError(try RetainedCommandHandshake(hello: invalid, macID: Data(), accountID: handshakeAccount,
            expression: selfExpression(), userID: geteuid(), auditSessionID: nil))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        XCTAssertThrowsError(try invalid.take()) { XCTAssertEqual($0 as? MachCommandHandshakeError, .retired) }
    }

    func testHelloRejectsWrongSenderMalformedDescriptorsCarrierAndOversizeBeforeImport() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), baseline = try sendReferences(reply.port)
        let offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32)).canonicalBytes
        let rejected = try receiver(endpoint, user: geteuid() ^ 1, maximum: 16384)
        try MachCommandWire.send(offer, destination: endpoint.port, replyPort: reply.port,
            identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
        XCTAssertThrowsError(try rejected.receiveHello(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .wrongPeer)
        }
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        let receiver = try receiver(endpoint, maximum: 16384)
        for variant in 0..<3 {
            try endpoint.sendInput(variant == 2 ? Data(count: 4097) : offer, fileport: reply.port,
                version: variant == 0 ? 2 : 1, descriptorCount: variant == 1 ? 2 : 1,
                identifier: MachCommandCallerReceiver.helloMessageID)
            XCTAssertThrowsError(try receiver.receiveHello(timeoutMilliseconds: 1000))
            XCTAssertEqual(try sendReferences(reply.port), baseline)
        }
        let valid = try hello(endpoint, reply: reply)
        valid.close()
        XCTAssertEqual(try sendReferences(reply.port), baseline)
    }

    func testHelloAndCommandInputCarriersCannotSubstituteForEachOther() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), receiver = try receiver(endpoint)
        let offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32)).canonicalBytes
        try MachCommandWire.send(offer, destination: endpoint.port, replyPort: reply.port,
            identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
        XCTAssertThrowsError(try receiver.receiveInput(timeoutMilliseconds: 1000))
        try endpoint.sendInput(offer, fileport: reply.port)
        XCTAssertThrowsError(try receiver.receiveHello(timeoutMilliseconds: 1000))
    }

    func testUnsupportedHandshakeReturnsAuthenticatedIncompatibilityWithoutDowngrade() throws {
        let endpoint = try Endpoint(), reply = try Endpoint()
        let old = try CommandHandshakeCapabilities(wireVersions: [1], submissionSchemaVersions: [1], inputCarrierVersions: [1])
        let packet = try hello(endpoint, reply: reply, capabilities: old)
        XCTAssertThrowsError(try serverHandshake(packet)) { XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible) }
        let response = try receiver(reply).receiveHelloReply(timeoutMilliseconds: 1000)
        defer { response.caller.close() }
        let offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: old)
        XCTAssertThrowsError(try CommandHandshakeReply.decode(response.payload, offer: offer, macID: handshakeMac, accountID: handshakeAccount)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible)
        }
    }

    func testHandshakeSendTimeoutReleasesPseudoReceivedRightsAndPreservesBorrowedPorts() throws {
        let endpoint = try Endpoint(), reply = try Endpoint()
        var status = mach_port_status_t(), count = mach_msg_type_number_t(MemoryLayout<mach_port_status_t>.size / MemoryLayout<integer_t>.size)
        XCTAssertEqual(withUnsafeMutablePointer(to: &status) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                mach_port_get_attributes(mach_task_self_, endpoint.port, Int32(MACH_PORT_RECEIVE_STATUS), $0, &count)
            }
        }, KERN_SUCCESS)
        for _ in 0..<status.mps_qlimit { try endpoint.send(Data([1])) }
        let endpointBaseline = try sendReferences(endpoint.port), replyBaseline = try sendReferences(reply.port)
        for _ in 0..<3 {
            XCTAssertThrowsError(try MachCommandWire.send(Data([1]), destination: endpoint.port, replyPort: reply.port,
                identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 10)) {
                XCTAssertEqual($0 as? MachCommandCallerError, .mach(MACH_SEND_TIMED_OUT))
            }
            XCTAssertEqual(try sendReferences(endpoint.port), endpointBaseline)
            XCTAssertEqual(try sendReferences(reply.port), replyBaseline)
        }
        let receiver = try receiver(endpoint)
        for _ in 0..<status.mps_qlimit { let value = try receiver.receive(timeoutMilliseconds: 1000); value.caller.close() }
        XCTAssertEqual(try sendReferences(endpoint.port), endpointBaseline)
    }

    func testClientTimeoutAndCancellationRetainBorrowedAuthorityRight() throws {
        let endpoint = try Endpoint(), baseline = try sendReferences(endpoint.port)
        XCTAssertThrowsError(try MachCommandHandshakeClient.negotiate(authorityPort: endpoint.port, expression: selfExpression(),
            userID: geteuid(), auditSessionID: nil, macID: handshakeMac, accountID: handshakeAccount, timeoutMilliseconds: 10))
        XCTAssertEqual(try sendReferences(endpoint.port), baseline)
        XCTAssertThrowsError(try MachCommandHandshakeClient.negotiate(authorityPort: endpoint.port, expression: selfExpression(),
            userID: geteuid(), auditSessionID: nil, macID: handshakeMac, accountID: handshakeAccount,
            checkCancellation: { throw MachCommandHandshakeError.retired }))
        XCTAssertEqual(try sendReferences(endpoint.port), baseline)
    }

    func testNegotiatedSenderAssemblesExactCaptureAndRejectsOtherBindingWithoutReadingInput() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), session = try serverHandshake(hello(endpoint, reply: reply))
        defer { session.close() }
        var pipeFDs: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&pipeFDs), 0)
        defer { for fd in pipeFDs { _ = Darwin.close(fd) } }
        let pending = Data("unread".utf8)
        XCTAssertEqual(pending.withUnsafeBytes { Darwin.write(pipeFDs[1], $0.baseAddress, $0.count) }, pending.count)
        let original = try commandSubmission()
        let claims = try CommandSubmission(schemaVersion: 1, executablePath: original.executablePath, arguments: original.arguments,
            directoryPath: original.directoryPath, requestedTargetUID: original.requestedTargetUID, environmentAdditions: original.environmentAdditions,
            ioMode: original.ioMode, disconnectBehavior: original.disconnectBehavior, unverifiedRationale: original.unverifiedRationale,
            binding: .init(id: original.binding.id, nonce: original.binding.nonce, callerBinding: session.profile.callerBinding), limits: assemblyLimits)
        let received = try inputSubmission(pipeFDs[0], payload: claims.canonicalBytes)
        let command = try session.assemble(received: TestInputInspection(received: received).received, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            captureSchemaVersion: 2, resolvedTarget: assemblyTarget, minimalEnvironment: assemblyEnvironment,
            streamBinding: Data(repeating: 0xd4, count: 16), submissionLimits: assemblyLimits, captureLimits: assemblyLimits)
        defer { command.close() }
        XCTAssertEqual(command.capture.submission, claims.binding)
        XCTAssertEqual(command.capture.arguments, claims.arguments)
        try command.withBorrowedInputDescriptor { fd in
            var bytes = [UInt8](repeating: 0, count: pending.count)
            XCTAssertEqual(Darwin.read(fd, &bytes, bytes.count), bytes.count)
            XCTAssertEqual(Data(bytes), pending)
        }
        let wrong = try inputSubmission(pipeFDs[0], payload: original.canonicalBytes)
        XCTAssertThrowsError(try session.assemble(received: TestInputInspection(received: wrong).received, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            captureSchemaVersion: 2, resolvedTarget: assemblyTarget, minimalEnvironment: assemblyEnvironment,
            streamBinding: Data(repeating: 0xd4, count: 16), submissionLimits: assemblyLimits, captureLimits: assemblyLimits))
        try expectAssemblyResourcesRetired(wrong)
        try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        session.close()
        let afterClose = try inputSubmission(pipeFDs[0], payload: claims.canonicalBytes)
        XCTAssertThrowsError(try session.assemble(received: TestInputInspection(received: afterClose).received, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            captureSchemaVersion: 2, resolvedTarget: assemblyTarget, minimalEnvironment: assemblyEnvironment,
            streamBinding: Data(repeating: 0xd4, count: 16), submissionLimits: assemblyLimits, captureLimits: assemblyLimits)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .retired)
        }
        try expectAssemblyResourcesRetired(afterClose)
    }

    func testHandshakeAuditBindingRejectsAnotherRealProcessAndExecIncarnation() throws {
        let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint)
        let receiver = try receiver(endpoint, expression: peer.expression)
        let first = try receiver.receive(timeoutMilliseconds: 5000)
        defer { first.caller.close() }
        let parentEndpoint = try Endpoint()
        try parentEndpoint.send(Data([1]))
        let parent = try self.receiver(parentEndpoint).receive(timeoutMilliseconds: 1000)
        defer { parent.caller.close() }
        XCTAssertFalse(first.caller.hasSameAuditBinding(as: parent.caller))
        XCTAssertTrue(first.caller.hasSameAuditBinding(as: first.caller))
        try peer.advance()
        let second = try receiver.receive(timeoutMilliseconds: 5000)
        defer { second.caller.close() }
        XCTAssertEqual(first.caller.requester.pid, second.caller.requester.pid)
        XCTAssertNotEqual(first.caller.requester.pidVersion, second.caller.requester.pidVersion)
        XCTAssertFalse(first.caller.hasSameAuditBinding(as: second.caller))
        try peer.stop()
    }

    func testSessionAssemblyRejectsAnotherKernelSenderEvenWithTheCorrectBinding() throws {
        let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint), reply = try Endpoint()
        let verified = try receiver(endpoint, expression: peer.expression).receive(timeoutMilliseconds: 5000)
        XCTAssertEqual(mach_port_mod_refs(mach_task_self_, reply.port, MACH_PORT_RIGHT_SEND, 1), KERN_SUCCESS)
        let offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32))
        let hello = MachCommandHello(payload: try offer.canonicalBytes, caller: verified.caller, reply: MachCommandReplyRight(taking: reply.port))
        let session = try serverHandshake(hello, expression: "true")
        defer { session.close() }
        let original = try commandSubmission()
        let claims = try CommandSubmission(schemaVersion: 1, executablePath: original.executablePath, arguments: original.arguments,
            directoryPath: original.directoryPath, requestedTargetUID: original.requestedTargetUID, environmentAdditions: original.environmentAdditions,
            ioMode: original.ioMode, disconnectBehavior: original.disconnectBehavior, unverifiedRationale: original.unverifiedRationale,
            binding: .init(id: original.binding.id, nonce: original.binding.nonce, callerBinding: session.profile.callerBinding), limits: assemblyLimits)
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { _ = Darwin.close(fd) }
        let incoming = try inputSubmission(fd, payload: claims.canonicalBytes)
        XCTAssertThrowsError(try session.assemble(received: TestInputInspection(received: incoming).received, expression: "true", userID: geteuid(), auditSessionID: nil,
            captureSchemaVersion: 2, resolvedTarget: assemblyTarget, minimalEnvironment: assemblyEnvironment,
            streamBinding: Data(repeating: 0xd4, count: 16), submissionLimits: assemblyLimits, captureLimits: assemblyLimits)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .wrongBinding)
        }
        try expectAssemblyResourcesRetired(incoming)
        try peer.advance()
        let replacement = try receiver(endpoint, expression: peer.expression).receive(timeoutMilliseconds: 5000)
        replacement.caller.close()
        try peer.stop()
    }

    func testPublicClientRequiresRootPolicyBeforeSendingAnyHello() throws {
        let endpoint = try Endpoint()
        let policy = try XPCPeerPolicy(teamID: "ABCD123456", componentIdentifier: "dev.remozio.authority",
            approvedCodeDirectoryHashes: [Data(repeating: 1, count: 20)], expectedUserID: geteuid())
        XCTAssertThrowsError(try MachCommandHandshakeClient.negotiate(authorityPort: endpoint.port, authorityPolicy: policy,
            macID: handshakeMac, accountID: handshakeAccount)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try receiver(endpoint).receiveHello(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testClientRejectsActualReplySenderWithWrongCredentialsBeforeDecodingItsPayload() throws {
        let reply = try Endpoint()
        try reply.send(Data([0]), identifier: MachCommandCallerReceiver.helloReplyMessageID)
        XCTAssertThrowsError(try receiver(reply, user: geteuid() ^ 1).receiveHelloReply(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .wrongPeer)
        }
    }


    // Serialized test inspection deliberately retains aliases. Product callers must use the sending APIs.
    private struct TestAttemptInspection: @unchecked Sendable { let attempt: RetainedCommandAdmissionAttempt }
    private struct TestInputInspection: @unchecked Sendable { let received: ReceivedMachCommandInputSubmission }
    // Callbacks execute synchronously in these fixtures. The wrapper permits deliberate reentry and alias inspection.
    private struct TestRegistryInspection: @unchecked Sendable {
        let tests: MachCommandCallerReceiverTests
        let owner: CommandSessionRegistry
        let received: ReceivedMachCommandInputSubmission
    }
    private let registryRevision = UUID()
    private func registry(_ maximum: Int = 4) throws -> CommandSessionRegistry {
        try CommandSessionRegistry(macID: handshakeMac, accountID: handshakeAccount, userID: geteuid(), maximumSessions: maximum)
    }
    private func registryContext(expression: String? = nil, revision: UUID? = nil) throws -> CommandSessionRegistry.Context {
        try .init(expression: expression ?? selfExpression(), roleRevision: revision ?? registryRevision)
    }
    private func registrySession(_ owner: CommandSessionRegistry, context: CommandSessionRegistry.Context? = nil) throws -> CommandHandshakeProfile {
        let endpoint = try Endpoint(), reply = try Endpoint(), context = try context ?? registryContext()
        let profile = try owner.accept(hello: hello(endpoint, reply: reply), context: { context })
        let response = try receiver(reply, maximum: 4096).receiveHelloReply(timeoutMilliseconds: 1000)
        defer { response.caller.close() }
        XCTAssertEqual(try CommandHandshakeReply.decode(response.payload,
            offer: CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32)), macID: handshakeMac, accountID: handshakeAccount), profile)
        return profile
    }
    private func registrySubmission(_ binding: Data, descriptor: Int32? = nil) throws -> ReceivedMachCommandInputSubmission {
        let original = try commandSubmission()
        let claims = try CommandSubmission(schemaVersion: 1, executablePath: original.executablePath, arguments: original.arguments,
            directoryPath: original.directoryPath, requestedTargetUID: original.requestedTargetUID, environmentAdditions: original.environmentAdditions,
            ioMode: original.ioMode, disconnectBehavior: original.disconnectBehavior, unverifiedRationale: original.unverifiedRationale,
            binding: .init(id: original.binding.id, nonce: original.binding.nonce, callerBinding: binding), limits: assemblyLimits)
        let fd = descriptor ?? Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw RetainedCommandInputError.system(errno) }
        defer { if descriptor == nil { _ = Darwin.close(fd) } }
        return try inputSubmission(fd, payload: claims.canonicalBytes)
    }
    private func registryCapture(_ owner: CommandSessionRegistry, received: ReceivedMachCommandInputSubmission,
                                 context: CommandSessionRegistry.Context? = nil, checkCancellation: @Sendable () throws -> Void = {}) throws -> RetainedCommandCapture {
        let context = try context ?? registryContext()
        return try owner.assemble(received: TestInputInspection(received: received).received, context: { context }, captureSchemaVersion: 2, resolvedTarget: assemblyTarget,
            minimalEnvironment: assemblyEnvironment, streamBinding: Data(repeating: 0xe4, count: 16),
            submissionLimits: assemblyLimits, captureLimits: assemblyLimits, checkCancellation: checkCancellation)
    }

    func testUnifiedReceiverRoutesInterleavedHelloAndOriginalInputOnOneQueue() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), receiver = try receiver(endpoint, maximum: 8192)
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { _ = Darwin.close(fd) }
        var fileport: mach_port_t = 0
        XCTAssertEqual(fileport_makeport(fd, &fileport), 0)
        defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        let offer = try CommandHandshakeOffer(nonce: Data(repeating: 7, count: 32)).canonicalBytes
        for _ in 0..<2 {
            try MachCommandWire.send(offer, destination: endpoint.port, replyPort: reply.port,
                identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
            try endpoint.sendInput(Data([1, 2]), fileport: fileport)
            guard case .hello(let hello) = try receiver.receiveNext(timeoutMilliseconds: 1000) else { return XCTFail("expected hello") }
            XCTAssertEqual(hello.payload, offer); hello.close()
            guard case .input(let input) = try receiver.receiveNext(timeoutMilliseconds: 1000) else { return XCTFail("expected input") }
            XCTAssertEqual(input.payload, Data([1, 2])); input.closeIfUnclaimed()
        }
    }

    func testUnifiedReceiverRejectsOtherCarriersOversizedControlAndWrongSenderWithoutLeakingRights() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), baseline = try sendReferences(reply.port)
        let receiver = try receiver(endpoint, maximum: 8192)
        for id in [MachCommandCallerReceiver.messageID, MachCommandCallerReceiver.helloReplyMessageID, mach_msg_id_t(123)] {
            try endpoint.sendInput(Data([1]), fileport: reply.port, version: 1, identifier: id)
            XCTAssertThrowsError(try receiver.receiveNext(timeoutMilliseconds: 1000))
            XCTAssertEqual(try sendReferences(reply.port), baseline)
        }
        try endpoint.sendInput(Data(count: 4097), fileport: reply.port, version: 1, identifier: MachCommandCallerReceiver.helloMessageID)
        XCTAssertThrowsError(try receiver.receiveNext(timeoutMilliseconds: 1000))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        try endpoint.sendInput(Data([1]), fileport: reply.port, version: 1, descriptorCount: 2, identifier: MachCommandCallerReceiver.helloMessageID)
        XCTAssertThrowsError(try receiver.receiveNext(timeoutMilliseconds: 1000))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        try endpoint.sendInput(Data([1]), fileport: reply.port, version: 1, identifier: MachCommandCallerReceiver.helloMessageID)
        XCTAssertThrowsError(try self.receiver(endpoint, user: geteuid() ^ 1).receiveNext(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .wrongPeer)
        }
        XCTAssertEqual(try sendReferences(reply.port), baseline)
    }

    func testRegistryRejectsCapacityBeforeAcceptingProfileAndPreservesItsExistingSession() throws {
        let owner = try registry(1), first = try registrySession(owner)
        defer { owner.close() }
        let endpoint = try Endpoint(), reply = try Endpoint(), baseline = try sendReferences(reply.port)
        let packet = try hello(endpoint, reply: reply), context = try registryContext()
        XCTAssertThrowsError(try owner.accept(hello: packet, context: { context })) {
            XCTAssertEqual($0 as? CommandSessionRegistryError, .capacity)
        }
        XCTAssertEqual(owner.retainedSessionCount, 1)
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        XCTAssertThrowsError(try receiver(reply).receiveHelloReply(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
        let capture = try registryCapture(owner, received: registrySubmission(first.callerBinding))
        capture.close()
    }

    func testRegistryCloseAndRetirementLeaveIndependentCaptureAndUnreadPipeIntact() throws {
        let owner = try registry(), profile = try registrySession(owner)
        var fds: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&fds), 0)
        defer { fds.forEach { _ = Darwin.close($0) } }
        let bytes = Data("still-unread".utf8)
        XCTAssertEqual(bytes.withUnsafeBytes { Darwin.write(fds[1], $0.baseAddress, $0.count) }, bytes.count)
        let received = try registrySubmission(profile.callerBinding, descriptor: fds[0])
        let capture = try registryCapture(owner, received: received)
        defer { capture.close() }
        try owner.retire(callerBinding: profile.callerBinding)
        XCTAssertEqual(owner.retainedSessionCount, 0)
        let rejected = try registrySubmission(profile.callerBinding)
        XCTAssertThrowsError(try registryCapture(owner, received: rejected)) {
            XCTAssertEqual($0 as? CommandSessionRegistryError, .unknownSession)
        }
        try expectAssemblyResourcesRetired(rejected)
        owner.close(); owner.close()
        XCTAssertThrowsError(try registryCapture(owner, received: received))
        try capture.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        try received.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        try capture.withBorrowedInputDescriptor { fd in
            var actual = [UInt8](repeating: 0, count: bytes.count)
            XCTAssertEqual(Darwin.read(fd, &actual, actual.count), actual.count)
            XCTAssertEqual(Data(actual), bytes)
        }
        let restarted = try registry()
        defer { restarted.close() }
        let stale = try registrySubmission(profile.callerBinding)
        XCTAssertThrowsError(try registryCapture(restarted, received: stale))
        try expectAssemblyResourcesRetired(stale)
    }

    func testRegistryRepeatedInputAndHelloTransfersCannotCloseEarlierOwners() throws {
        let owner = try registry(), endpoint = try Endpoint(), reply = try Endpoint(), packet = try hello(endpoint, reply: reply)
        defer { owner.close() }
        let context = try registryContext(), profile = try owner.accept(hello: packet, context: { context })
        XCTAssertThrowsError(try owner.accept(hello: packet, context: { context })) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .retired)
        }
        let received = try registrySubmission(profile.callerBinding), alias = received
        let capture = try registryCapture(owner, received: received)
        defer { capture.close() }
        XCTAssertThrowsError(try registryCapture(owner, received: alias)) {
            XCTAssertEqual($0 as? RetainedCommandCaptureError, .alreadyOwned)
        }
        try capture.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        try capture.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        XCTAssertEqual(owner.retainedSessionCount, 1)
    }

    func testRegistryRoleRevisionOrCurrentRequirementChangeRetiresSessionsWithoutClosingCaptures() throws {
        for revisionChanged in [true, false] {
            let owner = try registry(), profile = try registrySession(owner)
            defer { owner.close() }
            let capture = try registryCapture(owner, received: registrySubmission(profile.callerBinding))
            defer { capture.close() }
            let changed = try registryContext(expression: revisionChanged ? nil : "false", revision: revisionChanged ? UUID() : nil)
            XCTAssertEqual(try owner.prune(context: { changed }), 1)
            XCTAssertEqual(owner.retainedSessionCount, 0)
            let stale = try registrySubmission(profile.callerBinding)
            XCTAssertThrowsError(try registryCapture(owner, received: stale, context: changed))
            try expectAssemblyResourcesRetired(stale)
            try capture.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try capture.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        }
    }

    func testRegistryReentryClosesOnlyASeparateIncomingTransferAndCloseCancelsAssembly() throws {
        let owner = try registry(), profile = try registrySession(owner), original = try registrySubmission(profile.callerBinding)
        defer { owner.close() }
        let inspection = TestRegistryInspection(tests: self, owner: owner, received: original)
        let capture = try registryCapture(owner, received: original, checkCancellation: {
            XCTAssertThrowsError(try inspection.tests.registryCapture(inspection.owner, received: inspection.received)) {
                XCTAssertEqual($0 as? CommandSessionRegistryError, .operationActive)
            }
            let other = try inspection.tests.registrySubmission(profile.callerBinding)
            XCTAssertThrowsError(try inspection.tests.registryCapture(inspection.owner, received: other)) {
                XCTAssertEqual($0 as? CommandSessionRegistryError, .operationActive)
            }
            try inspection.tests.expectAssemblyResourcesRetired(other)
        })
        defer { capture.close() }
        let incoming = try registrySubmission(profile.callerBinding)
        XCTAssertThrowsError(try registryCapture(owner, received: incoming, checkCancellation: { inspection.owner.close() })) {
            XCTAssertEqual($0 as? CommandSessionRegistryError, .closed)
        }
        try expectAssemblyResourcesRetired(incoming)
        XCTAssertEqual(owner.retainedSessionCount, 0)
        try capture.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
    }

    func testRegistryPrunesExecChangedAndExitedRealPeersAndKeepsAnotherSession() throws {
        let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint), owner = try registry()
        defer { owner.close() }
        let context = try registryContext(expression: "true"), parent = try registrySession(owner, context: context)
        let receiver = try receiver(endpoint, expression: peer.expression)
        func accept(_ verified: ReceivedMachCommandSubmission) throws -> CommandHandshakeProfile {
            let reply = try Endpoint()
            XCTAssertEqual(mach_port_mod_refs(mach_task_self_, reply.port, MACH_PORT_RIGHT_SEND, 1), KERN_SUCCESS)
            let offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32))
            let packet = MachCommandHello(payload: try offer.canonicalBytes, caller: verified.caller, reply: MachCommandReplyRight(taking: reply.port))
            return try owner.accept(hello: packet, context: { context })
        }
        let first = try accept(receiver.receive(timeoutMilliseconds: 5000))
        let wrongProcess = try registrySubmission(first.callerBinding)
        XCTAssertThrowsError(try registryCapture(owner, received: wrongProcess, context: context)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .wrongBinding)
        }
        try expectAssemblyResourcesRetired(wrongProcess)
        try peer.advance()
        let second = try receiver.receive(timeoutMilliseconds: 5000)
        XCTAssertEqual(try owner.prune(context: { context }), 1)
        XCTAssertEqual(owner.retainedSessionCount, 1)
        _ = try accept(second)
        try peer.stop()
        XCTAssertEqual(try owner.prune(context: { context }), 1)
        let capture = try registryCapture(owner, received: registrySubmission(parent.callerBinding), context: context)
        capture.close()
    }

    func testRegistryRequiresActiveProtectedFrontendPolicyAndValidScope() throws {
        for maximum in [0, -1] { XCTAssertThrowsError(try registry(maximum)) }
        XCTAssertThrowsError(try CommandSessionRegistry(macID: Data(), accountID: handshakeAccount, userID: geteuid(), maximumSessions: 1))
        for disabled in [true, false] {
            let owner = try registry(), profile = try registrySession(owner)
            defer { owner.close() }
            let entry = try AuthorityCodeEntry(role: disabled ? .commandFrontend : .transport, teamID: "ABCD123456",
                identifier: "dev.remozio.command", installedGeneration: 3, minimumGeneration: 2,
                codeDirectoryHash: Data(repeating: 1, count: 20), active: !disabled)
            let snapshot = AuthorityCodePolicySnapshot(revision: UUID(), policy: try .init(entries: [entry]),
                roleRevisions: [entry.role: UUID()])
            XCTAssertThrowsError(try owner.prune(currentCodePolicy: snapshot)) {
                XCTAssertEqual($0 as? CommandSessionRegistryError, .invalidCodePolicy)
            }
            XCTAssertEqual(owner.retainedSessionCount, 0)
            let stale = try registrySubmission(profile.callerBinding)
            XCTAssertThrowsError(try registryCapture(owner, received: stale))
            try expectAssemblyResourcesRetired(stale)
        }
    }

    func testRegistryMalformedAndUnnegotiatedSubmissionsReleaseInputAndKeepLiveSession() throws {
        let owner = try registry(), profile = try registrySession(owner)
        defer { owner.close() }
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { _ = Darwin.close(fd) }
        for bytes in [Data([0]), try DeterministicCBOR.encode(.map([0: .unsigned(99)]), limits: assemblyLimits)] {
            let received = try inputSubmission(fd, payload: bytes)
            XCTAssertThrowsError(try registryCapture(owner, received: received))
            try expectAssemblyResourcesRetired(received)
            XCTAssertEqual(owner.retainedSessionCount, 1)
        }
        let capture = try registryCapture(owner, received: registrySubmission(profile.callerBinding))
        capture.close()
    }


    func testRegistryDerivesOnlyTheProtectedFrontendRoleAndDoesNotUseGlobalRevision() throws {
        let owner = try registry()
        defer { owner.close() }
        let entry = try AuthorityCodeEntry(role: .commandFrontend, teamID: "ABCD123456", identifier: "dev.remozio.command",
            installedGeneration: 3, minimumGeneration: 2, codeDirectoryHash: Data(repeating: 0xab, count: 20), active: true)
        let policy = try AuthorityCodePolicy(entries: [entry]), role = UUID()
        let first = try owner.context(.init(revision: UUID(), policy: policy, roleRevisions: [.commandFrontend: role]))
        let second = try owner.context(.init(revision: UUID(), policy: policy, roleRevisions: [.commandFrontend: role]))
        XCTAssertEqual(first.roleRevision, second.roleRevision)
        XCTAssertEqual(first.expression, second.expression)
        XCTAssertTrue(first.expression.contains("anchor apple generic"))
        XCTAssertTrue(first.expression.contains("identifier \"dev.remozio.command\""))
        XCTAssertTrue(first.expression.contains(String(repeating: "ab", count: 20)))
        XCTAssertThrowsError(try owner.context(.init(revision: UUID(), policy: policy, roleRevisions: [:])))
        let endpoint = try Endpoint(), reply = try Endpoint(), baseline = try sendReferences(reply.port)
        let packet = try hello(endpoint, reply: reply)
        let snapshot = AuthorityCodePolicySnapshot(revision: UUID(), policy: policy, roleRevisions: [.commandFrontend: role])
        // The fixture has ad-hoc code. A protected release policy must reject it before replying.
        do {
            _ = try owner.accept(hello: packet, currentCodePolicy: snapshot)
            XCTFail("release policy accepted ad-hoc fixture")
        } catch {}
        XCTAssertEqual(owner.retainedSessionCount, 0)
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        XCTAssertThrowsError(try receiver(reply).receiveHelloReply(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    private func host(_ endpoint: Endpoint, maximum: Int = 4, wait: UInt32 = 20,
                      capabilities: CommandHandshakeCapabilities = .current, mac: Data? = nil, account: Data? = nil,
                      context: (() throws -> CommandSessionRegistry.Context)? = nil) throws -> CommandReceiveHost {
        let initial = try registryContext()
        return try CommandReceiveHost(takingReceiveRight: endpoint.transferReceiveRight(), macID: mac ?? handshakeMac,
            accountID: account ?? handshakeAccount, userID: geteuid(), auditSessionID: nil, maximumSessions: maximum,
            maximumPayloadBytes: 8192, receiveWaitMilliseconds: wait, replyTimeoutMilliseconds: 20, capabilities: capabilities,
            context: { _ in try context?() ?? initial })
    }
    private func hostSession(_ host: CommandReceiveHost, endpoint: Endpoint,
                             capabilities: CommandHandshakeCapabilities = .current) throws -> CommandHandshakeProfile {
        let reply = try Endpoint(), offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: capabilities)
        try MachCommandWire.send(offer.canonicalBytes, destination: endpoint.port, replyPort: reply.port,
            identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
        guard case .hello(let profile) = try host.poll(handleInput: { $0.closeIfUnclaimed(); XCTFail("unexpected input") }) else {
            throw MachCommandHandshakeError.invalidMessage
        }
        let response = try receiver(reply, maximum: 4096).receiveHelloReply(timeoutMilliseconds: 1000)
        defer { response.caller.close() }
        XCTAssertEqual(try CommandHandshakeReply.decode(response.payload, offer: offer, macID: profile.macID, accountID: profile.accountID), profile)
        return profile
    }
    private func enqueueHostInput(_ endpoint: Endpoint, binding: Data, descriptor: Int32? = nil) throws {
        let original = try commandSubmission()
        let claim = try CommandSubmission(schemaVersion: 1, executablePath: original.executablePath, arguments: original.arguments,
            directoryPath: original.directoryPath, requestedTargetUID: original.requestedTargetUID,
            environmentAdditions: original.environmentAdditions, ioMode: original.ioMode,
            disconnectBehavior: original.disconnectBehavior, unverifiedRationale: original.unverifiedRationale,
            binding: .init(id: original.binding.id, nonce: original.binding.nonce, callerBinding: binding), limits: assemblyLimits)
        let fd = descriptor ?? Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw RetainedCommandInputError.system(errno) }
        defer { if descriptor == nil { _ = Darwin.close(fd) } }
        var carried: mach_port_t = 0
        guard fileport_makeport(fd, &carried) == 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = mach_port_deallocate(mach_task_self_, carried) }
        try endpoint.sendInput(claim.canonicalBytes, fileport: carried)
    }
    private func hostCapture(_ host: CommandReceiveHost, received: sending ReceivedMachCommandInputSubmission,
                             checkCancellation: @Sendable () throws -> Void = {}) throws -> sending RetainedCommandCapture {
        try host.assemble(received: received, captureSchemaVersion: 2, resolvedTarget: assemblyTarget,
            minimalEnvironment: assemblyEnvironment, streamBinding: Data(repeating: 0xe4, count: 16),
            submissionLimits: assemblyLimits, captureLimits: assemblyLimits, checkCancellation: checkCancellation)
    }
    private func receiveReferences(_ port: mach_port_t) -> mach_port_urefs_t {
        var count: mach_port_urefs_t = 0
        _ = mach_port_get_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, &count)
        return count
    }

    func testHostTransfersTypedAttemptToJournalAndKeepsQueueAfterPermanentRefusal() throws {
        let endpoint = try Endpoint(), host = try host(endpoint, capabilities: .admissionResults, mac: Data(repeating: 1, count: 16), account: Data(repeating: 2, count: 16))
        defer { host.close() }
        let profile = try hostSession(host, endpoint: endpoint, capabilities: .admissionResults)
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), reply = try Endpoint()
        let original = try commandSubmission(binding: .init(id: Data(repeating: 0xb2, count: 16), nonce: Data(repeating: 0xb3, count: 32),
            callerBinding: profile.callerBinding))
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        try MachCommandAdmissionWire.send(original.canonicalBytes, inputDescriptor: fd, destination: endpoint.port,
            replyPort: reply.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        XCTAssertEqual(try host.poll { received in
            let attempt = try host.prepareAdmission(received: received, submissionLimits: self.assemblyLimits)
            XCTAssertThrowsError(try self.admitAttempt(attempt, fixture: fixture, resolution: .refuse(.policyRejected)))
        }, .inputHandled)
        XCTAssertEqual(try typedOutcome(reply, submission: original, profile: profile), .notAdmitted(.policyRejected, .never))
        XCTAssertEqual(try host.poll { $0.closeIfUnclaimed(); XCTFail("Unexpected input") }, .idle)
        XCTAssertEqual(host.retainedSessionCount, 1)
    }

    func testHostAdmissionControllerReportsRequestFailureWithoutRetiringHealthyQueue() throws {
        guard geteuid() != 0 else { throw XCTSkip("Normal-user fixture") }
        let endpoint = try Endpoint(), host = try host(endpoint, capabilities: .admissionResults,
            mac: Data(repeating: 1, count: 16), account: Data(repeating: 2, count: 16))
        defer { host.close() }
        let profile = try hostSession(host, endpoint: endpoint, capabilities: .admissionResults)
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), reply = try Endpoint()
        let original = try commandSubmission(binding: .init(id: Data(repeating: 0xb2, count: 16), nonce: Data(repeating: 0xb3, count: 32),
            callerBinding: profile.callerBinding))
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        try MachCommandAdmissionWire.send(original.canonicalBytes, inputDescriptor: fd, destination: endpoint.port,
            replyPort: reply.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        var reported = false
        XCTAssertEqual(try host.pollAdmission(journal: XCTUnwrap(fixture.authority), submissionLimits: assemblyLimits,
            resolve: { _ in XCTFail("Unprivileged fixture must fail first"); return .refuse(.policyRejected) },
            draft: { _ in throw ApprovalCoordinatorError.invalidDraft }, now: { fixture.now() }, receiptTimeMs: nil,
            onResult: { result in
                reported = true
                guard case .failure(let error) = result else { return XCTFail("Unexpected success") }
                XCTAssertEqual(error as? JournalLeaseError, .rootRequired)
            }), .inputHandled)
        XCTAssertTrue(reported)
        XCTAssertEqual(try typedOutcome(reply, submission: original, profile: profile), .uncertain(.storageFailure))
        XCTAssertEqual(try host.poll { $0.closeIfUnclaimed(); XCTFail("Unexpected input") }, .idle)
        XCTAssertEqual(host.retainedSessionCount, 1)
    }

    func testHostOwnsQueueAndTransfersCaptureWithoutReadingOrClosingItsInput() throws {
        let endpoint = try Endpoint(), host = try host(endpoint), profile = try hostSession(host, endpoint: endpoint)
        var pipeFDs: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&pipeFDs), 0)
        defer { for fd in pipeFDs { _ = Darwin.close(fd) } }
        let bytes = Data("still unread".utf8)
        XCTAssertEqual(bytes.withUnsafeBytes { Darwin.write(pipeFDs[1], $0.baseAddress, $0.count) }, bytes.count)
        try enqueueHostInput(endpoint, binding: profile.callerBinding, descriptor: pipeFDs[0])
        var command: RetainedCommandCapture?
        XCTAssertEqual(try host.poll { command = try self.hostCapture(host, received: $0) }, .inputHandled)
        XCTAssertEqual(command?.capture.submission.callerBinding, profile.callerBinding)
        host.close(); host.close()
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
        try XCTUnwrap(command).withBorrowedInputDescriptor { fd in
            var actual = [UInt8](repeating: 0, count: bytes.count)
            XCTAssertEqual(Darwin.read(fd, &actual, actual.count), bytes.count)
            XCTAssertEqual(Data(actual), bytes)
        }
        command?.close()
    }

    func testHostPrunesOnIdleAndInvalidTrafficWhileKeepingTheReceiveLifetimeUsable() throws {
        let endpoint = try Endpoint()
        var current = try registryContext()
        let host = try host(endpoint, context: { current })
        _ = try hostSession(host, endpoint: endpoint)
        XCTAssertEqual(host.retainedSessionCount, 1)
        current = try registryContext(revision: UUID())
        XCTAssertEqual(try host.poll { $0.closeIfUnclaimed(); XCTFail("unexpected input") }, .idle)
        XCTAssertEqual(host.retainedSessionCount, 0)
        _ = try hostSession(host, endpoint: endpoint)
        current = try registryContext(revision: UUID())
        for _ in 0..<4 {
            try endpoint.send(Data([1]))
            XCTAssertEqual(try host.poll { $0.closeIfUnclaimed(); XCTFail("unexpected input") }, .rejected(.malformed))
            XCTAssertEqual(host.retainedSessionCount, 0)
        }
        _ = try hostSession(host, endpoint: endpoint)
        XCTAssertEqual(host.retainedSessionCount, 1)
        host.close()
    }

    func testHostReloadsAfterReceiptAndClosesImportedReplyWhenPolicyReadFails() throws {
        enum Failure: Error { case policy }
        let endpoint = try Endpoint(), reply = try Endpoint(), baseline = try sendReferences(reply.port)
        let current = try registryContext()
        var reads = 0
        let host = try host(endpoint, context: { reads += 1; if reads == 2 { throw Failure.policy }; return current })
        try MachCommandWire.send(CommandHandshakeOffer(nonce: Data(repeating: 1, count: 32)).canonicalBytes,
            destination: endpoint.port, replyPort: reply.port, identifier: MachCommandCallerReceiver.helloMessageID,
            timeoutMilliseconds: 1000)
        XCTAssertThrowsError(try host.poll { $0.closeIfUnclaimed(); XCTFail("unexpected input") }) {
            XCTAssertEqual($0 as? Failure, .policy)
        }
        XCTAssertEqual(reads, 2)
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        XCTAssertEqual(host.retainedSessionCount, 0)
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
        XCTAssertThrowsError(try host.poll { $0.closeIfUnclaimed() }) {
            XCTAssertEqual($0 as? CommandReceiveHostError, .stopped)
        }
    }

    func testHostPolicyFailureRetiresExistingSessionsAndQueuedRightsWithoutFallback() throws {
        enum Failure: Error { case policy }
        let endpoint = try Endpoint(), reply = try Endpoint(), current = try registryContext()
        var fail = false
        let host = try host(endpoint, context: { if fail { throw Failure.policy }; return current })
        _ = try hostSession(host, endpoint: endpoint)
        let baseline = try sendReferences(reply.port)
        try endpoint.sendInput(Data([1]), fileport: reply.port)
        fail = true
        XCTAssertThrowsError(try host.poll { $0.closeIfUnclaimed(); XCTFail("unexpected input") })
        XCTAssertEqual(host.retainedSessionCount, 0)
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
    }

    func testHostCapacityIncompatibilityAndMalformedHelloDoNotRetireOtherSessions() throws {
        let endpoint = try Endpoint(), host = try host(endpoint, maximum: 1), reply = try Endpoint()
        _ = try hostSession(host, endpoint: endpoint)
        let baseline = try sendReferences(reply.port)
        try MachCommandWire.send(CommandHandshakeOffer(nonce: Data(repeating: 1, count: 32)).canonicalBytes,
            destination: endpoint.port, replyPort: reply.port, identifier: MachCommandCallerReceiver.helloMessageID,
            timeoutMilliseconds: 1000)
        XCTAssertEqual(try host.poll { $0.closeIfUnclaimed() }, .rejected(.capacity))
        XCTAssertEqual(host.retainedSessionCount, 1)
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        host.close()
        let next = try Endpoint(), available = try self.host(next)
        let old = try CommandHandshakeCapabilities(wireVersions: [1], submissionSchemaVersions: [1], inputCarrierVersions: [1])
        try MachCommandWire.send(CommandHandshakeOffer(nonce: Data(repeating: 1, count: 32), capabilities: old).canonicalBytes,
            destination: next.port, replyPort: reply.port, identifier: MachCommandCallerReceiver.helloMessageID,
            timeoutMilliseconds: 1000)
        XCTAssertEqual(try available.poll { $0.closeIfUnclaimed() }, .rejected(.incompatible))
        let response = try receiver(reply, maximum: 4096).receiveHelloReply(timeoutMilliseconds: 1000)
        response.caller.close()
        try MachCommandWire.send(Data([0xa0]), destination: next.port, replyPort: reply.port,
            identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
        XCTAssertEqual(try available.poll { $0.closeIfUnclaimed() }, .rejected(.malformed))
        _ = try hostSession(available, endpoint: next)
        available.close()
    }

    func testHostStopDuringBoundedReceiveReleasesTheRightOnItsOwnerThread() throws {
        let endpoint = try Endpoint(), host = try host(endpoint, wait: 100), stop = host.stop
        let finished = DispatchSemaphore(value: 0)
        DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(10)) { stop.requestStop(); finished.signal() }
        XCTAssertThrowsError(try host.poll { $0.closeIfUnclaimed(); XCTFail("unexpected input") }) {
            XCTAssertEqual($0 as? CommandReceiveHostError, .stopped)
        }
        XCTAssertEqual(finished.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
    }

    func testHostRejectsNonFileportInputAndRunStillAssemblesTheNextSubmission() throws {
        let endpoint = try Endpoint(), carried = try Endpoint(), current = try registryContext()
        var reads = 0
        let host = try host(endpoint, context: { reads += 1; return current })
        let profile = try hostSession(host, endpoint: endpoint)
        let baseline = try sendReferences(carried.port), before = reads
        try endpoint.sendInput(Data([1]), fileport: carried.port)
        XCTAssertEqual(try host.poll { $0.closeIfUnclaimed(); XCTFail("malformed input reached handler") }, .rejected(.malformed))
        XCTAssertEqual(reads, before + 2)
        XCTAssertEqual(try sendReferences(carried.port), baseline)
        XCTAssertEqual(host.retainedSessionCount, 1)
        XCTAssertEqual(receiveReferences(endpoint.port), 1)
        try endpoint.sendInput(Data([2]), fileport: carried.port)
        try enqueueHostInput(endpoint, binding: profile.callerBinding)
        var command: RetainedCommandCapture?
        XCTAssertThrowsError(try host.run { received in
            XCTAssertEqual(host.retainedSessionCount, 1)
            command = try self.hostCapture(host, received: received)
            host.stop.requestStop()
        }) { XCTAssertEqual($0 as? CommandReceiveHostError, .stopped) }
        XCTAssertEqual(try sendReferences(carried.port), baseline)
        XCTAssertEqual(host.retainedSessionCount, 0)
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
        try XCTUnwrap(command).withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        command?.close()
    }

    func testHostNonFileportRejectionStillObservesPolicyReadFailure() throws {
        enum Failure: Error { case policy }
        let endpoint = try Endpoint(), carried = try Endpoint(), current = try registryContext()
        var reads = 0, failAt = Int.max
        let host = try host(endpoint, context: { reads += 1; if reads == failAt { throw Failure.policy }; return current })
        _ = try hostSession(host, endpoint: endpoint)
        let baseline = try sendReferences(carried.port)
        failAt = reads + 2
        try endpoint.sendInput(Data([1]), fileport: carried.port)
        XCTAssertThrowsError(try host.poll { $0.closeIfUnclaimed(); XCTFail("malformed input reached handler") }) {
            guard case Failure.policy = $0 else { return XCTFail("expected current policy failure: \($0)") }
        }
        XCTAssertEqual(try sendReferences(carried.port), baseline)
        XCTAssertEqual(host.retainedSessionCount, 0)
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
    }

    func testHostRunOwnsTheLoopAndHandlerCanAssembleWithoutReceiveReentry() throws {
        let endpoint = try Endpoint(), host = try host(endpoint), profile = try hostSession(host, endpoint: endpoint)
        try enqueueHostInput(endpoint, binding: profile.callerBinding)
        var command: RetainedCommandCapture?
        XCTAssertThrowsError(try host.run { received in
            XCTAssertThrowsError(try host.poll { $0.closeIfUnclaimed() }) { XCTAssertEqual($0 as? CommandReceiveHostError, .operationActive) }
            XCTAssertThrowsError(try host.run { $0.closeIfUnclaimed() }) { XCTAssertEqual($0 as? CommandReceiveHostError, .operationActive) }
            command = try self.hostCapture(host, received: received)
            host.stop.requestStop()
        }) { XCTAssertEqual($0 as? CommandReceiveHostError, .stopped) }
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
        try XCTUnwrap(command).withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        command?.close()
    }

    func testHostStopDuringAssemblyCancelsAndClosesOnlyTheIncomingObjects() throws {
        let endpoint = try Endpoint(), host = try host(endpoint), profile = try hostSession(host, endpoint: endpoint)
        try enqueueHostInput(endpoint, binding: profile.callerBinding)
        var earlier: RetainedCommandCapture?
        _ = try host.poll { earlier = try self.hostCapture(host, received: $0) }
        try enqueueHostInput(endpoint, binding: profile.callerBinding)
        let stop = host.stop
        var inspection: TestInputInspection?
        XCTAssertThrowsError(try host.poll { received in
            inspection = TestInputInspection(received: received)
            _ = try self.hostCapture(host, received: TestInputInspection(received: received).received,
                checkCancellation: { stop.requestStop() })
        }) { XCTAssertEqual($0 as? CommandReceiveHostError, .stopped) }
        try expectAssemblyResourcesRetired(XCTUnwrap(inspection).received)
        try XCTUnwrap(earlier).withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
        earlier?.close()
    }

    func testHostInvalidConfigurationAndDeinitReleaseOnlyTransferredReceiveRights() throws {
        for wait: UInt32 in [0, 60_001] {
            let endpoint = try Endpoint(), reply = try Endpoint(), baseline = try sendReferences(reply.port)
            try endpoint.sendInput(Data([1]), fileport: reply.port)
            XCTAssertThrowsError(try host(endpoint, wait: wait))
            XCTAssertEqual(receiveReferences(endpoint.port), 0)
            XCTAssertEqual(try sendReferences(reply.port), baseline)
        }
        let endpoint = try Endpoint()
        var owner: CommandReceiveHost? = try host(endpoint)
        XCTAssertNotNil(owner)
        owner = nil
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
    }

    func testHostCaptureTransfersToJournalAndHostRetirementPreservesTheQueuedRequest() throws {
        let fixture = try CommandRequestFixture(owned: true, commandSchema: 2), journal = try XCTUnwrap(fixture.authority)
        let endpoint = try Endpoint(), host = try host(endpoint), profile = try hostSession(host, endpoint: endpoint)
        try enqueueHostInput(endpoint, binding: profile.callerBinding)
        var request: IssuedRequestPayload?, inspection: TestInputInspection?
        _ = try host.poll { received in
            inspection = TestInputInspection(received: received)
            let command = try self.hostCapture(host, received: TestInputInspection(received: received).received)
            request = try journal.admitCommand(command, draft: fixture.draft(command), expression: self.selfExpression(),
                userID: geteuid(), auditSessionID: nil, now: { fixture.now() }, receiptTimeMs: nil)
        }
        let id = try XCTUnwrap(request).requestID
        host.close()
        XCTAssertEqual(try journal.withRequests { try $0.state(requestID: id).phase }, .queued)
        try XCTUnwrap(inspection).received.input.withBorrowedDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        let now = fixture.now(120)
        _ = try journal.withRequests { try $0.retirePending(requestID: id, reason: .cancelled, now: now, receiptTimeMs: nil) }
        try expectAssemblyResourcesRetired(XCTUnwrap(inspection).received)
    }

    func testHostAssemblyPreflightReentryDoesNotCloseItsActiveInput() throws {
        let endpoint = try Endpoint(), context = try registryContext()
        var reenter: (() throws -> Void)?
        let host = try host(endpoint, context: { try reenter?(); return context })
        let profile = try hostSession(host, endpoint: endpoint)
        try enqueueHostInput(endpoint, binding: profile.callerBinding)
        var command: RetainedCommandCapture?
        _ = try host.poll { received in
            let alias = TestInputInspection(received: received)
            reenter = {
                XCTAssertThrowsError(try self.hostCapture(host, received: alias.received)) {
                    XCTAssertEqual($0 as? CommandReceiveHostError, .operationActive)
                }
            }
            defer { reenter = nil }
            command = try self.hostCapture(host, received: alias.received)
        }
        try XCTUnwrap(command).withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        host.close(); command?.close()
    }

    func testHostReplyQueueTimeoutPreservesItsReceiveQueueAndOtherSessions() throws {
        let endpoint = try Endpoint(), host = try host(endpoint), reply = try Endpoint()
        _ = try hostSession(host, endpoint: endpoint)
        var status = mach_port_status_t(), count = mach_msg_type_number_t(MemoryLayout<mach_port_status_t>.size / MemoryLayout<integer_t>.size)
        XCTAssertEqual(withUnsafeMutablePointer(to: &status) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                mach_port_get_attributes(mach_task_self_, reply.port, Int32(MACH_PORT_RECEIVE_STATUS), $0, &count)
            }
        }, KERN_SUCCESS)
        for _ in 0..<status.mps_qlimit { try reply.send(Data([1])) }
        let baseline = try sendReferences(reply.port)
        try MachCommandWire.send(CommandHandshakeOffer(nonce: Data(repeating: 1, count: 32)).canonicalBytes,
            destination: endpoint.port, replyPort: reply.port, identifier: MachCommandCallerReceiver.helloMessageID,
            timeoutMilliseconds: 1000)
        XCTAssertEqual(try host.poll { $0.closeIfUnclaimed() }, .rejected(.replyFailure))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        XCTAssertEqual(host.retainedSessionCount, 1)
        _ = try hostSession(host, endpoint: endpoint)
        host.close()
    }

    func testHostRejectedAssemblyCanKeepItsOriginalSessionAndReceiveLoopUsable() throws {
        let endpoint = try Endpoint(), host = try host(endpoint), profile = try hostSession(host, endpoint: endpoint)
        try enqueueHostInput(endpoint, binding: Data(repeating: 0, count: 16))
        var inspected: TestInputInspection?
        XCTAssertEqual(try host.poll { received in
            inspected = TestInputInspection(received: received)
            XCTAssertThrowsError(try self.hostCapture(host, received: TestInputInspection(received: received).received)) {
                XCTAssertEqual($0 as? CommandSessionRegistryError, .unknownSession)
            }
        }, .inputHandled)
        try expectAssemblyResourcesRetired(XCTUnwrap(inspected).received)
        XCTAssertEqual(host.retainedSessionCount, 1)
        try enqueueHostInput(endpoint, binding: profile.callerBinding)
        _ = try host.poll { try self.hostCapture(host, received: $0).close() }
        host.close()
    }

    func testHostStopBeforeFirstWorkDisposesWithoutWaitingForDeinit() throws {
        for run in [false, true] {
            let endpoint = try Endpoint(), host = try host(endpoint)
            host.stop.requestStop()
            if run { XCTAssertThrowsError(try host.run { $0.closeIfUnclaimed() }) }
            else { XCTAssertThrowsError(try host.poll { $0.closeIfUnclaimed() }) }
            XCTAssertEqual(receiveReferences(endpoint.port), 0)
        }
    }

}

extension MachCommandCallerReceiverTests {
    // Same-process fixtures exercise actual kernel carriers. They do not prove privileged child execution.
    private func serveIO(_ port: mach_port_t, admission: Data?, terminal: Data?, release: DispatchSemaphore,
                         writeOutput: Bool = false, expectClosed: Bool = false, mapped: Bool = false) throws -> (DispatchSemaphore, OSAllocatedUnfairLock<Result<Void, Error>?>) {
        let expression = try selfExpression(), user = geteuid(), completed = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        DispatchQueue.global().async {
            defer { completed.signal() }
            result.withLock { output in output = Result {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression,
                    userID: user, auditSessionID: nil, maxPayloadBytes: 8192)
                let input = mapped ? try receiver.receiveMappedIOInput(timeoutMilliseconds: 5000) : try receiver.receiveIOInput(timeoutMilliseconds: 5000)
                defer { input.closeIfUnclaimed() }
                let channels = try XCTUnwrap(input.outputs)
                try channels.recheck()
                if let admission { try input.sendAdmissionReply(admission) }
                guard release.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                if expectClosed { XCTAssertThrowsError(try channels.recheck()); return }
                if writeOutput {
                    try channels.output.withBorrowedDescriptor { XCTAssertEqual(Darwin.write($0, "stdout", 6), 6) }
                    try channels.error.withBorrowedDescriptor { XCTAssertEqual(Darwin.write($0, "stderr", 6), 6) }
                }
                if let terminal { try channels.sendTerminalResult(terminal, timeoutMilliseconds: 1000) }
            } }
        }
        return (completed, result)
    }
    private func ioPayloads(profile: CommandHandshakeProfile, submission: CommandSubmission,
                            outcome: CommandAdmissionOutcome? = nil, terminal: CommandTerminalOutcome = .exited(7),
                            outputInterrupted: Bool = false) throws -> (Data, Data) {
        let request = CommandAdmittedRequest(requestID: Data(repeating: 6, count: 16),
            requestDigest: Data(repeating: 7, count: 32), challenge: Data(repeating: 8, count: 32))
        let admission = CommandAdmissionResultPayload(profile: profile, submission: submission.binding,
            submissionDigest: Data(SHA256.hash(data: submission.canonicalBytes)), outcome: outcome ?? .admitted(request))
        return (try admission.canonicalBytes, try CommandTerminalResultPayload(profile: profile, original: submission,
            request: request, outcome: terminal, outputInterrupted: outputInterrupted).canonicalBytes)
    }
    func testIOClientKeepsSessionAfterEmptyPollAndReceivesBoundTerminalAndOriginalStreams() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 3)
        let submission = try commandSubmission(), payloads = try ioPayloads(profile: handshake.profile, submission: submission)
        var input: [Int32] = [-1, -1], output: [Int32] = [-1, -1], error: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&input), 0); XCTAssertEqual(pipe(&output), 0); XCTAssertEqual(pipe(&error), 0)
        defer { for fd in input + output + error { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(input[1], "unread", 6), 6)
        let inputFlags = fcntl(input[0], F_GETFL), references = try sendReferences(endpoint.port)
        let release = DispatchSemaphore(value: 0)
        let server = try serveIO(endpoint.port, admission: payloads.0, terminal: payloads.1, release: release, writeOutput: true)
        defer { release.signal() }
        let result = try MachCommandIOClient.submit(submission, inputDescriptor: input[0], outputDescriptor: output[1], errorDescriptor: error[1],
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192)
        guard case .admitted(let session) = result else { return XCTFail("An admitted request must retain its terminal channel") }
        defer { session.close() }
        XCTAssertEqual(try sendReferences(endpoint.port), references)
        XCTAssertNil(try session.pollTerminalResult(timeoutMilliseconds: 250))
        release.signal()
        XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
        let terminal = try XCTUnwrap(session.pollTerminalResult(timeoutMilliseconds: 1000))
        XCTAssertEqual(terminal.outcome, .exited(7)); XCTAssertEqual(terminal.submission, submission.binding)
        XCTAssertEqual(try session.pollTerminalResult()?.outcome, .exited(7))
        var bytes = [UInt8](repeating: 0, count: 6)
        for (fd, expected) in [(input[0], "unread"), (output[0], "stdout"), (error[0], "stderr")] {
            XCTAssertEqual(Darwin.read(fd, &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data(expected.utf8))
        }
        XCTAssertEqual(fcntl(input[0], F_GETFL), inputFlags)
        XCTAssertEqual(try sendReferences(endpoint.port), references - 1)
    }
    func testIOClientRefusalAndUncertaintyCloseTheTerminalRightWithoutResubmission() throws {
        for outcome: CommandAdmissionOutcome in [.notAdmitted(.updateWaiting, .updateWaiting), .uncertain(.storageFailure)] {
            let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 3)
            let submission = try commandSubmission(), payloads = try ioPayloads(profile: handshake.profile, submission: submission, outcome: outcome)
            let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
            defer { _ = Darwin.close(input); _ = Darwin.close(output) }
            let release = DispatchSemaphore(value: 0), server = try serveIO(endpoint.port, admission: payloads.0,
                terminal: nil, release: release, expectClosed: true)
            defer { release.signal() }
            let result = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
                handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192)
            guard case .result(let verified) = result else { return XCTFail("A refusal must not retain an execution session") }
            XCTAssertEqual(verified.outcome, outcome)
            release.signal(); XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
            XCTAssertThrowsError(try receiver(endpoint).receiveIOInput(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
            XCTAssertGreaterThanOrEqual(fcntl(input, F_GETFD), 0); XCTAssertGreaterThanOrEqual(fcntl(output, F_GETFD), 0)
        }
    }
    func testIOClientMalformedTerminalRetiresSessionWithoutResubmission() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 3)
        let submission = try commandSubmission(), payloads = try ioPayloads(profile: handshake.profile, submission: submission)
        let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        let release = DispatchSemaphore(value: 0), server = try serveIO(endpoint.port, admission: payloads.0, terminal: Data([0xa0]), release: release)
        defer { release.signal() }
        let result = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192)
        guard case .admitted(let session) = result else { return XCTFail("An admitted request must retain its terminal channel") }
        release.signal(); XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
        XCTAssertThrowsError(try session.pollTerminalResult(timeoutMilliseconds: 1000))
        XCTAssertThrowsError(try session.pollTerminalResult()) { XCTAssertEqual($0 as? MachCommandHandshakeError, .retired) }
        XCTAssertThrowsError(try receiver(endpoint).receiveIOInput(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
    }
    func testIOClientCancellationClosesAdmittedTerminalBeforeAnyDispatch() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 3)
        let submission = try commandSubmission(), payloads = try ioPayloads(profile: handshake.profile, submission: submission)
        let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        let release = DispatchSemaphore(value: 0), server = try serveIO(endpoint.port, admission: payloads.0, terminal: nil, release: release, expectClosed: true)
        defer { release.signal() }
        let result = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192)
        guard case .admitted(let session) = result else { return XCTFail("An admitted request must retain its terminal channel") }
        XCTAssertThrowsError(try session.pollTerminalResult(checkCancellation: { throw CancellationError() })) { XCTAssertTrue($0 is CancellationError) }
        release.signal(); XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
    }
    func testIOClientRejectsPublicNonRootPolicyAndLegacyProfileBeforeExposingStreams() throws {
        let endpoint = try Endpoint()
        let policy = try XPCPeerPolicy(teamID: "TEAMID1234", componentIdentifier: "dev.remozio.fixture",
            approvedCodeDirectoryHashes: [Data(repeating: 1, count: 20)], expectedUserID: 1)
        XCTAssertThrowsError(try MachCommandIOClient.submit(commandSubmission(), inputDescriptor: -1, outputDescriptor: -1, errorDescriptor: -1,
            handshake: admissionClientFixture(endpoint.port, input: 4, wire: 3), authorityPolicy: policy, maximumPayloadBytes: 8192)) { XCTAssertEqual($0 as? MachCommandHandshakeError, .invalidConfiguration) }
        XCTAssertThrowsError(try MachCommandIOClient.submit(commandSubmission(), inputDescriptor: -1, outputDescriptor: -1, errorDescriptor: -1,
            handshake: admissionClientFixture(endpoint.port, wire: 2), expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible)
        }
        XCTAssertThrowsError(try receiver(endpoint).receiveIOInput(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        XCTAssertEqual(try sendReferences(endpoint.port), 1)
    }
}


extension MachCommandCallerReceiverTests {
    func testIOAdmissionAttemptRetainsAllStreamsThroughJournalAdmissionAndRetiresOnlyCopies() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let endpoint = try Endpoint(), helloReply = try Endpoint(), admissionReply = try Endpoint(), terminalReply = try Endpoint()
            let session = try RetainedCommandHandshake(hello: hello(endpoint, reply: helloReply, capabilities: .executionChannels),
                capabilities: .executionChannels, macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
            defer { session.close() }
            let submission = try commandSubmission(binding: .init(id: Data(repeating: 4, count: 16), nonce: Data(repeating: 5, count: 32),
                callerBinding: session.profile.callerBinding))
            var input: [Int32] = [-1, -1]; XCTAssertEqual(pipe(&input), 0)
            let output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
            defer { for fd in input + [output] { _ = Darwin.close(fd) } }
            XCTAssertEqual(Darwin.write(input[1], "unread", 6), 6)
            try MachCommandIOWire.send(submission.canonicalBytes, inputDescriptor: input[0], outputDescriptor: output, errorDescriptor: output,
                destination: endpoint.port, admissionReply: admissionReply.port, terminalReply: terminalReply.port,
                maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
            let received = try receiver(endpoint, maximum: 8192).receiveIOInput(timeoutMilliseconds: 1000)
            let channels = try XCTUnwrap(received.outputs)
            let attempt = try session.prepareAdmission(received: TestInputInspection(received: received).received,
                expression: selfExpression(), userID: geteuid(), auditSessionID: nil, submissionLimits: assemblyLimits)
            received.closeIfUnclaimed()
            try channels.recheck()
            let request = try admitAttempt(attempt, fixture: fixture)
            guard case .admitted(let identity) = try typedOutcome(admissionReply, submission: submission, profile: session.profile) else {
                return XCTFail("The journal must acknowledge the exact admitted request")
            }
            XCTAssertEqual(identity.requestID, request.requestID)
            XCTAssertEqual(try sendReferences(admissionReply.port), 1); XCTAssertEqual(try sendReferences(terminalReply.port), 2)
            try channels.recheck()
            let retiredAt = fixture.now(110)
            try XCTUnwrap(fixture.authority).withRequests { _ = try $0.retirePending(requestID: request.requestID, reason: .cancelled,
                now: retiredAt, receiptTimeMs: nil) }
            XCTAssertThrowsError(try channels.recheck())
            XCTAssertEqual(try sendReferences(terminalReply.port), 1)
            var bytes = [UInt8](repeating: 0, count: 6)
            XCTAssertEqual(Darwin.read(input[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("unread".utf8))
            XCTAssertGreaterThanOrEqual(fcntl(output, F_GETFD), 0)
        }
    }
    func testIOCaptureFailureClosesAllImportedChannelsAndPreservesBorrowedDescriptors() throws {
        let endpoint = try Endpoint(), admission = try Endpoint(), terminal = try Endpoint()
        let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        try MachCommandIOWire.send(commandSubmission(executablePath: "/not/a/remozio/program").canonicalBytes,
            inputDescriptor: input, outputDescriptor: output, errorDescriptor: output, destination: endpoint.port,
            admissionReply: admission.port, terminalReply: terminal.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        let received = try receiver(endpoint, maximum: 8192).receiveIOInput(timeoutMilliseconds: 1000)
        let channels = try XCTUnwrap(received.outputs)
        XCTAssertThrowsError(try assemble(received))
        try expectAssemblyResourcesRetired(received); XCTAssertThrowsError(try channels.recheck())
        XCTAssertEqual(try sendReferences(admission.port), 1); XCTAssertEqual(try sendReferences(terminal.port), 1)
        XCTAssertGreaterThanOrEqual(fcntl(input, F_GETFD), 0); XCTAssertGreaterThanOrEqual(fcntl(output, F_GETFD), 0)
    }
}


extension MachCommandCallerReceiverTests {
    func testIOClientLateTerminalOrCancellationAfterReceiptRetiresRatherThanReturningEmptyPoll() throws {
        for late in [false, true] {
            let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 3)
            let submission = try commandSubmission(), payloads = try ioPayloads(profile: handshake.profile, submission: submission)
            let input = Darwin.open("/dev/null", O_RDONLY), output = Darwin.open("/dev/null", O_WRONLY)
            defer { _ = Darwin.close(input); _ = Darwin.close(output) }
            let release = DispatchSemaphore(value: 0), server = try serveIO(endpoint.port, admission: payloads.0, terminal: payloads.1, release: release)
            defer { release.signal() }
            let result = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
                handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192)
            guard case .admitted(let session) = result else { return XCTFail("Admission must retain the terminal channel") }
            release.signal(); XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
            var samples = 0, cancellations = 0
            XCTAssertThrowsError(try session.pollTerminalResult(timeoutMilliseconds: 1000, checkCancellation: {
                cancellations += 1
                if !late, cancellations >= 2 { throw CancellationError() }
            }, clock: { samples += 1; return late && samples >= 4 ? 1000 : 0 })) {
                if late { XCTAssertEqual($0 as? CommandTerminalResultError, .deadlineExceeded) }
                else { XCTAssertTrue($0 is CancellationError) }
            }
            XCTAssertThrowsError(try session.pollTerminalResult()) { XCTAssertEqual($0 as? MachCommandHandshakeError, .retired) }
            XCTAssertThrowsError(try receiver(endpoint).receiveIOInput(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        }
    }
}

extension MachCommandCallerReceiverTests {
    private func ownerIOCommand(admission: Endpoint, terminal: Endpoint, inputDescriptor: Int32? = nil,
                                outputDescriptor: Int32? = nil, errorDescriptor: Int32? = nil,
                                executablePath: String = "/usr/bin/true", arguments: [Data]? = nil, wire: UInt64 = 3, ioMode: CommandIOMode = .pipes,
                                disconnect: StartedCommandDisconnect = .terminate) throws ->
        (ReceivedMachCommandInputSubmission, RetainedCommandCapture, CommandSubmission, CommandHandshakeProfile) {
        let endpoint = try Endpoint(), input = inputDescriptor ?? Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        let defaultOutput = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        let output = outputDescriptor ?? defaultOutput, error = errorDescriptor ?? output
        guard input >= 0, output >= 0, error >= 0 else { throw MachCommandCallerError.unavailable }
        defer { if inputDescriptor == nil { _ = Darwin.close(input) }; _ = Darwin.close(defaultOutput) }
        let submission = try commandSubmission(executablePath: executablePath, arguments: arguments, disconnect: disconnect, ioMode: ioMode)
        let profile = CommandHandshakeProfile(wireVersion: wire, submissionSchemaVersion: 1, inputCarrierVersion: 4,
            callerBinding: submission.binding.callerBinding, macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16))
        try MachCommandIOWire.send(submission.canonicalBytes, inputDescriptor: input, outputDescriptor: output, errorDescriptor: error,
            destination: endpoint.port, admissionReply: admission.port, terminalReply: terminal.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        let received = try receiver(endpoint, maximum: 8192).receiveIOInput(timeoutMilliseconds: 1000)
        return (received, try assemble(received, admissionProfile: profile), submission, profile)
    }
    private func ownerAdmission(_ endpoint: Endpoint, submission: CommandSubmission, profile: CommandHandshakeProfile) throws -> VerifiedCommandAdmissionResult {
        let raw = try receiver(endpoint, maximum: 4096).receiveAdmissionReply(timeoutMilliseconds: 1000)
        defer { raw.caller.close() }
        return try CommandAdmissionResultPayload.decode(raw.payload, profile: profile, original: submission)
    }
    private func ownerTerminal(_ endpoint: Endpoint, submission: CommandSubmission, admission: VerifiedCommandAdmissionResult) throws -> VerifiedCommandTerminalResult {
        let raw = try receiver(endpoint, maximum: 4096).receiveTerminalReply(timeoutMilliseconds: 1000)
        defer { raw.caller.close() }
        return try CommandTerminalResultPayload.decode(raw.payload, profile: admission.profile, original: submission, admission: admission)
    }
    private func ownerDecision(_ request: IssuedRequestPayload, fixture: CommandRequestFixture, decline: Bool) throws -> ConsumptionReceipt {
        let body = try DecisionPayload(macID: request.macID, accountID: request.accountID, requestID: request.requestID,
            requestDigest: request.requestDigest(bodyLimits: fixture.limits, signingLimits: fixture.limits), challenge: request.challenge,
            phoneID: Data(repeating: 5, count: 16), keyID: Data(repeating: decline ? 7 : 6, count: 16),
            action: request.permittedActions.first { $0.choice == (decline ? .decline : .execute) }!).encode(limits: fixture.limits)
        let input = try SigningInput.make(wireVersion: 1, messageType: .decision, purpose: decline ? .cancellation : .biometricAuthorization,
            canonicalPayload: body, payloadLimits: fixture.limits, inputLimits: fixture.limits)
        let signature = try (decline ? fixture.decision : fixture.biometric).signature(for: input).rawRepresentation
        let now = fixture.now(120)
        return try XCTUnwrap(fixture.authority).withRequests {
            try $0.consume(canonicalDecision: body, signature: signature, authenticatedPhoneID: Data(repeating: 5, count: 16),
                authenticatedEnrollmentEpoch: Data(repeating: 9, count: 16), now: now, receiptTimeMs: nil)
        }
    }
    func testIOOwnerCommittedPendingRetirementSendsExactTerminalOnce() throws {
        let cases: [(PendingRequestRetirement, UInt64, CommandTerminalOutcome)] = [(.cancelled, 120, .cancelledBeforeStart),
            (.deadlineElapsed, 200, .expired), (.targetTimedOut, 120, .expired), (.targetDisappeared, 120, .unknown), (.authorityRestart, 120, .cancelledBeforeStart)]
        for checkpointed in [false, true] {
            for (reason, time, expected) in cases {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
                let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
                let (received, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
                let request = try admitOwnedCommand(command, fixture: fixture)
                let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile), now = fixture.now(time)
                let state = try authority.withRequests { try $0.retirePending(requestID: request.requestID, reason: reason, now: now, receiptTimeMs: nil) }
                let terminal = try ownerTerminal(terminalPort, submission: submission, admission: admission)
                XCTAssertEqual(terminal.outcome, expected); XCTAssertEqual(terminal.request.requestID, request.requestID)
                XCTAssertEqual(terminal.request.requestDigest, state.requestDigest); XCTAssertEqual(terminal.request.challenge, state.challenge)
                XCTAssertEqual(terminal.submission, submission.binding); XCTAssertTrue(state.phase.isTerminal)
                try expectAssemblyResourcesRetired(received); XCTAssertEqual(try sendReferences(terminalPort.port), 1)
                XCTAssertThrowsError(try authority.withRequests { try $0.retirePending(requestID: request.requestID, reason: reason, now: now, receiptTimeMs: nil) })
                XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
                XCTAssertNotNil(try fixture.reservation(submission.binding.id))
            }
        }
    }
    func testIOOwnerSignedDeclineSendsDeniedAfterDurableConsumption() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (received, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            let request = try admitOwnedCommand(command, fixture: fixture), admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            let receipt = try ownerDecision(request, fixture: fixture, decline: true)
            XCTAssertEqual(receipt.event.outcome, .noDispatch)
            XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .denied)
            XCTAssertEqual(try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID)?.phase }, .declined)
            try expectAssemblyResourcesRetired(received)
            XCTAssertThrowsError(try ownerDecision(request, fixture: fixture, decline: true))
            XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        }
    }
    func testIOOwnerExpirySweepDeliversCommittedExpiryOnce() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            let request = try admitOwnedCommand(command, fixture: fixture), admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            let now = fixture.now(200)
            XCTAssertEqual(try authority.withRequests { try $0.expirePending(now: now, receiptTimeMs: nil).map(\.requestID) }, [request.requestID])
            XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .expired)
            XCTAssertTrue(try authority.withRequests { try $0.expirePending(now: now, receiptTimeMs: nil).isEmpty })
            XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        }
    }
    func testIOOwnerRejectedRetirementCommitCannotSendKnownNoEffect() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            let request = try admitOwnedCommand(command, fixture: fixture), admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            try fixture.sql("CREATE TRIGGER reject_terminal_audit BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
            let now = fixture.now(120)
            XCTAssertThrowsError(try authority.withRequests { try $0.retirePending(requestID: request.requestID, reason: .cancelled, now: now, receiptTimeMs: nil) })
            XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
            XCTAssertEqual(try authority.withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
            try fixture.sql("DROP TRIGGER reject_terminal_audit")
            _ = try authority.withRequests { try $0.retirePending(requestID: request.requestID, reason: .cancelled, now: now, receiptTimeMs: nil) }
            XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .cancelledBeforeStart)
        }
    }
    func testIOOwnerCheckpointPrepareOrFinalizeFailureCannotClaimKnownNoEffect() throws {
        for finalize in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: true, owned: true)
            let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (received, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            let request = try admitOwnedCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            let condition = finalize ? "NEW.pending IS NULL" : "NEW.pending IS NOT NULL"
            try fixture.sql("CREATE TRIGGER fail_terminal_checkpoint BEFORE UPDATE ON continuity_v1 WHEN \(condition) BEGIN SELECT RAISE(ABORT,'injected'); END", continuity: true)
            let now = fixture.now(120)
            XCTAssertThrowsError(try authority.withRequests { try $0.retirePending(requestID: request.requestID, reason: .cancelled, now: now, receiptTimeMs: nil) })
            XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .unknown)
            try expectAssemblyResourcesRetired(received); XCTAssertEqual(try sendReferences(terminalPort.port), 1)
            XCTAssertThrowsError(try authority.withRequests { try $0.state(requestID: request.requestID) })
            XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        }
    }
    func testIOOwnerFatalStorageFailureReportsOnlyUnknownAndReleasesChannels() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (received, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            _ = try admitOwnedCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            XCTAssertEqual(chmod(fixture.root.appendingPathComponent("store/journal.sqlite").path, 0o644), 0)
            XCTAssertThrowsError(try authority.withRequests { _ in XCTFail("Untrusted storage must not enter the request owner") })
            XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .unknown)
            try expectAssemblyResourcesRetired(received); XCTAssertEqual(try sendReferences(terminalPort.port), 1)
        }
    }
    func testIOOwnerFullTerminalQueueDoesNotDelayOrRollbackCommittedCancellation() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (received, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            let request = try admitOwnedCommand(command, fixture: fixture)
            _ = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            for _ in 0..<5 { try terminalPort.send(Data([1]), identifier: MachCommandCallerReceiver.terminalReplyMessageID) }
            let now = fixture.now(120), started = DispatchTime.now().uptimeNanoseconds
            let state = try authority.withRequests { try $0.retirePending(requestID: request.requestID, reason: .cancelled, now: now, receiptTimeMs: nil) }
            XCTAssertLessThan(DispatchTime.now().uptimeNanoseconds - started, 2_000_000_000)
            XCTAssertEqual(state.phase, .cancelled); XCTAssertEqual(try sendReferences(terminalPort.port), 1)
            try expectAssemblyResourcesRetired(received); XCTAssertNotNil(try fixture.reservation(submission.binding.id))
            for _ in 0..<5 {
                let raw = try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 1000)
                raw.caller.close(); XCTAssertEqual(raw.payload, Data([1]))
            }
            XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
            XCTAssertEqual(try authority.withRequests { try $0.state(requestID: request.requestID).phase }, .cancelled)
        }
    }
    func testIOOwnerClosureReportsUnknownOnceWithoutClaimingDurableNoEffect() throws {
        let fixture = try CommandRequestFixture(owned: true)
        let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
        let (received, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
        _ = try admitOwnedCommand(command, fixture: fixture)
        let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        try authority.close()
        XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .unknown)
        try expectAssemblyResourcesRetired(received)
        XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
    }
    func testIOOwnerGenericVerifiedResultDoesNotInventAChildExitStatus() throws {
        for event: RequestEvent in [.verifySuccess, .verifyFailure] {
            let fixture = try CommandRequestFixture(owned: true)
            let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            let request = try admitOwnedCommand(command, fixture: fixture), admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            _ = try ownerDecision(request, fixture: fixture, decline: false)
            let now = fixture.now(130)
            _ = try authority.withRequests { try $0.recordOutcome(requestID: request.requestID, expectedRevision: 0, event: .beginDispatch, now: now, receiptTimeMs: nil) }
            _ = try authority.withRequests { try $0.recordOutcome(requestID: request.requestID, expectedRevision: 1, event: event, now: now, receiptTimeMs: nil) }
            XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .unknown)
        }
    }
}

extension MachCommandCallerReceiverTests {
    func testIOOwnerClientReceivesCommittedCancellationAndExpiry() throws {
        for checkpointed in [false, true] {
            for expire in [false, true] {
                let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 3,
                    mac: Data(repeating: 1, count: 16), account: Data(repeating: 2, count: 16))
                let profile = handshake.profile, submission = try commandSubmission(), expression = try selfExpression()
                let user = geteuid(), limits = try assemblyLimits, target = assemblyTarget, environment = assemblyEnvironment
                let port = endpoint.port, release = DispatchSemaphore(value: 0), completed = DispatchSemaphore(value: 0)
                let result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
                DispatchQueue.global().async {
                    defer { completed.signal() }
                    result.withLock { output in output = Result {
                        let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
                        let authority = try XCTUnwrap(fixture.authority)
                        let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression,
                            userID: user, auditSessionID: nil, maxPayloadBytes: 8192)
                        let received = try receiver.receiveIOInput(timeoutMilliseconds: 5000)
                        let command = try RetainedCommandCapture(received: received, expectedCallerBinding: profile.callerBinding,
                            submissionSchemaVersion: 1, captureSchemaVersion: 1, expression: expression, userID: user,
                            auditSessionID: nil, resolvedTarget: target, minimalEnvironment: environment,
                            streamBinding: Data(repeating: 0xb4, count: 16), submissionLimits: limits, captureLimits: limits,
                            maximumAncestryEntries: 1, admissionProfile: profile)
                        let draft = fixture.draft(command)
                        let request = try authority.admitCommand(command, draft: draft, expression: expression,
                            userID: user, auditSessionID: nil, now: { fixture.now() }, receiptTimeMs: nil)
                        guard release.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                        let now = fixture.now(expire ? 200 : 120)
                        _ = try authority.withRequests { try $0.retirePending(requestID: request.requestID,
                            reason: expire ? .deadlineElapsed : .cancelled, now: now, receiptTimeMs: nil) }
                    } }
                }
                defer { release.signal() }
                let input = Darwin.open("/dev/null", O_RDONLY), output = Darwin.open("/dev/null", O_WRONLY)
                defer { _ = Darwin.close(input); _ = Darwin.close(output) }
                let admission: CommandIOAdmission
                do {
                    admission = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output,
                        errorDescriptor: output, handshake: handshake, expression: expression, userID: user,
                        auditSessionID: nil, maximumPayloadBytes: 8192)
                } catch {
                    release.signal(); XCTAssertEqual(completed.wait(timeout: .now() + 5), .success)
                    try result.withLock { try $0?.get() }
                    throw error
                }
                guard case .admitted(let session) = admission else { return XCTFail("The command owner must admit the original submission") }
                XCTAssertNil(try session.pollTerminalResult(timeoutMilliseconds: 10))
                release.signal(); XCTAssertEqual(completed.wait(timeout: .now() + 5), .success)
                try result.withLock { try $0?.get() }
                let terminal = try XCTUnwrap(session.pollTerminalResult(timeoutMilliseconds: 1000))
                XCTAssertEqual(terminal.outcome, expire ? .expired : .cancelledBeforeStart)
                guard case .admitted(let expected) = session.admission.outcome else { return XCTFail("The session must retain its admission") }
                XCTAssertEqual(terminal.request, expected); XCTAssertEqual(terminal.submission, submission.binding)
                XCTAssertEqual(try session.pollTerminalResult()?.outcome, terminal.outcome)
                session.close()
                XCTAssertThrowsError(try receiver(endpoint).receiveIOInput(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
            }
        }
    }
}

extension MachCommandCallerReceiverTests {
    func testExecutionResourceTransferRequiresConsumedOriginalCommandAndCannotRepeat() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed)
            let admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            let request = try admitCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            XCTAssertThrowsError(try fixture.requests.takeAuthorizedCommandExecution(requestID: request.requestID, now: fixture.now(115)))
            XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .queued)
            _ = try fixture.consume(request)
            let resources = try fixture.requests.takeAuthorizedCommandExecution(requestID: request.requestID, now: fixture.now(130))
            defer { resources.close() }
            XCTAssertEqual(resources.capture.canonicalBytes, request.canonicalCapture)
            XCTAssertEqual(resources.request.requestID, request.requestID)
            XCTAssertEqual(try sendReferences(terminalPort.port), 2)
            command.close()
            XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
            XCTAssertThrowsError(try fixture.requests.takeAuthorizedCommandExecution(requestID: request.requestID, now: fixture.now(130)))
            try resources.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
            try resources.withBorrowedDescriptors { input, output, error, directory in
                for fd in [input, output, error, directory] { XCTAssertGreaterThanOrEqual(fcntl(fd, F_GETFD), 0) }
                var info = stat(); XCTAssertEqual(fstat(directory, &info), 0); XCTAssertEqual(info.st_mode & S_IFMT, S_IFDIR)
            }
            fixture.requests.close()
            try resources.withBorrowedDescriptors { input, _, _, _ in XCTAssertGreaterThanOrEqual(fcntl(input, F_GETFD), 0) }
            XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10))
            try resources.sendTerminalOutcome(.unknown)
            XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .unknown)
            XCTAssertThrowsError(try resources.sendTerminalOutcome(.unknown))
            XCTAssertEqual(try sendReferences(terminalPort.port), 1)
        }
    }

    func testFinalExecutionRecheckRetiresStreamsButKeepsTheOriginalBoundTerminal() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed)
            let admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (received, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            let request = try admitCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            _ = try fixture.consume(request)
            let resources = try fixture.requests.takeAuthorizedCommandExecution(requestID: request.requestID, now: fixture.now(130))
            defer { resources.close() }
            XCTAssertThrowsError(try resources.recheck(expression: "identifier \"dev.remozio.wrong\"", userID: geteuid(), auditSessionID: nil))
            XCTAssertThrowsError(try resources.withBorrowedDescriptors { _, _, _, _ in () })
            try expectAssemblyResourcesRetired(received)
            XCTAssertEqual(try sendReferences(terminalPort.port), 2)
            _ = try fixture.requests.recordOutcome(requestID: request.requestID, expectedRevision: 0,
                event: .loseOutcome, now: fixture.now(130), receiptTimeMs: nil)
            try resources.sendTerminalOutcome(.unknown)
            let result = try ownerTerminal(terminalPort, submission: submission, admission: admission)
            XCTAssertEqual(result.outcome, .unknown)
            XCTAssertEqual(result.request.requestDigest, resources.request.requestDigest)
            XCTAssertEqual(result.request.challenge, request.challenge)
            XCTAssertEqual(result.submission, submission.binding)
            XCTAssertEqual(try sendReferences(terminalPort.port), 1)
            XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10))
        }
    }

    func testExecutionResourceTransferRejectsDeclinedOrAlreadyDispatchedRequests() throws {
        for decline in [false, true] {
            let fixture = try CommandRequestFixture()
            let admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            let request = try admitCommand(command, fixture: fixture)
            _ = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            _ = try fixture.consume(request, decline: decline)
            if !decline {
                _ = try fixture.requests.recordOutcome(requestID: request.requestID, expectedRevision: 0,
                    event: .beginDispatch, now: fixture.now(130), receiptTimeMs: nil)
            }
            XCTAssertThrowsError(try fixture.requests.takeAuthorizedCommandExecution(requestID: request.requestID, now: fixture.now(130)))
        }
    }

    func testExecutionTerminalFullQueueConsumesOneNonblockingAttempt() throws {
        let fixture = try CommandRequestFixture()
        let admissionPort = try Endpoint(), terminalPort = try Endpoint()
        let (received, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
        let request = try admitCommand(command, fixture: fixture)
        _ = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        _ = try fixture.consume(request)
        let resources = try fixture.requests.takeAuthorizedCommandExecution(requestID: request.requestID, now: fixture.now(130))
        for _ in 0..<5 { try terminalPort.send(Data([1]), identifier: MachCommandCallerReceiver.terminalReplyMessageID) }
        let started = DispatchTime.now().uptimeNanoseconds
        XCTAssertThrowsError(try resources.sendTerminalOutcome(.unknown))
        XCTAssertLessThan(DispatchTime.now().uptimeNanoseconds - started, 2_000_000_000)
        XCTAssertThrowsError(try resources.sendTerminalOutcome(.unknown))
        resources.close(); try expectAssemblyResourcesRetired(received)
        XCTAssertEqual(try sendReferences(terminalPort.port), 1)
    }
}


extension MachCommandCallerReceiverTests {
    func testExecutionHandoffPreservesQueuedPipeInputAfterPendingOwnerCloses() throws {
        var pipeFDs = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(pipe(&pipeFDs), 0)
        defer { for fd in pipeFDs { Darwin.close(fd) } }
        let flags = fcntl(pipeFDs[0], F_GETFL)
        XCTAssertGreaterThanOrEqual(flags, 0)
        XCTAssertEqual(fcntl(pipeFDs[0], F_SETFL, flags | O_NONBLOCK), 0)
        let original = Data("unread execution source".utf8)
        XCTAssertEqual(original.withUnsafeBytes { write(pipeFDs[1], $0.baseAddress, $0.count) }, original.count)
        let fixture = try CommandRequestFixture(), admissionPort = try Endpoint(), terminalPort = try Endpoint()
        let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort, inputDescriptor: pipeFDs[0])
        let request = try admitCommand(command, fixture: fixture)
        _ = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        _ = try fixture.consume(request)
        let resources = try fixture.requests.takeAuthorizedCommandExecution(requestID: request.requestID, now: fixture.now(130))
        defer { resources.close() }
        command.close(); fixture.requests.close()
        var actual = [UInt8](repeating: 0, count: original.count)
        try resources.withBorrowedDescriptors { input, _, _, _ in
            XCTAssertEqual(read(input, &actual, actual.count), actual.count)
        }
        XCTAssertEqual(Data(actual), original)
    }

    func testChangedExecutableAtFinalRecheckKeepsOriginalTerminalWithoutReplacingCapture() throws {
        let fixture = try CommandRequestFixture(), admissionPort = try Endpoint(), terminalPort = try Endpoint()
        let path = fixture.root.appendingPathComponent("approved-program")
        try Data(contentsOf: URL(fileURLWithPath: "/usr/bin/true")).write(to: path)
        XCTAssertEqual(chmod(path.path, 0o700), 0)
        let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort, executablePath: path.path)
        let request = try admitCommand(command, fixture: fixture)
        let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        _ = try fixture.consume(request)
        let resources = try fixture.requests.takeAuthorizedCommandExecution(requestID: request.requestID, now: fixture.now(130))
        defer { resources.close() }
        try Data("replaced program bytes".utf8).write(to: path)
        XCTAssertThrowsError(try resources.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil))
        XCTAssertThrowsError(try resources.withBorrowedDescriptors { _, _, _, _ in () })
        XCTAssertEqual(resources.capture.canonicalBytes, request.canonicalCapture)
        _ = try fixture.requests.recordOutcome(requestID: request.requestID, expectedRevision: 0,
            event: .loseOutcome, now: fixture.now(130), receiptTimeMs: nil)
        try resources.sendTerminalOutcome(.unknown)
        XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .unknown)
    }
}


extension MachCommandCallerReceiverTests {
    func testNativeDispatchObservationFaultStillReapsReleasedWorkWithoutKillingIt() throws {
        let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
        let source = try dispatchLauncher(fixture), launcher = fixture.root.appendingPathComponent("late-fault-child").path
        try FileManager.default.copyItem(atPath: source, toPath: launcher)
        let admissionPort = try Endpoint(), terminalPort = try Endpoint()
        let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort,
            executablePath: "/bin/sleep", arguments: [Data("sleep".utf8), Data("0.3".utf8)])
        let request = try admitOwnedCommand(command, fixture: fixture)
        let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        _ = try ownerDecision(request, fixture: fixture, decline: false)
        let started = DispatchTime.now().uptimeNanoseconds
        try beginDispatch(fixture, request: request, launcher: launcher)
        try awaitDispatchCleanup(authority)
        XCTAssertGreaterThan(DispatchTime.now().uptimeNanoseconds - started, 200_000_000)
        XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .unknown)
        let outcome = try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID) }
        XCTAssertEqual(outcome?.phase, .unknown); XCTAssertEqual(outcome?.revision, 2)
    }
}

extension MachCommandCallerReceiverTests {
    private struct NativeDispatchFixture {
        let fixture: CommandRequestFixture
        let authority: AuthorityJournal
        let launcher: String
        let request: IssuedRequestPayload
        let admission: VerifiedCommandAdmissionResult
        let terminal: Endpoint
        let submission: CommandSubmission
    }
    private func dispatchLauncher(_ fixture: CommandRequestFixture) throws -> String {
        let source = try XCTUnwrap(Bundle.module.url(forResource: "child", withExtension: "c", subdirectory: "Fixtures/command-process"))
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach"), path = fixture.root.appendingPathComponent("fixture-child")
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror", "-I", native.appendingPathComponent("include").path,
            source.path, native.appendingPathComponent("CommandChildSpecification.c").path, "-o", path.path]
        try compiler.run(); compiler.waitUntilExit()
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
        let probe = Process(); probe.executableURL = path; probe.arguments = []
        try probe.run(); probe.waitUntilExit()
        guard probe.terminationReason == .exit, probe.terminationStatus == 91 else { throw CocoaError(.executableNotLoadable) }
        return path.path
    }
    private func dispatchMonitor(_ fixture: CommandRequestFixture) throws -> String {
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach"), path = fixture.root.appendingPathComponent("fixture-monitor")
        if FileManager.default.fileExists(atPath: path.path) { return path.path }
        let wrapper = fixture.root.appendingPathComponent("fixture-monitor.c")
        let product = core.deletingLastPathComponent().appendingPathComponent("app/CommandMonitor/MonitorMain.c")
        // Substitute only the monitor UID guard. The synthetic launcher grants no privilege.
        try """
        #include <unistd.h>
        static uid_t fixture_root_uid(void) { return 0; }
        #define getuid fixture_root_uid
        #define geteuid fixture_root_uid
        #include "\(product.path)"
        """.write(to: wrapper, atomically: false, encoding: .utf8)
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror", "-I", native.appendingPathComponent("include").path,
            wrapper.path, native.appendingPathComponent("CommandProcess.c").path, native.appendingPathComponent("CommandChildSpecification.c").path,
            native.appendingPathComponent("CommandMonitorProtocol.c").path, "-o", path.path]
        try compiler.run(); compiler.waitUntilExit()
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
        // Complete first-launch policy evaluation before starting the request fixture's receive window.
        let probe = Process(); probe.executableURL = path
        probe.arguments = []
        try probe.run(); probe.waitUntilExit()
        guard probe.terminationReason == .exit, probe.terminationStatus == 64 else { throw CocoaError(.executableNotLoadable) }
        return path.path
    }
    private func nativeDispatchFixture(checkpointed: Bool = false, path: String = "/usr/bin/true",
                                       arguments: [Data]? = nil, retiredEnrollmentEpoch: UInt8? = nil,
                                       inputDescriptor: Int32? = nil) throws -> NativeDispatchFixture {
        let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true, retiredEnrollmentEpoch: retiredEnrollmentEpoch)
        let authority = try XCTUnwrap(fixture.authority), launcher = try dispatchLauncher(fixture)
        let admissionPort = try Endpoint(), terminal = try Endpoint()
        let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal,
            inputDescriptor: inputDescriptor, executablePath: path, arguments: arguments)
        let request = try admitOwnedCommand(command, fixture: fixture)
        let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        _ = try ownerDecision(request, fixture: fixture, decline: false)
        return NativeDispatchFixture(fixture: fixture, authority: authority, launcher: launcher,
            request: request, admission: admission, terminal: terminal, submission: submission)
    }
    private func beginDispatch(_ fixture: CommandRequestFixture, request: IssuedRequestPayload, launcher: String,
                               elevation: @escaping (CommandCapture) throws -> Void = { _ in },
                               clock: (() throws -> AuthorityMoment)? = nil,
                               runtimeFailure: Bool = false, launcherFailure: Bool = false, callerExpression: String? = nil) throws {
        let authority = try XCTUnwrap(fixture.authority), expression = try callerExpression ?? selfExpression(), now = fixture.now(130)
        try authority.beginCommandExecution(requestID: request.requestID, monitorPath: dispatchMonitor(fixture), childPath: launcher,
            preparationMilliseconds: 5000, fileCreationMask: 0o022, validateElevation: elevation, clock: clock ?? { now },
            runtime: { tx, approval, capture in
                if runtimeFailure { throw CommandExecutionError.policyChanged }
                try approval.requireCurrent(tx.requestDeliveryTrust())
                let snapshot = try XCTUnwrap(tx.codePolicy())
                let frontend = try XCTUnwrap(snapshot.policy.entries.first(where: { $0.role == .commandFrontend }))
                let token = try XCTUnwrap(snapshot.roleRevisions[.commandFrontend])
                let monitor = snapshot.policy.entries.first { $0.role == .commandMonitor } ?? frontend
                let monitorToken = snapshot.roleRevisions[.commandMonitor] ?? token
                return CommandExecutionRuntime(child: frontend, childRevision: token, monitor: monitor, monitorRevision: monitorToken, frontendRevision: token,
                    callerExpression: expression, userID: capture.requester.effectiveUID, sessionID: nil)
            }, launcher: { _ in
                if launcherFailure { throw CommandExecutionError.policyChanged }
                return { }
            })
    }
    private func awaitDispatchCleanup(_ authority: AuthorityJournal) throws {
        let deadline = Date().addingTimeInterval(8)
        while authority.activeCommandCount != 0 {
            if Date() >= deadline { XCTFail("Native command cleanup did not finish"); throw CommandExecutionError.unavailable }
            usleep(1000)
        }
    }
    private func nativeDispatchOutcome(_ test: NativeDispatchFixture) throws -> CommandTerminalOutcome {
        try ownerTerminal(test.terminal, submission: test.submission, admission: test.admission).outcome
    }
    func testNativeDispatchChangedMonitorRolePreventsReleaseWithoutChangingFrontendRole() throws {
        let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
        let source = try dispatchLauncher(fixture)
        let marker = fixture.root.appendingPathComponent("approved-effect")
        let admissionPort = try Endpoint(), terminal = try Endpoint()
        let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal,
            executablePath: "/usr/bin/touch", arguments: [Data("touch".utf8), Data(marker.path.utf8)])
        let request = try admitOwnedCommand(command, fixture: fixture)
        let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        _ = try ownerDecision(request, fixture: fixture, decline: false)
        try authority.write { tx in
            let old = try XCTUnwrap(tx.codePolicy()), frontend = try XCTUnwrap(old.policy.entries.first)
            let monitor = try AuthorityCodeEntry(role: .commandMonitor, teamID: frontend.teamID, identifier: "dev.remozio.test.monitor",
                installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 3, count: 20), active: true)
            _ = try tx.installCodePolicy(AuthorityCodePolicy(entries: old.policy.entries + [monitor]), expectedRevision: old.revision)
        }
        let launcher = fixture.root.appendingPathComponent("held-prepare-child")
        try FileManager.default.copyItem(atPath: source, toPath: launcher.path)
        try beginDispatch(fixture, request: request, launcher: launcher.path)
        try authority.write { tx in
            let old = try XCTUnwrap(tx.codePolicy()), monitor = try XCTUnwrap(old.policy.entries.first { $0.role == .commandMonitor })
            let changed = try AuthorityCodeEntry(role: monitor.role, teamID: monitor.teamID, identifier: monitor.identifier,
                installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 4, count: 20), active: true)
            let next = try tx.installCodePolicy(AuthorityCodePolicy(entries: old.policy.entries.filter { $0.role != .commandMonitor } + [changed]), expectedRevision: old.revision)
            XCTAssertEqual(next.roleRevisions[.commandFrontend], old.roleRevisions[.commandFrontend])
            XCTAssertNotEqual(next.roleRevisions[.commandMonitor], old.roleRevisions[.commandMonitor])
        }
        try Data().write(to: URL(fileURLWithPath: launcher.path + ".ready"))
        try awaitDispatchCleanup(authority)
        XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, .failedBeforeStart)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }
    func testNativeDispatchCommitsBeforeReleaseAndDeliversOriginalObservedExitWithoutReplay() throws {
        for checkpointed in [false, true] {
            let test = try nativeDispatchFixture(checkpointed: checkpointed), authority = test.authority
            try beginDispatch(test.fixture, request: test.request, launcher: test.launcher, elevation: { _ in
                XCTAssertThrowsError(try authority.close()) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive) }
            })
            XCTAssertThrowsError(try beginDispatch(test.fixture, request: test.request, launcher: test.launcher))
            try awaitDispatchCleanup(authority)
            XCTAssertEqual(try nativeDispatchOutcome(test), .exited(0))
            let id = test.request.requestID
            let outcome = try authority.withRequests { try $0.historicalOutcome(requestID: id) }
            XCTAssertEqual(outcome?.phase, .succeeded); XCTAssertEqual(outcome?.revision, 2)
            XCTAssertThrowsError(try beginDispatch(test.fixture, request: test.request, launcher: test.launcher))
            XCTAssertThrowsError(try receiver(test.terminal).receiveTerminalReply(timeoutMilliseconds: 10))
        }
    }
    func testNativeDispatchAcceptsCurrentEnrollmentWithRetiredHistoryInEitherEpochOrder() throws {
        for checkpointed in [false, true] {
            for retiredEpoch: UInt8 in [8, 10] {
                let test = try nativeDispatchFixture(checkpointed: checkpointed, retiredEnrollmentEpoch: retiredEpoch)
                let rows = try test.authority.read { try $0.requestDeliveryTrust().enrollments }
                XCTAssertEqual(rows.count, 2)
                XCTAssertEqual(rows.first?.approval.active, retiredEpoch > 9)
                XCTAssertEqual(rows.filter { $0.approval.active }.map(\.epoch), [Data(repeating: 9, count: 16)])
                try beginDispatch(test.fixture, request: test.request, launcher: test.launcher)
                try awaitDispatchCleanup(test.authority)
                XCTAssertEqual(try nativeDispatchOutcome(test), .exited(0))
                let id = test.request.requestID
                let outcome = try test.authority.withRequests { try $0.historicalOutcome(requestID: id) }
                XCTAssertEqual(outcome?.phase, .succeeded); XCTAssertEqual(outcome?.revision, 2)
            }
        }
    }
    private final class DispatchFailureCounter {
        let failAt: Int; private var count = 0
        init(failAt: Int) { self.failAt = failAt }
        func check(_ capture: CommandCapture) throws {
            count += 1
            if count == failAt { throw CommandExecutionError.policyChanged }
        }
    }
    func testNativeDispatchFinalPolicyFailureAfterCommitNeverStartsApprovedProgram() throws {
        for checkpointed in [false, true] {
            let marker = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: marker) }
            let test = try nativeDispatchFixture(checkpointed: checkpointed, path: "/usr/bin/touch",
                arguments: [Data("touch".utf8), Data(marker.path.utf8)])
            let counter = DispatchFailureCounter(failAt: 3)
            try beginDispatch(test.fixture, request: test.request, launcher: test.launcher, elevation: counter.check)
            try awaitDispatchCleanup(test.authority)
            XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
            XCTAssertEqual(try nativeDispatchOutcome(test), .failedBeforeStart)
            let id = test.request.requestID
            let outcome = try test.authority.withRequests { try $0.historicalOutcome(requestID: id) }
            XCTAssertEqual(outcome?.phase, .failed); XCTAssertEqual(outcome?.revision, 2)
        }
    }
    func testNativeDispatchStorageFailureBeforeCommitNeverReleasesAndReportsUnknown() throws {
        let marker = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: marker) }
        let test = try nativeDispatchFixture(path: "/usr/bin/touch", arguments: [Data("touch".utf8), Data(marker.path.utf8)])
        try test.fixture.sql("CREATE TRIGGER fail_dispatch BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'fixture'); END")
        try beginDispatch(test.fixture, request: test.request, launcher: test.launcher)
        XCTAssertEqual(try nativeDispatchOutcome(test), .unknown)
        XCTAssertEqual(test.authority.activeCommandCount, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
        try test.fixture.sql("DROP TRIGGER fail_dispatch")
        try awaitDispatchCleanup(test.authority)
        let id = test.request.requestID
        let outcome = try test.authority.withRequests { try $0.historicalOutcome(requestID: id) }
        XCTAssertEqual(outcome?.phase, .unknown); XCTAssertEqual(outcome?.revision, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }
    func testNativeDispatchCleanupSurvivesJournalClosureWithoutKillingReleasedWork() throws {
        let test = try nativeDispatchFixture(path: "/bin/sleep", arguments: [Data("sleep".utf8), Data("0.3".utf8)])
        try beginDispatch(test.fixture, request: test.request, launcher: test.launcher)
        let deadline = Date().addingTimeInterval(5), id = test.request.requestID
        while try test.authority.withRequests({ try $0.state(requestID: id).phase }) != .executing {
            if Date() >= deadline { throw CommandExecutionError.unavailable }; usleep(1000)
        }
        let started = DispatchTime.now().uptimeNanoseconds
        try test.authority.close()
        try awaitDispatchCleanup(test.authority)
        XCTAssertGreaterThan(DispatchTime.now().uptimeNanoseconds - started, 150_000_000)
        XCTAssertEqual(try nativeDispatchOutcome(test), .unknown)
    }
    func testNativeDispatchRejectsRevocationReplacementAndRestrictedWinnerBeforeSpawn() throws {
        for mutation in 0..<4 {
            let test = try nativeDispatchFixture()
            switch mutation {
            case 0: try test.fixture.sql("UPDATE approval_enrollments_v1 SET active=0")
            case 1:
                let replacement = P256.Signing.PrivateKey().publicKey.x963Representation.base64EncodedString()
                let body = try dispatchEnrollmentBody(test.fixture) { object in
                    var keys = object["keys"] as! [[String: Any]]; keys[0]["publicKey"] = replacement; object["keys"] = keys
                }
                try test.fixture.sql("UPDATE approval_enrollments_v1 SET body=x'\(body.map { String(format: "%02x", $0) }.joined())'")
            case 2:
                let replacement = Data(repeating: 8, count: 16).base64EncodedString()
                let body = try dispatchEnrollmentBody(test.fixture) { $0["epoch"] = replacement }
                try test.fixture.sql("UPDATE approval_enrollments_v1 SET epoch=x'08080808080808080808080808080808', body=x'\(body.map { String(format: "%02x", $0) }.joined())'")
            default:
                try test.fixture.sql("INSERT INTO gateway_trust_restrictions_v1 VALUES(x'05050505050505050505050505050505',1,x'04040404040404040404040404040404',x'01',zeroblob(64))")
            }
            XCTAssertThrowsError(try beginDispatch(test.fixture, request: test.request, launcher: test.launcher)) {
                XCTAssertEqual($0 as? CommandExecutionError, .policyChanged, "mutation \(mutation)")
            }
            XCTAssertEqual(test.authority.activeCommandCount, 0)
            XCTAssertEqual(try nativeDispatchOutcome(test), .failedBeforeStart)
            let id = test.request.requestID
            let outcome = try test.authority.withRequests { try $0.historicalOutcome(requestID: id) }
            XCTAssertEqual(outcome?.phase, .cancelled); XCTAssertEqual(outcome?.revision, 1)
        }
    }
    private final class TerminalCommitClock {
        private let lock = NSLock()
        private var calls = 0
        private var failTerminal = true
        let now: AuthorityMoment
        let failStartingCall: Int
        init(now: AuthorityMoment, failStartingCall: Int = 4) { self.now = now; self.failStartingCall = failStartingCall }
        func read() throws -> AuthorityMoment {
            try lock.withLock {
                calls += 1
                if calls >= failStartingCall && failTerminal { throw CommandExecutionError.unavailable }
                return now
            }
        }
        func recover() { lock.withLock { failTerminal = false } }
    }
    func testCommandOutcomeOwnerWithoutRuntimeValidationCannotSpawnOrRelease() throws {
        let fixture = try CommandRequestFixture(), admissionPort = try Endpoint(), terminal = try Endpoint()
        let launcher = try dispatchLauncher(fixture), marker = fixture.root.appendingPathComponent("unvalidated-target")
        let (_, command, _, _) = try ownerIOCommand(admission: admissionPort, terminal: terminal,
            executablePath: "/usr/bin/touch", arguments: [Data("touch".utf8), Data(marker.path.utf8)])
        let request = try admitCommand(command, fixture: fixture)
        _ = try fixture.consume(request)
        let approval = try fixture.requests.authorizedCommandApproval(requestID: request.requestID, now: fixture.now(130))
        let resources = try fixture.requests.takeAuthorizedCommandExecution(requestID: request.requestID, now: fixture.now(130))
        let now = fixture.now(130)
        let owner = CommandExecution(resources: resources, approval: approval, clock: { now }, receiptTime: { nil })
        defer {
            owner.cancelBeforeRelease()
            let deadline = Date().addingTimeInterval(8)
            while !owner.dispose() && Date() < deadline { _ = owner.poll(); usleep(1000) }
        }
        XCTAssertThrowsError(try owner.prepare(monitorPath: dispatchMonitor(fixture), childPath: launcher, preparationMilliseconds: 5000, fileCreationMask: 0o022)) {
            XCTAssertEqual($0 as? CommandExecutionError, .unavailable)
        }
        XCTAssertThrowsError(try owner.release()) { XCTAssertEqual($0 as? CommandExecutionError, .unavailable) }
        XCTAssertTrue(owner.dispose())
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }
    func testNativeDispatchPreSpawnValidationFailureRetainsUnknownUntilCommitRecovers() throws {
        for checkpointed in [false, true] {
            for runtimeFailure in [false, true] {
                let marker = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
                defer { try? FileManager.default.removeItem(at: marker) }
                let test = try nativeDispatchFixture(checkpointed: checkpointed, path: "/usr/bin/touch",
                    arguments: [Data("touch".utf8), Data(marker.path.utf8)])
                let clock = TerminalCommitClock(now: test.fixture.now(130), failStartingCall: 3)
                XCTAssertThrowsError(try beginDispatch(test.fixture, request: test.request, launcher: test.launcher,
                    clock: clock.read, runtimeFailure: runtimeFailure, launcherFailure: !runtimeFailure)) {
                    XCTAssertEqual($0 as? CommandExecutionError, .policyChanged)
                }
                XCTAssertEqual(try nativeDispatchOutcome(test), .unknown)
                XCTAssertEqual(test.authority.activeCommandCount, 1)
                let id = test.request.requestID
                XCTAssertEqual(try test.authority.withRequests { try $0.state(requestID: id).phase }, .authorized)
                XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
                XCTAssertThrowsError(try beginDispatch(test.fixture, request: test.request, launcher: test.launcher))
                clock.recover()
                try awaitDispatchCleanup(test.authority)
                let outcome = try test.authority.withRequests { try $0.historicalOutcome(requestID: id) }
                XCTAssertEqual(outcome?.phase, .unknown); XCTAssertEqual(outcome?.revision, 1)
                XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
                XCTAssertThrowsError(try receiver(test.terminal).receiveTerminalReply(timeoutMilliseconds: 10))
            }
        }
    }
    func testNativeDispatchTransientClockFailureRetainsOutcomeUntilDurableUnknownCommits() throws {
        for checkpointed in [false, true] {
            let marker = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: marker) }
            let test = try nativeDispatchFixture(checkpointed: checkpointed, path: "/bin/sh",
                arguments: [Data("sh".utf8), Data("-c".utf8), Data("printf once >> \"$1\"".utf8), Data("sh".utf8), Data(marker.path.utf8)])
            let clock = TerminalCommitClock(now: test.fixture.now(130))
            try beginDispatch(test.fixture, request: test.request, launcher: test.launcher, clock: clock.read)
            XCTAssertEqual(try nativeDispatchOutcome(test), .unknown)
            XCTAssertEqual(test.authority.activeCommandCount, 1)
            let id = test.request.requestID
            XCTAssertEqual(try test.authority.withRequests { try $0.state(requestID: id).phase }, .executing)
            XCTAssertThrowsError(try beginDispatch(test.fixture, request: test.request, launcher: test.launcher))
            clock.recover()
            try awaitDispatchCleanup(test.authority)
            let outcome = try test.authority.withRequests { try $0.historicalOutcome(requestID: id) }
            XCTAssertEqual(outcome?.phase, .unknown); XCTAssertEqual(outcome?.revision, 2)
            XCTAssertEqual(try Data(contentsOf: marker), Data("once".utf8))
            XCTAssertThrowsError(try receiver(test.terminal).receiveTerminalReply(timeoutMilliseconds: 10))
        }
    }
    func testNativeDispatchClosingStorageRetiresPendingUnknownOwner() throws {
        let test = try nativeDispatchFixture()
        let clock = TerminalCommitClock(now: test.fixture.now(130))
        try beginDispatch(test.fixture, request: test.request, launcher: test.launcher, clock: clock.read)
        XCTAssertEqual(try nativeDispatchOutcome(test), .unknown)
        XCTAssertEqual(test.authority.activeCommandCount, 1)
        try test.authority.close()
        try awaitDispatchCleanup(test.authority)
        XCTAssertEqual(test.authority.activeCommandCount, 0)
        XCTAssertThrowsError(try receiver(test.terminal).receiveTerminalReply(timeoutMilliseconds: 10))
    }
    func testNativeDispatchBusyResultCommitRetainsOriginalOwnerUntilStorageRecovers() throws {
        var pipeFDs: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&pipeFDs), 0)
        defer { for fd in pipeFDs where fd >= 0 { Darwin.close(fd) } }
        let test = try nativeDispatchFixture(path: "/bin/cat", inputDescriptor: pipeFDs[0])
        try beginDispatch(test.fixture, request: test.request, launcher: test.launcher)
        let deadline = Date().addingTimeInterval(5), id = test.request.requestID
        while try test.authority.withRequests({ try $0.state(requestID: id).phase }) != .executing {
            if Date() >= deadline { throw CommandExecutionError.unavailable }; usleep(1000)
        }
        var connection: OpaquePointer?
        XCTAssertEqual(sqlite3_open_v2(test.fixture.root.appendingPathComponent("store/journal.sqlite").path,
            &connection, SQLITE_OPEN_READWRITE, nil), SQLITE_OK)
        let db = try XCTUnwrap(connection)
        defer { sqlite3_exec(db, "ROLLBACK", nil, nil, nil); sqlite3_close(db) }
        XCTAssertEqual(sqlite3_exec(db, "BEGIN IMMEDIATE", nil, nil, nil), SQLITE_OK)
        XCTAssertEqual(Darwin.close(pipeFDs[1]), 0); pipeFDs[1] = -1
        XCTAssertEqual(try nativeDispatchOutcome(test), .unknown)
        XCTAssertEqual(test.authority.activeCommandCount, 1)
        XCTAssertEqual(try test.authority.withRequests { try $0.state(requestID: id).phase }, .executing)
        XCTAssertEqual(sqlite3_exec(db, "COMMIT", nil, nil, nil), SQLITE_OK)
        try awaitDispatchCleanup(test.authority)
        let outcome = try test.authority.withRequests { try $0.historicalOutcome(requestID: id) }
        XCTAssertEqual(outcome?.phase, .unknown); XCTAssertEqual(outcome?.revision, 2)
        XCTAssertThrowsError(try receiver(test.terminal).receiveTerminalReply(timeoutMilliseconds: 10))
    }
    func testNativeDispatchReportsObservedProgramFailureAndSignal() throws {
        for signal in [false, true] {
            let test = try nativeDispatchFixture(path: signal ? "/bin/sh" : "/usr/bin/false",
                arguments: signal ? [Data("sh".utf8), Data("-c".utf8), Data("kill -TERM $$".utf8)] : [Data("false".utf8)])
            try beginDispatch(test.fixture, request: test.request, launcher: test.launcher)
            try awaitDispatchCleanup(test.authority)
            XCTAssertEqual(try nativeDispatchOutcome(test), signal ? .signalled(UInt32(SIGTERM)) : .exited(1))
            let id = test.request.requestID
            let outcome = try test.authority.withRequests { try $0.historicalOutcome(requestID: id) }
            XCTAssertEqual(outcome?.phase, .failed); XCTAssertEqual(outcome?.revision, 2)
        }
    }
    func testNativeDispatchPublicEntryRequiresActualRootBeforeSpawning() throws {
        guard geteuid() != 0 else { throw XCTSkip("Unprivileged entry gate") }
        let test = try nativeDispatchFixture(), now = test.fixture.now(130)
        XCTAssertThrowsError(try test.authority.beginCommandExecution(requestID: test.request.requestID, monitorPath: dispatchMonitor(test.fixture), childPath: test.launcher,
            preparationMilliseconds: 5000, fileCreationMask: 0o022, validateElevation: { _ in }, clock: { now })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(test.authority.activeCommandCount, 0)
        XCTAssertEqual(try nativeDispatchOutcome(test), .failedBeforeStart)
    }
    private func dispatchEnrollmentBody(_ fixture: CommandRequestFixture, mutate: (inout [String: Any]) -> Void) throws -> Data {
        var db: OpaquePointer?, row: OpaquePointer?
        guard sqlite3_open_v2(fixture.root.appendingPathComponent("store/journal.sqlite").path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
              let db else { throw MachCommandCallerError.unavailable }
        defer { sqlite3_close(db) }
        guard sqlite3_prepare_v2(db, "SELECT body FROM approval_enrollments_v1 LIMIT 1", -1, &row, nil) == SQLITE_OK,
              let row else { throw MachCommandCallerError.unavailable }
        defer { sqlite3_finalize(row) }
        guard sqlite3_step(row) == SQLITE_ROW, let bytes = sqlite3_column_blob(row, 0) else { throw MachCommandCallerError.unavailable }
        let body = Data(bytes: bytes, count: Int(sqlite3_column_bytes(row, 0)))
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        mutate(&object)
        return try JSONSerialization.data(withJSONObject: object, options: .sortedKeys)
    }
}


extension MachCommandCallerReceiverTests {
    func testCallerLifetimeObservesActualExitWithoutRecapturingAPID() throws {
        let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint)
        let received = try receiver(endpoint, expression: peer.expression).receive(timeoutMilliseconds: 5000)
        let original = received.caller.requester
        XCTAssertFalse(received.caller.requesterExitObserved)
        try peer.stop()
        XCTAssertThrowsError(try received.caller.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil))
        XCTAssertTrue(received.caller.requesterExitObserved)
        received.caller.close()
        XCTAssertTrue(received.caller.requesterExitObserved)
        XCTAssertEqual(received.caller.requester, original)
    }

    func testCallerLifetimeExecThenExitNeverBecomesOriginalRequesterExit() throws {
        let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint)
        let receive = try receiver(endpoint, expression: peer.expression)
        let first = try receive.receive(timeoutMilliseconds: 5000)
        try peer.advance()
        let second = try receive.receive(timeoutMilliseconds: 5000)
        try peer.stop()
        XCTAssertThrowsError(try first.caller.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil))
        XCTAssertFalse(first.caller.requesterExitObserved)
        XCTAssertThrowsError(try second.caller.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil))
        XCTAssertTrue(second.caller.requesterExitObserved)
    }

    private func lifetimeCommand(_ fixture: CommandRequestFixture, path: String, arguments: [Data],
                                 disconnect: StartedCommandDisconnect = .terminate) throws -> (Peer, IssuedRequestPayload, String) {
        let endpoint = try Endpoint(), submission = try commandSubmission(executablePath: path, arguments: arguments, disconnect: disconnect)
        let peer = try Peer(endpoint: endpoint, submission: submission.canonicalBytes)
        let profile = CommandHandshakeProfile(wireVersion: 3, submissionSchemaVersion: 1, inputCarrierVersion: 4,
            callerBinding: submission.binding.callerBinding, macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16))
        let received = try receiver(endpoint, expression: peer.expression, maximum: 8192).receiveIOInput(timeoutMilliseconds: 5000)
        let command = try assemble(received, admissionProfile: profile, callerExpression: peer.expression)
        let request: IssuedRequestPayload
        if fixture.authority != nil {
            request = try admitOwnedCommand(command, fixture: fixture, callerExpression: peer.expression)
            _ = try ownerDecision(request, fixture: fixture, decline: false)
        } else {
            request = try fixture.requests.admitCommand(command, draft: fixture.draft(command), expression: peer.expression,
                userID: geteuid(), auditSessionID: nil, now: { fixture.now() }, receiptTimeMs: nil)
            _ = try fixture.consume(request)
        }
        return (peer, request, try dispatchLauncher(fixture))
    }

    func testCallerLifetimePreSpawnExitCommitsKnownNoDispatchForOriginalRequest() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), authority = try XCTUnwrap(fixture.authority)
            let marker = fixture.root.appendingPathComponent("must-not-run")
            let (peer, request, launcher) = try lifetimeCommand(fixture, path: "/usr/bin/touch", arguments: [Data("touch".utf8), Data(marker.path.utf8)])
            try peer.stop()
            XCTAssertThrowsError(try beginDispatch(fixture, request: request, launcher: launcher, callerExpression: peer.expression))
            try awaitDispatchCleanup(authority)
            let outcome = try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID) }
            XCTAssertEqual(outcome?.phase, .cancelled); XCTAssertEqual(outcome?.revision, 1)
            XCTAssertEqual(outcome?.event.outcome, .noDispatch)
            XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
            XCTAssertThrowsError(try beginDispatch(fixture, request: request, launcher: launcher, callerExpression: peer.expression))
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testCallerLifetimeUnspawnedOwnerUsesObservedExitRatherThanErrorType() throws {
        for callerExits in [false, true] {
            let fixture = try CommandRequestFixture()
            let (peer, request, launcher) = try lifetimeCommand(fixture, path: "/usr/bin/true", arguments: [Data("true".utf8)])
            let approval = try fixture.requests.authorizedCommandApproval(requestID: request.requestID, now: fixture.now(130))
            let resources = try fixture.requests.takeAuthorizedCommandExecution(requestID: request.requestID, now: fixture.now(130))
            let execution = CommandExecution(resources: resources, approval: approval, clock: { fixture.now(130) }, receiptTime: { nil },
                callerExpression: peer.expression, callerUserID: geteuid(), callerSessionID: nil,
                validateLauncher: {}, validateElevation: { _ in
                    if !callerExits { throw MachCommandCallerError.unavailable }
                })
            defer { XCTAssertTrue(execution.dispose()) }
            if callerExits { try peer.stop() }
            XCTAssertThrowsError(try execution.prepare(monitorPath: dispatchMonitor(fixture), childPath: launcher, preparationMilliseconds: 5000, fileCreationMask: 0o022))
            guard case .terminal(let outcome) = execution.poll() else { return XCTFail("Unspawned owner must retire") }
            XCTAssertEqual(outcome, callerExits ? .requesterExitedBeforeStart : .failedBeforeStart)
            XCTAssertEqual(resources.requesterExitObserved, callerExits)
            XCTAssertThrowsError(try execution.release())
            if !callerExits { try peer.stop() }
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testCallerLifetimeChangedPolicyRetiresRecordWithoutClaimingRequesterExit() throws {
        let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint)
        let received = try receiver(endpoint, expression: peer.expression).receive(timeoutMilliseconds: 5000)
        XCTAssertThrowsError(try received.caller.recheck(expression: "false", userID: geteuid(), auditSessionID: nil))
        XCTAssertFalse(received.caller.requesterExitObserved)
        try peer.advance()
        let next = try receiver(endpoint, expression: peer.expression).receive(timeoutMilliseconds: 5000)
        next.caller.close(); try peer.stop()
        XCTAssertFalse(received.caller.requesterExitObserved)
    }

    func testCallerLifetimeObserverBindsOriginalAuditTokenAndKeepsExecStateAfterExit() throws {
        let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint), receive = try receiver(endpoint, expression: peer.expression)
        let first = try receive.receive(timeoutMilliseconds: 5000)
        defer { first.caller.close() }
        var original = audit_token_t(), missing = false
        XCTAssertEqual(remozio_pid_audit_token(peer.pid, &original, &missing), KERN_SUCCESS)
        var observer: OpaquePointer?
        XCTAssertEqual(remozio_command_caller_observer_create(&original, &observer), 0)
        let bound = try XCTUnwrap(observer)
        defer { remozio_command_caller_observer_close(bound) }
        try peer.advance()
        let next = try receive.receive(timeoutMilliseconds: 5000)
        next.caller.close()
        var replacement: OpaquePointer?
        XCTAssertEqual(remozio_command_caller_observer_create(&original, &replacement), EAGAIN)
        XCTAssertNil(replacement)
        var state = REMOZIO_CALLER_UNCHANGED
        XCTAssertEqual(remozio_command_caller_observer_poll(bound, &state), 0)
        XCTAssertEqual(state, REMOZIO_CALLER_CHANGED)
        try peer.stop()
        XCTAssertEqual(remozio_command_caller_observer_poll(bound, &state), 0)
        XCTAssertEqual(state, REMOZIO_CALLER_CHANGED)
    }

    func testCallerLifetimeClosingObserverDoesNotSignalOrReapPeer() throws {
        let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint), receive = try receiver(endpoint, expression: peer.expression)
        let first = try receive.receive(timeoutMilliseconds: 5000)
        var token = audit_token_t(), missing = false, observer: OpaquePointer?
        XCTAssertEqual(remozio_pid_audit_token(peer.pid, &token, &missing), KERN_SUCCESS)
        XCTAssertEqual(remozio_command_caller_observer_create(&token, &observer), 0)
        remozio_command_caller_observer_close(observer)
        first.caller.close()
        XCTAssertEqual(kill(peer.pid, 0), 0)
        try peer.advance()
        let next = try receive.receive(timeoutMilliseconds: 5000)
        next.caller.close(); try peer.stop()
    }

    func testCallerLifetimeObserverFailureIsUnavailableAndNeverExitEvidence() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = try XCTUnwrap(Bundle.module.url(forResource: "caller-observer-fault", withExtension: "c", subdirectory: "Fixtures/command-process"))
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach"), binary = directory.appendingPathComponent("probe")
        let compile = Process(); compile.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compile.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
            "-I", native.path, "-I", native.appendingPathComponent("include").path, source.path,
            native.appendingPathComponent("Receive.c").path, "-framework", "Security", "-lbsm", "-o", binary.path]
        try compile.run(); compile.waitUntilExit()
        XCTAssertEqual(compile.terminationStatus, 0)
        guard compile.terminationStatus == 0 else { throw MachCommandCallerError.unavailable }
        let probe = Process(); probe.executableURL = binary
        try probe.run(); probe.waitUntilExit(); XCTAssertEqual(probe.terminationStatus, 0)
    }

    func testCallerLifetimeStartedCommandUsesOriginalVisibleDisconnectChoice() throws {
        for checkpointed in [false, true] {
            for disconnect: StartedCommandDisconnect in [.terminate, .continueRunning] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), authority = try XCTUnwrap(fixture.authority)
                let started = fixture.root.appendingPathComponent("started"), completed = fixture.root.appendingPathComponent("completed")
                let script = "printf started > '" + started.path + "'; /bin/sleep 0.3; printf completed > '" + completed.path + "'"
                let (peer, request, launcher) = try lifetimeCommand(fixture, path: "/bin/sh",
                    arguments: [Data("sh".utf8), Data("-c".utf8), Data(script.utf8)], disconnect: disconnect)
                try beginDispatch(fixture, request: request, launcher: launcher, callerExpression: peer.expression)
                let deadline = Date().addingTimeInterval(5)
                while !FileManager.default.fileExists(atPath: started.path) && Date() < deadline { usleep(1000) }
                XCTAssertTrue(FileManager.default.fileExists(atPath: started.path))
                try peer.stop(); try awaitDispatchCleanup(authority)
                let outcome = try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID) }
                XCTAssertEqual(outcome?.revision, 2)
                XCTAssertEqual(outcome?.phase, disconnect == .terminate ? .failed : .succeeded)
                XCTAssertEqual(FileManager.default.fileExists(atPath: completed.path), disconnect != .terminate)
                XCTAssertThrowsError(try beginDispatch(fixture, request: request, launcher: launcher, callerExpression: peer.expression))
            }
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testCallerLifetimeExitAfterHelperStartsPreventsReleaseWithoutPreSpawnClaim() throws {
        let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
        let marker = fixture.root.appendingPathComponent("unreleased")
        let (peer, request, launcher) = try lifetimeCommand(fixture, path: "/usr/bin/touch",
            arguments: [Data("touch".utf8), Data(marker.path.utf8)])
        let checks = OSAllocatedUnfairLock(initialState: 0)
        try beginDispatch(fixture, request: request, launcher: launcher, elevation: { _ in
            let next = checks.withLock { count in count += 1; return count }
            if next == 2 { try peer.stop() }
        }, callerExpression: peer.expression)
        try awaitDispatchCleanup(authority)
        XCTAssertEqual(checks.withLock { $0 }, 2)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
        let outcome = try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID) }
        XCTAssertEqual(outcome?.phase, .cancelled); XCTAssertEqual(outcome?.revision, 1)
        XCTAssertEqual(outcome?.event.outcome, .noDispatch)
    }
}

extension MachCommandCallerReceiverTests {
    private func streamBinding(_ profile: CommandHandshakeProfile, _ submission: CommandSubmission) -> CommandStreamBinding {
        .init(profile: profile, submission: submission.binding, submissionDigest: Data(SHA256.hash(data: submission.canonicalBytes)),
            request: .init(requestID: Data(repeating: 6, count: 16), requestDigest: Data(repeating: 7, count: 32), challenge: Data(repeating: 8, count: 32)))
    }
    private static func waitQueued(_ operation: () throws -> Bool) throws {
        let deadline = Date().addingTimeInterval(5)
        while !(try operation()) {
            guard Date() < deadline else { throw MachCommandCallerError.timeout }
            usleep(1000)
        }
    }
    func testStreamClientUsesPrivateControlsBackpressureAndOrderedOutputBeforeTerminal() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 4)
        let submission = try commandSubmission(), profile = handshake.profile, binding = streamBinding(profile, submission)
        let payloads = try ioPayloads(profile: profile, submission: submission)
        let expression = try selfExpression(), user = geteuid()
        let allowOpen = DispatchSemaphore(value: 0), allowControls = DispatchSemaphore(value: 0), completed = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        let binary = Data((0..<4096).map { UInt8($0 % 251) })
        let port = endpoint.port
        DispatchQueue.global().async {
            defer { completed.signal() }
            result.withLock { output in output = Result {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user, auditSessionID: nil, maxPayloadBytes: 8192)
                let received = try receiver.receiveIOInput(timeoutMilliseconds: 5000)
                defer { received.closeIfUnclaimed() }
                let terminal = try XCTUnwrap(received.outputs).takeTerminalReply()
                let stream = try MachCommandStreamAuthority(binding: binding, original: received.caller, terminal: terminal)
                defer { stream.close(); terminal.close() }
                try received.sendAdmissionReply(payloads.0)
                guard allowOpen.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                try Self.waitQueued { try stream.send(.opened) }
                guard allowControls.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                let expected: [CommandStreamFrame.Body] = Array(repeating: .signal(UInt32(SIGINT)), count: 4) +
                    [.resize(53, 143, 0, 0), .input(Data([0, 255, 10, 13])), .inputEnd, .cancel]
                var controls: [CommandStreamFrame.Body] = []
                let deadline = Date().addingTimeInterval(5)
                while controls.count < expected.count {
                    if let body = try stream.receiveControl(expression: expression, userID: user, auditSessionID: nil) { controls.append(body) }
                    guard Date() < deadline else { throw MachCommandCallerError.timeout }
                    usleep(1000)
                }
                XCTAssertEqual(controls, expected)
                try Self.waitQueued { try stream.send(.inputCredit(4)) }
                try Self.waitQueued { try stream.send(.output(binary)) }
                try Self.waitQueued { try stream.send(.output(Data([0xff, 0, 10]))) }
                try Self.waitQueued { try stream.send(.outputEnd) }
                while !stream.outputDrained {
                    let body = try stream.receiveControl(expression: expression, userID: user, auditSessionID: nil)
                    if let body { XCTAssertEqual(body, .outputDrained) }
                    guard Date() < deadline else { throw MachCommandCallerError.timeout }
                    usleep(1000)
                }
                try terminal.sendTerminalNonblocking(payloads.1)
            } }
        }
        defer { allowOpen.signal(); allowControls.signal() }
        let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        let io = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
            handshake: handshake, expression: expression, userID: user, auditSessionID: nil, maximumPayloadBytes: 8192)
        guard case .admitted(let session) = io else { return XCTFail("The session must own its original channels") }
        defer { session.close() }
        XCTAssertNil(try session.pollStreamEvent(timeoutMilliseconds: 10))
        XCTAssertThrowsError(try session.forwardInput(Data([1])))
        XCTAssertThrowsError(try session.pollTerminalResult()) { XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible) }
        allowOpen.signal()
        guard case .opened? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("The original Root must open the channel") }
        for _ in 0..<4 { XCTAssertTrue(try session.forwardSignal(UInt32(SIGINT))) }
        XCTAssertFalse(try session.resizeTerminal(rows: 53, columns: 143))
        allowControls.signal()
        try Self.waitQueued { try session.resizeTerminal(rows: 53, columns: 143) }
        try Self.waitQueued { try session.forwardInput(Data([0, 255, 10, 13])) == 4 }
        try Self.waitQueued { try session.finishInput() }
        XCTAssertThrowsError(try session.forwardInput(Data([1])))
        try Self.waitQueued { try session.cancelCommand() }
        var receivedBytes = Data(), ended = false, exit: CommandTerminalOutcome?
        let deadline = Date().addingTimeInterval(5)
        while exit == nil {
            if let event = try session.pollStreamEvent(timeoutMilliseconds: 1000) {
                switch event {
                case .output(let bytes): XCTAssertFalse(ended); receivedBytes.append(bytes)
                case .outputEnded: ended = true; try Self.waitQueued { try session.acknowledgeOutput() }
                case .inputCapacity(let capacity): XCTAssertEqual(capacity, 32768)
                case .terminal(let terminal): XCTAssertTrue(ended); exit = terminal.outcome
                case .opened: XCTFail("The stream must open once")
                case .jobState, .currentJob: XCTFail("A legacy PTY profile must not report job state")
                }
            }
            guard Date() < deadline else { throw MachCommandCallerError.timeout }
        }
        XCTAssertEqual(receivedBytes, binary + Data([0xff, 0, 10])); XCTAssertEqual(exit, .exited(7))
        XCTAssertEqual(completed.wait(timeout: .now() + 5), .success)
        try result.withLock { try XCTUnwrap($0).get() }
    }
    func testStreamReceiverRejectsReplayAndMalformedCarrierWithoutAdvancingOriginalSequence() throws {
        let source = try Endpoint(), destination = try Endpoint()
        try source.send(Data([1]))
        let original = try receiver(source).receive(timeoutMilliseconds: 1000)
        defer { original.caller.close() }
        let profile = try admissionClientFixture(source.port, input: 4, wire: 4).profile
        let binding = streamBinding(profile, try commandSubmission())
        XCTAssertEqual(mach_port_mod_refs(mach_task_self_, destination.port, MACH_PORT_RIGHT_SEND, 1), KERN_SUCCESS)
        let terminal = MachCommandReplyRight(taking: destination.port, identifier: MachCommandCallerReceiver.terminalReplyMessageID)
        defer { terminal.close() }
        let stream = try MachCommandStreamAuthority(binding: binding, original: original.caller, terminal: terminal)
        defer { stream.close() }
        XCTAssertTrue(try stream.send(.opened))
        let message = try receiver(destination, maximum: 8192).receiveExecutionEvent(timeoutMilliseconds: 1000)
        guard case .stream(let opened, let carried) = message else { return XCTFail("The stream must carry its private control right") }
        defer { opened.caller.close(); carried?.close() }
        let control = try XCTUnwrap(carried).takeControlRight(); defer { control.close() }
        let cancel = try CommandStreamFrame(sequence: 0, body: .cancel).encode(binding: binding)
        XCTAssertTrue(try MachCommandWire.sendStream(Data([0xa0]), destination: control.borrowed(), toAuthority: true))
        XCTAssertThrowsError(try stream.receiveControl(expression: selfExpression(), userID: geteuid(), auditSessionID: nil))
        XCTAssertTrue(try MachCommandWire.sendStream(cancel, destination: control.borrowed(), toAuthority: true))
        XCTAssertEqual(try stream.receiveControl(expression: selfExpression(), userID: geteuid(), auditSessionID: nil), .cancel)
        XCTAssertTrue(try MachCommandWire.sendStream(cancel, destination: control.borrowed(), toAuthority: true))
        XCTAssertThrowsError(try stream.receiveControl(expression: selfExpression(), userID: geteuid(), auditSessionID: nil))
        let resize = try CommandStreamFrame(sequence: 1, body: .resize(0, 0, 0, 0)).encode(binding: binding)
        XCTAssertTrue(try MachCommandWire.sendStream(resize, destination: control.borrowed(), toAuthority: true))
        XCTAssertEqual(try stream.receiveControl(expression: selfExpression(), userID: geteuid(), auditSessionID: nil), .resize(0, 0, 0, 0))
        let start = DispatchTime.now().uptimeNanoseconds
        XCTAssertNil(try stream.receiveControl(expression: selfExpression(), userID: geteuid(), auditSessionID: nil))
        XCTAssertLessThan(DispatchTime.now().uptimeNanoseconds - start, 100_000_000)
        let badAck = try CommandStreamFrame(sequence: 2, body: .outputDrained).encode(binding: binding)
        XCTAssertTrue(try MachCommandWire.sendStream(badAck, destination: control.borrowed(), toAuthority: true))
        XCTAssertThrowsError(try stream.receiveControl(expression: selfExpression(), userID: geteuid(), auditSessionID: nil))
        XCTAssertFalse(stream.outputDrained)
    }
}

extension MachCommandCallerReceiverTests {
    func testStreamRejectsAnotherCurrentSignedProcessWithoutConsumingOriginalSequence() throws {
        let source = try Endpoint(), output = try Endpoint()
        try source.send(Data([1]))
        let original = try receiver(source).receive(timeoutMilliseconds: 1000)
        defer { original.caller.close() }
        let profile = try admissionClientFixture(source.port, input: 4, wire: 4).profile
        let binding = streamBinding(profile, try commandSubmission())
        XCTAssertEqual(mach_port_mod_refs(mach_task_self_, output.port, MACH_PORT_RIGHT_SEND, 1), KERN_SUCCESS)
        let terminal = MachCommandReplyRight(taking: output.port, identifier: MachCommandCallerReceiver.terminalReplyMessageID)
        defer { terminal.close() }
        let stream = try MachCommandStreamAuthority(binding: binding, original: original.caller, terminal: terminal)
        defer { stream.close() }
        XCTAssertTrue(try stream.send(.opened))
        guard case .stream(let reply, let right) = try receiver(output, maximum: 8192).receiveExecutionEvent(timeoutMilliseconds: 1000) else { return XCTFail("The original output channel must receive its control right") }
        defer { reply.caller.close(); right?.close() }
        let control = try XCTUnwrap(right).takeControlRight(); defer { control.close() }
        let borrowed = try Endpoint(borrowingSendRight: control.borrowed())
        let bytes = try CommandStreamFrame(sequence: 0, body: .cancel).encode(binding: binding)
        let peer = try Peer(endpoint: borrowed, controlFrame: bytes)
        // Both actual code identities pass this fixture policy. The retained process binding must still reject the other process.
        let expression = "(" + (try selfExpression()) + ") or (" + peer.expression + ")"
        let deadline = Date().addingTimeInterval(5)
        var rejected = false
        while !rejected {
            do {
                let body = try stream.receiveControl(expression: expression, userID: geteuid(), auditSessionID: nil)
                XCTAssertNil(body)
            } catch {
                XCTAssertEqual(error as? MachCommandHandshakeError, .wrongBinding)
                rejected = true
            }
            guard Date() < deadline else { throw MachCommandCallerError.timeout }
            usleep(1000)
        }
        try peer.stop()
        XCTAssertTrue(try MachCommandWire.sendStream(bytes, destination: control.borrowed(), toAuthority: true))
        XCTAssertEqual(try stream.receiveControl(expression: expression, userID: geteuid(), auditSessionID: nil), .cancel)
    }
    func testStreamOpenAndOutputQueueTimeoutPreserveRightsAndSequenceForRetry() throws {
        let source = try Endpoint(), output = try MachCommandPrivateReplyPort(queueLimit: 1)
        defer { output.close() }
        try source.send(Data([1]))
        let original = try receiver(source).receive(timeoutMilliseconds: 1000)
        defer { original.caller.close() }
        let profile = try admissionClientFixture(source.port, input: 4, wire: 4).profile
        let binding = streamBinding(profile, try commandSubmission())
        XCTAssertEqual(mach_port_mod_refs(mach_task_self_, output.port, MACH_PORT_RIGHT_SEND, 1), KERN_SUCCESS)
        let terminal = MachCommandReplyRight(taking: output.port, identifier: MachCommandCallerReceiver.terminalReplyMessageID)
        defer { terminal.close() }
        let stream = try MachCommandStreamAuthority(binding: binding, original: original.caller, terminal: terminal)
        defer { stream.close() }
        let receive = try MachCommandCallerReceiver(receivePort: output.port, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maxPayloadBytes: 8192)
        XCTAssertTrue(try MachCommandWire.sendStream(Data([1]), destination: output.port))
        XCTAssertFalse(try stream.send(.opened))
        guard case .stream(let filler, _) = try receive.receiveExecutionEvent(timeoutMilliseconds: 1000) else { return XCTFail("The filler must occupy one queue slot") }
        filler.caller.close()
        XCTAssertTrue(try stream.send(.opened))
        XCTAssertFalse(try stream.send(.output(Data([0, 255]))))
        guard case .stream(let opened, let right) = try receive.receiveExecutionEvent(timeoutMilliseconds: 1000) else { return XCTFail("The retried grant must remain usable") }
        defer { opened.caller.close(); right?.close() }
        XCTAssertEqual(try CommandStreamFrame.decode(opened.payload, binding: binding, direction: .toFrontend).sequence, 0)
        let control = try XCTUnwrap(right).takeControlRight(); defer { control.close() }
        let cancel = try CommandStreamFrame(sequence: 0, body: .cancel).encode(binding: binding)
        XCTAssertTrue(try MachCommandWire.sendStream(cancel, destination: control.borrowed(), toAuthority: true))
        XCTAssertEqual(try stream.receiveControl(expression: selfExpression(), userID: geteuid(), auditSessionID: nil), .cancel)
        XCTAssertTrue(try stream.send(.output(Data([0, 255]))))
        guard case .stream(let bytes, let extra) = try receive.receiveExecutionEvent(timeoutMilliseconds: 1000) else { return XCTFail("The output must preserve its sequence") }
        defer { bytes.caller.close(); extra?.close() }
        XCTAssertNil(extra)
        XCTAssertEqual(try CommandStreamFrame.decode(bytes.payload, binding: binding, direction: .toFrontend), .init(sequence: 1, body: .output(Data([0, 255]))))
    }
}

extension MachCommandCallerReceiverTests {
    func testStreamClientRejectsNativeExitBeforeOpenAndAllowsKnownPreSpawnFailure() throws {
        let cases: [(CommandTerminalOutcome, Bool)] = [(.exited(0), false), (.failedBeforeStart, false),
            (.exited(0), true), (.failedBeforeStart, true)]
        for (outcome, interrupted) in cases {
            let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 4)
            let submission = try commandSubmission(), payloads = try ioPayloads(profile: handshake.profile, submission: submission, terminal: outcome, outputInterrupted: interrupted)
            let release = DispatchSemaphore(value: 0), server = try serveIO(endpoint.port, admission: payloads.0, terminal: payloads.1, release: release)
            defer { release.signal() }
            let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
            defer { _ = Darwin.close(input); _ = Darwin.close(output) }
            let io = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
                handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192)
            guard case .admitted(let session) = io else { return XCTFail("The original terminal channel must remain owned") }
            defer { session.close() }
            release.signal(); XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
            if outcome == .exited(0) || interrupted {
                XCTAssertThrowsError(try session.pollStreamEvent(timeoutMilliseconds: 1000)) { XCTAssertEqual($0 as? CommandStreamError, .closed) }
            } else {
                guard case .terminal(let result)? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("The pre-spawn result must remain available") }
                XCTAssertEqual(result.outcome, .failedBeforeStart)
            }
        }
    }
    func testStreamProfileCannotRunThroughTheUnconnectedNativePipeDispatcher() throws {
        let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
        let marker = fixture.root.appendingPathComponent("stream-must-not-dispatch")
        let admissionPort = try Endpoint(), terminal = try Endpoint()
        let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal,
            executablePath: "/usr/bin/touch", arguments: [Data("touch".utf8), Data(marker.path.utf8)], wire: 4)
        let request = try admitOwnedCommand(command, fixture: fixture)
        let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        _ = try ownerDecision(request, fixture: fixture, decline: false)
        XCTAssertThrowsError(try beginDispatch(fixture, request: request, launcher: dispatchLauncher(fixture))) { XCTAssertEqual($0 as? CommandExecutionError, .unavailable) }
        try awaitDispatchCleanup(authority)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
        XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, .failedBeforeStart)
    }
}

extension MachCommandCallerReceiverTests {
    func testStreamClientRejectsExcessCreditAndTerminalBeforeOutputEOFWithoutResubmission() throws {
        for earlyTerminal in [false, true] {
            let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 4)
            let submission = try commandSubmission(), profile = handshake.profile, binding = streamBinding(profile, submission)
            let payloads = try ioPayloads(profile: profile, submission: submission)
            let expression = try selfExpression(), user = geteuid(), port = endpoint.port
            let completed = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            let result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
            DispatchQueue.global().async {
                defer { completed.signal() }
                result.withLock { output in output = Result {
                    let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user, auditSessionID: nil, maxPayloadBytes: 8192)
                    let received = try receiver.receiveIOInput(timeoutMilliseconds: 5000)
                    defer { received.closeIfUnclaimed() }
                    let terminal = try XCTUnwrap(received.outputs).takeTerminalReply()
                    defer { terminal.close() }
                    let stream = try MachCommandStreamAuthority(binding: binding, original: received.caller, terminal: terminal)
                    defer { stream.close() }
                    try received.sendAdmissionReply(payloads.0)
                    try Self.waitQueued { try stream.send(.opened) }
                    if earlyTerminal { try terminal.sendTerminalNonblocking(payloads.1) }
                    else { try Self.waitQueued { try stream.send(.inputCredit(1)) } }
                    guard release.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                } }
            }
            defer { release.signal() }
            let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
            defer { _ = Darwin.close(input); _ = Darwin.close(output) }
            let io = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
                handshake: handshake, expression: expression, userID: user, auditSessionID: nil, maximumPayloadBytes: 8192)
            guard case .admitted(let session) = io else { return XCTFail("The original channel must remain owned") }
            defer { session.close() }
            guard case .opened? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("The stream must open before the invalid event") }
            XCTAssertThrowsError(try session.pollStreamEvent(timeoutMilliseconds: 1000)) {
                XCTAssertEqual($0 as? CommandStreamError, earlyTerminal ? .closed : .capacity)
            }
            XCTAssertThrowsError(try session.cancelCommand())
            release.signal(); XCTAssertEqual(completed.wait(timeout: .now() + 5), .success); try result.withLock { try XCTUnwrap($0).get() }
            XCTAssertThrowsError(try receiver(endpoint).receiveIOInput(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testStreamClientRejectsTerminalAfterEOFWithoutQueuedDrainAcknowledgment() throws {
        for fullControlQueue in [false, true] {
            let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 4)
            let submission = try commandSubmission(), profile = handshake.profile, binding = streamBinding(profile, submission)
            let payloads = try ioPayloads(profile: profile, submission: submission)
            let expression = try selfExpression(), user = geteuid(), port = endpoint.port
            let completed = DispatchSemaphore(value: 0), allowTerminal = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            let result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
            DispatchQueue.global().async {
                defer { completed.signal() }
                result.withLock { output in output = Result {
                    let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user, auditSessionID: nil, maxPayloadBytes: 8192)
                    let received = try receiver.receiveIOInput(timeoutMilliseconds: 5000)
                    defer { received.closeIfUnclaimed() }
                    let terminal = try XCTUnwrap(received.outputs).takeTerminalReply()
                    defer { terminal.close() }
                    let stream = try MachCommandStreamAuthority(binding: binding, original: received.caller, terminal: terminal)
                    defer { stream.close() }
                    try received.sendAdmissionReply(payloads.0)
                    try Self.waitQueued { try stream.send(.opened) }
                    try Self.waitQueued { try stream.send(.outputEnd) }
                    guard allowTerminal.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                    XCTAssertFalse(stream.outputDrained)
                    try terminal.sendTerminalNonblocking(payloads.1)
                    guard release.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                } }
            }
            defer { allowTerminal.signal(); release.signal() }
            let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
            defer { _ = Darwin.close(input); _ = Darwin.close(output) }
            let io = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
                handshake: handshake, expression: expression, userID: user, auditSessionID: nil, maximumPayloadBytes: 8192)
            guard case .admitted(let session) = io else { return XCTFail("The original channel must remain owned") }
            defer { session.close() }
            guard case .opened? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("The stream must open") }
            guard case .outputEnded? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("The output must end before the terminal") }
            if fullControlQueue {
                for _ in 0..<4 { XCTAssertTrue(try session.forwardSignal(UInt32(SIGINT))) }
                XCTAssertFalse(try session.acknowledgeOutput())
            }
            allowTerminal.signal()
            XCTAssertThrowsError(try session.pollStreamEvent(timeoutMilliseconds: 1000)) { XCTAssertEqual($0 as? CommandStreamError, .closed) }
            XCTAssertThrowsError(try session.pollStreamEvent(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandHandshakeError, .retired) }
            XCTAssertThrowsError(try session.acknowledgeOutput())
            release.signal(); XCTAssertEqual(completed.wait(timeout: .now() + 5), .success)
            try result.withLock { try XCTUnwrap($0).get() }
            XCTAssertThrowsError(try receiver(endpoint).receiveIOInput(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testNativePTYStreamsOutputAndCommitsBeforeDrainAcknowledgmentWithoutRepeatingOutcome() throws {
        let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
        let launcher = try dispatchLauncher(fixture), admissionPort = try Endpoint(), terminal = try Endpoint()
        let input = try RetainedCommandPTY(size: winsize(ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0))
        defer { input.close() }
        let original = try input.withBorrowedSlave { descriptor -> (Int32, termios) in
            var attributes = termios(); XCTAssertEqual(tcgetattr(descriptor, &attributes), 0)
            cfmakeraw(&attributes); XCTAssertEqual(tcsetattr(descriptor, TCSANOW, &attributes), 0)
            return (fcntl(descriptor, F_GETFL), attributes)
        }
        let (_, command, submission, profile) = try input.withBorrowedSlave {
            try ownerIOCommand(admission: admissionPort, terminal: terminal, inputDescriptor: $0,
                executablePath: "/bin/sh", arguments: [Data("sh".utf8), Data("-c".utf8),
                    Data("test -t 0 && test -t 1 && test -t 2 || exit 40; /bin/stty size; printf PTY_DONE; exit 7".utf8)],
                wire: 4, ioMode: .pty)
        }
        let request = try admitOwnedCommand(command, fixture: fixture)
        let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        guard case .admitted(let admitted) = admission.outcome else { return XCTFail("The original request must be admitted") }
        let binding = CommandStreamBinding(profile: profile, submission: submission.binding,
            submissionDigest: admission.submissionDigest, request: admitted)
        _ = try ownerDecision(request, fixture: fixture, decline: false)
        try beginDispatch(fixture, request: request, launcher: launcher)
        let receive = try receiver(terminal, maximum: 8192)
        var control: MachCommandAuthorityPort?, output = Data(), ended = false
        defer { control?.close() }
        while !ended {
            guard case .stream(let reply, let right) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
                return XCTFail("Output must drain before the original terminal result")
            }
            defer { reply.caller.close(); right?.close() }
            let frame = try CommandStreamFrame.decode(reply.payload, binding: binding, direction: .toFrontend)
            switch frame.body {
            case .opened: control = try XCTUnwrap(right).takeControlRight()
            case .output(let bytes): output.append(bytes)
            case .outputEnd: ended = true
            default: XCTFail("This command sends no input or credit")
            }
        }
        XCTAssertEqual(output, Data("24 80\nPTY_DONE".utf8))
        let deadline = Date().addingTimeInterval(2)
        while try authority.withRequests({ try $0.historicalOutcome(requestID: request.requestID) })?.revision != 2 {
            guard Date() < deadline else { throw CommandExecutionError.unavailable }; usleep(1000)
        }
        let before = try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID) }
        XCTAssertEqual(before?.revision, 2)
        XCTAssertEqual(authority.activeCommandCount, 1)
        XCTAssertThrowsError(try receive.receiveExecutionEvent(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        let lateInput = try CommandStreamFrame(sequence: 0, body: .input(Data("late".utf8))).encode(binding: binding)
        XCTAssertTrue(try MachCommandWire.sendStream(lateInput, destination: XCTUnwrap(control).borrowed(), toAuthority: true))
        let acknowledgment = try CommandStreamFrame(sequence: 1, body: .outputDrained).encode(binding: binding)
        XCTAssertTrue(try MachCommandWire.sendStream(acknowledgment, destination: XCTUnwrap(control).borrowed(), toAuthority: true))
        XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, .exited(7))
        try awaitDispatchCleanup(authority)
        let after = try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID) }
        XCTAssertEqual(after?.revision, before?.revision)
        XCTAssertThrowsError(try beginDispatch(fixture, request: request, launcher: launcher))
        try input.withBorrowedSlave { descriptor in
            var attributes = termios(); XCTAssertEqual(tcgetattr(descriptor, &attributes), 0)
            XCTAssertEqual(fcntl(descriptor, F_GETFL), original.0)
            XCTAssertEqual(attributes.c_lflag, original.1.c_lflag); XCTAssertEqual(attributes.c_iflag, original.1.c_iflag)
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testStreamClosedSendRightsPreserveQueuedControlAndThenReportDisconnect() throws {
        let source = try Endpoint(), output = try Endpoint()
        try source.send(Data([1]))
        let original = try receiver(source).receive(timeoutMilliseconds: 1000)
        defer { original.caller.close() }
        let profile = CommandHandshakeProfile(wireVersion: 4, submissionSchemaVersion: 1, inputCarrierVersion: 4,
            callerBinding: assemblyBinding, macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16))
        let binding = streamBinding(profile, try commandSubmission())
        XCTAssertEqual(mach_port_mod_refs(mach_task_self_, output.port, MACH_PORT_RIGHT_SEND, 1), KERN_SUCCESS)
        let terminal = MachCommandReplyRight(taking: output.port, identifier: MachCommandCallerReceiver.terminalReplyMessageID)
        defer { terminal.close() }
        let stream = try MachCommandStreamAuthority(binding: binding, original: original.caller, terminal: terminal)
        defer { stream.close() }
        XCTAssertTrue(try stream.send(.opened))
        guard case .stream(let reply, let carried) = try receiver(output, maximum: 8192).receiveExecutionEvent(timeoutMilliseconds: 1000) else {
            return XCTFail("The private control must be granted")
        }
        defer { reply.caller.close() }
        let control = try XCTUnwrap(carried).takeControlRight(); carried?.close()
        let cancel = try CommandStreamFrame(sequence: 0, body: .cancel).encode(binding: binding)
        XCTAssertTrue(try MachCommandWire.sendStream(cancel, destination: control.borrowed(), toAuthority: true))
        control.close()
        XCTAssertEqual(try stream.receiveControl(expression: selfExpression(), userID: geteuid(), auditSessionID: nil), .cancel)
        XCTAssertThrowsError(try stream.receiveControl(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? CommandStreamError, .closed)
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testNativePTYCanonicalInputEOFAndClosedControlsRetireTheOwnedChild() throws {
        for closeControls in [false, true] {
            let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
            let launcher = try dispatchLauncher(fixture), admissionPort = try Endpoint(), terminal = try Endpoint()
            let input = try RetainedCommandPTY(); defer { input.close() }
            try input.withBorrowedSlave { descriptor in
                var attributes = termios(); XCTAssertEqual(tcgetattr(descriptor, &attributes), 0)
                attributes.c_lflag |= UInt(ICANON); attributes.c_lflag &= ~UInt(ECHO)
                XCTAssertEqual(tcsetattr(descriptor, TCSANOW, &attributes), 0)
            }
            let path = closeControls ? "/bin/sh" : "/bin/cat"
            let arguments = closeControls ? [Data("sh".utf8), Data("-c".utf8), Data("printf READY; /bin/sleep 10".utf8)] : [Data("cat".utf8)]
            let (_, command, submission, profile) = try input.withBorrowedSlave {
                try ownerIOCommand(admission: admissionPort, terminal: terminal, inputDescriptor: $0,
                    executablePath: path, arguments: arguments, wire: 4, ioMode: .pty)
            }
            let request = try admitOwnedCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            guard case .admitted(let admitted) = admission.outcome else { return XCTFail("The original request must be admitted") }
            let binding = CommandStreamBinding(profile: profile, submission: submission.binding,
                submissionDigest: admission.submissionDigest, request: admitted)
            _ = try ownerDecision(request, fixture: fixture, decline: false)
            try beginDispatch(fixture, request: request, launcher: launcher)
            let receive = try receiver(terminal, maximum: 8192)
            guard case .stream(let opened, let carried) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
                return XCTFail("The private channel must open")
            }
            XCTAssertEqual(try CommandStreamFrame.decode(opened.payload, binding: binding, direction: .toFrontend).body, .opened)
            opened.caller.close()
            let control = try XCTUnwrap(carried).takeControlRight(); carried?.close(); defer { control.close() }
            if closeControls {
                guard case .stream(let reply, _) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
                    return XCTFail("The target must start before closing its controls")
                }
                defer { reply.caller.close() }
                XCTAssertEqual(try CommandStreamFrame.decode(reply.payload, binding: binding, direction: .toFrontend).body, .output(Data("READY".utf8)))
                control.close()
                XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, .signalled(UInt32(SIGKILL)))
            } else {
                let bytes = try CommandStreamFrame(sequence: 0, body: .input(Data("abc".utf8))).encode(binding: binding)
                let end = try CommandStreamFrame(sequence: 1, body: .inputEnd).encode(binding: binding)
                XCTAssertTrue(try MachCommandWire.sendStream(bytes, destination: control.borrowed(), toAuthority: true))
                XCTAssertTrue(try MachCommandWire.sendStream(end, destination: control.borrowed(), toAuthority: true))
                var output = Data(), credit: UInt32 = 0, ended = false
                while !ended {
                    guard case .stream(let reply, let extra) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
                        return XCTFail("Output must drain before the terminal result")
                    }
                    defer { reply.caller.close(); extra?.close() }
                    switch try CommandStreamFrame.decode(reply.payload, binding: binding, direction: .toFrontend).body {
                    case .output(let bytes): output.append(bytes)
                    case .inputCredit(let count): credit += count
                    case .outputEnd: ended = true
                    default: XCTFail("The stream must preserve its direction")
                    }
                }
                XCTAssertEqual(output, Data("abc".utf8)); XCTAssertEqual(credit, 3)
                let acknowledgment = try CommandStreamFrame(sequence: 2, body: .outputDrained).encode(binding: binding)
                XCTAssertTrue(try MachCommandWire.sendStream(acknowledgment, destination: control.borrowed(), toAuthority: true))
                XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, .exited(0))
            }
            try awaitDispatchCleanup(authority)
            XCTAssertEqual(try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID) }?.revision, 2)
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testNativePTYFullDuplexPreservesBinaryBytesThroughKernelBackpressure() throws {
        let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
        let launcher = try dispatchLauncher(fixture), admissionPort = try Endpoint(), terminal = try Endpoint()
        var queue = mach_port_limits_t(mpl_qlimit: 1)
        XCTAssertEqual(withUnsafeMutablePointer(to: &queue) {
            $0.withMemoryRebound(to: Int32.self, capacity: 1) {
                mach_port_set_attributes(mach_task_self_, terminal.port, MACH_PORT_LIMITS_INFO, $0, 1)
            }
        }, KERN_SUCCESS)
        let source = try XCTUnwrap(Bundle.module.url(forResource: "pty-bulk", withExtension: "c", subdirectory: "Fixtures/command-process"))
        let program = fixture.root.appendingPathComponent("fixture-pty-bulk")
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror", source.path, "-o", program.path]
        try compiler.run(); compiler.waitUntilExit(); XCTAssertEqual(compiler.terminationStatus, 0)
        let input = try RetainedCommandPTY(); defer { input.close() }
        try input.withBorrowedSlave { descriptor in
            var attributes = termios(); XCTAssertEqual(tcgetattr(descriptor, &attributes), 0)
            cfmakeraw(&attributes); XCTAssertEqual(tcsetattr(descriptor, TCSANOW, &attributes), 0)
        }
        let (_, command, submission, profile) = try input.withBorrowedSlave {
            try ownerIOCommand(admission: admissionPort, terminal: terminal, inputDescriptor: $0,
                executablePath: program.path, arguments: [Data("program".utf8)], wire: 4, ioMode: .pty)
        }
        let request = try admitOwnedCommand(command, fixture: fixture)
        let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        guard case .admitted(let admitted) = admission.outcome else { return XCTFail("The original request must be admitted") }
        let binding = CommandStreamBinding(profile: profile, submission: submission.binding,
            submissionDigest: admission.submissionDigest, request: admitted)
        _ = try ownerDecision(request, fixture: fixture, decline: false)
        try beginDispatch(fixture, request: request, launcher: launcher)
        let receive = try receiver(terminal, maximum: 8192), bytes = Data((0..<131072).map { UInt8($0 % 251) })
        var control: MachCommandAuthorityPort?, available = 0, sent = 0, outgoing: UInt64 = 0
        var incoming = CommandStreamReceiveSequence(direction: .toFrontend)
        var output = Data(), ended = false, inputEndSent = false, queueTimeouts = 0
        defer { control?.close() }
        // Shared CI runners still make steady progress through the deliberately slow one-slot output queue.
        let deadline = Date().addingTimeInterval(180)
        func enqueueInput(_ control: MachCommandAuthorityPort) throws {
            while sent < bytes.count, available > 0 {
                let count = min(4096, available, bytes.count - sent)
                let body = CommandStreamFrame(sequence: outgoing, body: .input(Data(bytes[sent..<(sent + count)])))
                if try MachCommandWire.sendStream(body.encode(binding: binding), destination: control.borrowed(), toAuthority: true) {
                    sent += count; available -= count; outgoing += 1
                } else { queueTimeouts += 1; break }
            }
        }
        do {
            while !ended {
                guard Date() < deadline else {
                    XCTFail("Bulk transfer stalled: sent=\(sent), output=\(output.count), credit=\(available), sequence=\(outgoing), inputEnd=\(inputEndSent), queueTimeouts=\(queueTimeouts)")
                    throw MachCommandCallerError.timeout
                }
                if let control {
                    if sent == 0 {
                        // The worker holds only the fixture journal. The original frontend keeps its non-Sendable control right.
                        let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
                        let paused = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
                        DispatchQueue.global().async {
                            defer { done.signal() }
                            let result = Result {
                                try authority.read { _ in
                                    entered.signal()
                                    guard resume.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                                }
                            }
                            paused.withLock { $0 = result }
                        }
                        defer { resume.signal() }
                        XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
                        try enqueueInput(control)
                        resume.signal()
                        XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
                        try paused.withLock { try XCTUnwrap($0).get() }
                    } else { try enqueueInput(control) }
                    if sent == bytes.count, !inputEndSent {
                        let end = try CommandStreamFrame(sequence: outgoing, body: .inputEnd).encode(binding: binding)
                        if try MachCommandWire.sendStream(end, destination: control.borrowed(), toAuthority: true) { outgoing += 1; inputEndSent = true }
                    }
                }
                guard case .stream(let reply, let carried) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
                    return XCTFail("All output must drain before the terminal result")
                }
                defer { reply.caller.close(); carried?.close() }
                let frame = try CommandStreamFrame.decode(reply.payload, binding: binding, direction: .toFrontend)
                try incoming.accept(frame)
                switch frame.body {
                case .opened: control = try XCTUnwrap(carried).takeControlRight(); available = 32768
                case .inputCredit(let count): available += Int(count); XCTAssertLessThanOrEqual(available, 32768)
                case .output(let bytes): output.append(bytes); usleep(3000)
                case .outputEnd: ended = true
                default: XCTFail("The stream must preserve its direction")
                }
            }
        } catch {
            XCTFail("Bulk transfer failed: error=\(error), sent=\(sent), output=\(output.count), credit=\(available), sequence=\(outgoing), inputEnd=\(inputEndSent), queueTimeouts=\(queueTimeouts)")
            throw error
        }
        XCTAssertEqual(sent, bytes.count); XCTAssertTrue(inputEndSent); XCTAssertGreaterThan(queueTimeouts, 0)
        let expected = bytes + Data((0..<1048576).map { UInt8(($0 * 17 + 3) % 251) })
        XCTAssertEqual(output, expected)
        let acknowledgment = try CommandStreamFrame(sequence: outgoing, body: .outputDrained).encode(binding: binding)
        try Self.waitQueued { try MachCommandWire.sendStream(acknowledgment, destination: XCTUnwrap(control).borrowed(), toAuthority: true) }
        XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, .exited(7))
        try awaitDispatchCleanup(authority)
        XCTAssertEqual(try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID) }?.revision, 2)
    }
}


extension MachCommandCallerReceiverTests {
    func testNativePTYSelectedContinueDrainsAfterControlClosureWithoutKillingOrRepeatingWork() throws {
        let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
        let launcher = try dispatchLauncher(fixture), admissionPort = try Endpoint(), terminal = try Endpoint()
        let marker = fixture.root.appendingPathComponent("continued-once")
        let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal,
            executablePath: "/bin/sh", arguments: [Data("sh".utf8), Data("-c".utf8),
                Data("printf READY; /bin/sleep 1; /usr/bin/head -c 1048576 /dev/zero; printf once >> \"$1\"; exit 7".utf8),
                Data("sh".utf8), Data(marker.path.utf8)], wire: 4, ioMode: .pty, disconnect: .continueRunning)
        let request = try admitOwnedCommand(command, fixture: fixture)
        let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        guard case .admitted(let admitted) = admission.outcome else { return XCTFail("The original request must be admitted") }
        let binding = CommandStreamBinding(profile: profile, submission: submission.binding,
            submissionDigest: admission.submissionDigest, request: admitted)
        _ = try ownerDecision(request, fixture: fixture, decline: false)
        try beginDispatch(fixture, request: request, launcher: launcher)
        let receive = try receiver(terminal, maximum: 8192)
        guard case .stream(let opened, let carried) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
            return XCTFail("The private stream must open")
        }
        XCTAssertEqual(try CommandStreamFrame.decode(opened.payload, binding: binding, direction: .toFrontend).body, .opened)
        opened.caller.close()
        let control = try XCTUnwrap(carried).takeControlRight(); carried?.close(); defer { control.close() }
        guard case .stream(let ready, let extra) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
            return XCTFail("The target must start before the controls close")
        }
        defer { ready.caller.close(); extra?.close() }
        XCTAssertEqual(try CommandStreamFrame.decode(ready.payload, binding: binding, direction: .toFrontend).body, .output(Data("READY".utf8)))
        control.close()
        let result: ReceivedMachCommandSubmission
        do {
            let deadline = Date().addingTimeInterval(180)
            while true {
                do { result = try receive.receiveTerminalReply(timeoutMilliseconds: 60000); break }
                catch MachCommandCallerError.timeout where Date() < deadline { continue }
            }
        }
        catch {
            XCTFail("Continue cleanup stalled: marker=\(FileManager.default.fileExists(atPath: marker.path)), owners=\(authority.activeCommandCount), phase=\(try authority.withRequests { try $0.state(requestID: request.requestID).phase })")
            throw error
        }
        defer { result.caller.close() }
        XCTAssertEqual(try CommandTerminalResultPayload.decode(result.payload, profile: profile, original: submission,
            admission: admission).outcome, .exited(7))
        try awaitDispatchCleanup(authority)
        XCTAssertEqual(try Data(contentsOf: marker), Data("once".utf8))
        XCTAssertEqual(try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID) }?.revision, 2)
        XCTAssertThrowsError(try beginDispatch(fixture, request: request, launcher: launcher))
        XCTAssertThrowsError(try receive.receiveTerminalReply(timeoutMilliseconds: 10))
    }

    func testNativePTYTerminalCommitFailureWaitsForOutputAcknowledgmentThenRecoversOnlyUnknown() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), authority = try XCTUnwrap(fixture.authority)
            let launcher = try dispatchLauncher(fixture), admissionPort = try Endpoint(), terminal = try Endpoint()
            let marker = fixture.root.appendingPathComponent("committed-once")
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal,
                executablePath: "/bin/sh", arguments: [Data("sh".utf8), Data("-c".utf8),
                    Data("printf once >> \"$1\"; printf OUT; exit 7".utf8), Data("sh".utf8), Data(marker.path.utf8)], wire: 4, ioMode: .pty)
            let request = try admitOwnedCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            guard case .admitted(let admitted) = admission.outcome else { return XCTFail("The original request must be admitted") }
            let binding = CommandStreamBinding(profile: profile, submission: submission.binding,
                submissionDigest: admission.submissionDigest, request: admitted)
            _ = try ownerDecision(request, fixture: fixture, decline: false)
            let clock = TerminalCommitClock(now: fixture.now(130)); defer { clock.recover() }
            try beginDispatch(fixture, request: request, launcher: launcher, clock: clock.read)
            let receive = try receiver(terminal, maximum: 8192)
            var control: MachCommandAuthorityPort?, output = Data(), ended = false
            defer { control?.close() }
            while !ended {
                guard case .stream(let reply, let right) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
                    return XCTFail("Output must drain before even an unknown terminal result")
                }
                defer { reply.caller.close(); right?.close() }
                switch try CommandStreamFrame.decode(reply.payload, binding: binding, direction: .toFrontend).body {
                case .opened: control = try XCTUnwrap(right).takeControlRight()
                case .output(let bytes): output.append(bytes)
                case .outputEnd: ended = true
                default: XCTFail("This command sends no input or credit")
                }
            }
            XCTAssertEqual(output, Data("OUT".utf8))
            XCTAssertEqual(authority.activeCommandCount, 1)
            XCTAssertEqual(try authority.withRequests { try $0.state(requestID: request.requestID).phase }, .executing)
            XCTAssertThrowsError(try receive.receiveExecutionEvent(timeoutMilliseconds: 10)) {
                XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
            }
            let acknowledgment = try CommandStreamFrame(sequence: 0, body: .outputDrained).encode(binding: binding)
            XCTAssertTrue(try MachCommandWire.sendStream(acknowledgment, destination: XCTUnwrap(control).borrowed(), toAuthority: true))
            XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, .unknown)
            XCTAssertEqual(authority.activeCommandCount, 1)
            clock.recover()
            try awaitDispatchCleanup(authority)
            let outcome = try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID) }
            XCTAssertEqual(outcome?.phase, .unknown); XCTAssertEqual(outcome?.revision, 2)
            XCTAssertEqual(try Data(contentsOf: marker), Data("once".utf8))
            XCTAssertThrowsError(try beginDispatch(fixture, request: request, launcher: launcher))
            XCTAssertThrowsError(try receive.receiveTerminalReply(timeoutMilliseconds: 10))
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testNativePTYControlsResizeAndSignalTheCurrentForegroundJob() throws {
        for cancel in [false, true] {
            let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
            let launcher = try dispatchLauncher(fixture), admissionPort = try Endpoint(), terminal = try Endpoint()
            let source = try XCTUnwrap(Bundle.module.url(forResource: "pty-controls", withExtension: "c", subdirectory: "Fixtures/command-process"))
            let program = fixture.root.appendingPathComponent("fixture-pty-controls")
            let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
            compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror", source.path, "-o", program.path]
            try compiler.run(); compiler.waitUntilExit(); XCTAssertEqual(compiler.terminationStatus, 0)
            let input = try RetainedCommandPTY(); defer { input.close() }
            try input.withBorrowedSlave { descriptor in
                var attributes = termios(); XCTAssertEqual(tcgetattr(descriptor, &attributes), 0)
                cfmakeraw(&attributes); XCTAssertEqual(tcsetattr(descriptor, TCSANOW, &attributes), 0)
            }
            let (_, command, submission, profile) = try input.withBorrowedSlave {
                try ownerIOCommand(admission: admissionPort, terminal: terminal, inputDescriptor: $0,
                    executablePath: program.path, arguments: [Data("program".utf8), Data((cancel ? "cancel" : "interrupt").utf8)],
                    wire: 4, ioMode: .pty)
            }
            let request = try admitOwnedCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            guard case .admitted(let admitted) = admission.outcome else { return XCTFail("The original request must be admitted") }
            let binding = CommandStreamBinding(profile: profile, submission: submission.binding,
                submissionDigest: admission.submissionDigest, request: admitted)
            _ = try ownerDecision(request, fixture: fixture, decline: false)
            try beginDispatch(fixture, request: request, launcher: launcher)
            let receive = try receiver(terminal, maximum: 8192)
            var control: MachCommandAuthorityPort?, output = Data(), ended = false, resized = false, signalled = false
            var incoming = CommandStreamReceiveSequence(direction: .toFrontend)
            defer { control?.close() }
            while !ended {
                guard case .stream(let reply, let right) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
                    return XCTFail("Output must drain before the original terminal result")
                }
                defer { reply.caller.close(); right?.close() }
                let frame = try CommandStreamFrame.decode(reply.payload, binding: binding, direction: .toFrontend)
                try incoming.accept(frame)
                switch frame.body {
                case .opened: control = try XCTUnwrap(right).takeControlRight()
                case .output(let bytes): output.append(bytes)
                case .outputEnd: ended = true
                default: XCTFail("This command sends no input or credit")
                }
                if !resized, output == Data("READY\n".utf8) {
                    let resize = try CommandStreamFrame(sequence: 0, body: .resize(53, 143, 0, 0)).encode(binding: binding)
                    XCTAssertTrue(try MachCommandWire.sendStream(resize, destination: XCTUnwrap(control).borrowed(), toAuthority: true))
                    resized = true
                }
                if !signalled, output == Data("READY\nRESIZED\n".utf8) {
                    let signal = try CommandStreamFrame(sequence: 1, body: cancel ? .cancel : .signal(UInt32(SIGINT))).encode(binding: binding)
                    XCTAssertTrue(try MachCommandWire.sendStream(signal, destination: XCTUnwrap(control).borrowed(), toAuthority: true))
                    signalled = true
                }
            }
            XCTAssertTrue(resized); XCTAssertTrue(signalled)
            XCTAssertEqual(output, Data((cancel ? "READY\nRESIZED\n" : "READY\nRESIZED\nCHILD_INT\nLEADER_END\n").utf8))
            let acknowledgment = try CommandStreamFrame(sequence: 2, body: .outputDrained).encode(binding: binding)
            XCTAssertTrue(try MachCommandWire.sendStream(acknowledgment, destination: XCTUnwrap(control).borrowed(), toAuthority: true))
            XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, cancel ? .signalled(UInt32(SIGKILL)) : .exited(7))
            try awaitDispatchCleanup(authority)
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testNativePTYControlsRequireTheCurrentProtectedFrontendRole() throws {
        for change in 0..<3 {
            let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
            let launcher = try dispatchLauncher(fixture), admissionPort = try Endpoint(), terminal = try Endpoint()
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal,
                executablePath: "/bin/sh", arguments: [Data("sh".utf8), Data("-c".utf8),
                    Data("printf READY; /bin/sleep 10".utf8)], wire: 4, ioMode: .pty)
            let request = try admitOwnedCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            guard case .admitted(let admitted) = admission.outcome else { return XCTFail("The original request must be admitted") }
            let binding = CommandStreamBinding(profile: profile, submission: submission.binding,
                submissionDigest: admission.submissionDigest, request: admitted)
            _ = try ownerDecision(request, fixture: fixture, decline: false)
            try beginDispatch(fixture, request: request, launcher: launcher)
            let receive = try receiver(terminal, maximum: 8192)
            guard case .stream(let opened, let carried) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
                return XCTFail("The private channel must open")
            }
            opened.caller.close()
            let control = try XCTUnwrap(carried).takeControlRight(); carried?.close(); defer { control.close() }
            guard case .stream(let ready, let extra) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
                return XCTFail("The command must start before its role changes")
            }
            defer { ready.caller.close(); extra?.close() }
            XCTAssertEqual(try CommandStreamFrame.decode(ready.payload, binding: binding, direction: .toFrontend).body, .output(Data("READY".utf8)))
            try authority.write { tx in
                let snapshot = try XCTUnwrap(tx.codePolicy()), old = try XCTUnwrap(snapshot.policy.entries.first)
                let entry = try AuthorityCodeEntry(role: old.role, teamID: old.teamID, identifier: old.identifier,
                    installedGeneration: old.installedGeneration, minimumGeneration: old.minimumGeneration,
                    codeDirectoryHash: change == 1 ? Data(repeating: 2, count: 20) : old.codeDirectoryHash, active: change != 2)
                _ = try tx.installCodePolicy(AuthorityCodePolicy(entries: [entry]), expectedRevision: snapshot.revision)
            }
            let signal = try CommandStreamFrame(sequence: 0, body: .signal(UInt32(SIGTERM))).encode(binding: binding)
            XCTAssertTrue(try MachCommandWire.sendStream(signal, destination: control.borrowed(), toAuthority: true))
            if change == 0 {
                guard case .stream(let eof, let extra) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
                    return XCTFail("Unchanged roles must keep the original control channel")
                }
                defer { eof.caller.close(); extra?.close() }
                XCTAssertEqual(try CommandStreamFrame.decode(eof.payload, binding: binding, direction: .toFrontend).body, .outputEnd)
                let acknowledgment = try CommandStreamFrame(sequence: 1, body: .outputDrained).encode(binding: binding)
                XCTAssertTrue(try MachCommandWire.sendStream(acknowledgment, destination: control.borrowed(), toAuthority: true))
            }
            let result = try ownerTerminal(terminal, submission: submission, admission: admission)
            XCTAssertEqual(result.outcome, .signalled(UInt32(change == 0 ? SIGTERM : SIGKILL)))
            XCTAssertEqual(result.outputInterrupted, change != 0)
            try awaitDispatchCleanup(authority)
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testNativePTYEarlySignalCannotKillThePreparedHelperBeforeCommittedRelease() throws {
        try verifyEarlyPTYControl(isInput: false)
    }
    func testNativePTYEarlyInterruptInputCannotKillThePreparedHelperBeforeCommittedRelease() throws {
        try verifyEarlyPTYControl(isInput: true)
    }
    private func verifyEarlyPTYControl(isInput: Bool) throws {
        let fixture = try CommandRequestFixture(), admissionPort = try Endpoint(), terminal = try Endpoint()
        let launcher = try dispatchLauncher(fixture), marker = fixture.root.appendingPathComponent("early-signal-target")
        let input = try RetainedCommandPTY()
        defer { input.close() }
        try input.withBorrowedSlave { descriptor in
            var attributes = termios()
            XCTAssertEqual(tcgetattr(descriptor, &attributes), 0)
            attributes.c_lflag |= tcflag_t(ICANON | ISIG)
            attributes.c_lflag &= ~tcflag_t(ECHO)
            withUnsafeMutableBytes(of: &attributes.c_cc) { $0[Int(VINTR)] = 3 }
            XCTAssertEqual(tcsetattr(descriptor, TCSANOW, &attributes), 0)
        }
        let (_, command, submission, profile) = try input.withBorrowedSlave {
            try ownerIOCommand(admission: admissionPort, terminal: terminal, inputDescriptor: $0,
                executablePath: "/bin/sh", arguments: [Data("sh".utf8), Data("-c".utf8),
                    Data("/bin/sleep 10 && /usr/bin/touch \"$1\"".utf8), Data("sh".utf8), Data(marker.path.utf8)], wire: 4, ioMode: .pty)
        }
        let request = try admitCommand(command, fixture: fixture)
        let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        guard case .admitted(let admitted) = admission.outcome else { return XCTFail("The original request must be admitted") }
        let binding = CommandStreamBinding(profile: profile, submission: submission.binding,
            submissionDigest: admission.submissionDigest, request: admitted)
        _ = try fixture.consume(request)
        let now = fixture.now(130)
        let approval = try fixture.requests.authorizedCommandApproval(requestID: request.requestID, now: now)
        let resources = try fixture.requests.takeAuthorizedCommandExecution(requestID: request.requestID, now: now)
        let owner = CommandExecution(resources: resources, approval: approval, clock: { now }, receiptTime: { nil },
            callerExpression: try selfExpression(), callerUserID: geteuid(), callerSessionID: nil,
            validateLauncher: {}, validateElevation: { _ in })
        var control: MachCommandAuthorityPort?
        defer {
            control?.close(); owner.cancelBeforeRelease()
            let deadline = Date().addingTimeInterval(8)
            while !owner.dispose() && Date() < deadline { _ = owner.poll(checkStreamPolicy: {}); usleep(1000) }
        }
        try owner.prepare(monitorPath: dispatchMonitor(fixture), childPath: launcher, preparationMilliseconds: 5000, fileCreationMask: 0o022)
        var prepared = false
        let preparationDeadline = Date().addingTimeInterval(5)
        while !prepared {
            if case .prepared = owner.poll(checkStreamPolicy: {}) { prepared = true }
            guard Date() < preparationDeadline else { throw MachCommandCallerError.timeout }
            usleep(1000)
        }
        let receive = try receiver(terminal, maximum: 8192)
        guard case .stream(let opened, let carried) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
            return XCTFail("The private channel must open before the target is released")
        }
        opened.caller.close()
        control = try XCTUnwrap(carried).takeControlRight(); carried?.close()
        let signal = try CommandStreamFrame(sequence: 0, body: isInput ? .input(Data([3])) : .signal(UInt32(SIGKILL))).encode(binding: binding)
        XCTAssertTrue(try MachCommandWire.sendStream(signal, destination: XCTUnwrap(control).borrowed(), toAuthority: true))
        _ = owner.poll(checkStreamPolicy: {})
        usleep(30000)
        guard case .prepared = owner.poll(checkStreamPolicy: {}) else {
            return XCTFail("An early control must leave the helper alive until the one committed release")
        }
        XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .authorized)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
        _ = try fixture.requests.recordOutcome(requestID: request.requestID, expectedRevision: 0, event: .beginDispatch,
            now: now, receiptTimeMs: nil)
        owner.dispatchRevision = 1
        try owner.recheck(); try owner.release()
        var outcome: CommandTerminalOutcome?
        let deadline = Date().addingTimeInterval(5)
        while outcome == nil {
            if case .terminal(let observed) = owner.poll(checkStreamPolicy: {}) { outcome = observed }
            guard Date() < deadline else { throw MachCommandCallerError.timeout }
            usleep(1000)
        }
        let observed = try XCTUnwrap(outcome)
        XCTAssertTrue(observed == .signalled(UInt32(isInput ? SIGINT : SIGKILL)) || observed == .failedBeforeStart ||
            isInput && observed == .exited(130), "Observed synthetic early-control outcome: \(observed)")
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
        var ended = false, credit: UInt32 = 0
        while !ended {
            guard case .stream(let event, let extra) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
                return XCTFail("Private output must end before the final result")
            }
            defer { event.caller.close(); extra?.close() }
            switch try CommandStreamFrame.decode(event.payload, binding: binding, direction: .toFrontend).body {
            case .inputCredit(let count): credit += count
            case .outputEnd: ended = true
            default: XCTFail("Only consumed input credit and output EOF are expected")
            }
        }
        XCTAssertEqual(credit, isInput ? 1 : 0)
        XCTAssertFalse(owner.dispose())
        let acknowledgment = try CommandStreamFrame(sequence: 1, body: .outputDrained).encode(binding: binding)
        XCTAssertTrue(try MachCommandWire.sendStream(acknowledgment, destination: XCTUnwrap(control).borrowed(), toAuthority: true))
        _ = owner.poll(checkStreamPolicy: {})
        _ = try fixture.requests.recordOutcome(requestID: request.requestID, expectedRevision: 1, event: .verifyFailure,
            now: now, receiptTimeMs: nil)
        owner.deliverTerminal(observed)
        XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, observed)
        XCTAssertTrue(owner.dispose())
        XCTAssertEqual(try fixture.requests.historicalOutcome(requestID: request.requestID)?.revision, 2)
    }
}


extension MachCommandCallerReceiverTests {
    func testStreamClientRetainsBoundNativeOutcomeAfterControlDetachment() throws {
        for outputEnded in [false, true] {
            let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 4)
            let submission = try commandSubmission(), profile = handshake.profile, binding = streamBinding(profile, submission)
            let payloads = try ioPayloads(profile: profile, submission: submission, terminal: .signalled(UInt32(SIGKILL)))
            let interrupted = try CommandTerminalResultPayload(profile: profile, original: submission,
                request: binding.request, outcome: .signalled(UInt32(SIGKILL)), outputInterrupted: true).canonicalBytes
            let expression = try selfExpression(), user = geteuid(), port = endpoint.port
            let allowTerminal = DispatchSemaphore(value: 0), completed = DispatchSemaphore(value: 0)
            let result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
            DispatchQueue.global().async {
                defer { completed.signal() }
                result.withLock { value in value = Result {
                    let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression,
                        userID: user, auditSessionID: nil, maxPayloadBytes: 8192)
                    let received = try receiver.receiveIOInput(timeoutMilliseconds: 5000)
                    defer { received.closeIfUnclaimed() }
                    let terminal = try XCTUnwrap(received.outputs).takeTerminalReply()
                    defer { terminal.close() }
                    let stream = try MachCommandStreamAuthority(binding: binding, original: received.caller, terminal: terminal)
                    defer { stream.close() }
                    try received.sendAdmissionReply(payloads.0)
                    try Self.waitQueued { try stream.send(.opened) }
                    try Self.waitQueued { try stream.send(.output(Data("before detachment".utf8))) }
                    if outputEnded { try Self.waitQueued { try stream.send(.outputEnd) } }
                    guard allowTerminal.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                    XCTAssertFalse(stream.outputDrained)
                    stream.close()
                    try terminal.sendTerminalNonblocking(interrupted)
                } }
            }
            defer { allowTerminal.signal() }
            let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
            defer { _ = Darwin.close(input); _ = Darwin.close(output) }
            let io = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
                handshake: handshake, expression: expression, userID: user, auditSessionID: nil, maximumPayloadBytes: 8192)
            guard case .admitted(let session) = io else { return XCTFail("The original session must be admitted") }
            defer { session.close() }
            guard case .opened? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("The stream must open") }
            guard case .output(let bytes)? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("Output must be received") }
            XCTAssertEqual(bytes, Data("before detachment".utf8))
            if outputEnded {
                guard case .outputEnded? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("Output must end") }
            }
            allowTerminal.signal()
            guard case .terminal(let terminal)? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else {
                return XCTFail("Control detachment must preserve the authenticated native outcome")
            }
            XCTAssertEqual(terminal.outcome, .signalled(UInt32(SIGKILL)))
            XCTAssertTrue(terminal.outputInterrupted)
            XCTAssertThrowsError(try session.forwardSignal(UInt32(SIGINT)))
            XCTAssertThrowsError(try session.acknowledgeOutput())
            XCTAssertEqual(completed.wait(timeout: .now() + 5), .success)
            try result.withLock { try XCTUnwrap($0).get() }
            XCTAssertThrowsError(try receiver(endpoint).receiveIOInput(timeoutMilliseconds: 10))
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testNativePTYInterruptedResultSurvivesFullOutputQueueUntilDrainOrPeerEndpointClosure() throws {
        for peerClosesEndpoint in [false, true] {
            let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
            let launcher = try dispatchLauncher(fixture), admissionPort = try Endpoint(), terminal = try Endpoint()
            var limits = mach_port_limits_t(mpl_qlimit: 4)
            XCTAssertEqual(withUnsafeMutablePointer(to: &limits) {
                $0.withMemoryRebound(to: integer_t.self, capacity: 1) {
                    mach_port_set_attributes(mach_task_self_, terminal.port, MACH_PORT_LIMITS_INFO, $0, 1)
                }
            }, KERN_SUCCESS)
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal,
                executablePath: "/bin/sh", arguments: [Data("sh".utf8), Data("-c".utf8),
                    Data("printf READY; /bin/dd if=/dev/zero bs=4096 count=8 2>/dev/null; /bin/sleep 10".utf8)], wire: 4, ioMode: .pty)
            let request = try admitOwnedCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            guard case .admitted(let admitted) = admission.outcome else { return XCTFail("The original request must be admitted") }
            let binding = CommandStreamBinding(profile: profile, submission: submission.binding,
                submissionDigest: admission.submissionDigest, request: admitted)
            _ = try ownerDecision(request, fixture: fixture, decline: false)
            try beginDispatch(fixture, request: request, launcher: launcher)
            let receive = try receiver(terminal, maximum: 8192)
            var control: MachCommandAuthorityPort?, incoming = CommandStreamReceiveSequence(direction: .toFrontend)
            defer { control?.close(); try? terminal.closeReceiveRight(); try? awaitDispatchCleanup(authority) }
            guard case .stream(let opened, let carried) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
                return XCTFail("The private channel must open")
            }
            opened.caller.close()
            try incoming.accept(CommandStreamFrame.decode(opened.payload, binding: binding, direction: .toFrontend))
            control = try XCTUnwrap(carried).takeControlRight(); carried?.close()
            guard case .stream(let ready, let extra) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
                return XCTFail("The command must run before its role changes")
            }
            ready.caller.close(); extra?.close()
            let first = try CommandStreamFrame.decode(ready.payload, binding: binding, direction: .toFrontend)
            try incoming.accept(first)
            guard case .output(let prefix) = first.body else { return XCTFail("Output must precede the role change") }
            XCTAssertTrue(prefix.starts(with: Data("READY".utf8)))
            let fullDeadline = Date().addingTimeInterval(5)
            var queued: mach_port_msgcount_t = 0
            while queued != 4 {
                var status = mach_port_status_t(), count = mach_msg_type_number_t(MemoryLayout<mach_port_status_t>.size / MemoryLayout<integer_t>.size)
                XCTAssertEqual(withUnsafeMutablePointer(to: &status) {
                    $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                        mach_port_get_attributes(mach_task_self_, terminal.port, Int32(MACH_PORT_RECEIVE_STATUS), $0, &count)
                    }
                }, KERN_SUCCESS)
                queued = status.mps_msgcount
                guard Date() < fullDeadline else { throw MachCommandCallerError.timeout }; usleep(1000)
            }
            try authority.write { tx in
                let snapshot = try XCTUnwrap(tx.codePolicy()), old = try XCTUnwrap(snapshot.policy.entries.first)
                let entry = try AuthorityCodeEntry(role: old.role, teamID: old.teamID, identifier: old.identifier,
                    installedGeneration: old.installedGeneration, minimumGeneration: old.minimumGeneration,
                    codeDirectoryHash: Data(repeating: 2, count: 20), active: true)
                _ = try tx.installCodePolicy(AuthorityCodePolicy(entries: [entry]), expectedRevision: snapshot.revision)
            }
            let signal = try CommandStreamFrame(sequence: 0, body: .signal(UInt32(SIGTERM))).encode(binding: binding)
            XCTAssertTrue(try MachCommandWire.sendStream(signal, destination: XCTUnwrap(control).borrowed(), toAuthority: true))
            let commitDeadline = Date().addingTimeInterval(5)
            var committed = try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID) }
            while committed?.revision != 2 {
                committed = try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID) }
                guard Date() < commitDeadline else { throw MachCommandCallerError.timeout }; usleep(1000)
            }
            XCTAssertEqual(authority.activeCommandCount, 1, "A full queue must retain the committed result owner")
            XCTAssertEqual(committed?.phase, .failed)
            if peerClosesEndpoint { try terminal.closeReceiveRight() }
            else {
                var result: VerifiedCommandTerminalResult?
                while result == nil {
                    switch try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) {
                    case .stream(let reply, let extra):
                        defer { reply.caller.close(); extra?.close() }
                        let frame = try CommandStreamFrame.decode(reply.payload, binding: binding, direction: .toFrontend)
                        try incoming.accept(frame)
                        guard case .output(let bytes) = frame.body else { return XCTFail("Queued output must retain its order") }
                        XCTAssertTrue(bytes.allSatisfy { $0 == 0 })
                    case .terminal(let reply):
                        defer { reply.caller.close() }
                        result = try CommandTerminalResultPayload.decode(reply.payload, profile: profile, original: submission, admission: admission)
                    }
                }
                XCTAssertEqual(result?.outcome, .signalled(UInt32(SIGKILL)))
                XCTAssertEqual(result?.outputInterrupted, true)
                XCTAssertThrowsError(try receive.receiveTerminalReply(timeoutMilliseconds: 10))
            }
            try awaitDispatchCleanup(authority)
            XCTAssertEqual(try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID) }?.revision, 2)
            XCTAssertThrowsError(try beginDispatch(fixture, request: request, launcher: launcher))
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testTerminalBackpressureRetainsOneExactOutcomeAndOriginalReplyRight() throws {
        let fixture = try CommandRequestFixture(), admissionPort = try Endpoint(), terminal = try Endpoint()
        var limits = mach_port_limits_t(mpl_qlimit: 1)
        XCTAssertEqual(withUnsafeMutablePointer(to: &limits) {
            $0.withMemoryRebound(to: integer_t.self, capacity: 1) {
                mach_port_set_attributes(mach_task_self_, terminal.port, MACH_PORT_LIMITS_INFO, $0, 1)
            }
        }, KERN_SUCCESS)
        let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal, wire: 4, ioMode: .pty)
        let request = try admitCommand(command, fixture: fixture)
        let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        _ = try fixture.consume(request)
        let resources = try fixture.requests.takeAuthorizedCommandExecution(requestID: request.requestID, now: fixture.now(130))
        defer { resources.close() }
        try terminal.send(Data([1]))
        for _ in 0..<3 {
            XCTAssertFalse(try resources.queueTerminalOutcome(.signalled(UInt32(SIGKILL)), outputInterrupted: true))
            XCTAssertEqual(try sendReferences(terminal.port), 2)
        }
        XCTAssertThrowsError(try resources.queueTerminalOutcome(.unknown, outputInterrupted: true)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try resources.queueTerminalOutcome(.signalled(UInt32(SIGKILL)), outputInterrupted: false)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try resources.sendTerminalOutcome(.unknown)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .retired)
        }
        let filler = try receiver(terminal).receive(timeoutMilliseconds: 1000)
        filler.caller.close(); XCTAssertEqual(filler.payload, Data([1]))
        XCTAssertTrue(try resources.queueTerminalOutcome(.signalled(UInt32(SIGKILL)), outputInterrupted: true))
        XCTAssertEqual(try sendReferences(terminal.port), 1)
        let result = try ownerTerminal(terminal, submission: submission, admission: admission)
        XCTAssertEqual(result.outcome, .signalled(UInt32(SIGKILL))); XCTAssertTrue(result.outputInterrupted)
        XCTAssertEqual(result.submission, submission.binding); XCTAssertEqual(result.request.requestID, request.requestID)
        XCTAssertThrowsError(try resources.queueTerminalOutcome(.signalled(UInt32(SIGKILL)), outputInterrupted: true)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .retired)
        }
        XCTAssertThrowsError(try receiver(terminal).receiveTerminalReply(timeoutMilliseconds: 10))
    }
}


extension MachCommandCallerReceiverTests {
    func testPipeControlClientUsesBackpressureWithoutPTYInputOrOutputAcknowledgments() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 5)
        let submission = try commandSubmission(), profile = handshake.profile, binding = streamBinding(profile, submission)
        let payloads = try ioPayloads(profile: profile, submission: submission, terminal: .exited(13))
        let expression = try selfExpression(), user = geteuid(), port = endpoint.port
        let drain = DispatchSemaphore(value: 0), completed = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        DispatchQueue.global().async {
            defer { completed.signal() }
            result.withLock { output in output = Result {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user,
                    auditSessionID: nil, maxPayloadBytes: 8192)
                let received = try receiver.receiveIOInput(timeoutMilliseconds: 5000)
                defer { received.closeIfUnclaimed() }
                let terminal = try XCTUnwrap(received.outputs).takeTerminalReply()
                let channel = try MachCommandStreamAuthority(binding: binding, original: received.caller, terminal: terminal)
                defer { channel.close(); terminal.close() }
                try received.sendAdmissionReply(payloads.0)
                try Self.waitQueued { try channel.send(.opened) }
                guard drain.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                var receivedControls: [CommandStreamFrame.Body] = []
                let deadline = Date().addingTimeInterval(5)
                while receivedControls.count < 5 {
                    if let body = try channel.receiveControl(expression: expression, userID: user, auditSessionID: nil) { receivedControls.append(body) }
                    guard Date() < deadline else { throw MachCommandCallerError.timeout }; usleep(1000)
                }
                XCTAssertEqual(receivedControls, Array(repeating: .signal(UInt32(SIGINT)), count: 4) + [.cancel])
                // Separate pipes need neither a PTY output EOF event nor an output acknowledgment.
                try terminal.sendTerminalNonblocking(payloads.1)
            } }
        }
        defer { drain.signal() }
        let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        let response = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
            handshake: handshake, expression: expression, userID: user, auditSessionID: nil, maximumPayloadBytes: 8192)
        guard case .admitted(let session) = response else { return XCTFail("The original session must remain attached") }
        defer { session.close() }
        guard case .opened? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("The private controls must open") }
        XCTAssertThrowsError(try session.forwardInput(Data([1]))) { XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible) }
        XCTAssertThrowsError(try session.finishInput())
        XCTAssertThrowsError(try session.resizeTerminal(rows: 24, columns: 80))
        XCTAssertThrowsError(try session.acknowledgeOutput())
        XCTAssertThrowsError(try session.pollTerminalResult())
        for _ in 0..<4 { XCTAssertTrue(try session.forwardSignal(UInt32(SIGINT))) }
        XCTAssertFalse(try session.cancelCommand())
        drain.signal(); try Self.waitQueued { try session.cancelCommand() }
        guard case .terminal(let terminal)? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("The original result must arrive") }
        XCTAssertEqual(terminal.outcome, .exited(13)); XCTAssertFalse(terminal.outputInterrupted)
        XCTAssertEqual(completed.wait(timeout: .now() + 5), .success)
        try result.withLock { try XCTUnwrap($0).get() }
    }
    func testPipeControlClientRejectsAProgramOutcomeBeforeItsOpenedEvent() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 5)
        let submission = try commandSubmission(), payloads = try ioPayloads(profile: handshake.profile, submission: submission)
        let release = DispatchSemaphore(value: 0)
        let (completed, result) = try serveIO(endpoint.port, admission: payloads.0, terminal: payloads.1, release: release)
        defer { release.signal() }
        let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        let response = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192)
        guard case .admitted(let session) = response else { return XCTFail("The request must be admitted") }
        defer { session.close() }; release.signal()
        XCTAssertThrowsError(try session.pollStreamEvent(timeoutMilliseconds: 1000)) { XCTAssertEqual($0 as? CommandStreamError, .closed) }
        XCTAssertEqual(completed.wait(timeout: .now() + 5), .success); try result.withLock { try XCTUnwrap($0).get() }
    }
    private func pipeOpened(_ terminal: Endpoint, profile: CommandHandshakeProfile, submission: CommandSubmission,
                            admission: VerifiedCommandAdmissionResult) throws -> MachCommandAuthorityPort {
        guard case .admitted(let request) = admission.outcome else { throw CommandStreamError.binding }
        guard case .stream(let opened, let carried) = try receiver(terminal, maximum: 8192).receiveExecutionEvent(timeoutMilliseconds: 2000) else {
            throw CommandStreamError.closed
        }
        defer { opened.caller.close(); carried?.close() }
        let binding = CommandStreamBinding(profile: profile, submission: submission.binding, submissionDigest: admission.submissionDigest, request: request)
        XCTAssertEqual(try CommandStreamFrame.decode(opened.payload, binding: binding, direction: .toFrontend).body, .opened)
        return try XCTUnwrap(carried).takeControlRight()
    }
    private func pipeSend(_ body: CommandStreamFrame.Body, control: MachCommandAuthorityPort, profile: CommandHandshakeProfile,
                          submission: CommandSubmission, admission: VerifiedCommandAdmissionResult, sequence: UInt64 = 0) throws {
        guard case .admitted(let request) = admission.outcome else { throw CommandStreamError.binding }
        let binding = CommandStreamBinding(profile: profile, submission: submission.binding, submissionDigest: admission.submissionDigest, request: request)
        let bytes = try CommandStreamFrame(sequence: sequence, body: body).encode(binding: binding)
        try Self.waitQueued { try MachCommandWire.sendStream(bytes, destination: control.borrowed(), toAuthority: true) }
    }
    private func waitForPipeMarker(_ marker: URL) throws {
        let deadline = Date().addingTimeInterval(5)
        while !FileManager.default.fileExists(atPath: marker.path) {
            guard Date() < deadline else { throw MachCommandCallerError.timeout }; usleep(1000)
        }
    }
    func testNativePipeControlsKeepBinaryStdinAndSeparateStdoutStderrWithoutFlagChanges() throws {
        let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
        let launcher = try dispatchLauncher(fixture), admissionPort = try Endpoint(), terminal = try Endpoint()
        let out = fixture.root.appendingPathComponent("stdout"), err = fixture.root.appendingPathComponent("stderr")
        let output = Darwin.open(out.path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0o600)
        let error = Darwin.open(err.path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0o600)
        var input: [Int32] = [-1, -1]; XCTAssertEqual(pipe(&input), 0)
        defer { _ = Darwin.close(input[0]); _ = Darwin.close(output); _ = Darwin.close(error) }
        let binary = Data([0x41, 0, 0xff, 10])
        XCTAssertEqual(binary.withUnsafeBytes { Darwin.write(input[1], $0.baseAddress, $0.count) }, binary.count)
        _ = Darwin.close(input[1])
        // An ordinary first file write changes a kernel flag on this runtime. Establish that baseline before capture.
        for fd in [output, error] {
            XCTAssertEqual(Darwin.write(fd, "fixture", 7), 7)
            XCTAssertEqual(ftruncate(fd, 0), 0); XCTAssertEqual(lseek(fd, 0, SEEK_SET), 0)
        }
        let flags = [input[0], output, error].map { fcntl($0, F_GETFL) }
        let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal,
            inputDescriptor: input[0], outputDescriptor: output, errorDescriptor: error, executablePath: "/bin/sh",
            arguments: [Data("sh".utf8), Data("-c".utf8), Data("test ! -t 0 && test ! -t 1 && test ! -t 2 || exit 40; /bin/cat; printf OUT; printf ERR >&2; exit 7".utf8)], wire: 5)
        var readable = pollfd(fd: input[0], events: Int16(POLLIN), revents: 0)
        XCTAssertEqual(poll(&readable, 1, 0), 1); XCTAssertNotEqual(readable.revents & Int16(POLLIN), 0)
        let request = try admitOwnedCommand(command, fixture: fixture), admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        _ = try ownerDecision(request, fixture: fixture, decline: false)
        try beginDispatch(fixture, request: request, launcher: launcher)
        let control = try pipeOpened(terminal, profile: profile, submission: submission, admission: admission); defer { control.close() }
        let result = try ownerTerminal(terminal, submission: submission, admission: admission)
        XCTAssertEqual(result.outcome, .exited(7)); XCTAssertFalse(result.outputInterrupted)
        try awaitDispatchCleanup(authority)
        XCTAssertEqual(try Data(contentsOf: out), binary + Data("OUT".utf8)); XCTAssertEqual(try Data(contentsOf: err), Data("ERR".utf8))
        XCTAssertEqual([input[0], output, error].map { fcntl($0, F_GETFL) }, flags)
    }
    func testNativePipeControlsSignalCancelAndRecheckTheCurrentFrontendRole() throws {
        for mode in ["signal", "cancel", "changedRole"] {
            let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
            let launcher = try dispatchLauncher(fixture), admissionPort = try Endpoint(), terminal = try Endpoint()
            let marker = fixture.root.appendingPathComponent("started")
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal,
                executablePath: "/bin/sh", arguments: [Data("sh".utf8), Data("-c".utf8),
                    Data("printf ready > \"$1\"; exec /bin/sleep 60".utf8), Data("sh".utf8), Data(marker.path.utf8)], wire: 5)
            let request = try admitOwnedCommand(command, fixture: fixture), admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            _ = try ownerDecision(request, fixture: fixture, decline: false); try beginDispatch(fixture, request: request, launcher: launcher)
            let control = try pipeOpened(terminal, profile: profile, submission: submission, admission: admission); defer { control.close() }
            try waitForPipeMarker(marker)
            if mode == "changedRole" {
                try authority.write { tx in
                    let snapshot = try XCTUnwrap(tx.codePolicy()), old = try XCTUnwrap(snapshot.policy.entries.first)
                    let entry = try AuthorityCodeEntry(role: old.role, teamID: old.teamID, identifier: old.identifier,
                        installedGeneration: old.installedGeneration, minimumGeneration: old.minimumGeneration,
                        codeDirectoryHash: Data(repeating: 2, count: 20), active: true)
                    _ = try tx.installCodePolicy(AuthorityCodePolicy(entries: [entry]), expectedRevision: snapshot.revision)
                }
            }
            try pipeSend(mode == "cancel" ? .cancel : .signal(UInt32(SIGTERM)), control: control, profile: profile, submission: submission, admission: admission)
            let result = try ownerTerminal(terminal, submission: submission, admission: admission)
            XCTAssertEqual(result.outcome, .signalled(UInt32(mode == "signal" ? SIGTERM : SIGKILL))); XCTAssertFalse(result.outputInterrupted)
            try awaitDispatchCleanup(authority)
        }
    }
    func testNativePipeControlsDisconnectHonorsSelectedContinueOrTerminateWithoutRepeatingWork() throws {
        for continuing in [false, true] {
            let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
            let launcher = try dispatchLauncher(fixture), admissionPort = try Endpoint(), terminal = try Endpoint()
            let started = fixture.root.appendingPathComponent("started"), finished = fixture.root.appendingPathComponent("finished")
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal,
                executablePath: "/bin/sh", arguments: [Data("sh".utf8), Data("-c".utf8),
                    Data("printf ready > \"$1\"; /bin/sleep 0.5; printf once >> \"$2\"; exit 7".utf8),
                    Data("sh".utf8), Data(started.path.utf8), Data(finished.path.utf8)], wire: 5,
                disconnect: continuing ? .continueRunning : .terminate)
            let request = try admitOwnedCommand(command, fixture: fixture), admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            _ = try ownerDecision(request, fixture: fixture, decline: false); try beginDispatch(fixture, request: request, launcher: launcher)
            let control = try pipeOpened(terminal, profile: profile, submission: submission, admission: admission)
            try waitForPipeMarker(started); control.close()
            XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome,
                           continuing ? .exited(7) : .signalled(UInt32(SIGKILL)))
            try awaitDispatchCleanup(authority)
            if continuing { XCTAssertEqual(try Data(contentsOf: finished), Data("once".utf8)) }
            else { XCTAssertFalse(FileManager.default.fileExists(atPath: finished.path)) }
            XCTAssertThrowsError(try beginDispatch(fixture, request: request, launcher: launcher))
        }
    }
    func testNativePipeControlsEarlySignalWaitsForTheOneCommittedRelease() throws {
        try verifyEarlyPipeControl(cancel: false)
    }
    func testNativePipeControlsCancellationBeforeReleaseExecutesNoTarget() throws {
        try verifyEarlyPipeControl(cancel: true)
    }
    private func verifyEarlyPipeControl(cancel: Bool) throws {
        let fixture = try CommandRequestFixture(), admissionPort = try Endpoint(), terminal = try Endpoint()
        let launcher = try dispatchLauncher(fixture), marker = fixture.root.appendingPathComponent("effect")
        let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal,
            executablePath: "/bin/sh", arguments: [Data("sh".utf8), Data("-c".utf8),
                Data("/bin/sleep 10; printf effect > \"$1\"".utf8), Data("sh".utf8), Data(marker.path.utf8)], wire: 5)
        let request = try admitCommand(command, fixture: fixture), admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        _ = try fixture.consume(request); let now = fixture.now(130)
        let approval = try fixture.requests.authorizedCommandApproval(requestID: request.requestID, now: now)
        let resources = try fixture.requests.takeAuthorizedCommandExecution(requestID: request.requestID, now: now)
        let owner = CommandExecution(resources: resources, approval: approval, clock: { now }, receiptTime: { nil },
            callerExpression: try selfExpression(), callerUserID: geteuid(), callerSessionID: nil, validateLauncher: {}, validateElevation: { _ in })
        defer {
            owner.cancelBeforeRelease(); let deadline = Date().addingTimeInterval(8)
            while !owner.dispose() && Date() < deadline { _ = owner.poll(checkStreamPolicy: {}); usleep(1000) }
        }
        try owner.prepare(monitorPath: dispatchMonitor(fixture), childPath: launcher, preparationMilliseconds: 5000, fileCreationMask: 0o022)
        let preparation = Date().addingTimeInterval(5)
        while true {
            if case .prepared = owner.poll(checkStreamPolicy: {}) { break }
            guard Date() < preparation else { throw MachCommandCallerError.timeout }; usleep(1000)
        }
        let control = try pipeOpened(terminal, profile: profile, submission: submission, admission: admission); defer { control.close() }
        try pipeSend(cancel ? .cancel : .signal(UInt32(SIGKILL)), control: control, profile: profile, submission: submission, admission: admission)
        _ = owner.poll(checkStreamPolicy: {}); usleep(30000)
        if cancel {
            XCTAssertThrowsError(try owner.release()) { XCTAssertEqual($0 as? CommandExecutionError, .unavailable) }
        } else {
            guard case .prepared = owner.poll(checkStreamPolicy: {}) else { return XCTFail("The prepared helper must survive before release") }
            _ = try fixture.requests.recordOutcome(requestID: request.requestID, expectedRevision: 0, event: .beginDispatch, now: now, receiptTimeMs: nil)
            owner.dispatchRevision = 1; try owner.recheck(); try owner.release()
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
        var outcome: CommandTerminalOutcome?
        let deadline = Date().addingTimeInterval(5)
        while outcome == nil {
            if case .terminal(let value) = owner.poll(checkStreamPolicy: {}) { outcome = value }
            guard Date() < deadline else { throw MachCommandCallerError.timeout }; usleep(1000)
        }
        let observed = try XCTUnwrap(outcome)
        if cancel { XCTAssertEqual(observed, .failedBeforeStart) }
        else { XCTAssertTrue(observed == .failedBeforeStart || observed == .signalled(UInt32(SIGKILL))) }
        _ = try fixture.requests.recordOutcome(requestID: request.requestID, expectedRevision: cancel ? 0 : 1,
            event: cancel ? .proveNoDispatch : .verifyFailure, now: now, receiptTimeMs: nil)
        owner.deliverTerminal(observed)
        XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, observed)
        XCTAssertTrue(owner.dispose()); XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }
}


extension MachCommandCallerReceiverTests {
    func testNativePipeControlProfileRejectsPTYCaptureBeforeTargetExecution() throws {
        let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
        let launcher = try dispatchLauncher(fixture), admissionPort = try Endpoint(), terminal = try Endpoint()
        let marker = fixture.root.appendingPathComponent("must-not-run")
        let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal,
            executablePath: "/usr/bin/touch", arguments: [Data("touch".utf8), Data(marker.path.utf8)], wire: 5, ioMode: .pty)
        let request = try admitOwnedCommand(command, fixture: fixture), admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        _ = try ownerDecision(request, fixture: fixture, decline: false)
        XCTAssertThrowsError(try beginDispatch(fixture, request: request, launcher: launcher)) {
            XCTAssertEqual($0 as? CommandExecutionError, .unavailable)
        }
        try awaitDispatchCleanup(authority)
        XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, .failedBeforeStart)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }
    func testPipeControlProfileCannotClaimPTYOutputInterruption() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 5)
        let submission = try commandSubmission()
        defer { handshake.close() }
        XCTAssertThrowsError(try ioPayloads(profile: handshake.profile, submission: submission, outputInterrupted: true)) {
            XCTAssertEqual($0 as? CommandTerminalResultError, .incompatible)
        }
    }
}

extension MachCommandCallerReceiverTests {
    func testJobClientCoalescesUnsentStatesUnderBackpressureAndKeepsPTYEOFSeparate() throws {
        for wire: UInt64 in [6, 7] {
            let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: wire)
            let submission = try commandSubmission(ioMode: wire == 6 ? .pty : .pipes)
            let profile = handshake.profile, binding = streamBinding(profile, submission), payloads = try ioPayloads(profile: profile, submission: submission)
            let expression = try selfExpression(), user = geteuid(), port = endpoint.port
            let opened = DispatchSemaphore(value: 0), full = DispatchSemaphore(value: 0), drained = DispatchSemaphore(value: 0)
            let completed = DispatchSemaphore(value: 0), result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
            DispatchQueue.global().async {
                defer { completed.signal() }
                result.withLock { output in output = Result {
                    let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user, auditSessionID: nil, maxPayloadBytes: 8192)
                    let received = try receiver.receiveIOInput(timeoutMilliseconds: 5000)
                    defer { received.closeIfUnclaimed() }
                    let terminal = try XCTUnwrap(received.outputs).takeTerminalReply()
                    let channel = try MachCommandStreamAuthority(binding: binding, original: received.caller, terminal: terminal)
                    defer { channel.close(); terminal.close() }
                    try received.sendAdmissionReply(payloads.0); try Self.waitQueued { try channel.send(.opened) }
                    guard opened.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                    if wire == 6 {
                        try Self.waitQueued { try channel.send(.outputEnd) }
                        let deadline = Date().addingTimeInterval(5)
                        while !channel.outputDrained {
                            _ = try channel.receiveControl(expression: expression, userID: user, auditSessionID: nil)
                            guard Date() < deadline else { throw MachCommandCallerError.timeout }; usleep(1000)
                        }
                    }
                    for revision: UInt64 in 1...4 { XCTAssertTrue(try channel.send(.jobState(.init(revision: revision, state: .continued)))) }
                    var policyChecks = 0
                    try channel.observeJobState(.init(revision: 5, state: .stopped(signal: UInt32(SIGSTOP), rawStopCode: UInt32(CLD_STOPPED), tracing: .unknown)))
                    try channel.flushJobState { policyChecks += 1 }
                    try channel.observeJobState(.init(revision: 7, state: .continued)); try channel.flushJobState { policyChecks += 1 }
                    XCTAssertThrowsError(try channel.observeJobState(.init(revision: 6, state: .continued)))
                    full.signal()
                    guard drained.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                    try channel.flushJobState { policyChecks += 1 }
                    try channel.observeJobState(.init(revision: 7, state: .continued)); try channel.flushJobState { throw CommandExecutionError.policyChanged }
                    XCTAssertEqual(policyChecks, 3)
                    try channel.observeJobState(.init(revision: 8, state: .continued)); try channel.observeJobState(nil); try channel.flushJobState { throw CommandExecutionError.policyChanged }
                    try terminal.sendTerminalNonblocking(payloads.1)
                } }
            }
            defer { opened.signal(); drained.signal() }
            let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
            defer { _ = Darwin.close(input); _ = Darwin.close(output) }
            let response = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
                handshake: handshake, expression: expression, userID: user, auditSessionID: nil, maximumPayloadBytes: 8192)
            guard case .admitted(let session) = response else { return XCTFail("The job session must be admitted") }
            defer { session.close() }
            guard case .opened? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("The controls must open first") }
            opened.signal()
            if wire == 6 {
                guard case .outputEnded? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("PTY output must end") }
                try Self.waitQueued { try session.acknowledgeOutput() }
            } else { XCTAssertThrowsError(try session.acknowledgeOutput()) }
            guard full.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
            for revision: UInt64 in 1...4 {
                guard case .jobState(let job)? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("The bound job must arrive") }
                XCTAssertEqual(job.revision, revision); XCTAssertEqual(job.state, .continued)
                XCTAssertEqual(job.submission, submission.binding)
                guard case .admitted(let request) = session.admission.outcome else { return XCTFail("The original request must remain retained") }
                XCTAssertEqual(job.request, request)
            }
            drained.signal()
            guard case .jobState(let latest)? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("Only the latest unsent state must arrive") }
            XCTAssertEqual(latest.revision, 7); XCTAssertEqual(latest.state, .continued)
            guard case .terminal(let terminal)? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("No duplicate or discarded state can precede the outcome") }
            XCTAssertEqual(terminal.outcome, .exited(7))
            XCTAssertEqual(completed.wait(timeout: .now() + 5), .success); try result.withLock { try XCTUnwrap($0).get() }
        }
    }
    func testJobClientRejectsRepeatedNativeRevisionEvenWithIncreasingChannelSequences() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 7)
        let submission = try commandSubmission(), profile = handshake.profile, binding = streamBinding(profile, submission)
        let payloads = try ioPayloads(profile: profile, submission: submission), expression = try selfExpression(), user = geteuid(), port = endpoint.port
        let consumed = DispatchSemaphore(value: 0), completed = DispatchSemaphore(value: 0), result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        DispatchQueue.global().async {
            defer { completed.signal() }
            result.withLock { output in output = Result {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user, auditSessionID: nil, maxPayloadBytes: 8192)
                let received = try receiver.receiveIOInput(timeoutMilliseconds: 5000); defer { received.closeIfUnclaimed() }
                let terminal = try XCTUnwrap(received.outputs).takeTerminalReply()
                let channel = try MachCommandStreamAuthority(binding: binding, original: received.caller, terminal: terminal)
                defer { channel.close(); terminal.close() }
                try received.sendAdmissionReply(payloads.0)
                for body: CommandStreamFrame.Body in [.opened, .jobState(.init(revision: 3, state: .continued)), .jobState(.init(revision: 3, state: .continued))] {
                    try Self.waitQueued { try channel.send(body) }
                }
                guard consumed.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
            } }
        }
        defer { consumed.signal() }
        let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        let response = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
            handshake: handshake, expression: expression, userID: user, auditSessionID: nil, maximumPayloadBytes: 8192)
        guard case .admitted(let session) = response else { return XCTFail("The session must remain original") }
        defer { session.close() }
        guard case .opened? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("Controls must open") }
        guard case .jobState(let job)? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("The first native revision must arrive") }
        XCTAssertEqual(job.revision, 3)
        XCTAssertThrowsError(try session.pollStreamEvent(timeoutMilliseconds: 1000)) { XCTAssertEqual($0 as? CommandStreamError, .sequence) }
        consumed.signal()
        XCTAssertEqual(completed.wait(timeout: .now() + 5), .success); try result.withLock { try XCTUnwrap($0).get() }
    }
    private func waitForNativeJob(_ terminal: Endpoint, profile: CommandHandshakeProfile, submission: CommandSubmission,
                                  admission: VerifiedCommandAdmissionResult, stopped: Bool) throws -> CommandJobStatePayload {
        guard case .admitted(let request) = admission.outcome else { throw CommandStreamError.binding }
        let binding = CommandStreamBinding(profile: profile, submission: submission.binding, submissionDigest: admission.submissionDigest, request: request)
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            guard case .stream(let reply, let right) = try receiver(terminal, maximum: 8192).receiveExecutionEvent(timeoutMilliseconds: 1000) else {
                throw CommandStreamError.closed
            }
            defer { reply.caller.close(); right?.close() }
            switch try CommandStreamFrame.decode(reply.payload, binding: binding, direction: .toFrontend).body {
            case .jobState(let value):
                if case .stopped = value.state { if stopped { return value } }
                else if !stopped { return value }
            case .output: break
            default: throw CommandStreamError.closed
            }
        }
        throw MachCommandCallerError.timeout
    }
    func testNativeJobEventsReportOwnedTargetStopContinueAndActualCancellationForBothModes() throws {
        for wire: UInt64 in [6, 7] {
            let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
            let launcher = try dispatchLauncher(fixture), admissionPort = try Endpoint(), terminal = try Endpoint()
            let marker = fixture.root.appendingPathComponent("started")
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal,
                executablePath: "/bin/sh", arguments: [Data("sh".utf8), Data("-c".utf8),
                    Data("printf ready > \"$1\"; exec /bin/sleep 60".utf8), Data("sh".utf8), Data(marker.path.utf8)],
                wire: wire, ioMode: wire == 6 ? .pty : .pipes)
            let request = try admitOwnedCommand(command, fixture: fixture), admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            _ = try ownerDecision(request, fixture: fixture, decline: false); try beginDispatch(fixture, request: request, launcher: launcher)
            let control = try pipeOpened(terminal, profile: profile, submission: submission, admission: admission); defer { control.close() }
            try waitForPipeMarker(marker)
            try pipeSend(.signal(UInt32(SIGSTOP)), control: control, profile: profile, submission: submission, admission: admission)
            let stopped = try waitForNativeJob(terminal, profile: profile, submission: submission, admission: admission, stopped: true)
            guard case .stopped(let signal, let code, _) = stopped.state else { return XCTFail("The original target must stop") }
            XCTAssertEqual(signal, UInt32(SIGSTOP)); XCTAssertEqual(code, UInt32(CLD_STOPPED))
            try pipeSend(.signal(UInt32(SIGCONT)), control: control, profile: profile, submission: submission, admission: admission, sequence: 1)
            let continued = try waitForNativeJob(terminal, profile: profile, submission: submission, admission: admission, stopped: false)
            XCTAssertEqual(continued.state, .continued); XCTAssertGreaterThan(continued.revision, stopped.revision)
            try pipeSend(.cancel, control: control, profile: profile, submission: submission, admission: admission, sequence: 2)
            if wire == 6 {
                guard case .admitted(let retained) = admission.outcome else { throw CommandStreamError.binding }
                let binding = CommandStreamBinding(profile: profile, submission: submission.binding, submissionDigest: admission.submissionDigest, request: retained)
                var ended = false
                let deadline = Date().addingTimeInterval(5)
                while !ended {
                    guard case .stream(let reply, let right) = try receiver(terminal, maximum: 8192).receiveExecutionEvent(timeoutMilliseconds: 1000) else {
                        throw CommandStreamError.closed
                    }
                    defer { reply.caller.close(); right?.close() }
                    let body = try CommandStreamFrame.decode(reply.payload, binding: binding, direction: .toFrontend).body
                    if body == .outputEnd { ended = true }
                    else if case .output = body { }
                    else { throw CommandStreamError.closed }
                    guard Date() < deadline else { throw MachCommandCallerError.timeout }
                }
                try pipeSend(.outputDrained, control: control, profile: profile, submission: submission, admission: admission, sequence: 3)
            }
            XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, .signalled(UInt32(SIGKILL)))
            try awaitDispatchCleanup(authority)
            XCTAssertThrowsError(try beginDispatch(fixture, request: request, launcher: launcher))
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testNativePTYCancellationGapRetainsOriginalTargetUntilMonitorCancellation() throws {
        let fixture = try CommandRequestFixture(owned: true), authority = try XCTUnwrap(fixture.authority)
        let launcher = try dispatchLauncher(fixture), admissionPort = try Endpoint(), terminal = try Endpoint()
        let source = try XCTUnwrap(Bundle.module.url(forResource: "pty-controls", withExtension: "c", subdirectory: "Fixtures/command-process"))
        let program = fixture.root.appendingPathComponent("fixture-pty-cancel-gap")
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror", source.path, "-o", program.path]
        try compiler.run(); compiler.waitUntilExit(); XCTAssertEqual(compiler.terminationStatus, 0)
        let input = try RetainedCommandPTY(); defer { input.close() }
        try input.withBorrowedSlave { descriptor in
            var attributes = termios(); XCTAssertEqual(tcgetattr(descriptor, &attributes), 0)
            cfmakeraw(&attributes); XCTAssertEqual(tcsetattr(descriptor, TCSANOW, &attributes), 0)
        }
        let (_, command, submission, profile) = try input.withBorrowedSlave {
            try ownerIOCommand(admission: admissionPort, terminal: terminal, inputDescriptor: $0,
                executablePath: program.path, arguments: [Data("program".utf8), Data("cancel-gap".utf8)], wire: 4, ioMode: .pty)
        }
        let request = try admitOwnedCommand(command, fixture: fixture)
        let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        guard case .admitted(let admitted) = admission.outcome else { return XCTFail("The original request must be admitted") }
        let binding = CommandStreamBinding(profile: profile, submission: submission.binding,
            submissionDigest: admission.submissionDigest, request: admitted)
        _ = try ownerDecision(request, fixture: fixture, decline: false)
        try beginDispatch(fixture, request: request, launcher: launcher)
        let receive = try receiver(terminal, maximum: 8192)
        guard case .stream(let opened, let carried) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
            return XCTFail("The original controls must open")
        }
        let openedFrame = try CommandStreamFrame.decode(opened.payload, binding: binding, direction: .toFrontend)
        opened.caller.close()
        let control = try XCTUnwrap(carried).takeControlRight(); carried?.close(); defer { control.close() }
        var incoming = CommandStreamReceiveSequence(direction: .toFrontend)
        try incoming.accept(openedFrame); XCTAssertEqual(openedFrame.body, .opened)
        func receiveOutput(_ expected: Data) throws {
            var output = Data()
            while output.count < expected.count {
                guard case .stream(let reply, let right) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
                    throw CommandStreamError.closed
                }
                defer { reply.caller.close(); right?.close() }
                let frame = try CommandStreamFrame.decode(reply.payload, binding: binding, direction: .toFrontend)
                try incoming.accept(frame)
                guard case .output(let bytes) = frame.body else { throw CommandStreamError.closed }
                output.append(bytes)
                guard output.count <= expected.count, expected.prefix(output.count) == output else { throw CommandStreamError.malformed }
            }
        }
        try receiveOutput(Data("READY\n".utf8))
        try pipeSend(.resize(53, 143, 0, 0), control: control, profile: profile, submission: submission, admission: admission)
        try receiveOutput(Data("RESIZED\n".utf8))
        try pipeSend(.signal(UInt32(SIGKILL)), control: control, profile: profile, submission: submission, admission: admission, sequence: 1)
        try receiveOutput(Data("CHILD_KILLED\n".utf8))
        do {
            let early = try receive.receiveExecutionEvent(timeoutMilliseconds: 100)
            switch early {
            case .stream(let reply, let right): reply.caller.close(); right?.close()
            case .terminal(let reply): reply.caller.close()
            }
            return XCTFail("The original target must remain alive across the cancellation gap")
        } catch MachCommandCallerError.timeout { }
        try pipeSend(.cancel, control: control, profile: profile, submission: submission, admission: admission, sequence: 2)
        guard case .stream(let reply, let right) = try receive.receiveExecutionEvent(timeoutMilliseconds: 2000) else {
            return XCTFail("Output must end after monitor cancellation")
        }
        defer { reply.caller.close(); right?.close() }
        let end = try CommandStreamFrame.decode(reply.payload, binding: binding, direction: .toFrontend)
        try incoming.accept(end); XCTAssertEqual(end.body, .outputEnd)
        try pipeSend(.outputDrained, control: control, profile: profile, submission: submission, admission: admission, sequence: 3)
        XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, .signalled(UInt32(SIGKILL)))
        try awaitDispatchCleanup(authority)
        XCTAssertThrowsError(try beginDispatch(fixture, request: request, launcher: launcher))
    }
}


extension MachCommandCallerReceiverTests {
    private func ownerMappedCommand(admission: Endpoint, terminal: Endpoint, input: Int32, output: Int32, error: Int32,
                                    path: String = "/usr/bin/true", arguments: [Data]? = nil, wire: UInt64 = 8,
                                    ioMode: CommandIOMode = .pty, schema: UInt64 = 3) throws ->
        (RetainedCommandCapture, CommandSubmission, CommandHandshakeProfile) {
        let endpoint = try Endpoint()
        let submission = try commandSubmission(executablePath: path, arguments: arguments, ioMode: ioMode)
        let profile = CommandHandshakeProfile(wireVersion: wire, submissionSchemaVersion: 1, inputCarrierVersion: 5,
            callerBinding: submission.binding.callerBinding, macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16))
        try MachCommandIOWire.sendMapped(submission.canonicalBytes, inputDescriptor: input, outputDescriptor: output,
            errorDescriptor: error, controlTerminalDescriptor: nil, destination: endpoint.port, admissionReply: admission.port,
            terminalReply: terminal.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        let received = try receiver(endpoint, maximum: 8192).receiveMappedIOInput(timeoutMilliseconds: 1000)
        return (try assemble(received, schema: schema, admissionProfile: profile), submission, profile)
    }

    func testMappedProfileRejectsWrongCaptureSchemaAndIOModeBeforeAdmission() throws {
        let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        for (wire, mode, schema): (UInt64, CommandIOMode, UInt64) in [(8, .pty, 1), (8, .pty, 2), (8, .pipes, 3), (9, .pty, 3)] {
            let admission = try Endpoint(), terminal = try Endpoint()
            XCTAssertThrowsError(try ownerMappedCommand(admission: admission, terminal: terminal, input: input,
                output: output, error: output, wire: wire, ioMode: mode, schema: schema)) {
                XCTAssertEqual($0 as? RetainedCommandCaptureError, .invalidContext)
            }
            XCTAssertGreaterThanOrEqual(fcntl(input, F_GETFD), 0)
            XCTAssertGreaterThanOrEqual(fcntl(output, F_GETFD), 0)
        }
    }

    func testMappedNativeDispatchUsesEveryAuthenticatedCallerRoutingMask() throws {
        for mask in 0...7 {
            let fixture = try CommandRequestFixture(owned: true, commandSchema: 3)
            let authority = try XCTUnwrap(fixture.authority), launcher = try dispatchLauncher(fixture)
            let report = fixture.root.appendingPathComponent("mapped-report")
            let submission = try commandSubmission(executablePath: launcher,
                arguments: [Data("mapped-program".utf8), Data("mapped-probe".utf8), Data(String(mask).utf8), Data(report.path.utf8)], ioMode: .pty)
            let endpoint = try Endpoint()
            let peer = try Peer(endpoint: endpoint, submission: submission.canonicalBytes, mappedTerminalMask: mask)
            let received = try receiver(endpoint, expression: peer.expression, maximum: 8192).receiveMappedIOInput(timeoutMilliseconds: 5000)
            let profile = CommandHandshakeProfile(wireVersion: 8, submissionSchemaVersion: 1, inputCarrierVersion: 5,
                callerBinding: submission.binding.callerBinding, macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16))
            let command = try assemble(received, schema: 3, admissionProfile: profile, callerExpression: peer.expression)
            XCTAssertEqual(command.capture.stdioLayout?.ptyMask, UInt32(mask))
            let request = try admitOwnedCommand(command, fixture: fixture, callerExpression: peer.expression)
            _ = try ownerDecision(request, fixture: fixture, decline: false)
            try beginDispatch(fixture, request: request, launcher: launcher, callerExpression: peer.expression)
            let deadline = Date().addingTimeInterval(8)
            while try authority.withRequests({ try $0.historicalOutcome(requestID: request.requestID) })?.revision != 2 {
                guard Date() < deadline else { throw MachCommandCallerError.timeout }; usleep(1000)
            }
            let outcome = try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID) }
            XCTAssertEqual(outcome?.phase, .failed, "Exit 7, mask \(mask)")
            XCTAssertEqual(String(decoding: try Data(contentsOf: report), as: UTF8.self), "7", "mask \(mask)")
            // This fixture closes its owned channels after the target result. It never sends a synthetic drain acknowledgment.
            try peer.stop()
            try awaitDispatchCleanup(authority)
            XCTAssertThrowsError(try beginDispatch(fixture, request: request, launcher: launcher, callerExpression: peer.expression))
        }
    }

    func testMappedNativeDispatchPreservesDirectBinaryInputAndSeparateOutputsWithoutCallerTTY() throws {
        for wire: UInt64 in [8, 9] {
            let fixture = try CommandRequestFixture(checkpointed: true, owned: true, commandSchema: 3)
            let authority = try XCTUnwrap(fixture.authority), launcher = try dispatchLauncher(fixture)
            let admissionPort = try Endpoint(), terminal = try Endpoint()
            let source = fixture.root.appendingPathComponent("input"), stdout = fixture.root.appendingPathComponent("stdout"), stderr = fixture.root.appendingPathComponent("stderr")
            let binary = Data([0, 255, 10, 13, 128, 65])
            try binary.write(to: source)
            let input = Darwin.open(source.path, O_RDONLY | O_CLOEXEC)
            let output = Darwin.open(stdout.path, O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC, 0o600)
            let error = Darwin.open(stderr.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            defer { for descriptor in [input, output, error] { _ = Darwin.close(descriptor) } }
            let originalFlags = [input, output, error].map { fcntl($0, F_GETFL) }
            let (command, submission, profile) = try ownerMappedCommand(admission: admissionPort, terminal: terminal,
                input: input, output: output, error: error, path: "/bin/sh", arguments: [Data("sh".utf8), Data("-c".utf8),
                    Data("/bin/cat; printf ERR >&2; exit 7".utf8)], wire: wire, ioMode: wire == 8 ? .pty : .pipes)
            XCTAssertNil(command.capture.stdioLayout?.terminal)
            XCTAssertEqual(command.capture.stdioLayout?.ptyMask, 0)
            XCTAssertEqual(command.capture.stdioLayout?.output.flags, [.append])
            let request = try admitOwnedCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            guard case .admitted(let admitted) = admission.outcome else { return XCTFail("The exact schema-3 request must be admitted") }
            let binding = CommandStreamBinding(profile: profile, submission: submission.binding, submissionDigest: admission.submissionDigest, request: admitted)
            _ = try ownerDecision(request, fixture: fixture, decline: false)
            XCTAssertEqual(lseek(input, 0, SEEK_CUR), 0)
            try beginDispatch(fixture, request: request, launcher: launcher)
            let receive = try receiver(terminal, maximum: 8192)
            var control: MachCommandAuthorityPort?, outputEnded = false, result: VerifiedCommandTerminalResult?
            defer { control?.close() }
            while result == nil {
                switch try receive.receiveExecutionEvent(timeoutMilliseconds: 5000) {
                case .stream(let reply, let right):
                    defer { reply.caller.close(); right?.close() }
                    let frame = try CommandStreamFrame.decode(reply.payload, binding: binding, direction: .toFrontend)
                    switch frame.body {
                    case .opened: control = try XCTUnwrap(right).takeControlRight()
                    case .outputEnd:
                        outputEnded = true
                        let ack = try CommandStreamFrame(sequence: 0, body: .outputDrained).encode(binding: binding)
                        try Self.waitQueued { try MachCommandWire.sendStream(ack, destination: XCTUnwrap(control).borrowed(), toAuthority: true) }
                    case .output: XCTFail("Direct outputs must not be copied into the terminal stream")
                    case .inputCredit, .jobState: break
                    default: XCTFail("Unexpected mapped execution event")
                    }
                case .terminal(let reply):
                    defer { reply.caller.close() }
                    result = try CommandTerminalResultPayload.decode(reply.payload, profile: profile, original: submission, admission: admission)
                }
            }
            XCTAssertEqual(result?.outcome, .exited(7))
            XCTAssertEqual(outputEnded, wire == 8)
            try awaitDispatchCleanup(authority)
            XCTAssertEqual(try Data(contentsOf: stdout), binary)
            XCTAssertEqual(try Data(contentsOf: stderr), Data("ERR".utf8))
            // Darwin may add its write-history bit. Portable flags and access modes must stay unchanged.
            for (index, descriptor) in [input, output, error].enumerated() {
                XCTAssertEqual(fcntl(descriptor, F_GETFL) & (O_ACCMODE | O_APPEND | O_NONBLOCK | O_ASYNC | O_SYNC),
                    originalFlags[index] & (O_ACCMODE | O_APPEND | O_NONBLOCK | O_ASYNC | O_SYNC))
            }
            XCTAssertThrowsError(try beginDispatch(fixture, request: request, launcher: launcher))
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testMappedClientRequiresItsExplicitCarrierPathAndMatchingModeWithoutFallback() throws {
        let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        for (wire, mapped, mode): (UInt64, Bool, CommandIOMode) in [(8, false, .pty), (9, false, .pipes),
            (6, true, .pty), (7, true, .pipes), (8, true, .pipes), (9, true, .pty)] {
            let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: wire >= 8 ? 5 : 4, wire: wire)
            let submission = try commandSubmission(ioMode: mode)
            do {
                _ = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
                    handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
                    maximumPayloadBytes: 8192, mapped: mapped)
                XCTFail("An incompatible carrier or mode must fail before sending")
            } catch { XCTAssertEqual(error as? MachCommandHandshakeError, .incompatible) }
            XCTAssertThrowsError(try receiver(endpoint).receiveExecutionEvent(timeoutMilliseconds: 10)) {
                XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
            }
        }
    }
    func testMappedClientSubmitsTheExplicitCarrierAndKeepsOriginalDescriptorsOnRejection() throws {
        for wire: UInt64 in [8, 9] {
            let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 5, wire: wire)
            let submission = try commandSubmission(ioMode: wire == 8 ? .pty : .pipes)
            let payloads = try ioPayloads(profile: handshake.profile, submission: submission, outcome: .notAdmitted(.policyRejected, .never))
            let release = DispatchSemaphore(value: 0)
            release.signal()
            let server = try serveIO(endpoint.port, admission: payloads.0, terminal: nil, release: release, mapped: true)
            let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
            defer { _ = Darwin.close(input); _ = Darwin.close(output) }
            let inputFlags = fcntl(input, F_GETFL), outputFlags = fcntl(output, F_GETFL)
            let result = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
                handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192, mapped: true)
            guard case .result(let admission) = result else { return XCTFail("The mapped rejection must have no execution session") }
            XCTAssertEqual(admission.outcome, .notAdmitted(.policyRejected, .never))
            XCTAssertEqual(admission.submission, submission.binding)
            XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success)
            try server.1.withLock { try XCTUnwrap($0).get() }
            XCTAssertEqual(fcntl(input, F_GETFL), inputFlags)
            XCTAssertEqual(fcntl(output, F_GETFL), outputFlags)
        }
    }
}


extension MachCommandCallerReceiverTests {
    func testMappedFinalStreamFlagChangeAfterDispatchCommitPreventsTheApprovedEffect() throws {
        for wire: UInt64 in [8, 9] {
            let fixture = try CommandRequestFixture(checkpointed: true, owned: true, commandSchema: 3)
            let authority = try XCTUnwrap(fixture.authority), launcher = try dispatchLauncher(fixture)
            let marker = fixture.root.appendingPathComponent("must-not-execute")
            let admissionPort = try Endpoint(), terminal = try Endpoint()
            let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
            defer { _ = Darwin.close(input); _ = Darwin.close(output) }
            let originalFlags = fcntl(output, F_GETFL)
            let (command, submission, profile) = try ownerMappedCommand(admission: admissionPort, terminal: terminal,
                input: input, output: output, error: output, path: "/usr/bin/touch", arguments: [Data("touch".utf8), Data(marker.path.utf8)],
                wire: wire, ioMode: wire == 8 ? .pty : .pipes)
            let request = try admitOwnedCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            _ = try ownerDecision(request, fixture: fixture, decline: false)
            let checks = OSAllocatedUnfairLock(initialState: 0)
            let finalCheck = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0)
            defer { resume.signal() }
            try beginDispatch(fixture, request: request, launcher: launcher, elevation: { _ in
                let check = checks.withLock { count in count += 1; return count }
                if check == 3 {
                    finalCheck.signal()
                    guard resume.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                    XCTAssertEqual(fcntl(output, F_SETFL, originalFlags | O_APPEND), 0)
                }
            })
            XCTAssertEqual(finalCheck.wait(timeout: .now() + 5), .success)
            let receive = try receiver(terminal, maximum: 8192)
            guard case .stream(let opened, let carried) = try receive.receiveExecutionEvent(timeoutMilliseconds: 1000) else {
                return XCTFail("The private control grant must precede the final release check")
            }
            opened.caller.close()
            let control = try XCTUnwrap(carried).takeControlRight(); carried?.close(); defer { control.close() }
            resume.signal()
            try awaitDispatchCleanup(authority)
            XCTAssertEqual(checks.withLock { $0 }, 3)
            var terminalResult: VerifiedCommandTerminalResult?
            while terminalResult == nil {
                switch try receive.receiveExecutionEvent(timeoutMilliseconds: 1000) {
                case .stream(let reply, let right): reply.caller.close(); right?.close()
                case .terminal(let reply):
                    defer { reply.caller.close() }
                    terminalResult = try CommandTerminalResultPayload.decode(reply.payload, profile: profile, original: submission, admission: admission)
                }
            }
            XCTAssertEqual(terminalResult?.outcome, .failedBeforeStart)
            XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
            let outcome = try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID) }
            XCTAssertEqual(outcome?.revision, 2)
            XCTAssertEqual(outcome?.phase, .failed)
            XCTAssertEqual(fcntl(output, F_GETFL) & O_APPEND, O_APPEND)
            XCTAssertGreaterThanOrEqual(fcntl(input, F_GETFD), 0)
            XCTAssertThrowsError(try beginDispatch(fixture, request: request, launcher: launcher))
        }
    }
}

extension MachCommandCallerReceiverTests {
    func testFrontendRelayUsesAuthenticatedSessionAndDrainsPartialOutputBeforeResult() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 6)
        let submission = try commandSubmission(), profile = handshake.profile, binding = streamBinding(profile, submission)
        let payloads = try ioPayloads(profile: profile, submission: submission)
        let expression = try selfExpression(), user = geteuid(), port = endpoint.port
        let allowOpen = DispatchSemaphore(value: 0), completed = DispatchSemaphore(value: 0)
        let inputWhileBlocked = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        let binaryInput = Data([0, 255, 10, 13])
        let binaryOutput = Data((0..<4096).map { UInt8($0 % 251) }) + Data([255, 0, 13])
        DispatchQueue.global().async {
            defer { completed.signal() }
            result.withLock { outcome in outcome = Result {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user,
                    auditSessionID: nil, maxPayloadBytes: 8192)
                let received = try receiver.receiveIOInput(timeoutMilliseconds: 5000)
                defer { received.closeIfUnclaimed() }
                let terminal = try XCTUnwrap(received.outputs).takeTerminalReply()
                let stream = try MachCommandStreamAuthority(binding: binding, original: received.caller, terminal: terminal)
                defer { stream.close(); terminal.close() }
                try received.sendAdmissionReply(payloads.0)
                guard allowOpen.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                try Self.waitQueued { try stream.send(.opened) }
                var controls: [CommandStreamFrame.Body] = []
                let inputDeadline = Date().addingTimeInterval(5)
                while controls.count < 1 {
                    if let control = try stream.receiveControl(expression: expression, userID: user, auditSessionID: nil) {
                        controls.append(control)
                    }
                    guard Date() < inputDeadline else { throw MachCommandCallerError.timeout }
                    usleep(1000)
                }
                XCTAssertEqual(controls, [.resize(53, 143, 0, 0)])
                try Self.waitQueued { try stream.send(.output(Data(binaryOutput.prefix(4096)))) }
                while controls.count < 3 {
                    if let control = try stream.receiveControl(expression: expression, userID: user, auditSessionID: nil) {
                        controls.append(control)
                    }
                    guard Date() < inputDeadline else { throw MachCommandCallerError.timeout }
                    usleep(1000)
                }
                XCTAssertEqual(controls, [.resize(53, 143, 0, 0), .input(binaryInput), .inputEnd])
                inputWhileBlocked.signal()
                try Self.waitQueued { try stream.send(.output(Data(binaryOutput.dropFirst(4096)))) }
                try Self.waitQueued { try stream.send(.outputEnd) }
                let outputDeadline = Date().addingTimeInterval(5)
                while !stream.outputDrained {
                    if let control = try stream.receiveControl(expression: expression, userID: user, auditSessionID: nil) {
                        XCTAssertEqual(control, .outputDrained)
                    }
                    guard Date() < outputDeadline else { throw MachCommandCallerError.timeout }
                    usleep(1000)
                }
                try Self.waitQueued { try stream.send(.jobState(.init(revision: 1,
                    state: .stopped(signal: UInt32(SIGSTOP), rawStopCode: UInt32(CLD_STOPPED), tracing: .unknown)))) }
                try terminal.sendTerminalNonblocking(payloads.1)
            } }
        }
        defer { allowOpen.signal() }
        let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        let io = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
            handshake: handshake, expression: expression, userID: user, auditSessionID: nil, maximumPayloadBytes: 8192)
        guard case .admitted(let session) = io else { return XCTFail("The original authenticated channel must remain owned") }
        defer { session.close() }
        let terminal = FrontendRelayTestTerminal()
        terminal.writeBlocked = true; terminal.writeCounts = [0, 3, 0, 71]
        let relay = try CommandFrontendRelay(channel: session, terminal: terminal)
        defer { try? relay.close() }
        guard case .waiting = try relay.advance(timeoutMilliseconds: 1000) else { return XCTFail("Admission must not open the stream") }
        XCTAssertEqual(terminal.activateCalls, 0); XCTAssertEqual(terminal.readCalls, 0)
        allowOpen.signal()
        var final: VerifiedCommandTerminalResult?, sawJob = false, suppliedInput = false, receivedBlockedInput = false
        let deadline = Date().addingTimeInterval(10)
        while final == nil {
            switch try relay.advance(timeoutMilliseconds: 1000) {
            case .terminal(let value): final = value
            case .jobState(let job):
                sawJob = true; XCTAssertEqual(job.revision, 1)
                XCTAssertEqual(job.submission, submission.binding)
                XCTAssertTrue(terminal.needsRestore)
            case .currentJob: XCTFail("A historical profile must not report a current job query")
            case .suspended, .foregroundRequired, .interrupted: XCTFail("Historical job metadata must not suspend this foreground relay")
            case .waiting, .progress: break
            }
            if !suppliedInput, terminal.writeCalls > 0 {
                XCTAssertTrue(terminal.written.isEmpty)
                terminal.reads = [.bytes(binaryInput), .end]; suppliedInput = true
            }
            if !receivedBlockedInput, inputWhileBlocked.wait(timeout: .now()) == .success {
                XCTAssertTrue(terminal.written.isEmpty)
                terminal.writeBlocked = false; receivedBlockedInput = true
            }
            guard Date() < deadline else { throw MachCommandCallerError.timeout }
            usleep(1000)
        }
        XCTAssertEqual(final?.outcome, .exited(7)); XCTAssertEqual(terminal.written, binaryOutput)
        XCTAssertTrue(suppliedInput); XCTAssertTrue(receivedBlockedInput); XCTAssertTrue(terminal.reads.isEmpty)
        XCTAssertGreaterThanOrEqual(terminal.readCalls, 2); XCTAssertTrue(sawJob)
        XCTAssertFalse(relay.needsTerminalRestoration); XCTAssertGreaterThan(terminal.closeCalls, 0)
        XCTAssertEqual(completed.wait(timeout: .now() + 5), .success)
        try result.withLock { try XCTUnwrap($0).get() }
    }
}

// The receiver stays alive until the signal worker joins. This wrapper never transfers thread ownership.
private struct FrontendSignalTestThread: @unchecked Sendable {
    let thread: pthread_t
    func signalResize() { _ = pthread_kill(thread, SIGWINCH) }
}

extension MachCommandCallerReceiverTests {
    func testFrontendRelayKeepsAuthenticatedChannelAfterActualLocalSignalInterruptsReceive() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 6)
        let submission = try commandSubmission(), profile = handshake.profile, binding = streamBinding(profile, submission)
        let payloads = try ioPayloads(profile: profile, submission: submission)
        let expression = try selfExpression(), user = geteuid(), port = endpoint.port
        let allowOpen = DispatchSemaphore(value: 0), completed = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        DispatchQueue.global().async {
            defer { completed.signal() }
            result.withLock { outcome in outcome = Result {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user,
                    auditSessionID: nil, maxPayloadBytes: 8192)
                let received = try receiver.receiveIOInput(timeoutMilliseconds: 5000)
                defer { received.closeIfUnclaimed() }
                let terminal = try XCTUnwrap(received.outputs).takeTerminalReply()
                let stream = try MachCommandStreamAuthority(binding: binding, original: received.caller, terminal: terminal)
                defer { stream.close(); terminal.close() }
                try received.sendAdmissionReply(payloads.0)
                guard allowOpen.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                try Self.waitQueued { try stream.send(.opened) }
                try Self.waitQueued { try stream.send(.outputEnd) }
                let deadline = Date().addingTimeInterval(5)
                while !stream.outputDrained {
                    if let control = try stream.receiveControl(expression: expression, userID: user, auditSessionID: nil) {
                        switch control {
                        case .resize, .outputDrained: break
                        default: XCTFail("The interruption must not invent input or execution")
                        }
                    }
                    guard Date() < deadline else { throw MachCommandCallerError.timeout }
                    usleep(1000)
                }
                try terminal.sendTerminalNonblocking(payloads.1)
            } }
        }
        defer { allowOpen.signal() }
        let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        let response = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output,
            errorDescriptor: output, handshake: handshake, expression: expression, userID: user,
            auditSessionID: nil, maximumPayloadBytes: 8192)
        guard case .admitted(let session) = response else { return XCTFail("The original admission must remain retained") }
        defer { session.close() }
        let terminal = FrontendRelayTestTerminal(), relay = try CommandFrontendRelay(channel: session, terminal: terminal)
        defer { try? relay.close() }
        var action = sigaction(), previous = sigaction()
        action.__sigaction_u.__sa_handler = { _ in }
        sigemptyset(&action.sa_mask)
        XCTAssertEqual(sigaction(SIGWINCH, &action, &previous), 0)
        defer { _ = sigaction(SIGWINCH, &previous, nil) }
        var mask = sigset_t(), oldMask = sigset_t()
        sigemptyset(&mask); sigaddset(&mask, SIGWINCH)
        XCTAssertEqual(pthread_sigmask(SIG_UNBLOCK, &mask, &oldMask), 0)
        defer { _ = pthread_sigmask(SIG_SETMASK, &oldMask, nil) }
        let receiverThread = FrontendSignalTestThread(thread: pthread_self())
        let stopSignals = DispatchSemaphore(value: 0), signalsComplete = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            defer { signalsComplete.signal() }
            for _ in 0..<200 {
                if stopSignals.wait(timeout: .now() + .milliseconds(10)) == .success { break }
                receiverThread.signalResize()
            }
        }
        var signalsJoined = false
        defer { stopSignals.signal(); if !signalsJoined { _ = signalsComplete.wait(timeout: .now() + 5) } }
        guard case .interrupted = try relay.advance(timeoutMilliseconds: 1000) else {
            return XCTFail("An actual zero-consumption Mach interruption must yield without closing")
        }
        XCTAssertEqual(terminal.activateCalls, 0); XCTAssertEqual(terminal.readCalls, 0)
        stopSignals.signal()
        let joined = signalsComplete.wait(timeout: .now() + 5)
        signalsJoined = joined == .success; XCTAssertEqual(joined, .success)
        allowOpen.signal()
        var final: VerifiedCommandTerminalResult?
        let deadline = Date().addingTimeInterval(5)
        while final == nil {
            if case .terminal(let value) = try relay.advance(timeoutMilliseconds: 1000) { final = value }
            guard Date() < deadline else { throw MachCommandCallerError.timeout }
        }
        XCTAssertEqual(final?.outcome, .exited(7)); XCTAssertEqual(final?.submission, submission.binding)
        XCTAssertFalse(relay.needsTerminalRestoration)
        XCTAssertEqual(completed.wait(timeout: .now() + 5), .success)
        try result.withLock { try XCTUnwrap($0).get() }
    }
}

extension MachCommandCallerReceiverTests {
    func testFrontendNonblockingPreviewKeepsAuthenticationBudgetAndQueuedBinaryPackets() throws {
        let endpoint = try Endpoint(), receive = try receiver(endpoint, maximum: 8192)
        XCTAssertThrowsError(try receive.receiveExecutionEvent(timeoutMilliseconds: 5000, nonblocking: true)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
        let first = Data([0, 255, 13, 10]), second = Data([3, 0, 128])
        XCTAssertTrue(try MachCommandWire.sendStream(first, destination: endpoint.port))
        XCTAssertTrue(try MachCommandWire.sendStream(second, destination: endpoint.port))
        XCTAssertThrowsError(try receive.receiveExecutionEvent(timeoutMilliseconds: 0, nonblocking: true)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .configuration)
        }
        for expected in [first, second] {
            guard case .stream(let reply, let carried) = try receive.receiveExecutionEvent(timeoutMilliseconds: 5000, nonblocking: true) else {
                return XCTFail("The original authenticated packet must remain queued")
            }
            defer { reply.caller.close(); carried?.close() }
            XCTAssertNil(carried); XCTAssertEqual(reply.payload, expected)
        }
        XCTAssertThrowsError(try receive.receiveExecutionEvent(timeoutMilliseconds: 5000, nonblocking: true)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }
}

extension MachCommandCallerReceiverTests {
    private func runCurrentJobQuery(wire: UInt64, mode: String = "valid") throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 5, wire: wire)
        let submission = try commandSubmission(ioMode: wire == 10 ? .pty : .pipes)
        let profile = handshake.profile, binding = streamBinding(profile, submission), payloads = try ioPayloads(profile: profile, submission: submission)
        let expression = try selfExpression(), user = geteuid(), port = endpoint.port
        let receivedQuery = DispatchSemaphore(value: 0), allowReply = DispatchSemaphore(value: 0), completed = DispatchSemaphore(value: 0)
        let full = DispatchSemaphore(value: 0), drained = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        DispatchQueue.global().async {
            defer { completed.signal() }
            result.withLock { output in output = Result {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user,
                    auditSessionID: nil, maxPayloadBytes: 8192)
                let received = try receiver.receiveMappedIOInput(timeoutMilliseconds: 5000)
                defer { received.closeIfUnclaimed() }
                let terminal = try XCTUnwrap(received.outputs).takeTerminalReply()
                let channel = try MachCommandStreamAuthority(binding: binding, original: received.caller, terminal: terminal)
                defer { channel.close(); terminal.close() }
                try received.sendAdmissionReply(payloads.0); try Self.waitQueued { try channel.send(.opened) }
                var nonce: Data?
                let deadline = Date().addingTimeInterval(5)
                while nonce == nil {
                    if let body = try channel.receiveControl(expression: expression, userID: user, auditSessionID: nil) {
                        guard case .queryCurrentJob(let value) = body else { throw CommandStreamError.malformed }
                        nonce = value
                    }
                    guard Date() < deadline else { throw MachCommandCallerError.timeout }; usleep(1000)
                }
                receivedQuery.signal()
                guard allowReply.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                if mode == "continue" {
                    var continued = false
                    while !continued {
                        if let body = try channel.receiveControl(expression: expression, userID: user, auditSessionID: nil) {
                            XCTAssertEqual(body, .signal(UInt32(SIGCONT))); continued = true
                        }
                        guard Date() < deadline else { throw MachCommandCallerError.timeout }; usleep(1000)
                    }
                }
                if mode == "regression" {
                    try Self.waitQueued { try channel.send(.jobState(.init(revision: 4,
                        state: .stopped(signal: UInt32(SIGSTOP), rawStopCode: UInt32(CLD_STOPPED), tracing: .untraced)))) }
                }
                if mode == "wrongNonce" {
                    var wrong = try XCTUnwrap(nonce); wrong[0] ^= 1
                    try Self.waitQueued { try channel.send(.currentJob(.init(nonce: wrong,
                        state: .stopped(signal: UInt32(SIGSTOP), revision: 3)))) }
                } else if mode == "backpressure" {
                    for revision: UInt64 in 1...4 {
                        XCTAssertTrue(try channel.send(.jobState(.init(revision: revision,
                            state: .stopped(signal: UInt32(SIGSTOP), rawStopCode: UInt32(CLD_STOPPED), tracing: .untraced)))))
                    }
                    var reads = 0, checks = 0
                    try channel.flushCurrentJob(expression: expression, userID: user, auditSessionID: nil,
                        checkPolicy: { checks += 1 }, currentState: { reads += 1; return .stopped(signal: UInt32(SIGSTOP), revision: 5) })
                    full.signal()
                    guard drained.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                    try channel.flushCurrentJob(expression: expression, userID: user, auditSessionID: nil,
                        checkPolicy: { checks += 1 }, currentState: { reads += 1; return .running })
                    XCTAssertEqual(reads, 2); XCTAssertEqual(checks, 4)
                } else {
                    var checks = 0
                    try channel.flushCurrentJob(expression: expression, userID: user, auditSessionID: nil,
                        checkPolicy: { checks += 1 }, currentState: { .stopped(signal: UInt32(SIGSTOP), revision: 3) })
                    XCTAssertEqual(checks, 2)
                    try channel.flushCurrentJob(expression: expression, userID: user, auditSessionID: nil,
                        checkPolicy: { throw CommandExecutionError.policyChanged }, currentState: { throw CommandExecutionError.unavailable })
                    if mode == "replay" {
                        try Self.waitQueued { try channel.send(.currentJob(.init(nonce: XCTUnwrap(nonce),
                            state: .stopped(signal: UInt32(SIGSTOP), revision: 3)))) }
                    }
                    if mode == "expired" {
                        var second: Data?
                        while second == nil {
                            if let body = try channel.receiveControl(expression: expression, userID: user, auditSessionID: nil) {
                                guard case .queryCurrentJob(let value) = body else { throw CommandStreamError.malformed }
                                second = value
                            }
                            guard Date() < deadline else { throw MachCommandCallerError.timeout }; usleep(1000)
                        }
                        XCTAssertNotEqual(second, nonce)
                        try channel.flushCurrentJob(expression: expression, userID: user, auditSessionID: nil,
                            checkPolicy: {}, currentState: { .running })
                    }
                }
            } }
        }
        defer { allowReply.signal(); drained.signal() }
        let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        let response = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
            handshake: handshake, expression: expression, userID: user, auditSessionID: nil, maximumPayloadBytes: 8192, mapped: true)
        guard case .admitted(let session) = response else { return XCTFail("The current job session must be admitted") }
        defer { session.close() }
        guard case .opened? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("The original controls must open") }
        XCTAssertTrue(try session.requestCurrentJob(timeoutMilliseconds: mode == "expired" ? 10 : 1000))
        XCTAssertFalse(try session.requestCurrentJob())
        guard receivedQuery.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
        if mode == "continue" { try Self.waitQueued { try session.forwardSignal(UInt32(SIGCONT)) } }
        if mode == "local" { session.invalidateCurrentJobQuery() }
        if mode == "expired" { usleep(20000) }
        allowReply.signal()
        if mode == "backpressure" {
            guard full.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
            for _ in 0..<4 {
                guard case .jobState? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("The full queue must drain") }
            }
            drained.signal()
        }
        if mode == "regression" {
            guard case .jobState? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("The newer job revision must arrive") }
        }
        if mode == "wrongNonce" || mode == "regression" {
            XCTAssertThrowsError(try session.pollStreamEvent(timeoutMilliseconds: 1000)) {
                XCTAssertEqual($0 as? CommandStreamError, mode == "regression" ? .sequence : .binding)
            }
            XCTAssertThrowsError(try session.requestCurrentJob())
        } else {
            guard case .currentJob(let value)? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else { return XCTFail("The bound query must receive a response") }
            XCTAssertEqual(value.state, mode == "backpressure" ? .running :
                mode == "continue" || mode == "local" || mode == "expired" ? .unknown : .stopped(signal: UInt32(SIGSTOP), revision: 3))
            XCTAssertEqual(value.submission, submission.binding)
            XCTAssertEqual(value.request, binding.request)
            if mode == "expired" {
                XCTAssertTrue(try session.requestCurrentJob(timeoutMilliseconds: 1000))
                guard case .currentJob(let second)? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else {
                    return XCTFail("An expired query must retain the original channel")
                }
                XCTAssertEqual(second.state, .running); XCTAssertEqual(second.request, value.request)
            }
            if mode == "replay" {
                XCTAssertThrowsError(try session.pollStreamEvent(timeoutMilliseconds: 1000)) { XCTAssertEqual($0 as? CommandStreamError, .binding) }
            }
        }
        guard completed.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
        try XCTUnwrap(result.withLock { $0 }).get()
    }
    func testCurrentJobQueryUsesTheOriginalAuthenticatedMappedChannelForBothModes() throws {
        for wire: UInt64 in [10, 11] { try runCurrentJobQuery(wire: wire) }
    }
    func testCurrentJobQueryBecomesUnknownAfterQueuedOrLocalContinuation() throws {
        for wire: UInt64 in [10, 11] { for mode in ["continue", "local"] { try runCurrentJobQuery(wire: wire, mode: mode) } }
    }
    func testCurrentJobQueryRejectsWrongNonceReplayAndRegressedJobRevision() throws {
        for mode in ["wrongNonce", "replay", "regression"] { try runCurrentJobQuery(wire: 11, mode: mode) }
    }
    func testCurrentJobQueryRecomputesTheReplyAfterActualMachBackpressure() throws {
        for wire: UInt64 in [10, 11] { try runCurrentJobQuery(wire: wire, mode: "backpressure") }
    }
    func testCurrentJobQueryExpiryReturnsUnknownWithoutCancelingTheOriginalCommand() throws {
        for wire: UInt64 in [10, 11] { try runCurrentJobQuery(wire: wire, mode: "expired") }
    }
    private final class WorkerPort: Sendable { let value = Mutex<mach_port_t>(0) }
    private static func workerHost(port: WorkerPort, context: CommandSessionRegistry.Context,
                                   policyRead: @escaping @Sendable () throws -> Void = {},
                                   receiveWaitMilliseconds: UInt32 = 10,
                                   observeTimeout: (@Sendable (MachCommandReceiveTimeoutStage) -> Void)? = nil) throws -> CommandReceiveHost {
        var receiver: mach_port_t = 0
        guard mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &receiver) == KERN_SUCCESS else {
            throw MachCommandCallerError.configuration
        }
        let host = try CommandReceiveHost(takingReceiveRight: receiver, macID: Data(repeating: 1, count: 16),
            accountID: Data(repeating: 2, count: 16), userID: geteuid(), auditSessionID: nil, maximumSessions: 4,
            maximumPayloadBytes: 8192, receiveWaitMilliseconds: receiveWaitMilliseconds, replyTimeoutMilliseconds: 100,
            capabilities: .admissionResults, context: { _ in try policyRead(); return context }, observeTimeout: observeTimeout)
        guard mach_port_insert_right(mach_task_self_, receiver, receiver, UInt32(MACH_MSG_TYPE_MAKE_SEND)) == KERN_SUCCESS else {
            host.close(); throw MachCommandCallerError.configuration
        }
        port.value.withLock { $0 = receiver }
        return host
    }
    private func receiveWorker(_ fixture: CommandRequestFixture, port: WorkerPort,
                               makeHost: (@Sendable () throws -> CommandReceiveHost)? = nil,
                               policyRead: @escaping @Sendable () throws -> Void = {},
                               receiptTime: @escaping @Sendable () -> UInt64? = { nil },
                               onAdmission: @escaping @Sendable (Result<IssuedRequestPayload, any Error>) -> Void = { _ in },
                               report: @escaping @Sendable (AuthorityCommandReceiveWorker.Status) -> Void = { _ in }) throws -> AuthorityCommandReceiveWorker {
        let journal = try XCTUnwrap(fixture.authority), epoch = fixture.clock
        let context = CommandSessionRegistry.Context(expression: "always", roleRevision: UUID())
        return try AuthorityCommandReceiveWorker(ownedJournal: journal, submissionLimits: assemblyLimits,
            makeHost: makeHost ?? { try Self.workerHost(port: port, context: context, policyRead: policyRead) },
            resolve: { _ in .refuse(.policyRejected) }, draft: { _ in throw ApprovalCoordinatorError.invalidDraft },
            clock: { .init(epoch: epoch, milliseconds: 110) }, receiptTime: receiptTime, onAdmission: onAdmission, report: report)
    }
    private func receiveRightPresent(_ port: mach_port_t) -> Bool {
        var type: mach_port_type_t = 0
        return mach_port_type(mach_task_self_, port, &type) == KERN_SUCCESS && (type & (UInt32(1) << (MACH_PORT_RIGHT_RECEIVE + 16))) != 0
    }
    @MainActor private func waitForReceiveWorker(_ condition: @Sendable () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !condition(), ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(1)) }
        guard condition() else { throw MachCommandCallerError.timeout }
    }
    func testReceiveWorkerPublicConstructionRefusesNormalUserBeforeFactory() throws {
        guard getuid() != 0 || geteuid() != 0 else { throw XCTSkip("Normal-user gate") }
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), factories = Mutex(0)
        let epoch = fixture.clock
        XCTAssertThrowsError(try AuthorityCommandReceiveWorker(journal: XCTUnwrap(fixture.authority), submissionLimits: assemblyLimits,
            makeHost: { factories.withLock { $0 += 1 }; throw CommandReceiveHostError.invalidConfiguration },
            resolve: { _ in .refuse(.policyRejected) }, draft: { _ in throw ApprovalCoordinatorError.invalidDraft },
            clock: { .init(epoch: epoch, milliseconds: 110) })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(factories.withLock { $0 }, 0)
    }
    @MainActor func testReceiveWorkerSamplesReceiptTimeOnlyAfterActualCommandInput() async throws {
        guard geteuid() != 0 else { throw XCTSkip("Normal-user fixture") }
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), port = WorkerPort()
        let reads = Mutex(0), sampled = Mutex<[UInt64]>([]), current = Mutex<UInt64>(100), admitted = Mutex(false)
        let worker = try receiveWorker(fixture, port: port, policyRead: { reads.withLock { $0 += 1 } }, receiptTime: {
            let now = current.withLock { $0 }; sampled.withLock { $0.append(now) }; return now
        }, onAdmission: {
            guard case .failure(let error) = $0 else { return XCTFail("Normal-user fixture admitted a command") }
            XCTAssertEqual(error as? JournalLeaseError, .rootRequired)
            admitted.withLock { $0 = true }
        })
        try await worker.start()
        let destination = port.value.withLock { $0 }
        defer { worker.requestStop(); _ = mach_port_deallocate(mach_task_self_, destination) }
        var phase = "policy warm-up"
        do {
            try await waitForReceiveWorker { reads.withLock { $0 >= 3 } }
            XCTAssertTrue(sampled.withLock { $0.isEmpty })
            let helloReply = try Endpoint(), offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: .admissionResults)
            phase = "hello send"
            try MachCommandWire.send(offer.canonicalBytes, destination: destination, replyPort: helloReply.port,
                identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
            phase = "hello reply"
            let response = try receiver(helloReply, maximum: 4096).receiveHelloReply(timeoutMilliseconds: 1000)
            defer { response.caller.close() }
            let profile = try CommandHandshakeReply.decode(response.payload, offer: offer,
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16))
            XCTAssertTrue(sampled.withLock { $0.isEmpty })
            current.withLock { $0 = 777 }
            let inputReply = try Endpoint()
            let submission = try commandSubmission(binding: .init(id: Data(repeating: 0xb2, count: 16), nonce: Data(repeating: 0xb3, count: 32),
                callerBinding: profile.callerBinding))
            let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
            phase = "command submission"
            try MachCommandAdmissionWire.send(submission.canonicalBytes, inputDescriptor: fd, destination: destination,
                replyPort: inputReply.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
            phase = "admission callback"
            try await waitForReceiveWorker { admitted.withLock { $0 } }
            await worker.close()
            XCTAssertEqual(sampled.withLock { $0 }, [777]); XCTAssertFalse(worker.isRetired)
        } catch {
            let observation = "receipt fixture \(phase): status=\(worker.status), retired=\(worker.isRetired), "
                + "reads=\(reads.withLock { $0 }), samples=\(sampled.withLock { $0.count }), admitted=\(admitted.withLock { $0 })"
            XCTFail(observation)
            await worker.close()
            XCTAssertEqual(worker.status, .closed)
            XCTAssertFalse(receiveRightPresent(destination), "Timed-out receipt worker retained its receive right")
            throw error
        }
    }

    @MainActor func testReceiveWorkerOwnsNativeHelloAndClosesBeforeSharedJournal() async throws {
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), port = WorkerPort()
        let worker = try receiveWorker(fixture, port: port)
        try await worker.start()
        let destination = port.value.withLock { $0 }
        defer { _ = mach_port_deallocate(mach_task_self_, destination) }
        XCTAssertEqual(worker.status, .running); XCTAssertTrue(receiveRightPresent(destination))
        let reply = try Endpoint(), offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: .admissionResults)
        try MachCommandWire.send(offer.canonicalBytes, destination: destination, replyPort: reply.port,
            identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
        let response = try receiver(reply, maximum: 4096).receiveHelloReply(timeoutMilliseconds: 1000)
        defer { response.caller.close() }
        let profile = try CommandHandshakeReply.decode(response.payload, offer: offer,
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16))
        XCTAssertTrue(profile.supportsAdmissionResults)
        async let first: Void = worker.close()
        async let second: Void = worker.close()
        _ = await (first, second)
        XCTAssertEqual(worker.status, .closed); XCTAssertFalse(worker.isRetired)
        XCTAssertFalse(receiveRightPresent(destination))
        XCTAssertEqual(try XCTUnwrap(fixture.authority).read { _ in 17 }, 17)
    }
    @MainActor func testReceiveWorkerInitialPolicyFailureNeverReportsReadyAndReleasesRight() async throws {
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), port = WorkerPort()
        let states = Mutex<[AuthorityCommandReceiveWorker.Status]>([])
        let worker = try receiveWorker(fixture, port: port, policyRead: { throw CommandSessionRegistryError.invalidCodePolicy },
            report: { state in states.withLock { $0.append(state) } })
        do { try await worker.start(); XCTFail("Invalid policy started a receiver") }
        catch { XCTAssertEqual(error as? CommandSessionRegistryError, .invalidCodePolicy) }
        await worker.close()
        let destination = port.value.withLock { $0 }; defer { _ = mach_port_deallocate(mach_task_self_, destination) }
        XCTAssertFalse(states.withLock { $0.contains(.running) })
        XCTAssertFalse(receiveRightPresent(destination)); XCTAssertTrue(worker.isRetired)
        XCTAssertEqual(worker.status, .closed)
    }
    @MainActor func testReceiveWorkerCloseWaitsForLateFactoryAndNeverReadsItsPolicy() async throws {
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), port = WorkerPort()
        let entered = Mutex(false), finished = Mutex(false), reads = Mutex(0), gate = DispatchSemaphore(value: 0)
        let context = CommandSessionRegistry.Context(expression: "always", roleRevision: UUID())
        let worker = try receiveWorker(fixture, port: port, makeHost: {
            entered.withLock { $0 = true }; gate.wait()
            return try Self.workerHost(port: port, context: context, policyRead: { reads.withLock { $0 += 1 } })
        })
        let start = Task { try await worker.start() }
        defer { start.cancel(); gate.signal() }
        try await waitForReceiveWorker { entered.withLock { $0 } }
        let close = Task { await worker.close(); finished.withLock { $0 = true } }
        try await waitForReceiveWorker { worker.status == .stopping }
        XCTAssertFalse(finished.withLock { $0 })
        gate.signal()
        do { try await start.value; XCTFail("Late factory became ready") }
        catch { XCTAssertEqual(error as? CommandReceiveHostError, .stopped) }
        await close.value
        let destination = port.value.withLock { $0 }; defer { _ = mach_port_deallocate(mach_task_self_, destination) }
        XCTAssertEqual(reads.withLock { $0 }, 0); XCTAssertFalse(receiveRightPresent(destination))
        XCTAssertTrue(finished.withLock { $0 }); XCTAssertFalse(worker.isRetired)
    }
    @MainActor func testReceiveWorkerCancelledStartupCleansLateHostBeforeCloseReturns() async throws {
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), port = WorkerPort()
        let entered = Mutex(false), reads = Mutex(0), gate = DispatchSemaphore(value: 0)
        let context = CommandSessionRegistry.Context(expression: "always", roleRevision: UUID())
        let worker = try receiveWorker(fixture, port: port, makeHost: {
            entered.withLock { $0 = true }; gate.wait()
            return try Self.workerHost(port: port, context: context, policyRead: { reads.withLock { $0 += 1 } })
        })
        let start = Task { try await worker.start() }
        defer { start.cancel(); gate.signal() }
        try await waitForReceiveWorker { entered.withLock { $0 } }
        start.cancel()
        try await waitForReceiveWorker { worker.status == .stopping }
        gate.signal()
        do { try await start.value; XCTFail("Cancelled startup succeeded") } catch is CancellationError {} catch { throw error }
        await worker.close()
        let destination = port.value.withLock { $0 }; defer { _ = mach_port_deallocate(mach_task_self_, destination) }
        XCTAssertEqual(reads.withLock { $0 }, 0); XCTAssertFalse(receiveRightPresent(destination))
        XCTAssertFalse(worker.isRetired)
    }
    @MainActor func testReceiveWorkerCancellationAtReadinessStopsRetainedWorkerWithoutExplicitClose() async throws {
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), port = WorkerPort()
        let ready = Mutex(false), gate = DispatchSemaphore(value: 0)
        let worker = try receiveWorker(fixture, port: port, report: {
            if $0 == .running { ready.withLock { $0 = true }; gate.wait() }
        })
        let start = Task { try await worker.start() }
        defer { start.cancel(); gate.signal(); worker.requestStop() }
        try await waitForReceiveWorker { ready.withLock { $0 } }
        start.cancel(); gate.signal()
        do { try await start.value; XCTFail("Cancelled startup succeeded") }
        catch is CancellationError {} catch { throw error }
        try await waitForReceiveWorker { worker.status == .closed }
        let destination = port.value.withLock { $0 }; defer { _ = mach_port_deallocate(mach_task_self_, destination) }
        XCTAssertFalse(receiveRightPresent(destination)); XCTAssertFalse(worker.isRetired)
        XCTAssertEqual(try XCTUnwrap(fixture.authority).read { _ in 17 }, 17)
        await worker.close()
    }
    @MainActor func testReceiveWorkerIdlePolicyFailureRetiresAfterInitialReady() async throws {
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), port = WorkerPort(), failed = Mutex(false)
        let worker = try receiveWorker(fixture, port: port, policyRead: {
            if failed.withLock({ $0 }) { throw CommandSessionRegistryError.invalidCodePolicy }
        })
        try await worker.start(); failed.withLock { $0 = true }
        try await waitForReceiveWorker { worker.isRetired }
        await worker.close()
        let destination = port.value.withLock { $0 }; defer { _ = mach_port_deallocate(mach_task_self_, destination) }
        XCTAssertFalse(receiveRightPresent(destination)); XCTAssertTrue(worker.isRetired)
    }
    @MainActor func testReceiveWorkerDeinitStopsQueueWithoutRetainingItself() async throws {
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), port = WorkerPort(), closed = Mutex(false)
        var worker: AuthorityCommandReceiveWorker? = try receiveWorker(fixture, port: port, report: {
            if $0 == .closed { closed.withLock { $0 = true } }
        })
        weak let reference = worker
        try await XCTUnwrap(worker).start()
        let destination = port.value.withLock { $0 }; defer { _ = mach_port_deallocate(mach_task_self_, destination) }
        worker = nil
        XCTAssertNil(reference)
        try await waitForReceiveWorker { closed.withLock { $0 } }
        XCTAssertFalse(receiveRightPresent(destination))
    }
    @MainActor func testReceiveWorkerCloseBeforeStartDoesNotCallFactory() async throws {
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), port = WorkerPort(), factories = Mutex(0)
        let worker = try receiveWorker(fixture, port: port, makeHost: {
            factories.withLock { $0 += 1 }; throw CommandReceiveHostError.invalidConfiguration
        })
        await worker.close()
        do { try await worker.start(); XCTFail("Closed worker started") }
        catch { XCTAssertEqual(error as? CommandReceiveHostError, .stopped) }
        XCTAssertEqual(factories.withLock { $0 }, 0); XCTAssertEqual(worker.status, .closed)
    }

}

extension MachCommandCallerReceiverTests {
    private struct ElevationGrantState: Sendable { var targets: Set<UInt32> = [geteuid()]; var reads = 0; var failAtRead: Int? }
    private final class ElevationGrantBox: Sendable { let state = Mutex(ElevationGrantState()) }
    private enum ElevationReadFailure: Error { case unavailable }

    private func currentElevation(_ box: ElevationGrantBox, macID: Data = Data(repeating: 1, count: 16),
                                  callerUID: UInt32 = geteuid()) throws -> CurrentCommandElevationPolicy {
        let accountID = Data(repeating: 2, count: 16)
        return try .init(macID: macID, accountID: accountID, callerUID: callerUID, load: {
            try box.state.withLock {
                $0.reads += 1
                if $0.reads == $0.failAtRead { throw ElevationReadFailure.unavailable }
                return try CommandElevationPolicy(macID: macID, accountID: accountID, callerUID: callerUID,
                    allowedTargetUIDs: $0.targets, independentPolicyDisclosureAccepted: true)
            }
        })
    }
    private func admitWithElevation(_ attempt: RetainedCommandAdmissionAttempt, fixture: CommandRequestFixture,
                                    policy: CurrentCommandElevationPolicy,
                                    build: ((CommandCapture) throws -> ApprovalRequestDraft)? = nil) throws -> IssuedRequestPayload {
        try XCTUnwrap(fixture.authority).admitCommandAttempt(attempt, expression: selfExpression(), elevationPolicy: policy,
            captureSchemaVersion: 1, minimalEnvironment: assemblyEnvironment, streamBinding: Data(repeating: 0xe4, count: 16),
            captureLimits: assemblyLimits, maximumAncestryEntries: 1,
            draft: build ?? { self.admissionDraft($0, fixture: fixture) }, now: { fixture.now() }, receiptTimeMs: nil)
    }

    func testCurrentElevationAdmissionRejectsDeniedScopeBeforeFilesystemCapture() throws {
        for checkpointed in [false, true] {
            for mismatch in 0..<3 {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
                let box = ElevationGrantBox()
                if mismatch == 0 { box.state.withLock { $0.targets = [] } }
                let policy = try currentElevation(box, macID: Data(repeating: mismatch == 1 ? 3 : 1, count: 16),
                    callerUID: mismatch == 2 ? geteuid() + 1 : geteuid())
                let (attempt, submission, profile) = try admissionAttempt(reply: reply, executable: "/missing-before-policy")
                let before = try fixture.auditRecordCount
                XCTAssertThrowsError(try admitWithElevation(attempt, fixture: fixture, policy: policy)) {
                    XCTAssertEqual($0 as? CommandAdmissionControllerError, .refused(.policyRejected))
                }
                XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .notAdmitted(.policyRejected, .never))
                XCTAssertNil(try fixture.reservation(submission.binding.id)); XCTAssertEqual(try fixture.auditRecordCount, before)
                XCTAssertEqual(box.state.withLock { $0.reads }, mismatch == 0 ? 1 : 0)
                XCTAssertEqual(try sendReferences(reply.port), 1)
            }
        }
    }

    func testCurrentElevationAdmissionCapturesActualCredentialsAndRechecksBeforePublication() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
            let box = ElevationGrantBox(), policy = try currentElevation(box)
            let (attempt, submission, profile) = try admissionAttempt(reply: reply)
            let expected = try CommandTargetResolver.resolve(uid: geteuid())
            let request = try admitWithElevation(attempt, fixture: fixture, policy: policy, build: {
                XCTAssertEqual($0.target, expected); XCTAssertEqual($0.requester.realUID, geteuid())
                XCTAssertEqual($0.requester.effectiveUID, geteuid())
                return self.admissionDraft($0, fixture: fixture)
            })
            guard case .admitted(let identity) = try typedOutcome(reply, submission: submission, profile: profile) else {
                return XCTFail("Current grants must admit the authenticated capture")
            }
            XCTAssertEqual(identity.requestID, request.requestID); XCTAssertEqual(box.state.withLock { $0.reads }, 3)
            XCTAssertNotNil(try fixture.reservation(submission.binding.id))
        }
    }

    func testCurrentElevationRevocationDuringDraftNeverPublishesRequest() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
            let box = ElevationGrantBox(), policy = try currentElevation(box)
            let (attempt, submission, profile) = try admissionAttempt(reply: reply)
            let before = try fixture.auditRecordCount
            XCTAssertThrowsError(try admitWithElevation(attempt, fixture: fixture, policy: policy, build: {
                box.state.withLock { $0.targets = [] }
                return self.admissionDraft($0, fixture: fixture)
            })) { XCTAssertEqual($0 as? CommandElevationPolicyError, .policyRejected) }
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.admissionRejected))
            XCTAssertNil(try fixture.reservation(submission.binding.id)); XCTAssertEqual(try fixture.auditRecordCount, before)
            XCTAssertEqual(box.state.withLock { $0.reads }, 3); XCTAssertEqual(try sendReferences(reply.port), 1)
        }
    }

    func testCurrentElevationReadFailureHasNoCachedAdmissionFallback() throws {
        for checkpointed in [false, true] {
            for failAt in 1...3 {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
                let box = ElevationGrantBox(); box.state.withLock { $0.failAtRead = failAt }
                let policy = try currentElevation(box), (attempt, submission, profile) = try admissionAttempt(reply: reply)
                let before = try fixture.auditRecordCount
                XCTAssertThrowsError(try admitWithElevation(attempt, fixture: fixture, policy: policy)) {
                    XCTAssertTrue($0 is ElevationReadFailure)
                }
                XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.admissionRejected))
                XCTAssertNil(try fixture.reservation(submission.binding.id)); XCTAssertEqual(try fixture.auditRecordCount, before)
                XCTAssertEqual(box.state.withLock { $0.reads }, failAt); XCTAssertEqual(try sendReferences(reply.port), 1)
            }
        }
    }

    func testCurrentElevationExecutionRejectsAnotherJournalScopeBeforeControllerCreation() throws {
        let fixture = try CommandRequestFixture(owned: true), box = ElevationGrantBox()
        let policy = try currentElevation(box, macID: Data(repeating: 3, count: 16))
        let authority = try XCTUnwrap(fixture.authority), before = try fixture.auditRecordCount, moment = fixture.now()
        XCTAssertThrowsError(try authority.beginCommandExecution(requestID: Data(count: 16), monitorPath: "/missing-monitor",
            childPath: "/missing-child", preparationMilliseconds: 1000, fileCreationMask: 0o077,
            elevationPolicy: policy, clock: { moment })) {
            XCTAssertEqual($0 as? CommandElevationPolicyError, .policyRejected)
        }
        XCTAssertEqual(box.state.withLock { $0.reads }, 0); XCTAssertEqual(try fixture.auditRecordCount, before)
    }
}

extension MachCommandCallerReceiverTests {
    private func elevationWorker(_ fixture: CommandRequestFixture, port: WorkerPort,
                                 policy: CurrentCommandElevationPolicy,
                                 streamBinding: @escaping @Sendable () throws -> Data,
                                 onAdmission: @escaping @Sendable (Result<IssuedRequestPayload, any Error>) -> Void,
                                 diagnostics: ReceiveDiagnostics? = nil) throws -> AuthorityCommandReceiveWorker {
        let journal = try XCTUnwrap(fixture.authority), epoch = fixture.clock, expression = try selfExpression()
        let context = CommandSessionRegistry.Context(expression: "always", roleRevision: UUID())
        let limits = fixture.limits, environment = assemblyEnvironment, contract = fixture.contract
        return try AuthorityCommandReceiveWorker(submissionLimits: assemblyLimits,
            makeHost: { try Self.workerHost(port: port, context: context, policyRead: {},
                observeTimeout: { stage in diagnostics?.record(stage) }) },
            admit: { attempt, time, stop in
                try journal.admitCommandAttempt(attempt, expression: expression, elevationPolicy: policy,
                    captureSchemaVersion: 1, minimalEnvironment: environment, streamBinding: streamBinding,
                    captureLimits: limits, maximumAncestryEntries: 1, draft: {
                        .init(contract: contract, requiredFeatures: [], capture: $0.canonicalBytes,
                            actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
                            firstObservedAt: .init(epoch: epoch, milliseconds: 100), deadlineMilliseconds: 200,
                            createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1100)
                    }, now: { .init(epoch: epoch, milliseconds: 110) }, receiptTimeMs: time,
                    checkCancellation: { try stop.check() })
            }, receiptTime: { 777 }, onAdmission: onAdmission,
            observeReceive: { event in diagnostics?.record(event) })
    }

    private func workerElevationProfile(_ destination: mach_port_t) throws -> CommandHandshakeProfile {
        let reply = try Endpoint(), offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: .admissionResults)
        try MachCommandWire.send(offer.canonicalBytes, destination: destination, replyPort: reply.port,
            identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
        let response = try receiver(reply, maximum: 4096).receiveHelloReply(timeoutMilliseconds: 1000)
        defer { response.caller.close() }
        return try CommandHandshakeReply.decode(response.payload, offer: offer,
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16))
    }
    private func workerElevationSubmission(_ destination: mach_port_t, reply: Endpoint, profile: CommandHandshakeProfile,
                                          descriptor: Int32, id: UInt8, executable: String = "/usr/bin/true") throws -> CommandSubmission {
        let submission = try commandSubmission(executablePath: executable,
            binding: .init(id: Data(repeating: id, count: 16), nonce: Data(repeating: id, count: 32), callerBinding: profile.callerBinding))
        try MachCommandAdmissionWire.send(submission.canonicalBytes, inputDescriptor: descriptor, destination: destination,
            replyPort: reply.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        return submission
    }

    @MainActor func testReceiveWorkerElevationReloadsGrantAndRetainsHealthyQueueAfterDenial() async throws {
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), port = WorkerPort(), box = ElevationGrantBox()
        let bindings = Mutex(0), outcomes = Mutex(0), policy = try currentElevation(box), diagnostics = ReceiveDiagnostics()
        let worker = try elevationWorker(fixture, port: port, policy: policy, streamBinding: {
            bindings.withLock { $0 += 1 }; return Data(repeating: 0xe4, count: 16)
        }, onAdmission: { _ in outcomes.withLock { $0 += 1 } }, diagnostics: diagnostics)
        try await worker.start()
        let destination = port.value.withLock { $0 }, descriptor = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        defer { worker.requestStop(); _ = mach_port_deallocate(mach_task_self_, destination); _ = Darwin.close(descriptor) }
        func waitForOutcome(_ expected: Int, phase: String) async throws {
            do { try await waitForReceiveWorker { outcomes.withLock { $0 == expected } } }
            catch {
                let observation = "\(phase): status=\(worker.status), retired=\(worker.isRetired), "
                    + "outcomes=\(outcomes.withLock { $0 }), reads=\(box.state.withLock { $0.reads }), "
                    + "bindings=\(bindings.withLock { $0 }), receive=\(diagnostics.snapshot)"
                XCTFail(observation)
                await worker.close()
                XCTAssertEqual(worker.status, .closed)
                XCTAssertFalse(receiveRightPresent(destination), "Timed-out worker retained its receive right")
                throw error
            }
        }
        let profile = try workerElevationProfile(destination), first = try Endpoint(), second = try Endpoint()
        let allowed = try workerElevationSubmission(destination, reply: first, profile: profile, descriptor: descriptor, id: 0xb2)
        try await waitForOutcome(1, phase: "initial admission")
        guard case .admitted = try typedOutcome(first, submission: allowed, profile: profile) else {
            await worker.close(); return XCTFail("The original authenticated attempt must reach current policy admission")
        }
        let before = try fixture.auditRecordCount
        box.state.withLock { $0.targets = [] }
        let denied = try workerElevationSubmission(destination, reply: second, profile: profile,
            descriptor: descriptor, id: 0xb4, executable: "/missing-before-policy")
        try await waitForOutcome(2, phase: "revoked grant")
        XCTAssertEqual(try typedOutcome(second, submission: denied, profile: profile), .notAdmitted(.policyRejected, .never))
        XCTAssertNil(try fixture.reservation(denied.binding.id)); XCTAssertEqual(try fixture.auditRecordCount, before)
        XCTAssertEqual(box.state.withLock { $0.reads }, 4); XCTAssertEqual(bindings.withLock { $0 }, 1)
        XCTAssertFalse(worker.isRetired); XCTAssertEqual(worker.status, .running)
        XCTAssertGreaterThanOrEqual(fcntl(descriptor, F_GETFD), 0)
        await worker.close()
    }

    @MainActor func testReceiveWorkerElevationBindingFailureReturnsTypedUncertaintyWithoutCaptureOrReservation() async throws {
        let fixture = try CommandRequestFixture(owned: true), port = WorkerPort(), box = ElevationGrantBox()
        let completed = Mutex(false), policy = try currentElevation(box)
        let worker = try elevationWorker(fixture, port: port, policy: policy, streamBinding: {
            throw ElevationReadFailure.unavailable
        }, onAdmission: { result in
            guard case .failure(let error) = result else { return XCTFail("A failed binding must prevent admission") }
            XCTAssertTrue(error is ElevationReadFailure); completed.withLock { $0 = true }
        })
        try await worker.start()
        let destination = port.value.withLock { $0 }, descriptor = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        defer { worker.requestStop(); _ = mach_port_deallocate(mach_task_self_, destination); _ = Darwin.close(descriptor) }
        let profile = try workerElevationProfile(destination), reply = try Endpoint(), before = try fixture.auditRecordCount
        let submission = try workerElevationSubmission(destination, reply: reply, profile: profile,
            descriptor: descriptor, id: 0xb2, executable: "/missing-before-binding")
        try await waitForReceiveWorker { completed.withLock { $0 } }
        XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.admissionRejected))
        XCTAssertNil(try fixture.reservation(submission.binding.id)); XCTAssertEqual(try fixture.auditRecordCount, before)
        XCTAssertEqual(box.state.withLock { $0.reads }, 1); XCTAssertFalse(worker.isRetired)
        XCTAssertEqual(try sendReferences(reply.port), 1); XCTAssertGreaterThanOrEqual(fcntl(descriptor, F_GETFD), 0)
        await worker.close()
    }

    func testReceiveWorkerCurrentElevationPublicConstructionRefusesOrdinaryAccountBeforeFactories() throws {
        guard getuid() != 0 || geteuid() != 0 else { throw XCTSkip("Ordinary-account gate") }
        let fixture = try CommandRequestFixture(owned: true), box = ElevationGrantBox(), factories = Mutex(0)
        let epoch = fixture.clock
        XCTAssertThrowsError(try AuthorityCommandReceiveWorker(journal: XCTUnwrap(fixture.authority), submissionLimits: assemblyLimits,
            makeHost: { factories.withLock { $0 += 1 }; throw CommandReceiveHostError.invalidConfiguration },
            elevationPolicy: currentElevation(box), captureSchemaVersion: 1, minimalEnvironment: assemblyEnvironment,
            captureLimits: assemblyLimits, streamBinding: { factories.withLock { $0 += 1 }; return Data(count: 16) },
            draft: { _ in throw ApprovalCoordinatorError.invalidDraft }, clock: { .init(epoch: epoch, milliseconds: 110) })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(factories.withLock { $0 }, 0); XCTAssertEqual(box.state.withLock { $0.reads }, 0)
    }
}

extension MachCommandCallerReceiverTests {
    private func configuredCommandPresence() throws -> AuthorityPresenceStartupConfiguration {
        func id(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
        let key = P256.Signing.PrivateKey().publicKey.x963Representation
        let service = try AuthorityServiceConfiguration(macID: id(1), accountID: id(2), journalDirectory: "/Library/Remozio/journal",
            serviceName: "dev.remozio.authority", teamID: "TEAMID1234", transportIdentifier: "dev.remozio.transport",
            transportHashes: [id(3, 20)], transportUID: 401, maximumPayloadBytes: 262_144, continuityDirectory: "/Library/Remozio/continuity")
        let request = try AuthorityRequestStartupConfiguration(service: service, keyRecordPath: "/Library/Remozio/key.cbor", authorityPublicKey: key)
        let registration = try GatewayRegistrationIdentity(ownerID: id(3), macID: id(1), accountID: id(2), gatewayID: id(4),
            lifecycleEpoch: id(5), rootPublicKey: key)
        let wake = try AuthorityWakeStartupConfiguration(request: request, registration: registration,
            gatewayServiceName: "dev.remozio.gateway.root", gatewayUID: 402, teamID: "TEAMID1234",
            gatewayIdentifier: "dev.remozio.gateway", gatewayHashes: [id(4, 20)])
        return try .init(wake: wake, ownerUID: geteuid(), appServiceName: "dev.remozio.presence", teamID: "TEAMID1234",
            appIdentifier: "dev.remozio.mac", appHashes: [id(6, 20)],
            policy: .init(observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 1000))
    }

    func testConfiguredDraftAdmitsNativeMappedInputWithConfiguredAgeLifetimeAndActions() throws {
        for wire: UInt64 in [10, 11] {
            let fixture = try CommandRequestFixture(checkpointed: true, owned: true, commandSchema: 3)
            let journal = try XCTUnwrap(fixture.authority), box = ElevationGrantBox(), policy = try currentElevation(box)
            let configuration = try AuthorityCommandStartupConfiguration(presence: configuredCommandPresence(),
                serviceName: "dev.remozio.command", policyPath: "/Library/Remozio/elevation.cbor", environment: assemblyEnvironment,
                submissionLimits: assemblyLimits, captureLimits: fixture.limits, maximumAncestryEntries: 0,
                approvalLifetimeMilliseconds: 9000)
            var port: mach_port_t = 0
            XCTAssertEqual(mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &port), KERN_SUCCESS)
            let context = CommandSessionRegistry.Context(expression: "always", roleRevision: UUID())
            let host = try CommandReceiveHost(takingReceiveRight: port, macID: configuration.macID,
                accountID: configuration.accountID, userID: configuration.callerUID, auditSessionID: nil,
                maximumSessions: configuration.maximumSessions, maximumPayloadBytes: configuration.submissionLimits.maxBytes,
                receiveWaitMilliseconds: configuration.receiveWaitMilliseconds,
                replyTimeoutMilliseconds: configuration.replyTimeoutMilliseconds, capabilities: configuration.capabilities,
                context: { _ in context })
            defer { host.close() }
            XCTAssertEqual(mach_port_insert_right(mach_task_self_, port, port, UInt32(MACH_MSG_TYPE_MAKE_SEND)), KERN_SUCCESS)
            defer { _ = mach_port_deallocate(mach_task_self_, port) }
            let helloReply = try Endpoint(), offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32),
                capabilities: .init(wireVersions: [wire], submissionSchemaVersions: [1], inputCarrierVersions: [5]))
            try MachCommandWire.send(offer.canonicalBytes, destination: port, replyPort: helloReply.port,
                identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
            _ = try host.poll(handleInput: { _ in XCTFail("Unexpected command during hello") })
            let response = try receiver(helloReply, maximum: 4096).receiveHelloReply(timeoutMilliseconds: 1000)
            defer { response.caller.close() }
            let profile = try CommandHandshakeReply.decode(response.payload, offer: offer,
                macID: configuration.macID, accountID: configuration.accountID)
            XCTAssertEqual(profile.wireVersion, wire)
            let reply = try Endpoint(), terminal = try Endpoint(), null = Darwin.open("/dev/null", O_RDWR | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(null, 0); defer { _ = Darwin.close(null) }
            let submission = try commandSubmission(binding: .init(id: Data(repeating: 0xb2, count: 16),
                nonce: Data(repeating: 0xb3, count: 32), callerBinding: profile.callerBinding), ioMode: wire == 10 ? .pty : .pipes)
            try MachCommandIOWire.sendMapped(submission.canonicalBytes, inputDescriptor: null, outputDescriptor: null,
                errorDescriptor: null, controlTerminalDescriptor: nil, destination: port, admissionReply: reply.port,
                terminalReply: terminal.port, maximumPayloadBytes: configuration.submissionLimits.maxBytes, timeoutMilliseconds: 1000)
            let before = try fixture.auditRecordCount
            var issued: IssuedRequestPayload?
            _ = try host.pollAdmission(submissionLimits: configuration.submissionLimits, receiptTime: { 777 }, admit: { attempt, time, stop in
                try journal.admitCommandAttempt(attempt, expression: selfExpression(), elevationPolicy: policy,
                    captureSchemaVersion: AuthorityCommandStartupConfiguration.captureSchemaVersion,
                    minimalEnvironment: configuration.environment, streamBinding: Data(repeating: 0xe4, count: 16),
                    captureLimits: configuration.captureLimits, maximumAncestryEntries: configuration.maximumAncestryEntries,
                    draft: { try configuration.commandDraft($0, observed: fixture.now(100), unixMilliseconds: 1000) },
                    now: { fixture.now(110) }, receiptTimeMs: time, checkCancellation: { try stop.check() })
            }, onResult: { issued = try $0.get() })
            let request = try XCTUnwrap(issued)
            guard case .admitted(let admission) = try typedOutcome(reply, submission: submission, profile: profile) else {
                return XCTFail("Native mapped command was not admitted")
            }
            XCTAssertEqual(admission.requestID, request.requestID); XCTAssertEqual(request.contract.schemaVersion, 3)
            XCTAssertEqual(request.createdUnixMilliseconds, 1000); XCTAssertEqual(request.expiresUnixMilliseconds, 10_000)
            XCTAssertEqual(Set(request.permittedActions), [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)])
            let state = try journal.withRequests { try $0.state(requestID: request.requestID) }
            XCTAssertEqual(state.phase, .queued); XCTAssertEqual(state.firstObservedAt, fixture.now(100))
            XCTAssertEqual(state.deadlineMilliseconds, 9100); XCTAssertEqual(try fixture.auditRecordCount, before + 1)
            let capture = try CommandCapture(canonicalBytes: request.canonicalCapture, limits: configuration.captureLimits, expectedSchemaVersion: 3)
            XCTAssertEqual(capture.arguments, submission.arguments)
            for entry in configuration.environment where !submission.environmentAdditions.contains(where: { $0.name == entry.name }) {
                XCTAssertTrue(capture.environment.contains(entry))
            }
            for addition in submission.environmentAdditions {
                XCTAssertTrue(capture.environment.contains(.init(name: addition.name, value: addition.value, source: .requested)))
            }
            XCTAssertEqual(capture.target.uid, geteuid()); XCTAssertTrue(capture.ancestry.entries.isEmpty)
            XCTAssertEqual(box.state.withLock { $0.reads }, 3)
            XCTAssertGreaterThanOrEqual(fcntl(null, F_GETFD), 0)
            let cancelledAt = fixture.now(120)
            _ = try journal.withRequests { try $0.retirePending(requestID: request.requestID, reason: .cancelled, now: cancelledAt, receiptTimeMs: nil) }
        }
    }
}

extension MachCommandCallerReceiverTests {
    private func noticeDecision(_ request: IssuedRequestPayload, fixture: CommandRequestFixture,
                                decline: Bool = false) throws -> (Data, Data) {
        let body = try DecisionPayload(macID: request.macID, accountID: request.accountID, requestID: request.requestID,
            requestDigest: request.requestDigest(bodyLimits: fixture.limits, signingLimits: fixture.limits), challenge: request.challenge,
            phoneID: Data(repeating: 5, count: 16), keyID: Data(repeating: decline ? 7 : 6, count: 16),
            action: .init(choice: decline ? .decline : .execute, scope: .currentRequest)).encode(limits: fixture.limits)
        let input = try SigningInput.make(wireVersion: 1, messageType: .decision,
            purpose: decline ? .cancellation : .biometricAuthorization, canonicalPayload: body,
            payloadLimits: fixture.limits, inputLimits: fixture.limits)
        return (body, try (decline ? fixture.decision : fixture.biometric).signature(for: input).rawRepresentation)
    }

    func testCommandNoticeRunsAfterLockOnNewDurableApproval() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let journal = try XCTUnwrap(fixture.authority), (_, command) = try requestCommand()
            let request = try admitOwnedCommand(command, fixture: fixture), time = fixture.now(120)
            if checkpointed {
                let presented = fixture.now(115)
                _ = try journal.withRequests { try $0.markPresented(requestID: request.requestID, now: presented, receiptTimeMs: nil) }
            }
            let (body, signature) = try noticeDecision(request, fixture: fixture)
            let notices = Mutex<[AuthorityCommandAuthorizationNotice]>([])
            let result = try journal.withValidatedCommandExchange(requestID: request.requestID, decisionSupplied: true,
                validate: { _ in }, body: { owner in
                    _ = try owner.consume(canonicalDecision: body, signature: signature,
                        authenticatedPhoneID: Data(repeating: 5, count: 16), authenticatedEnrollmentEpoch: Data(repeating: 9, count: 16),
                        now: time, receiptTimeMs: nil)
                    return 42
                }, onCommandAuthorized: { notice in
                    let done = DispatchSemaphore(value: 0), read = Mutex<RequestPhase?>(nil)
                    DispatchQueue.global().async {
                        defer { done.signal() }
                        do { let phase = try journal.withRequests { try $0.state(requestID: notice.requestID).phase }; read.withLock { $0 = phase } }
                        catch { XCTFail("Callback journal read failed: \(error)") }
                    }
                    XCTAssertEqual(done.wait(timeout: .now() + 2), .success, "Notification must run after the journal lock is released")
                    XCTAssertEqual(read.withLock { $0 }, .authorized)
                    notices.withLock { $0.append(notice) }
                })
            XCTAssertEqual(result, 42)
            let received = notices.withLock { $0 }
            XCTAssertEqual(received.count, 1); XCTAssertEqual(received.first?.requestID, request.requestID)
            XCTAssertEqual(received.first?.requestDigest, try request.requestDigest(bodyLimits: fixture.limits, signingLimits: fixture.limits))
            XCTAssertEqual(received.first?.challenge, request.challenge)
            try journal.withValidatedCommandExchange(requestID: request.requestID, decisionSupplied: false,
                validate: { _ in }, body: { _ in () }, onCommandAuthorized: { _ in XCTFail("Status query repeated notification") })
            XCTAssertThrowsError(try journal.withValidatedCommandExchange(requestID: request.requestID, decisionSupplied: true,
                validate: { _ in }, body: { owner in
                    try owner.consume(canonicalDecision: body, signature: signature,
                        authenticatedPhoneID: Data(repeating: 5, count: 16), authenticatedEnrollmentEpoch: Data(repeating: 9, count: 16),
                        now: time, receiptTimeMs: nil)
                }, onCommandAuthorized: { _ in XCTFail("Repeated decision repeated notification") }))
        }
    }

    func testCommandNoticeSurvivesPostConsumptionHandlerFailureWithoutDuplicate() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let journal = try XCTUnwrap(fixture.authority), (_, command) = try requestCommand()
            let request = try admitOwnedCommand(command, fixture: fixture), time = fixture.now(120)
            let (body, signature) = try noticeDecision(request, fixture: fixture), notices = Mutex<[AuthorityCommandAuthorizationNotice]>([])
            XCTAssertThrowsError(try journal.withValidatedCommandExchange(requestID: request.requestID, decisionSupplied: true,
                validate: { _ in }, body: { owner -> Void in
                    _ = try owner.consume(canonicalDecision: body, signature: signature,
                        authenticatedPhoneID: Data(repeating: 5, count: 16), authenticatedEnrollmentEpoch: Data(repeating: 9, count: 16),
                        now: time, receiptTimeMs: nil)
                    throw ApprovalCoordinatorError.unavailable
                }, onCommandAuthorized: { notice in notices.withLock { $0.append(notice) } })) {
                    XCTAssertEqual($0 as? ApprovalCoordinatorError, .unavailable)
                }
            XCTAssertEqual(notices.withLock { $0.count }, 1)
            XCTAssertEqual(try journal.withRequests { try $0.state(requestID: request.requestID).phase }, .authorized)
            try journal.withValidatedCommandExchange(requestID: request.requestID, decisionSupplied: true,
                validate: { _ in }, body: { _ in () }, onCommandAuthorized: { _ in XCTFail("Lost-reply reconciliation repeated notification") })
        }
    }

    func testCommandNoticeIgnoresDeclineExpiryAndBadSignature() throws {
        for scenario in [0, 1, 2] {
            let fixture = try CommandRequestFixture(checkpointed: true, owned: true)
            let journal = try XCTUnwrap(fixture.authority), (_, command) = try requestCommand()
            let request = try admitOwnedCommand(command, fixture: fixture), time = fixture.now(scenario == 1 ? 200 : 120)
            let (body, goodSignature) = try noticeDecision(request, fixture: fixture, decline: scenario == 0)
            let signature = scenario == 2 ? Data(repeating: 0, count: 64) : goodSignature
            let operation = {
                try journal.withValidatedCommandExchange(requestID: request.requestID, decisionSupplied: true,
                    validate: { _ in }, body: { owner in
                        try owner.consume(canonicalDecision: body, signature: signature,
                            authenticatedPhoneID: Data(repeating: 5, count: 16), authenticatedEnrollmentEpoch: Data(repeating: 9, count: 16),
                            now: time, receiptTimeMs: nil)
                    }, onCommandAuthorized: { _ in XCTFail("Rejected or declined decision notified the executor") })
            }
            if scenario == 0 { _ = try operation() } else { XCTAssertThrowsError(try operation()) }
            let phase = try journal.withRequests { try $0.state(requestID: request.requestID).phase }
            XCTAssertEqual(phase, scenario == 0 ? .declined : scenario == 1 ? .expired : .queued)
        }
    }

    func testCommandNoticeDoesNotInvokeBodyWhenAuthenticationFails() throws {
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), journal = try XCTUnwrap(fixture.authority)
        XCTAssertThrowsError(try journal.withValidatedCommandExchange(requestID: Data(repeating: 8, count: 16), decisionSupplied: true,
            validate: { _ in throw AuthorityTransportAccessError.policyMismatch }, body: { _ in XCTFail("Rejected authentication invoked exchange"); return 0 },
            onCommandAuthorized: { _ in XCTFail("Rejected authentication notified executor") })) {
                XCTAssertEqual($0 as? AuthorityTransportAccessError, .policyMismatch)
            }
    }
}

extension MachCommandCallerReceiverTests {
    private func executionNotice(_ request: IssuedRequestPayload, journal: AuthorityJournal) throws -> AuthorityCommandAuthorizationNotice {
        try journal.withRequests { .init(state: try $0.state(requestID: request.requestID)) }
    }

    func testUnownedExecutionRejectionPreservesOriginalBindingsAndCommitsNoDispatchOnce() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let journal = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminal = try Endpoint()
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal)
            let request = try admitOwnedCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            _ = try ownerDecision(request, fixture: fixture, decline: false)
            let original = try executionNotice(request, journal: journal)
            let time = fixture.now(130)
            try journal.validateCommandAuthorizationNotice(original, now: time)
            let current = try journal.withRequests { try $0.state(requestID: request.requestID) }
            for (digest, challenge) in [(Data(repeating: 0xff, count: 32), current.challenge), (current.requestDigest, Data(repeating: 0xff, count: 32))] {
                let wrong = AuthorityCommandAuthorizationNotice(state: .init(requestKind: .command, macID: current.macID,
                    accountID: current.accountID, requestDigest: digest, challenge: challenge, reason: .none,
                    terminalAt: nil, decisionPhoneID: current.decisionPhoneID, requestID: current.requestID,
                    phase: .authorized, revision: current.revision, firstObservedAt: current.firstObservedAt,
                    deadlineMilliseconds: current.deadlineMilliseconds))
                XCTAssertThrowsError(try journal.validateCommandAuthorizationNotice(wrong, now: time))
                XCTAssertFalse(try journal.cancelUnownedCommandExecution(wrong, now: time, receiptTimeMs: nil))
                XCTAssertEqual(try journal.withRequests { try $0.state(requestID: request.requestID).phase }, .authorized)
            }
            XCTAssertTrue(try journal.cancelUnownedCommandExecution(original, now: time, receiptTimeMs: nil))
            XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, .cancelledBeforeStart)
            XCTAssertEqual(try journal.withRequests { try $0.state(requestID: request.requestID).phase }, .cancelled)
            XCTAssertEqual(try journal.withRequests { try $0.historicalOutcome(requestID: request.requestID) }?.revision, 1)
            XCTAssertEqual(journal.activeCommandCount, 0)
            XCTAssertFalse(try journal.cancelUnownedCommandExecution(original, now: time, receiptTimeMs: nil))
            XCTAssertThrowsError(try receiver(terminal).receiveTerminalReply(timeoutMilliseconds: 10))
        }
    }

    func testUnownedRejectionCannotCancelAnExistingNativeExecutionOwner() throws {
        for checkpointed in [false, true] {
            let fixture = try nativeDispatchFixture(checkpointed: checkpointed, path: "/bin/sh",
                arguments: [Data("sh".utf8), Data("-c".utf8), Data("/bin/sleep 0.1; exit 7".utf8)])
            let notice = try executionNotice(fixture.request, journal: fixture.authority)
            try beginDispatch(fixture.fixture, request: fixture.request, launcher: fixture.launcher)
            XCTAssertEqual(fixture.authority.activeCommandCount, 1)
            XCTAssertFalse(try fixture.authority.cancelUnownedCommandExecution(notice, now: fixture.fixture.now(130), receiptTimeMs: nil))
            XCTAssertEqual(try nativeDispatchOutcome(fixture), .exited(7))
            try awaitDispatchCleanup(fixture.authority)
            let requestID = fixture.request.requestID
            XCTAssertEqual(try fixture.authority.withRequests { try $0.historicalOutcome(requestID: requestID) }?.revision, 2)
        }
    }

    @MainActor func testNonqueuedExecutionNoticeCommitsCancellationAndRepliesToTheOriginalFrontend() async throws {
        for checkpointed in [false, true] {
            for saturated in [false, true] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
                let journal = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminal = try Endpoint()
                let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal)
                let request = try admitOwnedCommand(command, fixture: fixture)
                let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
                _ = try ownerDecision(request, fixture: fixture, decline: false)
                let original = try executionNotice(request, journal: journal), time = fixture.now(130)
                let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0)
                let worker = try AuthorityCommandExecutionWorker(maximumPending: 1, begin: { notice, check in
                    XCTAssertNotEqual(notice.requestID, original.requestID, "The rejected command must never begin")
                    entered.signal()
                    guard resume.wait(timeout: .now() + 3) == .success else { throw CommandExecutionError.unavailable }
                    try check()
                }, rejectUnowned: { notice in
                    let cancelled = try journal.cancelUnownedCommandExecution(notice, now: time, receiptTimeMs: nil)
                    if notice.requestID == original.requestID { XCTAssertTrue(cancelled) }
                })
                defer { resume.signal(); worker.requestStop() }
                try worker.start()
                if saturated {
                    let current = try journal.withRequests { try $0.state(requestID: request.requestID) }
                    let pending = AuthorityCommandAuthorizationNotice(state: .init(requestKind: .command, macID: current.macID,
                        accountID: current.accountID, requestDigest: current.requestDigest, challenge: current.challenge, reason: .none,
                        terminalAt: nil, decisionPhoneID: nil, requestID: Data(repeating: 0xfe, count: 16), phase: .authorized,
                        revision: current.revision, firstObservedAt: current.firstObservedAt, deadlineMilliseconds: current.deadlineMilliseconds))
                    XCTAssertEqual(worker.enqueue(pending), .queued)
                    XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
                } else { worker.requestStop() }
                XCTAssertEqual(worker.enqueue(original), saturated ? .capacity : .closed)
                XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, .cancelledBeforeStart)
                XCTAssertEqual(try journal.withRequests { try $0.state(requestID: request.requestID).phase }, .cancelled)
                XCTAssertEqual(try journal.withRequests { try $0.historicalOutcome(requestID: request.requestID) }?.revision, 1)
                XCTAssertEqual(journal.activeCommandCount, 0)
                resume.signal(); await worker.close()
                XCTAssertEqual(worker.isRetired, saturated)
                XCTAssertThrowsError(try receiver(terminal).receiveTerminalReply(timeoutMilliseconds: 10))
            }
        }
    }

    @MainActor func testExecutionWorkerRejectionUsesOriginalDurableRequestAndFrontendReply() async throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let journal = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminal = try Endpoint()
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal)
            let request = try admitOwnedCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            _ = try ownerDecision(request, fixture: fixture, decline: false)
            let notice = try executionNotice(request, journal: journal), time = fixture.now(130)
            let attempted = DispatchSemaphore(value: 0)
            let worker = try AuthorityCommandExecutionWorker(begin: { notice, check in
                try check(); try journal.validateCommandAuthorizationNotice(notice, now: time)
                throw CommandExecutionError.unavailable
            }, rejectUnowned: { notice in
                XCTAssertTrue(try journal.cancelUnownedCommandExecution(notice, now: time, receiptTimeMs: nil))
            }, report: { _, result in
                if case .success = result { XCTFail("A rejected attempt must not report success") }
                attempted.signal()
            })
            try worker.start(); XCTAssertEqual(worker.enqueue(notice), .queued)
            XCTAssertEqual(attempted.wait(timeout: .now() + 3), .success)
            XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, .cancelledBeforeStart)
            await worker.close()
            XCTAssertFalse(worker.isRetired); XCTAssertEqual(journal.activeCommandCount, 0)
            XCTAssertEqual(try journal.withRequests { try $0.state(requestID: request.requestID).phase }, .cancelled)
        }
    }
}

extension MachCommandCallerReceiverTests {
    private func nativeSchedulingWorker(_ fixture: CommandRequestFixture, launcher: String, failAfterPreparation: Bool,
        report: @escaping @Sendable (AuthorityCommandAuthorizationNotice, Result<Void, any Error>) -> Void) throws -> AuthorityCommandExecutionWorker {
        let journal = try XCTUnwrap(fixture.authority), expression = try selfExpression()
        let monitor = try dispatchMonitor(fixture), time = fixture.now(130)
        return try AuthorityCommandExecutionWorker(begin: { notice, check in
            try check(); try journal.validateCommandAuthorizationNotice(notice, now: time)
            try journal.beginCommandExecution(requestID: notice.requestID, monitorPath: monitor, childPath: launcher,
                preparationMilliseconds: 5000, fileCreationMask: 0o077, validateElevation: { _ in try check() }, clock: { time },
                runtime: { transaction, approval, capture in
                    try approval.requireCurrent(transaction.requestDeliveryTrust())
                    let snapshot = try XCTUnwrap(transaction.codePolicy())
                    let frontend = try XCTUnwrap(snapshot.policy.entries.first { $0.role == .commandFrontend })
                    let revision = try XCTUnwrap(snapshot.roleRevisions[.commandFrontend])
                    return CommandExecutionRuntime(child: frontend, childRevision: revision, monitor: frontend,
                        monitorRevision: revision, frontendRevision: revision, callerExpression: expression,
                        userID: capture.requester.effectiveUID, sessionID: nil)
                }, launcher: { _ in { try check() } })
            if failAfterPreparation { throw CommandExecutionError.unavailable }
        }, rejectUnowned: { notice in
            _ = try journal.cancelUnownedCommandExecution(notice, now: time, receiptTimeMs: nil)
        }, report: report)
    }

    @MainActor func testSignedCommandNoticeSchedulesMappedNativeExecutionOnceAfterHandlerFailure() async throws {
        for wire: UInt64 in [10, 11] {
            for failAfterPreparation in [false, true] {
                let fixture = try CommandRequestFixture(checkpointed: true, owned: true, commandSchema: 3)
                let journal = try XCTUnwrap(fixture.authority), launcher = try dispatchLauncher(fixture)
                let admissionPort = try Endpoint(), terminal = try Endpoint(), null = Darwin.open("/dev/null", O_RDWR | O_CLOEXEC)
                XCTAssertGreaterThanOrEqual(null, 0); defer { _ = Darwin.close(null) }
                let marker = fixture.root.appendingPathComponent("executed-once")
                let (command, submission, profile) = try ownerMappedCommand(admission: admissionPort, terminal: terminal,
                    input: null, output: null, error: null, path: "/bin/sh",
                    arguments: [Data("sh".utf8), Data("-c".utf8), Data("printf once >> \"$1\"; exit 7".utf8),
                        Data("sh".utf8), Data(marker.path.utf8)], wire: wire, ioMode: wire == 10 ? .pty : .pipes)
                let request = try admitOwnedCommand(command, fixture: fixture)
                let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
                guard case .admitted(let admitted) = admission.outcome else { return XCTFail("The exact mapped request must be admitted") }
                let binding = CommandStreamBinding(profile: profile, submission: submission.binding,
                    submissionDigest: admission.submissionDigest, request: admitted)
                let completed = DispatchSemaphore(value: 0), notices = Mutex<[AuthorityCommandAuthorizationNotice]>([])
                let worker = try nativeSchedulingWorker(fixture, launcher: launcher, failAfterPreparation: failAfterPreparation,
                    report: { _, _ in completed.signal() })
                try worker.start()
                let (body, signature) = try noticeDecision(request, fixture: fixture), time = fixture.now(120)
                XCTAssertThrowsError(try journal.withValidatedCommandExchange(requestID: request.requestID, decisionSupplied: true,
                    validate: { _ in }, body: { owner in
                        _ = try owner.consume(canonicalDecision: body, signature: signature,
                            authenticatedPhoneID: Data(repeating: 5, count: 16), authenticatedEnrollmentEpoch: Data(repeating: 9, count: 16),
                            now: time, receiptTimeMs: nil)
                        throw ApprovalCoordinatorError.unavailable
                    }, onCommandAuthorized: { notice in
                        notices.withLock { $0.append(notice) }; XCTAssertEqual(worker.enqueue(notice), .queued)
                    }))
                XCTAssertEqual(completed.wait(timeout: .now() + 3), .success)
                let notice = try XCTUnwrap(notices.withLock { $0.first })
                XCTAssertEqual(notices.withLock { $0.count }, 1)
                let receive = try receiver(terminal, maximum: 8192)
                var control: MachCommandAuthorityPort?, sequence = CommandStreamReceiveSequence(direction: .toFrontend)
                var acknowledged = false, result: VerifiedCommandTerminalResult?
                defer { control?.close() }
                let deadline = Date().addingTimeInterval(5)
                while result == nil {
                    guard Date() < deadline else { throw MachCommandCallerError.timeout }
                    switch try receive.receiveExecutionEvent(timeoutMilliseconds: 1000) {
                    case .stream(let reply, let carried):
                        defer { reply.caller.close(); carried?.close() }
                        let frame = try CommandStreamFrame.decode(reply.payload, binding: binding, direction: .toFrontend)
                        try sequence.accept(frame)
                        switch frame.body {
                        case .opened: control = try XCTUnwrap(carried).takeControlRight()
                        case .outputEnd:
                            let acknowledgment = try CommandStreamFrame(sequence: 0, body: .outputDrained).encode(binding: binding)
                            try Self.waitQueued { try MachCommandWire.sendStream(acknowledgment, destination: XCTUnwrap(control).borrowed(), toAuthority: true) }
                            acknowledged = true
                        case .inputCredit, .jobState: break
                        default: XCTFail("The mapped fixture must receive only its negotiated control events")
                        }
                    case .terminal(let reply):
                        defer { reply.caller.close() }
                        result = try CommandTerminalResultPayload.decode(reply.payload, profile: profile, original: submission, admission: admission)
                    }
                }
                XCTAssertEqual(result?.outcome, .exited(7)); XCTAssertEqual(acknowledged, wire == 10)
                try awaitDispatchCleanup(journal)
                XCTAssertEqual(try Data(contentsOf: marker), Data("once".utf8))
                XCTAssertEqual(try journal.withRequests { try $0.historicalOutcome(requestID: request.requestID) }?.revision, 2)
                XCTAssertEqual(worker.enqueue(notice), .queued)
                XCTAssertEqual(completed.wait(timeout: .now() + 3), .success)
                await worker.close()
                XCTAssertEqual(try Data(contentsOf: marker), Data("once".utf8)); XCTAssertEqual(journal.activeCommandCount, 0)
                XCTAssertThrowsError(try receive.receiveTerminalReply(timeoutMilliseconds: 10))
            }
        }
    }
}

extension MachCommandCallerReceiverTests {
    @MainActor func testRuntimeCloseJoinsLateAuthorizationBeforeDrainingExecutionAndClosingJournal() async throws {
        try await delayedAuthorizationShutdown(releaseByDeinit: false)
    }

    @MainActor func testRuntimeDeinitJoinsLateAuthorizationBeforeDrainingExecutionAndClosingJournal() async throws {
        try await delayedAuthorizationShutdown(releaseByDeinit: true)
    }

    @MainActor private func delayedAuthorizationShutdown(releaseByDeinit: Bool) async throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let journal = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminal = try Endpoint()
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminal)
            let request = try admitOwnedCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            let (body, signature) = try noticeDecision(request, fixture: fixture), time = fixture.now(130)
            let entered = Mutex(false), rejected = Mutex(false), closed = Mutex(false)
            let resume = DispatchSemaphore(value: 0), requestID = request.requestID
            let worker = try AuthorityCommandExecutionWorker(begin: { _, _ in XCTFail("A shutdown notice must never execute") },
                rejectUnowned: { notice in
                    XCTAssertTrue(try journal.cancelUnownedCommandExecution(notice, now: time, receiptTimeMs: nil))
                    rejected.withLock { $0 = true }
                })
            defer { resume.signal(); worker.requestStop() }
            let registration = try GatewayRegistrationIdentity(ownerID: Data(repeating: 3, count: 16),
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                gatewayID: Data(repeating: 4, count: 16), lifecycleEpoch: Data(repeating: 5, count: 16),
                rootPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
            var service: AuthorityWakeService? = try .init(makePublisher: { throw GatewayRootChannelError.closed },
                hints: AuthorityWakeHintSource(registration: registration), interval: 100, startRequests: {}, closeRequests: {
                    XCTAssertTrue(rejected.withLock { $0 })
                    XCTAssertEqual(try journal.withRequests { try $0.state(requestID: requestID).phase }, .cancelled)
                    XCTAssertEqual(try journal.withRequests { try $0.historicalOutcome(requestID: requestID) }?.revision, 1)
                    try journal.close(); closed.withLock { $0 = true }
                }, commandExecutionWorker: worker, stopRequestProducers: { await journal.stopCommandExchanges() })
            try await service?.start()
            let exchange = Task.detached {
                try journal.withValidatedCommandExchange(requestID: requestID, decisionSupplied: true, validate: { _ in }, body: { owner in
                    _ = try owner.consume(canonicalDecision: body, signature: signature,
                        authenticatedPhoneID: Data(repeating: 5, count: 16), authenticatedEnrollmentEpoch: Data(repeating: 9, count: 16),
                        now: time, receiptTimeMs: nil)
                    return 17
                }, onCommandAuthorized: { notice in
                    entered.withLock { $0 = true }
                    XCTAssertEqual(resume.wait(timeout: .now() + 10), .success)
                    XCTAssertEqual(worker.enqueue(notice), .closed)
                })
            }
            for _ in 0..<300 where !entered.withLock({ $0 }) { try await Task.sleep(for: .milliseconds(10)) }
            XCTAssertTrue(entered.withLock { $0 })
            var cleanup: Task<Void, any Error>?
            weak var released = service
            if releaseByDeinit { service = nil }
            else {
                let closingService = try XCTUnwrap(service)
                cleanup = Task { try await closingService.close() }
            }
            var producerStopped = false
            for _ in 0..<300 {
                do { try journal.beginCommandExchange(); journal.endCommandExchange() }
                catch ApprovalCoordinatorError.unavailable { producerStopped = true; break }
                try await Task.sleep(for: .milliseconds(10))
            }
            XCTAssertTrue(producerStopped)
            if releaseByDeinit { XCTAssertNil(released) }
            XCTAssertFalse(closed.withLock { $0 }); XCTAssertFalse(rejected.withLock { $0 })
            XCTAssertEqual(try journal.withRequests { try $0.state(requestID: requestID).phase }, .authorized)
            XCTAssertThrowsError(try journal.close()) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive) }
            XCTAssertThrowsError(try journal.withValidatedCommandExchange(requestID: requestID, decisionSupplied: true,
                validate: { _ in XCTFail("A stopped producer must not validate another exchange") },
                body: { _ in XCTFail("A stopped producer must not consume another decision"); return 0 },
                onCommandAuthorized: { _ in XCTFail("A stopped producer must not notify") })) {
                    XCTAssertEqual($0 as? ApprovalCoordinatorError, .unavailable)
                }
            resume.signal()
            let result = try await exchange.value; XCTAssertEqual(result, 17)
            try await cleanup?.value
            for _ in 0..<300 where !closed.withLock({ $0 }) { try await Task.sleep(for: .milliseconds(10)) }
            XCTAssertTrue(closed.withLock { $0 }); XCTAssertTrue(rejected.withLock { $0 })
            XCTAssertEqual(try ownerTerminal(terminal, submission: submission, admission: admission).outcome, .cancelledBeforeStart)
            XCTAssertEqual(journal.activeCommandCount, 0)
            XCTAssertThrowsError(try journal.read { _ in 0 })
        }
    }
}

extension MachCommandCallerReceiverTests {
    private final class ReceiveDiagnostics: Sendable {
        private struct Counts {
            var idle = 0, hello = 0, inputHandled = 0
            var malformed = 0, wrongPeer = 0, incompatible = 0, capacity = 0, replyFailure = 0
            var previewWait = 0, authenticatedPreview = 0, packetReceive = 0
        }
        private let counts = Mutex(Counts())
        private func increment(_ value: inout Int) { if value < Int.max { value += 1 } }
        func record(_ event: AuthorityCommandReceiveWorker.ReceiveObservation) {
            counts.withLock {
                switch event {
                case .idle: increment(&$0.idle)
                case .hello: increment(&$0.hello)
                case .inputHandled: increment(&$0.inputHandled)
                case .rejected(.malformed): increment(&$0.malformed)
                case .rejected(.wrongPeer): increment(&$0.wrongPeer)
                case .rejected(.incompatible): increment(&$0.incompatible)
                case .rejected(.capacity): increment(&$0.capacity)
                case .rejected(.replyFailure): increment(&$0.replyFailure)
                }
            }
        }
        func record(_ stage: MachCommandReceiveTimeoutStage) {
            counts.withLock {
                switch stage {
                case .previewWait: increment(&$0.previewWait)
                case .authenticatedPreview: increment(&$0.authenticatedPreview)
                case .packetReceive: increment(&$0.packetReceive)
                }
            }
        }
        var snapshot: String {
            counts.withLock {
                "idle=\($0.idle), hello=\($0.hello), input=\($0.inputHandled), malformed=\($0.malformed), "
                    + "wrongPeer=\($0.wrongPeer), incompatible=\($0.incompatible), capacity=\($0.capacity), "
                    + "replyFailure=\($0.replyFailure), previewWait=\($0.previewWait), "
                    + "authenticatedPreview=\($0.authenticatedPreview), packetReceive=\($0.packetReceive)"
            }
        }
        var helloCount: Int { counts.withLock { $0.hello } }
        var malformedCount: Int { counts.withLock { $0.malformed } }
    }

    func testReceiveTimeoutDiagnosticsDistinguishEmptyQueue() throws {
        let endpoint = try Endpoint(), observations = Mutex<[MachCommandReceiveTimeoutStage]>([])
        let receive = try MachCommandCallerReceiver(receivePort: endpoint.port, expression: selfExpression(),
            userID: geteuid(), auditSessionID: nil, maxPayloadBytes: 4096,
            observeTimeout: { stage in observations.withLock { $0.append(stage) } })
        XCTAssertThrowsError(try receive.receiveNext(timeoutMilliseconds: 1)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
        XCTAssertEqual(observations.withLock { $0 }, [.previewWait])
        XCTAssertTrue(receiveRightPresent(endpoint.port))
    }

    func testReceiveTimeoutDiagnosticsIdentifyAuthenticatedDiscardAndReleaseReplyRight() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), observations = Mutex<[MachCommandReceiveTimeoutStage]>([])
        let times = Mutex<[UInt64]>([0, 1_000_000])
        let offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: .admissionResults)
        try MachCommandWire.send(offer.canonicalBytes, destination: endpoint.port, replyPort: reply.port,
            identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
        let receive = try MachCommandCallerReceiver(receivePort: endpoint.port, expression: selfExpression(),
            userID: geteuid(), auditSessionID: nil, maxPayloadBytes: 4096,
            observeTimeout: { stage in observations.withLock { $0.append(stage) } },
            uptimeNanoseconds: { times.withLock { $0.removeFirst() } })
        XCTAssertThrowsError(try receive.receiveHello(timeoutMilliseconds: 1)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
        XCTAssertEqual(observations.withLock { $0 }, [.authenticatedPreview])
        XCTAssertTrue(times.withLock { $0.isEmpty })
        XCTAssertEqual(try sendReferences(reply.port), 1)
        XCTAssertThrowsError(try receiver(endpoint).receiveNext(timeoutMilliseconds: 1)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
        XCTAssertTrue(receiveRightPresent(endpoint.port))
    }

    func testReceiveTimeoutDiagnosticsDoNotReplacePeerAuthentication() throws {
        let endpoint = try Endpoint(), observations = Mutex<[MachCommandReceiveTimeoutStage]>([]), clockReads = Mutex(0)
        try endpoint.send(Data([1]))
        let receive = try MachCommandCallerReceiver(receivePort: endpoint.port, expression: selfExpression(),
            userID: geteuid() ^ 1, auditSessionID: nil, maxPayloadBytes: 64,
            observeTimeout: { stage in observations.withLock { $0.append(stage) } },
            uptimeNanoseconds: { clockReads.withLock { $0 += 1; return UInt64($0) * 1_000_000 } })
        XCTAssertThrowsError(try receive.receive(timeoutMilliseconds: 1)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .wrongPeer)
        }
        XCTAssertTrue(observations.withLock { $0.isEmpty })
        XCTAssertEqual(clockReads.withLock { $0 }, 1)
    }

    @MainActor func testReceiveWorkerDiagnosticsObserveMalformedThenHelloWithoutAdmission() async throws {
        let port = WorkerPort(), diagnostics = ReceiveDiagnostics(), admissions = Mutex(0)
        let context = CommandSessionRegistry.Context(expression: "always", roleRevision: UUID())
        let worker = try AuthorityCommandReceiveWorker(submissionLimits: assemblyLimits,
            makeHost: { try Self.workerHost(port: port, context: context, receiveWaitMilliseconds: 1000,
                observeTimeout: { diagnostics.record($0) }) },
            admit: { _, _, _ in throw CommandReceiveHostError.invalidConfiguration },
            onAdmission: { _ in admissions.withLock { $0 += 1 } },
            observeReceive: { diagnostics.record($0) })
        try await worker.start()
        let destination = port.value.withLock { $0 }
        defer { worker.requestStop(); _ = mach_port_deallocate(mach_task_self_, destination) }
        do {
            let reply = try Endpoint()
            try MachCommandWire.send(Data([0xff]), destination: destination, replyPort: reply.port,
                identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
            try await waitForReceiveWorker { diagnostics.malformedCount == 1 }
            _ = try workerElevationProfile(destination)
            try await waitForReceiveWorker { diagnostics.helloCount == 1 }
            XCTAssertEqual(admissions.withLock { $0 }, 0)
            XCTAssertEqual(worker.status, .running); XCTAssertFalse(worker.isRetired)
            await worker.close()
            XCTAssertEqual(worker.status, .closed); XCTAssertFalse(receiveRightPresent(destination))
        } catch {
            XCTFail("Receive observations: \(diagnostics.snapshot)")
            await worker.close(); throw error
        }
    }
}

extension MachCommandCallerReceiverTests {
    private func receiverWithExpiredAuthenticationBudget(_ endpoint: Endpoint, userID: uid_t? = nil) throws -> MachCommandCallerReceiver {
        let ticks = Mutex<UInt64>(0)
        return try MachCommandCallerReceiver(receivePort: endpoint.port, expression: selfExpression(),
            userID: userID ?? geteuid(), auditSessionID: nil, maxPayloadBytes: 8192,
            uptimeNanoseconds: { ticks.withLock { let value = $0; $0 += 2_000_000; return value } })
    }

    func testQueuedListenerHelloSurvivesAuthenticationBeyondPollBudget() throws {
        let endpoint = try Endpoint(), reply = try Endpoint()
        let offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: .admissionResults)
        try MachCommandWire.send(offer.canonicalBytes, destination: endpoint.port, replyPort: reply.port,
            identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
        guard case .hello(let hello) = try receiverWithExpiredAuthenticationBudget(endpoint).receiveNext(timeoutMilliseconds: 1) else {
            return XCTFail("The authenticated queued hello must survive the poll budget")
        }
        XCTAssertEqual(hello.payload, try offer.canonicalBytes)
        hello.close()
        XCTAssertEqual(try sendReferences(reply.port), 1)
        XCTAssertThrowsError(try receiver(endpoint).receiveNext(timeoutMilliseconds: 1)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testQueuedListenerInputCarriersSurviveAuthenticationWithoutTakingBorrowedDescriptors() throws {
        var input: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&input), 0)
        let descriptor = input[0], output = Darwin.open("/dev/null", O_RDWR | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(output, 0)
        defer { input.forEach { _ = Darwin.close($0) }; _ = Darwin.close(output) }
        let untouched = Data([0xfa, 0x00, 0x31])
        XCTAssertEqual(untouched.withUnsafeBytes { Darwin.write(input[1], $0.baseAddress, $0.count) }, untouched.count)
        _ = Darwin.close(input[1]); input[1] = -1
        var fileport: mach_port_t = 0
        XCTAssertEqual(fileport_makeport(descriptor, &fileport), 0)
        defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        for version in 2...5 {
            let endpoint = try Endpoint(), admission = try Endpoint(), terminal = try Endpoint(), payload = Data([UInt8(version)])
            switch version {
            case 2: try endpoint.sendInput(payload, fileport: fileport)
            case 3: try MachCommandAdmissionWire.send(payload, inputDescriptor: descriptor, destination: endpoint.port,
                replyPort: admission.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
            case 4: try MachCommandIOWire.send(payload, inputDescriptor: descriptor, outputDescriptor: output,
                errorDescriptor: output, destination: endpoint.port, admissionReply: admission.port,
                terminalReply: terminal.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
            default: try MachCommandIOWire.sendMapped(payload, inputDescriptor: descriptor, outputDescriptor: output,
                errorDescriptor: output, controlTerminalDescriptor: nil, destination: endpoint.port,
                admissionReply: admission.port, terminalReply: terminal.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
            }
            guard case .input(let input) = try receiverWithExpiredAuthenticationBudget(endpoint).receiveNext(timeoutMilliseconds: 1) else {
                return XCTFail("The original input carrier must survive the poll budget")
            }
            XCTAssertEqual(input.payload, payload); XCTAssertEqual(input.carrierVersion, UInt32(version))
            input.closeIfUnclaimed()
            XCTAssertGreaterThanOrEqual(fcntl(descriptor, F_GETFD), 0)
            XCTAssertEqual(try sendReferences(admission.port), 1); XCTAssertEqual(try sendReferences(terminal.port), 1)
            XCTAssertThrowsError(try receiver(endpoint).receiveNext(timeoutMilliseconds: 1)) {
                XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
            }
        }
        var retained = Data(count: untouched.count)
        let readCount = retained.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
        XCTAssertEqual(readCount, untouched.count); XCTAssertEqual(retained, untouched)
    }

    func testQueuedListenerBudgetCannotBypassPeerOrDescriptorChecks() throws {
        let endpoint = try Endpoint(), reply = try Endpoint()
        let offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: .admissionResults)
        try MachCommandWire.send(offer.canonicalBytes, destination: endpoint.port, replyPort: reply.port,
            identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
        XCTAssertThrowsError(try receiverWithExpiredAuthenticationBudget(endpoint, userID: geteuid() ^ 1).receiveNext(timeoutMilliseconds: 1)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .wrongPeer)
        }
        XCTAssertEqual(try sendReferences(reply.port), 1)
        try endpoint.sendInput(offer.canonicalBytes, fileport: reply.port, version: 1, descriptorCount: 2,
            identifier: MachCommandCallerReceiver.helloMessageID)
        XCTAssertThrowsError(try receiverWithExpiredAuthenticationBudget(endpoint).receiveNext(timeoutMilliseconds: 1)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .malformed)
        }
        XCTAssertEqual(try sendReferences(reply.port), 1)
    }

    func testReplyReceiversKeepStrictAuthenticationDeadlines() throws {
        for identifier in [MachCommandCallerReceiver.helloReplyMessageID, MachCommandCallerReceiver.admissionReplyMessageID,
                           MachCommandCallerReceiver.terminalReplyMessageID] {
            let endpoint = try Endpoint()
            try endpoint.send(Data([1]), identifier: identifier)
            let receive = try receiverWithExpiredAuthenticationBudget(endpoint)
            XCTAssertThrowsError(try {
                switch identifier {
                case MachCommandCallerReceiver.helloReplyMessageID:
                    let response = try receive.receiveHelloReply(timeoutMilliseconds: 1); response.caller.close()
                case MachCommandCallerReceiver.admissionReplyMessageID:
                    let response = try receive.receiveAdmissionReply(timeoutMilliseconds: 1); response.caller.close()
                default:
                    let response = try receive.receiveTerminalReply(timeoutMilliseconds: 1); response.caller.close()
                }
            }()) {
                if identifier == MachCommandCallerReceiver.terminalReplyMessageID {
                    XCTAssertEqual($0 as? CommandTerminalResultError, .deadlineExceeded)
                } else { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
            }
        }
    }

    func testExecutionEventReceiverDoesNotInheritListenerBudgetSemantics() throws {
        for identifier in [MachCommandCallerReceiver.streamOutputMessageID, MachCommandCallerReceiver.terminalReplyMessageID] {
            let endpoint = try Endpoint()
            try endpoint.send(Data([1]), identifier: identifier)
            XCTAssertThrowsError(try receiverWithExpiredAuthenticationBudget(endpoint).receiveExecutionEvent(timeoutMilliseconds: 1)) {
                if identifier == MachCommandCallerReceiver.terminalReplyMessageID {
                    XCTAssertEqual($0 as? CommandTerminalResultError, .deadlineExceeded)
                } else { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
            }
        }
    }
}
