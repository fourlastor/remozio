#!/usr/bin/env python3
"""Exercise the production loopback carrier with disposable sockets and TLS."""
import base64
import json
import os
from pathlib import Path
import select
import socket
import ssl
import struct
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]


def exact(sock, count):
    result = bytearray()
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise EOFError("Carrier closed")
        result.extend(chunk)
    return bytes(result)


def frame(opcode, payload, final=True):
    mask = b"\x01\x02\x03\x04"
    length = len(payload)
    prefix = bytes([(128 if final else 0) | opcode])
    prefix += bytes([128 | length]) if length < 126 else bytes([254]) + struct.pack("!H", length)
    return prefix + mask + bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))


def received(sock):
    header = exact(sock, 2)
    length = header[1] & 127
    if length == 126:
        length = struct.unpack("!H", exact(sock, 2))[0]
    if length > 32768 or header[1] & 128 or header[0] & 0x70:
        raise RuntimeError("Unexpected carrier frame")
    return header[0] & 15, exact(sock, length)


def binary(sock, length):
    result = bytearray()
    while len(result) < length:
        opcode, data = received(sock)
        if opcode != 2 or not data:
            raise RuntimeError("Expected binary carrier bytes")
        result.extend(data)
    if len(result) != length:
        raise RuntimeError("Unexpected extra carrier bytes")
    return bytes(result)


def upgrade(sock, *, protocol="remozio.ciphertext.v1", extensions=False):
    key = base64.b64encode(os.urandom(16)).decode()
    extra = "Sec-WebSocket-Extensions: permessage-deflate\r\n" if extensions else ""
    sock.sendall((f"GET /approval HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n"
                  f"Sec-WebSocket-Protocol: {protocol}\r\n{extra}\r\n").encode())
    headers = bytearray()
    while not headers.endswith(b"\r\n\r\n"):
        headers.extend(exact(sock, 1))
        if len(headers) > 16384:
            raise RuntimeError("Unbounded upgrade response")
    return bytes(headers)


class Probe:
    def __init__(self, executable, port, timeout=15000):
        self.process = subprocess.Popen([str(executable), "--target-port", str(port), "--timeout-ms", str(timeout)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            if not select.select([self.process.stdout], [], [], 5)[0]:
                raise RuntimeError("Relay readiness timed out")
            report = json.loads(self.process.stdout.readline())
            if report.get("schemaVersion") != 1 or not 1 <= report["port"] <= 65535:
                raise RuntimeError("Unexpected relay readiness report")
            self.port = report["port"]
        except BaseException:
            self.close()
            raise

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=5)

    def close(self):
        self.process.terminate()
        try:
            self.process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate()
            raise RuntimeError("Relay did not drain on termination")
        if self.process.returncode != 0:
            raise RuntimeError("Relay probe failed")


def framing(executable, mode):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(1)
    seen = bytearray()
    accepted = []
    failures = []

    def echo():
        try:
            raw, _ = listener.accept()
            accepted.append(True)
            with raw:
                raw.settimeout(6)
                while chunk := raw.recv(32768):
                    seen.extend(chunk)
                    raw.sendall(chunk)
        except socket.timeout:
            if mode not in ("wrongProtocol", "textRejected", "oversizeRejected", "fragmentedOversizeRejected"):
                failures.append("TCP fixture timed out")
        except OSError:
            if mode not in ("wrongProtocol", "textRejected", "oversizeRejected", "fragmentedOversizeRejected"):
                failures.append("TCP fixture failed")

    worker = threading.Thread(target=echo)
    probe = None
    worker_started = False
    expected = b""
    try:
        probe = Probe(executable, listener.getsockname()[1])
        with probe.connect() as sock:
            headers = upgrade(sock, protocol=("wrong.v1" if mode == "wrongProtocol" else
                                        "remozio.ciphertext.v2, remozio.ciphertext.v1" if mode == "protocolFallback" else
                                        "remozio.ciphertext.v1"),
                              extensions=mode == "extensionsNotNegotiated")
            worker.start()
            worker_started = True
            if mode == "wrongProtocol":
                if headers.startswith(b"HTTP/1.1 101"):
                    raise RuntimeError("Wrong subprotocol accepted")
            else:
                if not headers.startswith(b"HTTP/1.1 101") or b"remozio.ciphertext.v1" not in headers:
                    raise RuntimeError("Valid upgrade refused")
                if b"sec-websocket-extensions:" in headers.lower():
                    raise RuntimeError("Compression was negotiated")
                if mode == "fragmentedBinary":
                    expected = b"firstsecond"
                    sock.sendall(frame(2, b"first", False) + frame(0, b"second"))
                elif mode == "pingBinary":
                    sock.sendall(frame(9, b"ping"))
                    if received(sock) != (10, b"ping"):
                        raise RuntimeError("Ping response missing")
                    expected = b"opaque"
                    sock.sendall(frame(2, expected))
                elif mode == "binaryLimit":
                    expected = bytes(range(256)) * 128
                    sock.sendall(frame(2, expected))
                elif mode == "emptyBinary":
                    expected = b"after-empty"
                    sock.sendall(frame(2, b"") + frame(2, expected))
                elif mode in ("extensionsNotNegotiated", "protocolFallback"):
                    expected = b"uncompressed"
                    sock.sendall(frame(2, expected))
                else:
                    if mode == "fragmentedOversizeRejected":
                        sock.sendall(frame(2, b"x" * 16384, False) + frame(0, b"x" * 16385))
                    else:
                        sock.sendall(frame(1 if mode == "textRejected" else 2,
                                           b"text" if mode == "textRejected" else b"x" * 32769))
                    try:
                        opcode, _ = received(sock)
                        if opcode != 8:
                            raise RuntimeError("Invalid payload was forwarded")
                    except (EOFError, ConnectionResetError):
                        pass
                if expected and binary(sock, len(expected)) != expected:
                    raise RuntimeError("Opaque bytes changed")
        worker.join(timeout=2)
        if worker.is_alive() or failures or bytes(seen) != expected:
            raise RuntimeError(f"Carrier fixture did not finish correctly: {mode}")
        if mode in ("wrongProtocol", "textRejected", "oversizeRejected", "fragmentedOversizeRejected") and accepted:
            raise RuntimeError("Rejected upgrade reached the TCP destination")
    finally:
        listener.close()
        try:
            if probe is not None:
                probe.close()
        finally:
            if worker_started:
                worker.join(timeout=7)


def tls(executable):
    with tempfile.TemporaryDirectory(prefix="remozio-relay-tls-") as directory:
        root = Path(directory)
        certificate, key = root / "certificate.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-keyout", str(key), "-out", str(certificate), "-days", "1", "-nodes", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost", "-addext", "extendedKeyUsage=serverAuth,clientAuth"],
                       check=True, capture_output=True, timeout=10)
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.minimum_version = server.maximum_version = ssl.TLSVersion.TLSv1_3
        server.load_cert_chain(certificate, key)
        server.load_verify_locations(certificate)
        server.verify_mode = ssl.CERT_REQUIRED
        client = ssl.create_default_context(cafile=str(certificate))
        client.minimum_version = client.maximum_version = ssl.TLSVersion.TLSv1_3
        client.load_cert_chain(certificate, key)
        payload = os.urandom(50000)
        evidence, failures = {}, []
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(8)

        def serve():
            try:
                raw, _ = listener.accept()
                with server.wrap_socket(raw, server_side=True) as secure:
                    secure.settimeout(8)
                    evidence["clientCertificateVerified"] = bool(secure.getpeercert())
                    evidence["tlsVersion"] = secure.version()
                    data = exact(secure, len(payload))
                    if data != payload:
                        raise RuntimeError("TLS payload changed")
                    secure.sendall(data)
            except BaseException as error:
                failures.append(type(error).__name__)

        worker = threading.Thread(target=serve); worker.start()
        probe = Probe(executable, listener.getsockname()[1])
        try:
            with probe.connect() as sock:
                if not upgrade(sock).startswith(b"HTTP/1.1 101"):
                    raise RuntimeError("TLS carrier upgrade refused")
                incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                secure = client.wrap_bio(incoming, outgoing, server_hostname="localhost")

                def flush():
                    while outgoing.pending:
                        sock.sendall(frame(2, outgoing.read(32768)))

                def refill():
                    opcode, data = received(sock)
                    if opcode != 2 or not data:
                        raise RuntimeError("TLS carrier rejected")
                    incoming.write(data)

                while True:
                    try:
                        secure.do_handshake(); flush(); break
                    except ssl.SSLWantReadError:
                        flush(); refill()
                evidence["serverCertificateVerified"] = bool(secure.getpeercert())
                secure.write(payload); flush()
                result = bytearray()
                while len(result) < len(payload):
                    try:
                        result.extend(secure.read(32768))
                    except ssl.SSLWantReadError:
                        flush(); refill()
                if bytes(result) != payload:
                    raise RuntimeError("TLS round trip changed")
                evidence["opaqueRoundTripBytes"] = len(result)
            worker.join(timeout=3)
            if worker.is_alive() or failures:
                raise RuntimeError("TLS fixture did not finish")
        finally:
            listener.close(); probe.close(); worker.join(timeout=10)
    if root.exists():
        raise RuntimeError("Disposable TLS files remain")
    return evidence


def capacity_and_shutdown(executable):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0)); listener.listen(2); listener.settimeout(4)
    drained = threading.Event()
    failures = []

    def echo():
        try:
            raw, _ = listener.accept()
            with raw:
                raw.settimeout(6)
                while chunk := raw.recv(32768):
                    raw.sendall(chunk)
            drained.set()
        except OSError:
            failures.append("Active destination did not drain")

    worker = threading.Thread(target=echo); worker.start()
    probe = Probe(executable, listener.getsockname()[1])
    closed = False
    try:
        with probe.connect() as first:
            if not upgrade(first).startswith(b"HTTP/1.1 101"):
                raise RuntimeError("First connection refused")
            first.sendall(frame(2, b"held"))
            if binary(first, 4) != b"held":
                raise RuntimeError("First connection unavailable")
            with probe.connect() as second:
                try:
                    response = upgrade(second)
                    if response.startswith(b"HTTP/1.1 101"):
                        raise RuntimeError("Connection cap was exceeded")
                except (EOFError, ConnectionResetError):
                    pass
            probe.close(); closed = True
            if not drained.wait(3):
                raise RuntimeError("Owner shutdown left its destination open")
            try:
                opcode, _ = received(first)
                if opcode != 8:
                    raise RuntimeError("Owner shutdown left its client open")
            except (EOFError, ConnectionResetError):
                pass
        worker.join(timeout=2)
        if worker.is_alive() or failures:
            raise RuntimeError("Active shutdown fixture did not finish")
        listener.settimeout(0.3)
        try:
            extra, _ = listener.accept()
            extra.close()
            raise RuntimeError("Rejected second client opened a destination")
        except socket.timeout:
            pass
    finally:
        if not closed:
            probe.close()
        listener.close(); worker.join(timeout=7)


def silent_client_deadline(executable):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(0.3)
    probe = Probe(executable, listener.getsockname()[1], timeout=300)
    try:
        with probe.connect() as sock:
            sock.settimeout(3)
            try:
                if sock.recv(1):
                    raise RuntimeError("Silent upgrade received application output")
            except ConnectionResetError:
                pass
        try:
            extra, _ = listener.accept()
            extra.close()
            raise RuntimeError("Silent upgrade opened a destination")
        except socket.timeout:
            pass
    finally:
        listener.close(); probe.close()


def main():
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise RuntimeError("Run the disposable relay experiment as an ordinary user")
    package = ROOT / "experiments/macos"
    subprocess.run(["swift", "build", "--package-path", str(package), "--triple", "arm64-apple-macosx26.0",
                    "--product", "ApprovalRelayProbe", "--disable-keychain", "--disable-netrc"],
                   check=True, capture_output=True, text=True, timeout=600)
    binary_dir = subprocess.check_output(["swift", "build", "--package-path", str(package),
        "--triple", "arm64-apple-macosx26.0", "--show-bin-path"], text=True, timeout=30).strip()
    executable = Path(binary_dir) / "ApprovalRelayProbe"
    cases = ["fragmentedBinary", "pingBinary", "binaryLimit", "wrongProtocol", "textRejected",
             "oversizeRejected", "fragmentedOversizeRejected", "emptyBinary", "extensionsNotNegotiated", "protocolFallback"]
    for case in cases:
        framing(executable, case)
    capacity_and_shutdown(executable)
    silent_client_deadline(executable)
    evidence = tls(executable)
    if evidence.get("tlsVersion") != "TLSv1.3" or not all(evidence.get(field) for field in
            ("clientCertificateVerified", "serverCertificateVerified")):
        raise RuntimeError("Mutual TLS did not pass")
    evidence.update(experiment="native-approval-relay", schemaVersion=1, status="passed", cases=cases,
                    hostMacOS=subprocess.check_output(["sw_vers", "-productVersion"], text=True).strip(),
                    loopbackOnly=True, connectionLimitVerified=True, activeShutdownDrained=True,
                    silentUpgradeDeadlineVerified=True, sameDisposableCertificateForBothRoles=True,
                    productionKeysUsed=False, cloudflareTested=False, androidDeviceTested=False,
                    enrolledRemozioExchangeTested=False)
    print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    main()
