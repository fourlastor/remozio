#!/usr/bin/env python3
"""Opt-in TPM/OpenSSL integration: isolated simulator or explicit operator hardware probe."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time

ALPN = "remozio-experiment/1"
ATTRIBUTES = 0x00040472  # fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth, noDA, sign
PROVIDERS = ["-provider", "default", "-provider", "tpm2", "-propquery", "?provider=default"]
DEADLINE = 12


class Refused(RuntimeError):
    pass


def signing_template(blob):
    """Validate the complete TPM2B_PUBLIC P256 signing-only template, not tool text."""
    if len(blob) != 88 or struct.unpack_from(">H", blob)[0] != len(blob) - 2:
        raise Refused("malformed-public-record")
    kind, digest, attrs, authsize = struct.unpack_from(">HHIH", blob, 2)
    if (kind, digest, attrs, authsize) != (0x23, 0x0B, ATTRIBUTES, 0):
        raise Refused("unsupported-public-template")
    symmetric, scheme, curve, kdf, xsize = struct.unpack_from(">HHHHH", blob, 12)
    if (symmetric, scheme, curve, kdf, xsize) != (0x10, 0x10, 3, 0x10, 32):
        raise Refused("unsupported-ecc-parameters")
    if len(blob) != 88 or struct.unpack_from(">H", blob, 54)[0] != 32:
        raise Refused("malformed-ecc-point")
    return {"type": "ecc", "nameAlgorithm": "sha256", "curve": "nist_p256",
            "attributes": "0x00040472", "fixedTPM": True, "fixedParent": True,
            "sensitiveDataOrigin": True, "sign": True, "decrypt": False,
            "restricted": False, "userWithAuth": True, "noDA": True}



def validate_wrapped_record(record, public):
    """Bind assertions to the actual TSS2 record; refuse software PEM/substituted metadata."""
    lines = record.splitlines()
    if not lines or lines[0] != b"-----BEGIN TSS2 PRIVATE KEY-----" or lines[-1] != b"-----END TSS2 PRIVATE KEY-----":
        raise Refused("not-a-tss2-wrapped-record")
    der = base64.b64decode(b"".join(lines[1:-1]), validate=True)

    def take(data, offset):
        if offset + 2 > len(data):
            raise Refused("malformed-tss2-record")
        tag, length = data[offset], data[offset + 1]
        offset += 2
        if length & 0x80:
            count = length & 0x7F
            if count not in (1, 2) or offset + count > len(data):
                raise Refused("malformed-tss2-length")
            length = int.from_bytes(data[offset:offset + count], "big")
            offset += count
        end = offset + length
        if end > len(data):
            raise Refused("truncated-tss2-record")
        return tag, data[offset:end], end

    tag, body, end = take(der, 0)
    if tag != 0x30 or end != len(der):
        raise Refused("malformed-tss2-sequence")
    fields, offset = [], 0
    while offset < len(body):
        tag, value, offset = take(body, offset)
        fields.append((tag, value))
    if len(fields) != 5 or fields[1] not in ((0xA0, b"\x01\x01\xff"), (0xA0, b"\x01\x01\x01")):
        raise Refused("fixture-auth-indicator-not-empty")
    if len(fields) == 5 and fields[1][0] == 0xA0:
        empty_auth = fields.pop(1)[1]
        if empty_auth not in (b"\x01\x01\xff", b"\x01\x01\x01"):
            raise Refused("fixture-auth-indicator-not-empty")
    if (len(fields) != 4 or fields[0] != (6, bytes.fromhex("6781050a0103")) or
            fields[1] != (2, bytes.fromhex("40000001")) or fields[2] != (4, public) or fields[3][0] != 4):
        raise Refused("wrapped-record-public-or-parent-mismatch")
    private = fields[3][1]
    if len(private) < 3 or int.from_bytes(private[:2], "big") != len(private) - 2:
        raise Refused("malformed-tpm-private-record")
    signing_template(public)

def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


class Experiment:
    def __init__(self, directory, env, tpm2, swtpm, abrmd):
        self.directory, self.env = directory, env
        self.tpm2, self.swtpm, self.abrmd = tpm2, swtpm, abrmd
        self.broker = self.bus = None
        self.process = None
        self.socket = directory / "tpm.sock"
        self.env.update(TPM2TOOLS_TCTI="tabrmd:bus_type=session",
                        TPM2OPENSSL_TCTI="tabrmd:bus_type=session",
                        DBUS_SESSION_BUS_ADDRESS=f"unix:path={directory / 'bus.sock'}")

    def run(self, *args, expected=True, data=None):
        result = subprocess.run([str(a) for a in args], cwd=self.directory, env=self.env,
                                input=data, capture_output=True, timeout=DEADLINE)
        if expected and result.returncode:
            # Keep reports free of key material, paths, device identifiers, command output.
            raise Refused(f"command-failed:{Path(str(args[0])).name}:{args[1]}")
        return result

    def tool(self, *args):
        return self.run(self.tpm2, *args)

    def openssl(self, *args, **kwargs):
        return self.run("openssl", *args, **kwargs)

    def start(self, state="state"):
        directory = self.directory / state
        directory.mkdir(exist_ok=True, mode=0o700)
        self.process = subprocess.Popen([
            str(self.swtpm), "socket", "--tpm2", "--tpmstate", f"dir={directory}",
            "--server", f"type=unixio,path={self.socket}",
            "--ctrl", f"type=unixio,path={self.socket}.ctrl",
            "--flags", "not-need-init,startup-clear"], env=self.env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 3
        while not self.socket.exists():
            if self.process.poll() is not None or time.monotonic() > deadline:
                raise Refused("simulator-start-failed")
            time.sleep(.02)
        self.bus = subprocess.Popen(["dbus-daemon", "--session", "--nofork",
                                     f"--address={self.env['DBUS_SESSION_BUS_ADDRESS']}"],
                                    env=self.env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 3
        while not (self.directory / "bus.sock").exists():
            if self.bus.poll() is not None or time.monotonic() > deadline:
                raise Refused("private-bus-start-failed")
            time.sleep(.02)
        self.broker = subprocess.Popen([str(self.abrmd), "--session", "--max-transients=8",
                                        f"--tcti=swtpm:path={self.socket}"], env=self.env,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 4
        while self.run(self.tpm2, "getcap", "properties-fixed", expected=False).returncode:
            if self.broker.poll() is not None or time.monotonic() > deadline:
                raise Refused("private-resource-manager-start-failed")
            time.sleep(.05)

    def halt(self):
        for process in (self.broker, self.bus):
            if process:
                stop(process)
        self.broker = self.bus = None
        (self.directory / "bus.sock").unlink(missing_ok=True)
        if self.process:
            stop(self.process)
            self.process = None
        for path in (self.socket, Path(f"{self.socket}.ctrl")):
            path.unlink(missing_ok=True)

    def provision(self):
        # The lifecycle selects a private simulator or an explicit operator-approved TPM RM.
        # Match tpm2-openssl 1.3.0 primaryEccTemplate, including noDA, exactly.
        self.tool("createprimary", "-C", "o", "-G", "ecc", "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt", "-c", "parent.ctx")
        for purpose in ("authority", "transport"):
            self.tool("create", "-C", "parent.ctx", "-G", "ecc256", "-g", "sha256",
                      "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda",
                      "-u", f"{purpose}.pub", "-r", f"{purpose}.priv")
            signing_template((self.directory / f"{purpose}.pub").read_bytes())
            self.tool("encodeobject", "-C", "o", "-u", f"{purpose}.pub",
                      "-r", f"{purpose}.priv", "-o", f"{purpose}.pem", "-p")
            validate_wrapped_record((self.directory / f"{purpose}.pem").read_bytes(),
                                    (self.directory / f"{purpose}.pub").read_bytes())
            self.openssl("pkey", *PROVIDERS, "-passin", "pass:", "-in", f"{purpose}.pem",
                         "-pubout", "-out", f"{purpose}.spki")
        if (self.directory / "authority.spki").read_bytes() == (self.directory / "transport.spki").read_bytes():
            raise Refused("key-purpose-collision")

    def sign(self, purpose="authority", expected=True, env=None):
        prior = self.env
        if env is not None:
            self.env = env
        try:
            return self.openssl("dgst", *PROVIDERS, "-sha256", "-sign", f"{purpose}.pem",
                                "-passin", "pass:", "-out", "signature.der", "message",
                                expected=expected)
        finally:
            self.env = prior

    def verify(self, purpose="authority"):
        self.sign(purpose)
        self.openssl("dgst", "-sha256", "-verify", f"{purpose}.spki", "-signature", "signature.der", "message")

    def certificates(self):
        self.openssl("req", *PROVIDERS, "-new", "-x509", "-passin", "pass:",
                     "-key", "transport.pem", "-subj", "/CN=localhost", "-days", "1",
                     "-addext", "subjectAltName=DNS:localhost", "-out", "server.crt")
        for name in ("client", "wrong-client"):
            self.openssl("req", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                         "-noenc", "-keyout", f"{name}.key", "-out", f"{name}.crt", "-days", "1",
                         "-subj", f"/CN={name}")

    def tls(self, control=None):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        with tempfile.TemporaryFile() as output:
            command = ["openssl", "s_server", *PROVIDERS, "-accept", f"127.0.0.1:{port}",
                       "-cert", "server.crt", "-key", "transport.pem", "-pass", "pass:",
                       "-Verify", "1", "-verify_return_error", "-CAfile", "client.crt",
                       "-no-CApath", "-no-CAstore", "-tls1_3", "-alpn", ALPN,
                       "-no_ticket", "-num_tickets", "0", "-max_early_data", "0",
                       "-naccept", "1", "-rev"]
            server = subprocess.Popen(command, cwd=self.directory, env=self.env, stdin=subprocess.DEVNULL,
                                      stdout=output, stderr=output)
            try:
                deadline = time.monotonic() + 4
                while True:
                    output.seek(0)
                    if b"ACCEPT" in output.read():
                        break
                    if server.poll() is not None or time.monotonic() > deadline:
                        raise Refused("tls-listener-not-ready")
                    time.sleep(.02)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
                ctx.load_verify_locations(str(self.directory / "server.crt"))
                name = "wrong-client" if control == "wrong-client" else "client"
                ctx.load_cert_chain(str(self.directory / f"{name}.crt"), str(self.directory / f"{name}.key"))
                ctx.set_alpn_protocols(["unrelated/1" if control == "wrong-alpn" else ALPN])
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=4) as raw:
                        with ctx.wrap_socket(raw, server_hostname="localhost") as channel:
                            if channel.version() != "TLSv1.3":
                                raise Refused("tls-version")
                            if channel.selected_alpn_protocol() != ALPN:
                                raise Refused("tls-alpn-rejected")
                            # Explicit SPKI pin check before sending application bytes.
                            public = self.openssl("x509", "-inform", "DER", "-pubkey", "-noout",
                                                  data=channel.getpeercert(binary_form=True)).stdout
                            actual_der = self.openssl("pkey", "-pubin", "-outform", "DER", data=public).stdout
                            pinned_der = self.openssl("pkey", "-pubin", "-outform", "DER",
                                                      data=(self.directory / "transport.spki").read_bytes()).stdout
                            pin = hashlib.sha256(actual_der).digest()
                            expected = hashlib.sha256(pinned_der).digest()
                            if control == "wrong-pin":
                                expected = bytes(32)
                            if pin != expected:
                                raise Refused("tls-pin-rejected")
                            channel.sendall(b"remozio-tpm-test\n")
                            if channel.recv(128) != b"tset-mpt-oizomer\n":
                                raise Refused("tls-payload")
                            if channel.session_reused or channel.session.has_ticket:
                                raise Refused("tls-resumption")
                except (ssl.SSLError, Refused) as error:
                    if control == "wrong-pin" and str(error) == "tls-pin-rejected":
                        return True
                    if control == "wrong-alpn":
                        if str(error) == "tls-alpn-rejected":
                            return True
                        if isinstance(error, ssl.SSLError):
                            server.wait(timeout=4)
                            output.seek(0)
                            if b"no application protocol" in output.read():
                                return True
                        raise Refused("missing-alpn-verifier-rejection")
                    if control != "wrong-client" or not isinstance(error, ssl.SSLError):
                        raise
                    # A client read failure alone is insufficient: require server's verify error.
                    server.wait(timeout=4)
                    output.seek(0)
                    if b"certificate verify failed" not in output.read():
                        raise Refused("missing-client-verifier-rejection")
                    return True
                if control:
                    raise Refused("negative-control-opened")
                return True
            finally:
                stop(server)


def validate_checks(checks):
    if any(value is not True for name, value in checks.items() if name != "signingTemplate"):
        raise Refused("incomplete-or-failed-check")


def run_experiment(args):
    if platform.system() != "Linux" or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise Refused("requires-ordinary-linux-user")
    env = os.environ.copy()
    # Ignore inherited provider configs/TCTIs: the experiment chooses its own simulator.
    env["OPENSSL_CONF"] = "/dev/null"
    env["TPM2TOOLS_AUTOFLUSH"] = "yes"
    for name in ("TPM2TOOLS_TCTI", "TPM2OPENSSL_TCTI", "TPM2OPENSSL_PARENT_AUTH"):
        env.pop(name, None)
    if args.runtime_root:
        root = args.runtime_root.resolve()
        libs = root / "usr/lib/x86_64-linux-gnu"
        env["LD_LIBRARY_PATH"] = f"{libs}:{libs / 'swtpm'}"
        env["OPENSSL_MODULES"] = str(libs / "ossl-modules")
        tpm2, swtpm = root / "usr/bin/tpm2", root / "usr/bin/swtpm"
        abrmd = root / "usr/sbin/tpm2-abrmd"
    else:
        tpm2, swtpm = shutil.which("tpm2"), shutil.which("swtpm")
        abrmd = shutil.which("tpm2-abrmd")
    if not all(item and Path(item).is_file() for item in (tpm2, swtpm, abrmd)) or not shutil.which("dbus-daemon"):
        raise Refused("missing-simulator-dependencies")
    checks = {}
    with tempfile.TemporaryDirectory(prefix="remozio-tpm-") as temporary:
        directory = Path(temporary)
        e = Experiment(directory, env, tpm2, swtpm, abrmd)
        try:
            e.start()
            versions = {
                "opensslCLI": e.run("openssl", "version").stdout.decode().strip(),
                "tpm2Tools": e.run(tpm2, "--version").stdout.decode().strip(),
                "swtpm": e.run(swtpm, "--version").stdout.decode().splitlines()[0],
                "abrmd": e.run(abrmd, "--version").stdout.decode().strip(),
            }
            e.provision()
            checks["signingTemplate"] = signing_template((directory / "authority.pub").read_bytes())
            checks["separatePurposeKeys"] = True
            (directory / "message").write_bytes(b"Remozio disposable authority signature fixture v1")
            e.verify()
            checks["createReopenSignVerify"] = True
            original = (directory / "authority.pem").read_bytes()
            e.halt()
            e.start()
            e.verify()
            checks["simulatorProcessRestartRetention"] = (directory / "authority.pem").read_bytes() == original
            for kind, contents in (("missing", None), ("corrupt", b"invalid TPM key record")):
                key = directory / "authority.pem"
                key.unlink()
                if contents is not None:
                    key.write_bytes(contents)
                if e.sign(expected=False).returncode == 0:
                    raise Refused("invalid-record-signed")
                key.write_bytes(original)
                checks[f"{kind}RecordRejected"] = True
            # TPM key cannot be exported as a software EC scalar.
            exported = e.openssl("pkey", *PROVIDERS, "-passin", "pass:", "-in", "authority.pem",
                                 "-outform", "DER", expected=False)
            if exported.returncode != 0 or not exported.stdout:
                raise Refused("opaque-key-serialization-failed")
            if exported.returncode == 0:
                # Provider DER is opaque TSS2, not a software private key; ask only default provider to decode.
                decoded = e.openssl("pkey", "-provider", "default", "-inform", "DER", "-text", "-noout",
                                    data=exported.stdout, expected=False)
                if decoded.returncode == 0:
                    raise Refused("software-private-key-exported")
            checks["softwarePrivateScalarExportRejected"] = True
            unavailable = e.env.copy()
            unavailable["TPM2OPENSSL_TCTI"] = f"swtpm:path={directory / 'absent-tpm.sock'}"
            if e.sign(expected=False, env=unavailable).returncode == 0:
                raise Refused("unavailable-tpm-signed")
            checks["unavailableTPMSigningRejected"] = True
            e.certificates()
            software_der = e.openssl("pkey", "-provider", "default", "-in", "client.key", "-outform", "DER").stdout
            e.openssl("pkey", "-provider", "default", "-inform", "DER", "-text", "-noout", data=software_der)
            checks["softwarePrivateKeyDecoderHealthyControl"] = True
            checks["tls13OnlyALPNNoTicketsNoEarlyDataConfigured"] = True
            for control, field in ((None, "mutualTLS13Exchange"), ("wrong-pin", "wrongServerSPKIPinRejected"),
                                   ("wrong-client", "wrongClientCertificateRejected"), ("wrong-alpn", "wrongALPNRejected")):
                checks[field] = e.tls(control)
            e.halt()
            e.start("independent-state")
            # Recreate same transient parent template on a different seed, not copied state.
            e.tool("createprimary", "-C", "o", "-G", "ecc", "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt", "-c", "other-parent.ctx")
            e.tool("create", "-C", "other-parent.ctx", "-G", "ecc256", "-g", "sha256",
                   "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda",
                   "-u", "healthy.pub", "-r", "healthy.priv")
            signing_template((directory / "healthy.pub").read_bytes())
            e.tool("encodeobject", "-C", "o", "-u", "healthy.pub", "-r", "healthy.priv", "-o", "healthy.pem", "-p")
            e.openssl("pkey", *PROVIDERS, "-passin", "pass:", "-in", "healthy.pem", "-pubout", "-out", "healthy.spki")
            e.verify("healthy")
            checks["independentSimulatorFreshKeySignVerify"] = True
            if e.sign(expected=False).returncode == 0:
                raise Refused("independent-tpm-accepted-key")
            checks["wrappedRecordOnIndependentSimulatorRejected"] = True
        finally:
            e.halt()
    checks["temporaryStateRemoved"] = not directory.exists()
    validate_checks(checks)
    return {"experiment": "linux-tpm-tls", "schemaVersion": 1, "status": "passed",
            "evidenceClass": "software-tpm-simulator-only", "checks": checks,
            "recordedAtUTC": datetime.now(timezone.utc).isoformat(), "toolVersions": versions,
            "runtime": {"os": platform.system(), "kernel": platform.release(), "architecture": platform.machine(),
                        "openssl": ssl.OPENSSL_VERSION, "tcti": "tabrmd:bus_type=session -> swtpm:private-unix-socket",
                        "resourceManager": "private tpm2-abrmd; max-transients=8; sequential operations; one TLS listener/client",
                        "clientTLSLibrary": ssl.OPENSSL_VERSION, "serverPinAtClient": "SHA256(SPKI DER)",
                        "clientIdentityAtServer": "designated self-signed fixture certificate trust anchor",
                        "alpn": ALPN, "maxCommandSeconds": DEADLINE},
            "hardwareTPMTested": False, "hardwareRebootTested": False, "protectedServiceAccountTested": False,
            "androidPeerTested": False, "productionSwiftBridgeTested": False,
            "scriptSHA256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


# Hardware mode uses the proven transient parent/key adapter, with a distinct
# lifecycle: it cannot construct/start a simulator or a resource-manager service.
class HardwareProbe(Experiment):
    def __init__(self, directory, env, tpm2):
        self.directory, self.env, self.tpm2 = directory, env, tpm2

    def start(self, *args):
        raise Refused("hardware-lifecycle-cannot-start-services")

    def halt(self):
        raise Refused("hardware-lifecycle-cannot-stop-services")


HARDWARE_RECORDS = ("authority.pub", "authority.pem", "authority.spki",
                    "transport.pub", "transport.pem", "transport.spki", "manifest.json")


def hardware_directory(path, create):
    import stat
    path = Path(os.path.abspath(path))
    # Reject links and untrusted/writable ancestors. A root-owned sticky /tmp is safe
    # only beneath a private ordinary-user-owned immediate parent.
    system_owner = Path("/").stat().st_uid
    for ancestor in (path.parent, *path.parent.parents):
        info = ancestor.lstat()
        trusted_sticky = info.st_uid == system_owner and bool(info.st_mode & stat.S_ISVTX)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (system_owner, os.getuid()) or
                (info.st_mode & 0o022 and not trusted_sticky)):
            raise Refused("unsafe-hardware-directory-ancestor")
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
        raise Refused("hardware-directory-needs-private-user-parent")
    if create:
        if path.exists() or path.is_symlink():
            raise Refused("hardware-fixture-already-exists")
        return path
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700:
        raise Refused("unsafe-hardware-directory")
    if set(item.name for item in path.iterdir()) != set(HARDWARE_RECORDS):
        raise Refused("missing-or-unexpected-hardware-records")
    for name in HARDWARE_RECORDS:
        info = (path / name).lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_nlink != 1 or info.st_mode & 0o777 != 0o600 or not 0 < info.st_size < 65536):
            raise Refused("unsafe-hardware-record")
    if json.loads((path / "manifest.json").read_text()) != {
            "experiment": "linux-tpm-tls-disposable-hardware-fixture", "schemaVersion": 1}:
        raise Refused("wrong-hardware-fixture-kind")
    return path


def run_hardware(args):
    if platform.system() != "Linux" or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise Refused("requires-ordinary-linux-user")
    if args.tcti != "device:/dev/tpmrm0" or not args.acknowledge_empty_owner_auth:
        raise Refused("hardware-needs-explicit-resource-manager-and-known-empty-owner-auth")
    if not args.hardware_directory or args.create_fixture == args.reuse_fixture:
        raise Refused("hardware-needs-directory-and-exactly-one-fixture-action")
    if args.operator_phase != "initial" and args.create_fixture:
        raise Refused("restart-phase-cannot-create-new-identity")
    retained = hardware_directory(args.hardware_directory, args.create_fixture)
    if not os.access("/dev/tpmrm0", os.R_OK | os.W_OK):
        raise Refused("hardware-resource-manager-access-unavailable")
    env = os.environ.copy()
    env["OPENSSL_CONF"] = "/dev/null"
    env["TPM2TOOLS_AUTOFLUSH"] = "yes"
    env.pop("TPM2OPENSSL_PARENT_AUTH", None)
    env.update(TPM2TOOLS_TCTI=args.tcti, TPM2OPENSSL_TCTI=args.tcti)
    if args.runtime_root:
        libs = args.runtime_root.resolve() / "usr/lib/x86_64-linux-gnu"
        env["LD_LIBRARY_PATH"] = f"{libs}:{libs / 'swtpm'}"
        env["OPENSSL_MODULES"] = str(libs / "ossl-modules")
        tpm2 = args.runtime_root.resolve() / "usr/bin/tpm2"
    else:
        tpm2 = shutil.which("tpm2")
    if not tpm2 or not Path(tpm2).is_file():
        raise Refused("missing-tpm2-tools")
    checks = {}
    with tempfile.TemporaryDirectory(prefix="remozio-hardware-probe-") as temporary:
        directory = Path(temporary)
        e = HardwareProbe(directory, env, tpm2)
        if args.create_fixture:
            e.provision()
            (directory / "manifest.json").write_text(json.dumps({
                "experiment": "linux-tpm-tls-disposable-hardware-fixture", "schemaVersion": 1}))
        else:
            for name in HARDWARE_RECORDS:
                (directory / name).write_bytes((retained / name).read_bytes())
        for purpose in ("authority", "transport"):
            validate_wrapped_record((directory / f"{purpose}.pem").read_bytes(),
                                    (directory / f"{purpose}.pub").read_bytes())
            actual = e.openssl("pkey", *PROVIDERS, "-passin", "pass:", "-in", f"{purpose}.pem", "-pubout").stdout
            if actual != (directory / f"{purpose}.spki").read_bytes():
                raise Refused("hardware-public-identity-mismatch")
        checks["signingTemplate"] = signing_template((directory / "authority.pub").read_bytes())
        if (directory / "authority.spki").read_bytes() == (directory / "transport.spki").read_bytes():
            raise Refused("key-purpose-collision")
        checks["separatePurposeKeys"] = True
        (directory / "message").write_bytes(b"Remozio disposable hardware signature fixture v1")
        for purpose in ("authority", "transport"):
            e.verify(purpose)
        checks["bothKeysReopenedAndSignaturesVerified"] = True
        # Damage only temporary copies, never the operator's retained records.
        original = (directory / "authority.pem").read_bytes()
        for kind, contents in (("missing", None), ("corrupt", b"invalid TPM key record")):
            (directory / "authority.pem").unlink()
            if contents is not None:
                (directory / "authority.pem").write_bytes(contents)
            if e.sign(expected=False).returncode == 0:
                raise Refused("invalid-record-signed")
            (directory / "authority.pem").write_bytes(original)
            checks[f"{kind}RecordRejected"] = True
        unavailable = env.copy()
        unavailable["TPM2OPENSSL_TCTI"] = f"swtpm:path={directory / 'absent-tpm.sock'}"
        if e.sign(expected=False, env=unavailable).returncode == 0:
            raise Refused("unavailable-tpm-signed")
        checks["unavailableTPMSigningRejected"] = True
        opaque = e.openssl("pkey", *PROVIDERS, "-passin", "pass:", "-in", "authority.pem", "-outform", "DER").stdout
        if not opaque or e.openssl("pkey", "-provider", "default", "-inform", "DER", "-text", "-noout",
                                  data=opaque, expected=False).returncode == 0:
            raise Refused("software-private-key-exported-or-empty")
        checks["softwarePrivateScalarExportRejected"] = True
        e.certificates()
        software = e.openssl("pkey", "-provider", "default", "-in", "client.key", "-outform", "DER").stdout
        e.openssl("pkey", "-provider", "default", "-inform", "DER", "-text", "-noout", data=software)
        checks["softwarePrivateKeyDecoderHealthyControl"] = True
        for control, name in ((None, "mutualTLS13Exchange"), ("wrong-pin", "wrongServerSPKIPinRejected"),
                              ("wrong-client", "wrongClientCertificateRejected"), ("wrong-alpn", "wrongALPNRejected")):
            checks[name] = e.tls(control)
        validate_checks(checks)
        if args.create_fixture:
            # mkdir and exclusive file creation refuse overwriting even if raced.
            retained.mkdir(mode=0o700)
            for name in HARDWARE_RECORDS:
                fd = os.open(retained / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write((directory / name).read_bytes())
    checks["temporaryTLSStateRemoved"] = not directory.exists()
    validate_checks(checks)
    return {"experiment": "linux-tpm-tls", "schemaVersion": 1, "status": "passed",
            "evidenceClass": "operator-selected-tpmrm-device", "hardwareTPMTested": False,
            "tpmResourceManagerDeviceTested": True, "physicalHardwareTPMVerified": False,
            "hardwareRebootAutomaticallyVerified": False, "operatorDeclaredPhase": args.operator_phase,
            "retainedFixtureCreated": args.create_fixture, "retainedIdentityReopened": args.reuse_fixture,
            "checks": checks, "recordedAtUTC": datetime.now(timezone.utc).isoformat(),
            "runtime": {"kernel": platform.release(), "architecture": platform.machine(), "tcti": args.tcti,
                        "resourceManager": "kernel /dev/tpmrm0; one TLS pair at a time",
                        "serverPinAtClient": "SHA256(SPKI DER)",
                        "clientIdentityAtServer": "designated self-signed fixture certificate trust anchor",
                        "alpn": ALPN},
            "protectedServiceAccountTested": False, "androidPeerTested": False,
            "productionSwiftBridgeTested": False,
            "scriptSHA256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--simulator", action="store_true", help="Use a private disposable software TPM")
    mode.add_argument("--hardware", action="store_true", help="Operator-only: explicitly use the hardware RM")
    parser.add_argument("--tcti", help="Hardware mode requires exactly device:/dev/tpmrm0")
    parser.add_argument("--acknowledge-empty-owner-auth", action="store_true",
                        help="Operator declares owner auth is known empty; do not probe unknown auth")
    parser.add_argument("--hardware-directory", type=Path, help="Retained disposable hardware fixture directory")
    parser.add_argument("--create-fixture", action="store_true")
    parser.add_argument("--reuse-fixture", action="store_true")
    parser.add_argument("--operator-phase", choices=("initial", "after-service-restart", "after-reboot"), default="initial")
    parser.add_argument("--runtime-root", type=Path, help="Optional extracted Ubuntu amd64 package root")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.simulator and any((args.tcti, args.acknowledge_empty_owner_auth, args.hardware_directory,
                                   args.create_fixture, args.reuse_fixture, args.operator_phase != "initial")):
            raise Refused("simulator-refuses-hardware-options")
        report = run_hardware(args) if args.hardware else run_experiment(args)
    except (Refused, OSError, ValueError, subprocess.TimeoutExpired) as error:
        # Do not print subprocess output or arbitrary exception paths.
        reason = str(error) if isinstance(error, Refused) else type(error).__name__
        print(json.dumps({"experiment": "linux-tpm-tls", "schemaVersion": 1, "status": "blocked",
                          "reason": reason, "hardwareTPMTested": False}, sort_keys=True))
        return 77
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
