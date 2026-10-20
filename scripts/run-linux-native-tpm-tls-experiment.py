#!/usr/bin/env python3
"""Opt-in disposable Swift/C/OpenSSL provider experiment; private simulator only."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import subprocess
import tempfile
import time

HARNESS = Path(__file__).with_name("run-linux-tpm-tls-experiment.py")
SPEC = importlib.util.spec_from_file_location("native_tpm_existing_harness", HARNESS)
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
Refused = BASE.Refused
FIELDS = {"status", "keyProviderTPM2", "signatureProviderTPM2", "clientVerificationRejected",
          "alpnRejected", "applicationBytesReceived", "applicationBytesSent", "signatureBytes"}
STATUSES = {"ok", "environment", "provider", "key_load", "wrong_provider", "public_key", "sign", "io",
            "timeout", "client_verification", "alpn", "peer_closed", "payload", "tls", "argument", "certificate"}


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def native_report(data):
    try:
        if len(data) > 2048:
            raise ValueError()
        report = json.loads(data, object_pairs_hook=unique_fields)
        if set(report) != FIELDS or report["status"] not in STATUSES:
            raise ValueError()
        for field in ("keyProviderTPM2", "signatureProviderTPM2", "clientVerificationRejected", "alpnRejected"):
            if type(report[field]) is not bool:
                raise ValueError()
        for field in ("applicationBytesReceived", "applicationBytesSent", "signatureBytes"):
            if type(report[field]) is not int or not 0 <= report[field] <= 80:
                raise ValueError()
        return report
    except (ValueError, TypeError, KeyError):
        raise Refused("invalid-native-report") from None


def remaining_time(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise Refused("native-process-timeout")
    return remaining


def finish_native(process, deadline=None):
    try:
        timeout = BASE.DEADLINE if deadline is None else max(0, deadline - time.monotonic())
        return process.communicate(timeout=timeout)[0]
    except subprocess.TimeoutExpired:
        BASE.stop(process)
        if process.stdout:
            process.stdout.close()
        raise Refused("native-process-timeout") from None


class NativeExperiment(BASE.Experiment):
    def __init__(self, directory, env, tpm2, swtpm, abrmd, probe):
        super().__init__(directory, env, tpm2, swtpm, abrmd)
        self.probe = probe
        self.last_signature_bytes = 0

    def sign(self, purpose="authority", expected=True, env=None):
        if purpose not in ("authority", "healthy"):
            raise Refused("unsupported-native-signing-purpose")
        result = subprocess.run([str(self.probe), "sign", purpose], cwd=self.directory,
                                env=self.env if env is None else env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=BASE.DEADLINE)
        report = native_report(result.stdout)
        if (result.returncode == 0) != (report["status"] == "ok"):
            raise Refused("native-sign-exit-mismatch")
        if expected:
            if (report["status"] != "ok" or not report["keyProviderTPM2"] or
                    not report["signatureProviderTPM2"] or not 8 <= report["signatureBytes"] <= 80):
                raise Refused("native-provider-sign-failed")
            self.last_signature_bytes = report["signatureBytes"]
        return result

    def peer_public_key(self, deadline, *arguments, data=None):
        result = subprocess.run(["openssl", *arguments], cwd=self.directory, env=self.env,
            input=data, capture_output=True, timeout=remaining_time(deadline))
        if result.returncode != 0:
            raise Refused("native-peer-public-key-failed")
        return result.stdout

    def tls(self, control=None):
        # Keep the listener open through spawn; the child inherits this exact loopback socket.
        with socket.socket() as listener, tempfile.TemporaryFile() as diagnostics:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            deadline = time.monotonic() + BASE.DEADLINE
            server = subprocess.Popen([str(self.probe), "tls", str(listener.fileno())],
                cwd=self.directory, env=self.env, pass_fds=(listener.fileno(),),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=diagnostics)
            client_failure = None
            expected_pin_rejection = False
            try:
                if control == "stalled-client":
                    # TCP connects but sends no TLS bytes; the native absolute network deadline must fire.
                    with socket.create_connection(listener.getsockname(), timeout=min(4, remaining_time(deadline))):
                        report = native_report(finish_native(server, deadline))
                    if (report["status"] != "timeout" or server.returncode != 77 or
                            not report["keyProviderTPM2"] or report["applicationBytesReceived"] != 0 or
                            report["applicationBytesSent"] != 0):
                        raise Refused("native-network-timeout-control")
                    return True
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
                context.load_verify_locations(str(self.directory / "server.crt"))
                client = "wrong-client" if control == "wrong-client" else "client"
                context.load_cert_chain(str(self.directory / f"{client}.crt"), str(self.directory / f"{client}.key"))
                if control != "omitted-alpn":
                    context.set_alpn_protocols(["unrelated/1" if control == "wrong-alpn" else BASE.ALPN])
                try:
                    with socket.create_connection(listener.getsockname(), timeout=min(5, remaining_time(deadline))) as raw:
                        raw.settimeout(min(5, remaining_time(deadline)))
                        with context.wrap_socket(raw, server_hostname="localhost") as channel:
                            selected_alpn = None if control == "omitted-alpn" else BASE.ALPN
                            if channel.version() != "TLSv1.3" or channel.selected_alpn_protocol() != selected_alpn:
                                raise Refused("native-tls-profile")
                            public = self.peer_public_key(deadline, "x509", "-inform", "DER", "-pubkey", "-noout",
                                data=channel.getpeercert(binary_form=True))
                            actual = self.peer_public_key(deadline, "pkey", "-pubin", "-outform", "DER", data=public)
                            expected = self.peer_public_key(deadline, "pkey", "-pubin", "-outform", "DER",
                                data=(self.directory / "transport.spki").read_bytes())
                            pin = bytes(32) if control == "wrong-pin" else hashlib.sha256(expected).digest()
                            if hashlib.sha256(actual).digest() != pin:
                                expected_pin_rejection = control == "wrong-pin"
                                raise Refused("native-pin-rejected")
                            message = b"invalid\n" if control == "wrong-payload" else b"remozio-tpm-test\n"
                            channel.settimeout(remaining_time(deadline))
                            channel.sendall(message)
                            response = bytearray()
                            while len(response) < 17:
                                channel.settimeout(remaining_time(deadline))
                                chunk = channel.recv(128)
                                if not chunk:
                                    break
                                response.extend(chunk)
                            if control != "wrong-payload" and bytes(response) != b"tset-mpt-oizomer\n":
                                raise Refused("native-tls-payload")
                            if channel.session_reused or channel.session.has_ticket:
                                raise Refused("native-tls-resumption")
                except (ssl.SSLError, ConnectionError, Refused) as error:
                    client_failure = error
                report = native_report(finish_native(server, deadline))
                if (server.returncode == 0) != (report["status"] == "ok"):
                    raise Refused("native-tls-exit-mismatch")
                if not report["keyProviderTPM2"]:
                    raise Refused("native-tls-provider")
                if control == "wrong-pin":
                    accepted = (expected_pin_rejection and report["status"] in ("peer_closed", "tls") and
                        report["applicationBytesReceived"] == 0 and report["applicationBytesSent"] == 0)
                elif control == "wrong-client":
                    accepted = (isinstance(client_failure, (ssl.SSLError, ConnectionError)) and
                        report["status"] == "client_verification" and report["clientVerificationRejected"] and
                        report["applicationBytesReceived"] == 0 and report["applicationBytesSent"] == 0)
                elif control == "wrong-alpn":
                    accepted = (isinstance(client_failure, (ssl.SSLError, ConnectionError)) and report["status"] == "alpn" and
                        report["alpnRejected"] and report["applicationBytesReceived"] == 0 and report["applicationBytesSent"] == 0)
                elif control == "omitted-alpn":
                    # This peer deliberately attempts delivery after a handshake without ALPN.
                    # Checking only the Python peer would leave the native server bypass untested.
                    accepted = (report["status"] == "alpn" and report["alpnRejected"] and
                        report["applicationBytesReceived"] == 0 and report["applicationBytesSent"] == 0)
                elif control == "wrong-payload":
                    accepted = report["status"] == "payload" and report["applicationBytesSent"] == 0
                else:
                    accepted = (client_failure is None and report["status"] == "ok" and server.returncode == 0 and
                        report["applicationBytesReceived"] == 17 and report["applicationBytesSent"] == 17)
                if not accepted:
                    raise Refused("native-tls-control-failed")
                return True
            finally:
                BASE.stop(server)


def run_native(args):
    if platform.system() != "Linux" or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise Refused("requires-ordinary-linux-user")
    root = args.runtime_root.resolve()
    libs = root / "usr/lib/x86_64-linux-gnu"
    probe = args.probe.resolve()
    tools = [root / "usr/bin/tpm2", root / "usr/bin/swtpm", root / "usr/sbin/tpm2-abrmd"]
    if not probe.is_file() or not os.access(probe, os.X_OK) or not all(item.is_file() for item in tools):
        raise Refused("missing-native-simulator-dependencies")
    env = os.environ.copy()
    env.update(OPENSSL_CONF="/dev/null", OPENSSL_MODULES=str(libs / "ossl-modules"),
               LD_LIBRARY_PATH=f"{libs}:{libs / 'swtpm'}", TPM2TOOLS_AUTOFLUSH="yes")
    for name in ("TPM2TOOLS_TCTI", "TPM2OPENSSL_TCTI", "TPM2OPENSSL_PARENT_AUTH"):
        env.pop(name, None)
    checks = {}
    with tempfile.TemporaryDirectory(prefix="remozio-native-tpm-") as temporary:
        directory = Path(temporary)
        experiment = NativeExperiment(directory, env, *tools, probe)
        try:
            experiment.start()
            versions = {"openssl": experiment.openssl("version").stdout.decode().strip(),
                "tpm2Tools": BASE.tpm2_version(experiment.run(tools[0], "--version").stdout)}
            experiment.provision()
            (directory / "message").write_bytes(b"Remozio disposable authority signature fixture v1")
            experiment.verify()
            checks["nativeAuthorityProviderSignAndIndependentVerify"] = True
            checks["separateAuthorityAndTransportKeys"] = True
            original = (directory / "authority.pem").read_bytes()
            experiment.halt()
            experiment.start()
            experiment.verify()
            checks["nativeReopenAfterSimulatorRestart"] = (directory / "authority.pem").read_bytes() == original
            for kind, contents in (("missing", None), ("corrupt", b"invalid TPM key record")):
                record = directory / "authority.pem"
                record.unlink()
                if contents is not None:
                    record.write_bytes(contents)
                if experiment.sign(expected=False).returncode == 0:
                    raise Refused("native-invalid-record-signed")
                record.write_bytes(original)
                checks[f"native{kind.title()}RecordRejected"] = True
            unavailable = experiment.env.copy()
            unavailable["TPM2OPENSSL_TCTI"] = f"swtpm:path={directory / 'absent-tpm.sock'}"
            if experiment.sign(expected=False, env=unavailable).returncode == 0:
                raise Refused("native-unavailable-tpm-signed")
            checks["nativeUnavailableTPMRejected"] = True
            # Deliberately inherited device routing must fail before the native provider is opened.
            unsafe = experiment.env.copy()
            unsafe["TPM2OPENSSL_TCTI"] = "device:/dev/tpmrm0"
            rejected = experiment.sign(expected=False, env=unsafe)
            checks["nativeDeviceRouteRefusedBeforeProviderLoad"] = native_report(rejected.stdout)["status"] == "environment"
            experiment.certificates()
            record = directory / "authority.pem"
            record.write_bytes((directory / "client.key").read_bytes())
            rejected = experiment.sign(expected=False)
            checks["nativeSoftwarePrivateKeyRejected"] = native_report(rejected.stdout)["status"] == "wrong_provider"
            record.write_bytes(original)
            for control, name in ((None, "nativeMutualTLS13Exchange"), ("wrong-pin", "nativeWrongServerPinRejected"),
                ("wrong-client", "nativeWrongClientRejected"), ("wrong-alpn", "nativeWrongALPNRejected"),
                ("omitted-alpn", "nativeOmittedALPNRejected"),
                ("wrong-payload", "nativeWrongPayloadRefused"), ("stalled-client", "nativeStalledHandshakeTimesOut")):
                checks[name] = experiment.tls(control)
            # A transport identity must match the transport public sidecar before starting TLS.
            transport = directory / "transport.spki"
            saved_transport = transport.read_bytes()
            transport.write_bytes((directory / "authority.spki").read_bytes())
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0)); listener.listen(1)
                result = subprocess.run([str(probe), "tls", str(listener.fileno())], cwd=directory,
                    env=experiment.env, pass_fds=(listener.fileno(),), stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=BASE.DEADLINE)
            checks["nativeWrongTransportSPKIRejected"] = result.returncode == 77 and native_report(result.stdout)["status"] == "public_key"
            transport.write_bytes(saved_transport)
            certificate = directory / "server.crt"
            saved_certificate = certificate.read_bytes()
            certificate.write_bytes((directory / "client.crt").read_bytes())
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0)); listener.listen(1)
                result = subprocess.run([str(probe), "tls", str(listener.fileno())], cwd=directory,
                    env=experiment.env, pass_fds=(listener.fileno(),), stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=BASE.DEADLINE)
            checks["nativeMismatchedCertificateRejected"] = result.returncode == 77 and native_report(result.stdout)["status"] == "certificate"
            certificate.write_bytes(saved_certificate)
            experiment.halt()
            experiment.start("independent-state")
            experiment.tool("createprimary", "-C", "o", "-G", "ecc", "-a",
                "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt", "-c", "other-parent.ctx")
            experiment.tool("create", "-C", "other-parent.ctx", "-G", "ecc256", "-g", "sha256", "-a",
                "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda", "-u", "healthy.pub", "-r", "healthy.priv")
            BASE.signing_template((directory / "healthy.pub").read_bytes())
            experiment.tool("encodeobject", "-C", "o", "-u", "healthy.pub", "-r", "healthy.priv", "-o", "healthy.pem", "-p")
            experiment.openssl("pkey", *BASE.PROVIDERS, "-passin", "pass:", "-in", "healthy.pem", "-pubout", "-out", "healthy.spki")
            experiment.verify("healthy")
            checks["nativeIndependentSimulatorHealthyKeySigns"] = True
            checks["nativeOldRecordOnIndependentSimulatorRejected"] = experiment.sign(expected=False).returncode != 0
        finally:
            experiment.halt()
    checks["temporaryStateRemoved"] = not directory.exists()
    BASE.validate_checks(checks)
    sources = [Path(__file__), HARNESS]
    native_sources = Path(__file__).resolve().parents[1] / "experiments/linux-native-tpm-tls"
    sources += [native_sources / "Package.swift"] + sorted(path for path in (native_sources / "Sources").rglob("*")
        if path.is_file() and (path.suffix in (".c", ".h", ".swift") or path.name == "module.modulemap"))
    return {"experiment": "linux-native-tpm-tls", "schemaVersion": 1, "status": "passed",
        "evidenceClass": "native-swift-openssl-private-simulator-only", "checks": checks,
        "recordedAtUTC": datetime.now(timezone.utc).isoformat(), "toolVersions": versions,
        "runtime": {"os": platform.system(), "kernel": platform.release(), "architecture": platform.machine(),
            "tcti": "private session abrmd to private swtpm Unix socket", "maxChildSeconds": BASE.DEADLINE,
            "nativeNetworkDeadlineMilliseconds": 4000, "alpn": BASE.ALPN,
            "signatureRepresentation": "ASN.1 DER ECDSA/SHA256; no Remozio wire signature"},
        "nativeSwiftProviderSignTested": True, "nativeSwiftTLSProbeTested": True,
        "productionSwiftBridgeTested": False, "hardwareTPMTested": False,
        "protectedServiceAccountTested": False, "androidPeerTested": False,
        "nativeProbeSHA256": hashlib.sha256(probe.read_bytes()).hexdigest(),
        "sourceSHA256": {str(path.relative_to(Path(__file__).resolve().parents[1])): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in sources}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--simulator", action="store_true", required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        report = run_native(args)
    except Refused as error:
        print(json.dumps({"experiment": "linux-native-tpm-tls", "status": "blocked-or-failed", "reason": str(error),
                          "hardwareTPMTested": False}, sort_keys=True))
        return 77
    except (OSError, subprocess.TimeoutExpired, ValueError):
        print(json.dumps({"experiment": "linux-native-tpm-tls", "status": "blocked-or-failed",
                          "reason": "native-runtime-or-deadline-failure", "hardwareTPMTested": False}, sort_keys=True))
        return 77
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
