# Linux TPM and real TLS experiment

[Recorded simulator evidence](linux-tpm-tls-evidence.json) demonstrates a TPM-provider
P-256 signing key completing actual mutual TLS 1.3 through OpenSSL 3.5.3. This is
**software TPM simulator evidence only**. It does not establish physical TPM
nonexportability, reboot retention, protected account access or Android interoperability.

The host used Ubuntu 25.10 amd64, kernel 6.17.0-41-generic. Ubuntu packages were
downloaded and extracted under `/tmp`; no packages or services were installed.
The runner did not open `/dev/tpm0` or `/dev/tpmrm0`, change their permissions,
clear a TPM, or change a system service. Simulator state, wrapped keys, certificates,
software client keys and signatures lived in a private temporary directory removed
on completion. The report contains assertions and runtime metadata only.

## What passed

| Control | Result and boundary |
| --- | --- |
| Create, reopen, sign, verify | Separate authority and transport keys; fresh OpenSSL processes reopen wrapped `TSS2 PRIVATE KEY` records. |
| Template | Parse binary `TPM2B_PUBLIC` for both keys: P-256, SHA-256 name, exact attributes `0x00040472`: fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth, noDA, sign; no decrypt/restricted flags, empty policy, null signing scheme. The actual wrapped PEM record must embed the same public bytes, loadable-key OID, owner-hierarchy parent and explicit empty-authorization indicator. |
| Retention | Restart the software TPM, private resource manager and private bus, then sign with the same wrapped record and verify the same public key. This is process restart, not a physical machine reboot. |
| Private scalar | TPM-provider DER cannot be decoded as a software private key by OpenSSL's default provider; a software EC private key successfully passes that decoder as a healthy control. A TSS2 wrapped blob is still written; this is not a claim that no opaque private record exists. |
| Lost/damaged record | Missing and malformed wrapped key records cannot sign. An unavailable TPM socket also refuses signing. No automatic replacement or software fallback. |
| Actual TLS | TPM provider server key, disposable software client key, mandatory client certificate verification, exact synthetic request/reversed response on IPv4 loopback. |
| Server pin | Client validates the self-signed fixture certificate and explicitly checks SHA-256 of SPKI DER before sending application bytes. A wrong SPKI pin is rejected at that gate. |
| Client identity | Server trusts only the designated self-signed client fixture certificate; a different self-signed client fails with an observed server `certificate verify failed`, not just a timeout. This is certificate anchoring, not a custom server SPKI callback. |
| Channel profile | TLS 1.3 only; `remozio-experiment/1` ALPN; unrelated ALPN requires the explicit server no-application-protocol diagnostic (or a local selected-ALPN rejection), not an unrelated SSL failure. Tickets/early data disabled in server configuration; positive client reports no reused session/ticket. Resumption attacks are not exhaustively tested. |
| Cross-TPM copy | Original wrapped record cannot sign on a second independently initialized simulator with the same transient parent template and a different TPM seed. A fresh second-simulator key signs/verifies successfully before the old-record refusal is accepted. Copying the entire simulator state is outside this test. |
| Cleanup | Every child is terminated/reaped and the private directory is removed, including on exceptions. Each command has a 12-second deadline; listener and connection setup have bounded waits. |

The two keys are purpose-separated; the authority signature is a synthetic fixture,
not a Remozio wire signature or approved command. Certificates are one-day disposable
self-signed fixtures. The ALPN identifies this experiment, not a production negotiation.

## Resource manager is part of the result

The selected stack is OpenSSL `tpm2` provider 1.3.0, tpm2-tools 5.7,
tpm2-abrmd 3.0.0, swtpm 0.7.3 and libtpms 0.9.3 (Ubuntu package revisions below).
The provider/private operations pass through `tabrmd:bus_type=session` to a private
`--session` abrmd instance, which connects to a private swtpm Unix socket. A private
`dbus-daemon --session --nofork` provides only that experiment's session bus.
No existing user's session bus or system TPM service is used.

A direct swtpm TCTI attempt failed during real `openssl s_server` startup with
`TPM_RC_OBJECT_MEMORY` (`0x902`). Releasing test-tool transient handles and preferring
default-provider non-key algorithms did not make that direct path pass. The successful
run uses abrmd with at most eight logical transient objects per connection. Operations
are sequential and only one TLS server/client pair is active at a time. This does
not establish real `/dev/tpmrm0` resource capacity, concurrent handshakes, contention
with other users/services, suspend/resume, or a usable production concurrency limit.

OpenSSL's default provider is preferred for general crypto. A TPM-backed signing key
cannot silently become a software key: the wrapped record is generated from the
asserted TPM public template, signed successfully only with the TPM provider, and
refuses use on an independent TPM. No software server-key generation path exists.
The runner creates a deterministic **transient** owner-hierarchy ECC parent using
`tpm2-openssl` 1.3.0's exact `primaryEccTemplate`, including noDA. The wrapped child
record names the owner hierarchy, so the provider recreates the same parent for
fresh-process signing. No persistent handle is provisioned and no global flush is
used. Parent/child contexts belong only to the disposable private resource manager.
The earlier persistent-handle proof was replaced with this safer path and rerun.
`TPM2TOOLS_AUTOFLUSH=yes` releases only each tool's own transient objects/context-loaded
parent; the provider also releases its private objects. This does not flush another
process's objects. The TSS2 record parser refuses mismatched sidecars, a persistent
parent handle, a software PEM, a false empty-auth indicator or a damaged private blob
before invoking the key provider. For tools 5.7, `encodeobject -p` is necessary to
emit the true `emptyAuth` field despite that option's misleading authorization label;
subsequent parsing asserts the actual field and fails closed on other behavior.

## Reproduce explicitly

With the tools already available, run as an ordinary Linux user:

```sh
timeout 120s python3 scripts/run-linux-tpm-tls-experiment.py --simulator
```

Exit 0 requires every assertion. Exit 77 means blocked/failed, with a bounded,
secret-free reason. Failure is not a passing hardware result. No mode probes for or automatically selects a real TPM. Hardware requires a separate explicit mode and operator declarations. Invocation without an explicit mode is refused.

For the isolated Ubuntu amd64 package layout used here, an operator can download
and extract packages without installing them:

```sh
mkdir -p /tmp/remozio-tpm-runtime/debs /tmp/remozio-tpm-runtime/root
cd /tmp/remozio-tpm-runtime/debs
apt-get download swtpm libtpms0 tpm2-tools tpm2-openssl libtss2-fapi1t64 tpm2-abrmd libtss2-tcti-tabrmd0
for deb in ./*.deb; do dpkg-deb -x "$deb" /tmp/remozio-tpm-runtime/root; done
cd /path/to/remozio
timeout 120s python3 scripts/run-linux-tpm-tls-experiment.py --simulator \
  --runtime-root /tmp/remozio-tpm-runtime/root
```

The successful package revisions were `swtpm 0.7.3-0ubuntu8`,
`libtpms0 0.9.3-0ubuntu5`, `tpm2-tools 5.7-1`, `tpm2-openssl 1.3.0-1`,
`libtss2-fapi1t64 4.1.3-1.2ubuntu1`, `tpm2-abrmd 3.0.0-1.2`, and
`libtss2-tcti-tabrmd0 3.0.0-1.2`. Shared TSS libraries were the host's
4.1.3-1.2ubuntu1. The extraction recipe assumes compatible host libraries and
`dbus-daemon`/OpenSSL already exist; it does not install missing dependencies.
The optional runtime-root layout is deliberately Ubuntu amd64 specific.

## Hardware adapter control without hardware

The separate [control](../../experiments/linux-tpm-tls/check_hardware_adapter.py)
executes the hardware create/reuse lifecycle through a private-simulator test double.
It substitutes the device-access check, replaces both TPM TCTIs with the private
session broker and guards every command against physical device routing. It proves
that retained records survive simulator restart unchanged and mismatched embedded
parents/public sidecars are refused before any key-provider invocation. Persistent
handle and NV inventories stay empty. This is still simulator evidence.

```sh
timeout 120s python3 experiments/linux-tpm-tls/check_hardware_adapter.py \
  --runtime-root /tmp/remozio-tpm-runtime/root
```

## Prepared human hardware gate

**The hardware mode is implemented but has not been run on this host's TPM.**
This user currently lacks read/write TPM access. The runner will return 77 before
starting tools if `/dev/tpmrm0` access is unavailable. An interactive operator must
arrange authorized access according to the intended deployment policy. The runner
never changes TPM permissions, resets a hierarchy, installs a service, provisions a
persistent handle or globally flushes contexts.

The adapter requires `--hardware`, exactly `--tcti device:/dev/tpmrm0`, a private
ordinary-user-owned fixture parent directory, a create/reuse choice, and
`--acknowledge-empty-owner-auth`. That last flag means the operator **knows** the
owner hierarchy uses empty authorization. It does not discover or reset ownership.
Do not use it when owner authorization is unknown or nonempty. Provider 1.3.0's
transient-parent decode path cannot pass nonempty owner authorization; supporting
such a deployment requires a separate reviewed adapter. No password is accepted
in command arguments. Root/setuid execution and mixed simulator/hardware options
are refused.

The simulator-tested transient parent/key methods are reused, but hardware mode
cannot start/stop a simulator, D-Bus or resource-manager service. The kernel resource
manager owns each process's transient contexts. Only wrapped authority/transport
records, public templates/SPKIs and a fixed fixture-kind manifest are retained.
Certificates, software client keys, signatures and damaged-record controls remain
in a separate temporary directory. Reuse validates ownership, modes, regular-file
status, link count, exact record set, manifest and embedded key template/parent;
it never overwrites or regenerates the retained identity. An interrupted initial
fixture publication can leave incomplete files; reuse refuses them and requires
operator cleanup and explicit recovery.

After the operator has independently confirmed the prerequisites, these are the
concrete invocations. They are documentation for the operator; **do not execute them
as part of unattended preparation**:

```sh
# This creates only a private user-owned output parent, not TPM permissions/services.
mkdir -p -m 700 "$HOME/.local/state/remozio-experiments"
timeout 120s python3 scripts/run-linux-tpm-tls-experiment.py --hardware \
  --tcti device:/dev/tpmrm0 --acknowledge-empty-owner-auth \
  --hardware-directory "$HOME/.local/state/remozio-experiments/tpm-tls-fixture" \
  --create-fixture > /tmp/remozio-hardware-initial.json

# A fresh process must reopen exactly the retained identity.
timeout 120s python3 scripts/run-linux-tpm-tls-experiment.py --hardware \
  --tcti device:/dev/tpmrm0 --acknowledge-empty-owner-auth \
  --hardware-directory "$HOME/.local/state/remozio-experiments/tpm-tls-fixture" \
  --reuse-fixture > /tmp/remozio-hardware-reopen.json

# Only after the operator performs a real reboot, rerun with the same fixture:
timeout 120s python3 scripts/run-linux-tpm-tls-experiment.py --hardware \
  --tcti device:/dev/tpmrm0 --acknowledge-empty-owner-auth \
  --hardware-directory "$HOME/.local/state/remozio-experiments/tpm-tls-fixture" \
  --reuse-fixture --operator-phase after-reboot > /tmp/remozio-hardware-after-reboot.json
```

Add `--runtime-root /tmp/remozio-tpm-runtime/root` if using the isolated compatible
Ubuntu amd64 tool layout. After reboot that temporary runtime may need extracting
again. Keep the fixture directory through the reboot. The phase field is an operator
declaration; the runner does not itself prove that a reboot/service restart occurred.
Review and retain the secret-free JSON results plus the operator's reboot chronology.
Never commit the retained key records or fixture directory. No physical TPM result is included in this change. Even when a future run opens
`/dev/tpmrm0`, its report claims only `tpmResourceManagerDeviceTested`, with
`physicalHardwareTPMVerified: false`; the path alone is not physical attestation.

Each hardware invocation exercises both-key reopen/sign/verify, actual loopback
mutual TLS, wrong SPKI pin, wrong client and wrong ALPN, missing/corrupt temporary
record refusal, an unavailable TPM socket, and failed software private-key decoding
with a software decoder healthy control. A false assertion returns 77. A different
physical TPM/copy test still requires a separately authorized second machine. The
mode is not a production initializer; its empty-auth disposable keys rely on local
file protection and do not select the production service's authorization policy.
The operator-selected device could itself be virtual; this is not TPM attestation.

## Remaining gates

The current evidence does not establish `/dev/tpmrm0` concurrency/capacity, protected
service-account isolation, prelogin access, lock/logout, suspend/resume, provider/TPM
busy recovery or physical cross-machine refusal. Measure bounded concurrent TLS
handshakes and define production limits from those results. Hardware phase labels
alone cannot satisfy these missing scenarios. Damaged/missing production identity
must block use and require explicit recovery, never silent re-enrollment or a
software-key fallback.

The production Swift TLS bridge remains undecided. This establishes a native
OpenSSL CLI/provider signing path, not SwiftNIO/Network.framework API integration,
protected identity storage, production certificate issuance/renewal, phone pairing,
or approval execution. Whole-host backup rollback is outside the accepted guarantee;
ordinary crash consistency and current-state checks remain required.

Primary API references: [TPM provider transient parent template](https://github.com/tpm2-software/tpm2-openssl/blob/1.3.0/src/tpm2-provider-pkey.c),
[TPM provider keys](https://github.com/tpm2-software/tpm2-openssl/blob/1.3.0/docs/keys.md),
[provider initialization and resource-manager advice](https://github.com/tpm2-software/tpm2-openssl/blob/1.3.0/README.md),
[OpenSSL s_server](https://docs.openssl.org/3.5/man1/openssl-s_server/),
[TPM public attributes](https://github.com/tpm2-software/tpm2-tss/blob/4.1.3/include/tss2/tss2_tpm2_types.h),
and [tools 5.7 empty-auth encoding](https://github.com/tpm2-software/tpm2-tools/blob/5.7/tools/misc/tpm2_encodeobject.c).
