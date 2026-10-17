# Disposable Linux TPM/TLS adapter

The executable implementation is [the Python harness](../../scripts/run-linux-tpm-tls-experiment.py).
It composes Ubuntu's `tpm2-tools`, `swtpm`, `tpm2-abrmd`, `tpm2-openssl`,
OpenSSL 3 and Python `ssl`; it is not a production identity store or Swift adapter.

Read the [experiment contract and human hardware gate](../../docs/experiments/linux-tpm-tls.md)
before running. The development evidence uses explicit `--simulator`. Its TPM commands are routed
through a newly created private session bus/resource manager to a newly created
software TPM Unix socket. The separately guarded `--hardware` mode is prepared for
an interactive operator and has not been run against hardware. It requires explicit
known-empty-owner-auth and resource-manager selection plus a private retained
fixture directory. Neither mode installs or changes services, resets a TPM or
provisions a persistent handle. Production identities and enrolled phones are excluded.
