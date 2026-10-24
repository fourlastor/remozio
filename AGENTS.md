# Remozio agent workflow

Use the repository's [babysit-pr skill](.agents/skills/babysit-pr/SKILL.md) for every open PR. Its watcher is the readiness authority. Follow its review triage, batching, and cleanup rules.

Run `./scripts/check-local.sh` before each push. It runs the repository checks and portable Kotlin/Android tasks on both hosts, the shared Swift protocol and host suites on Linux, and the native Mac builds/tests plus `:phone-core:approvalFlowTest` on macOS. The Mac interoperability peers are not executable on Linux; CI must pass the Mac build and interoperability jobs before merge. Use Python 3.11 or later on Linux and 3.13 or later on macOS (the Mac fixture cleanup calls `os.waitid`, which CPython provides on macOS from 3.13), JDK 21, Swift 6.2 or later on Linux, and set `ANDROID_HOME` to an Android SDK with platform 37.0 and build tools 37.0.0. macOS needs the supported Xcode toolchain. When the XPC experiment changes, also run its live checks on a supported Mac GUI session and retain the evidence. CI builds and unit tests do not substitute for live experiment results.

Keep PRs focused. Record what an experiment proves and what remains untested. Do not collect secrets in committed evidence. Device-dependent end-to-end checks wait for the user's interactive session.
