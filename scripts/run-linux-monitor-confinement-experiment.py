#!/usr/bin/env python3
"""Supervised monitor-confinement measurement: can an AppArmor policy limit a process that holds
CAP_SYS_PTRACE so that its ptrace-mediated access reaches only processes that run the installed
frontend image, and so that it cannot write files, execute or open IP sockets? A measurement,
not a production admission path.

Run once as root through sudo from the operator's session. The runner refuses to start while
any rmzmc- profile is loaded. It creates a disposable group, a disposable monitor user and four
temporary profiles (loaded into the kernel only), measures every case, then removes all of it.
The report holds booleans, errno names, categories, labels with the run tag replaced, settings
and hashes only.

If the runner itself is killed, its profiles stay loaded until reboot. Remove them by name:
list the rmzmc- names in /sys/kernel/security/apparmor/profiles and write each name to
/sys/kernel/security/apparmor/.remove."""
import argparse
import datetime
import grp
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import signal
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "experiments/linux-monitor-confinement"
PROBE, PROFILES = FIXTURES / "probe.c", FIXTURES / "profiles.in"
PROTECTED_RUNNER = ROOT / "scripts/run-linux-protected-launch-experiment.py"
# The #728 runner gives the frontend and monitor fixtures, the owned-process and account helpers
# and the monitor report vocabulary. Loading it also loads run-linux-caller-experiment.py (its
# own import). Nothing here calls either measure().
_spec = importlib.util.spec_from_file_location("remozio_protected_launch_runner", PROTECTED_RUNNER)
PL = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(PL)

BASE_PREFIX = "remozio-monitor-confinement-experiment-"
PROFILE_PREFIX = "rmzmc-"
APPARMOR = Path("/sys/kernel/security/apparmor")
LOADED_PROFILES, REMOVE_PROFILE = APPARMOR / "profiles", APPARMOR / ".remove"
CGROUP_SYSTEM = Path("/sys/fs/cgroup/system.slice")
TOOLS = ("aa-exec", "apparmor_parser", "systemd-run", "systemctl", "journalctl")
# The frontend is the #728 image; the monitor (unchanged source) and the probe are built static
# too, so the profiles need no loader or library rules.
BUILDS = {"frontend": (PL.FRONTEND, ("-static", "-no-pie")), "monitor": (PL.MONITOR, ("-static",)),
          "probe": (PROBE, ("-static",))}
ROLES = ("frontend", "monitor", "probe", "complain")
ABI_LINE = "abi <abi/4.0>,"
TAG_PATTERN = re.compile(r"[0-9a-f]{8}")
JOURNAL_LIMIT = 4 << 20

UNCONFINED = "unconfined"
FRONTEND_LABEL, MONITOR_LABEL, PROBE_LABEL = (f"rmzmc-{role}-<tag> (enforce)" for role in ("frontend", "monitor", "probe"))
COMPLAIN_LABEL = "rmzmc-complain-<tag> (complain)"
LABELS = frozenset({UNCONFINED, FRONTEND_LABEL, MONITOR_LABEL, PROBE_LABEL, COMPLAIN_LABEL, "not-measured", "other"})

ERRNO = frozenset({"ok", "EPERM", "EACCES", "ESRCH", "EFAULT", "EINVAL", "ENOSYS", "EBADF", "ENOENT", "other"})
PROBE_VALUES = ERRNO | {"match", "mismatch", "short", "not-attempted", "yes", "no", "none", "ptrace-only",
                        "not-requested", "failed", "usage", "no-go", "overflow"}
REFUSED = ("EACCES", "EPERM")

# Identity after the #728 self-drop (shape A) and as systemd starts it (shape B).
IDENTITY_A = {"selfDrop": "ok", "credentialsExact": "yes", "capsEffective": "ptrace-only",
              "capsPermitted": "ptrace-only", "capsBounding": "ptrace-only", "capsInheritable": "none",
              "capsAmbient": "none", "noNewPrivs": "yes", "rootRegain": "EPERM"}
IDENTITY_B = {**IDENTITY_A, "selfDrop": "not-requested", "capsInheritable": "ptrace-only",
              "capsAmbient": "ptrace-only"}
# /proc/<pid>/mem is mode 0600 and owned by the target's UID, or by root when the target is not
# dumpable. The probe's identity is never that owner and holds no DAC capability, so the open
# fails with EACCES in the permission check, before AppArmor or the ptrace check sees it, for
# every target here, confined or not. Reach is shown by seize, process_vm_readv and pidfd_getfd.
# /proc/<pid>/maps is 0444 and checked with PTRACE_MODE_READ: it measures AppArmor's ptrace
# read permission (the monitor profile has a file rule for it), refused with EACCES.
# The probe holds CAP_SYS_PTRACE, so the capability hook passes and AppArmor refuses the seize
# with EACCES, which ptrace_attach returns as is (measured in the first supervised run; #728
# measured EPERM without AppArmor). process_vm_readv and pidfd_getfd turn any refusal into EPERM.
SLEEPER_REFUSED = {"seize": "EACCES", "memOpen": "EACCES", "memRead": "not-attempted", "vmRead": "EPERM",
                   "pidfdOpen": "ok", "pidfdGetfd": "EPERM", "getfdCopyIsPipe": "not-attempted", "mapsRead": "EACCES",
                   "statusRead": "ok"}
SLEEPER_REACHED = {**SLEEPER_REFUSED, "seize": "ok", "vmRead": "match", "pidfdGetfd": "ok", "getfdCopyIsPipe": "yes",
                   "mapsRead": "ok"}
FRONTEND_REACHED = {"seize": "ok", "interrupt": "yes", "vmRead": "match", "memOpen": "EACCES", "detach": "ok"}
FRONTEND_REFUSED = {"seize": "EACCES", "interrupt": "not-attempted", "vmRead": "EPERM", "memOpen": "EACCES",
                    "detach": "not-attempted"}
SIDE_REFUSED = {"fileCreate": REFUSED, "exec": REFUSED, "inetSocket": REFUSED}
SIDE_WORKING = {"fileCreate": "ok", "exec": "ok", "inetSocket": "ok"}

# The #728 monitor tables, with its AppArmor categories required here.
ADMITTED = {**PL.ADMITTED, "monitorAppArmor": "confined", "frontendAppArmor": "confined"}
NOT_SEIZED = {**PL.NOT_SEIZED, "seize": "EACCES", "monitorAppArmor": "confined",
              "frontendAppArmor": "not-attempted"}
FRONTEND_EXITS = {0: "accepted", 2: "rejected", 3: "forbidden-returned", 4: "usage", 5: "policy-setup-failed",
                  10: "connect-EACCES", 11: "socket-failure", 12: "protocol-failure"}

USERNS = [{"userns": REFUSED, "uidMap": "not-attempted", "mount": "not-attempted"},
          {"userns": "ok", "uidMap": tuple(ERRNO), "mount": REFUSED}]


def _expect(values):
    return {key: frozenset(value if isinstance(value, tuple) else (value,)) for key, value in values.items()}


def _role(role, values):
    return {f"{role}.{key}": value for key, value in values.items()}


def _probe(shape, targets, expect, labels, side=False):
    """targets: role -> target kind; labels: role -> expected label (the probe's under "probe")."""
    return {"kind": "probe", "shape": shape, "targets": targets, "side": side, "expect": _expect(expect),
            "labels": labels}


def _monitor(frontend, expect, exit_name, frontend_label):
    return {"kind": "monitor", "frontend": frontend, "expect": _expect(expect), "frontendExit": exit_name,
            "labels": {"monitor": MONITOR_LABEL, "frontend": frontend_label}}


# Run order. f3 runs last: it removes the frontend profile.
CASES = {
    "p1c": _monitor("installed", ADMITTED, "accepted", FRONTEND_LABEL),
    "n1c": _probe("A", {"sleeper": "root-sleeper", "frontend": "installed"},
                  {**IDENTITY_A, **_role("sleeper", SLEEPER_REFUSED), **_role("frontend", FRONTEND_REACHED)},
                  {"probe": MONITOR_LABEL, "sleeper": UNCONFINED, "frontend": FRONTEND_LABEL}),
    # A shape B unit that does not start is recorded (unitStart) and fails: shape B is then unmeasured.
    "n2c": _probe("B", {"sleeper": "root-sleeper", "frontend": "installed"},
                  {**IDENTITY_B, **_role("sleeper", SLEEPER_REFUSED), **_role("frontend", FRONTEND_REACHED),
                   **SIDE_REFUSED},
                  {"probe": PROBE_LABEL, "sleeper": UNCONFINED, "frontend": FRONTEND_LABEL}, side=True),
    "n3c": _probe("A", {"operator": "operator-sleeper", "copy": "copy"},
                  {**IDENTITY_A, **_role("operator", SLEEPER_REFUSED), **_role("copy", FRONTEND_REFUSED)},
                  {"probe": MONITOR_LABEL, "operator": UNCONFINED, "copy": UNCONFINED}),
    "n4c": _probe("A", {}, {**IDENTITY_A, **SIDE_REFUSED}, {"probe": MONITOR_LABEL}, side=True),
    "n5c": _monitor("other", NOT_SEIZED, "rejected", UNCONFINED),
    "n6c": {"kind": "userns", "expect": [_expect(item) for item in USERNS]},
    # The recorded limit: a Root process that runs the installed frontend has the frontend label.
    "n7c": _probe("A", {"root": "root-frontend"}, {**IDENTITY_A, **_role("root", FRONTEND_REACHED)},
                  {"probe": MONITOR_LABEL, "root": FRONTEND_LABEL}),
    "c1": _probe("none-A", {"sleeper": "root-sleeper"},
                 {**IDENTITY_A, **_role("sleeper", SLEEPER_REACHED), **SIDE_WORKING},
                 {"probe": UNCONFINED, "sleeper": UNCONFINED}, side=True),
    "c2": _probe("none-B", {"sleeper": "root-sleeper"},
                 {**IDENTITY_B, **_role("sleeper", SLEEPER_REACHED), **SIDE_WORKING},
                 {"probe": UNCONFINED, "sleeper": UNCONFINED}, side=True),
    "f1": _probe("complain", {"sleeper": "root-sleeper"}, {**IDENTITY_A, **_role("sleeper", SLEEPER_REACHED)},
                 {"probe": COMPLAIN_LABEL, "sleeper": UNCONFINED}),
    "f2": {"kind": "absent"},
    "k1": {"kind": "kill", "labels": {"probe": MONITOR_LABEL}},
    "f3": _monitor("installed", NOT_SEIZED, "rejected", UNCONFINED),
}


# --- Profiles --------------------------------------------------------------------------------

def base_for(tag):
    return PL.BASE_PARENT / (BASE_PREFIX + tag)


def profile_blocks(text):
    """The abi line and every profile block (header to closing brace) by name."""
    abi, blocks, current = None, {}, None
    for line in text.splitlines():
        if current is not None:
            current.append(line)
            if line == "}":
                name = current[0].split()[1]
                if name in blocks:
                    raise ValueError("duplicate profile")
                blocks[name] = "\n".join(current)
                current = None
        elif line.startswith("profile "):
            current = [line]
        elif line.startswith("abi "):
            abi = line
        elif line.strip() and not line.startswith("#"):
            raise ValueError("rule outside a profile")
    if current is not None or abi != ABI_LINE:
        raise ValueError("unterminated profile or unexpected abi")
    return abi, blocks


def render_profiles(template, tag, base):
    """Exact substitution of the tag and the run directory; one loadable text per profile. The
    complain profile for f1 is the monitor profile under another name, in complain mode."""
    if not TAG_PATTERN.fullmatch(tag) or Path(base) != base_for(tag):
        raise ValueError("unexpected tag or run directory")
    text = template.replace("@@TAG@@", tag).replace("@@BASE@@", str(base))
    if "@@" in text:
        raise ValueError("unrendered placeholder")
    abi, blocks = profile_blocks(text)
    if set(blocks) != {f"{PROFILE_PREFIX}{role}-{tag}" for role in ROLES[:3]}:
        raise ValueError("unexpected profile names")
    monitor = blocks[f"{PROFILE_PREFIX}monitor-{tag}"]
    complain = monitor.replace(f"{PROFILE_PREFIX}monitor-{tag}", f"{PROFILE_PREFIX}complain-{tag}")
    blocks[f"{PROFILE_PREFIX}complain-{tag}"] = complain.replace("flags=(enforce)", "flags=(complain)", 1)
    return {name: f"{abi}\n\n{block}\n" for name, block in blocks.items()}


def loaded_profiles():
    """Name -> mode from the kernel's list (root-readable)."""
    data = LOADED_PROFILES.read_bytes()
    result = {}
    for line in data.decode("utf-8", "replace").splitlines():
        name, separator, mode = line.rpartition(" (")
        if separator and mode.endswith(")"):
            result[name] = mode[:-1]
    return result


LABEL_MODES = ("enforce", "complain", "kill", "unconfined", "mixed")
STACK_PARTS = {UNCONFINED: UNCONFINED, **{f"rmzmc-{role}-<tag>": role
                                          for role in ("frontend", "monitor", "probe", "complain")}}


def sanitize_label(raw, tag):
    """A closed value: a known label, a stack of known parts ("stack(probe+unconfined) (mode)"),
    "not-measured" or "other". Nothing else from the kernel string is published."""
    text = raw.decode("ascii", "replace").strip("\0 \n") if isinstance(raw, bytes) else "not-measured"
    text = text.replace(tag, "<tag>") if tag else text
    if text in LABELS:
        return text
    body, separator, mode = text.rpartition(" (")
    if not separator or not mode.endswith(")") or mode[:-1] not in LABEL_MODES or "//&" not in body:
        return "other"
    parts = body.split("//&")
    if len(parts) > 4:
        return "other"
    return f"stack({'+'.join(STACK_PARTS.get(part, 'other') for part in parts)}) ({mode[:-1]})"


def read_label(pid, tag):
    try:
        with open(f"/proc/{pid}/attr/apparmor/current", "rb") as stream:
            raw = stream.read(257)
    except OSError:
        return "not-measured"
    return "other" if len(raw) > 256 else sanitize_label(raw, tag)


def wait_for_image(pid, image, deadline):
    """True once /proc/<pid>/exe is the given image: after an aa-exec, the exec has happened."""
    want = os.stat(image)
    while time.monotonic() < deadline:
        try:
            info = os.stat(f"/proc/{pid}/exe")
            if (info.st_dev, info.st_ino) == (want.st_dev, want.st_ino):
                return True
        except FileNotFoundError:
            pass  # the link can be briefly absent during the exec
        except OSError:
            return False
        time.sleep(0.01)
    return False


# --- Reports ---------------------------------------------------------------------------------

def _labels_mismatch(spec, labels):
    return [f"label.{role}" for role, label in spec["labels"].items() if labels.get(role) != label]


def evaluate_probe(case, raw, returncode, labels):
    """The probe report against the case table; labels against the expected labels."""
    spec = CASES[case]
    result = {"passed": False, "labels": dict(sorted(labels.items()))}
    try:
        report = PL.parse_report(raw)
    except (ValueError, RecursionError):
        result["error_type"] = "InvalidProbeReport"
        return result
    if set(report) - set(spec["expect"]) - {"error"} or any(value not in PROBE_VALUES for value in report.values()):
        result["error_type"] = "InvalidProbeReport"
        return result
    result["probe"] = dict(sorted(report.items()))
    mismatches = [f"probe.{key}" for key in PL._mismatches(report, spec["expect"])]
    if "error" in report:
        mismatches.append("probe.error")
    if returncode != 0:
        mismatches.append("probe.exitStatus")
    mismatches += _labels_mismatch(spec, labels)
    result["mismatches"] = sorted(mismatches)
    result["passed"] = not mismatches
    return result


def evaluate_monitor(case, raw, returncode, frontend_rc, labels):
    spec = CASES[case]
    result = {"passed": False, "labels": dict(sorted(labels.items())),
              "frontendExit": frontend_exit(frontend_rc)}
    try:
        monitor = PL.parse_report(raw)
    except (ValueError, RecursionError):
        result["error_type"] = "InvalidMonitorReport"
        return result
    if "error" in monitor:
        result["error_type"] = "MonitorError"
        if monitor["error"] in PL.MONITOR_ERRORS:
            result["monitorError"] = monitor["error"]
        return result
    if set(monitor) != set(PL.MONITOR_KEYS) or any(value not in PL.MONITOR_KEYS[key] for key, value in monitor.items()):
        result["error_type"] = "InvalidMonitorReport"
        return result
    result["monitor"] = dict(sorted(monitor.items()))
    mismatches = [f"monitor.{key}" for key in PL._mismatches(monitor, spec["expect"])]
    if returncode != 0:
        mismatches.append("monitor.exitStatus")
    if result["frontendExit"] != spec["frontendExit"]:
        mismatches.append("frontendExit")
    mismatches += _labels_mismatch(spec, labels)
    result["mismatches"] = sorted(mismatches)
    result["passed"] = not mismatches
    return result


def evaluate_userns(raw):
    result = {"passed": False}
    try:
        report = PL.parse_report(raw)
    except (ValueError, RecursionError):
        result["error_type"] = "InvalidHelperReport"
        return result
    if set(report) != {"userns", "uidMap", "mount"} or any(value not in PROBE_VALUES for value in report.values()):
        result["error_type"] = "InvalidHelperReport"
        return result
    result["helper"] = dict(sorted(report.items()))
    result["passed"] = any(not PL._mismatches(report, item) for item in CASES["n6c"]["expect"])
    return result


def frontend_exit(code):
    if code is None:
        return "unknown"
    if code < 0:
        return "signaled"
    return FRONTEND_EXITS.get(code, "other")


# --- Host ------------------------------------------------------------------------------------

def _feature(path, limit=4096):
    value = PL._policy_bytes(APPARMOR / "features" / path, limit)
    return value.decode("ascii", "replace").split() if value is not None else None


def apparmor_metadata(parser_version):
    lsm = PL._policy_bytes("/sys/kernel/security/lsm", 256) or b""
    words = lambda path: set(_feature(path) or ())
    return {"lsm": lsm.decode() if re.fullmatch(rb"[a-z,]{1,128}\n?", lsm) else "unavailable",
            "ptraceMask": sorted(words("ptrace/mask") & {"read", "trace"}),
            "afUnixMediation": _feature("network/af_unix") == ["yes"],
            "signalMediation": {"kill", "term"} <= words("signal/mask"),
            "postNnpSubset": _feature("domain/post_nnp_subset") == ["yes"],
            "parserVersion": parser_version}


def parser_version(parser, timeout):
    code, output = PL.run_owned([parser, "--version"], timeout)
    match = re.match(rb"AppArmor parser version ([0-9][0-9A-Za-z.~+-]{0,31})\n", output)
    return match[1].decode() if code == 0 and match else "unknown"


def source_hashes():
    paths = (Path(__file__).resolve(), PROBE, PROFILES, PROTECTED_RUNNER, PL.FRONTEND, PL.MONITOR, PL.CLEANUP_SOURCE)
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


DENIAL_FIELDS = re.compile(r'(\w+)=("[^"]*"|\S+)')
DENIAL_WORD = re.compile(r"[a-z_:-]{1,32}")


def sanitize_target(name, tag, base):
    name = name.replace(str(base), "<base>")
    name = re.sub(r"^/proc/[0-9]+(?=/|$)", "/proc/<pid>", name)
    allowed = (r"<base>/[a-z]+(/[a-z0-9.*-]+)?", r"/proc/<pid>(/[a-z_/]+)?", r"/proc/sys/kernel/cap_last_cap",
               r"/usr/bin/true", r"/dev/null", r"/proc/self/[a-z_/]+")
    return name if any(re.fullmatch(pattern, name) for pattern in allowed) else "other"


def summarize_denials(text, tag, base):
    """AppArmor audit lines of this run's profiles, reduced to closed fields and counted."""
    roles = {f"{PROFILE_PREFIX}{role}-{tag}": role for role in ROLES}
    counts = {}
    for line in text.splitlines():
        if "apparmor=" not in line or tag not in line:
            continue
        fields = {key: value.strip('"') for key, value in DENIAL_FIELDS.findall(line)}
        if fields.get("apparmor") not in ("DENIED", "ALLOWED") or fields.get("profile") not in roles:
            continue
        word = lambda key: fields[key] if key in fields and DENIAL_WORD.fullmatch(fields[key]) else "none"
        peer = fields.get("peer", "none")
        entry = (fields["apparmor"], roles[fields["profile"]], word("operation"), word("class"),
                 word("denied_mask") if "denied_mask" in fields else word("requested_mask"),
                 roles.get(peer, "unconfined" if peer == "unconfined" else "none" if peer == "none" else "other"),
                 word("signal"), sanitize_target(fields["name"], tag, base) if "name" in fields else "none")
        counts[entry] = counts.get(entry, 0) + 1
    keys = ("result", "profile", "operation", "class", "mask", "peer", "signal", "target")
    return [dict(zip(keys, entry), count=count) for entry, count in sorted(counts.items())[:64]]


# --- Measurement -----------------------------------------------------------------------------

def _retire(process):
    """The #728 kill-and-reap of the process's group, plus its stderr pipe."""
    try:
        return PL._retire(process)
    finally:
        if process is not None and process.stderr is not None:
            process.stderr.close()


def _read_line(process, deadline, limit=1024):
    data = bytearray()
    while not data.endswith(b"\n"):
        if len(data) >= limit:
            raise PL.OutputLimitError()
        data.extend(PL._read_exact(process, deadline, 1))
    return bytes(data)


def _retire_all(processes):
    results = [_retire(process) for process in processes]
    return all(results)


class Run(PL.Run):
    """Disposable host state; cleanup stops units, removes profiles, then the #728 state."""

    def __init__(self, operator, timeout, tools):
        super().__init__(operator, timeout)
        self.base = base_for(self.tag)
        self.group_name, self.monitor_name = f"rmzcg{self.tag}", f"rmzcm{self.tag}"
        self.tools = tools
        self.profiles, self.loaded, self.units = {}, [], []
        # Set when a case could not confirm that all its processes ended: profiles then stay.
        self.unreaped = False
        self.target_seconds = str(int(timeout) + 5)

    def path(self, *parts):
        return self.base.joinpath(*parts)

    def name(self, role):
        return f"{PROFILE_PREFIX}{role}-{self.tag}"

    def setup(self):
        os.mkdir(self.base, 0o755)
        self.base_created = True
        os.chmod(self.base, 0o755)
        for name, mode in (("build", 0o700), ("run", 0o755), ("s", 0o755), ("profiles", 0o700)):
            os.mkdir(self.path(name), mode)
            os.chmod(self.path(name), mode)
        builds = {}
        for name, (source, extra) in BUILDS.items():
            output = self.path("build", name)
            code, _ = PL.run_owned([shutil.which("cc", path=PL.TOOL_ENV["PATH"]) or "/usr/bin/cc", *PL.CC_FLAGS, *extra,
                                    "-o", str(output), str(source)], min(60, 4 * self.timeout))
            if code != 0 or not output.is_file():
                raise RuntimeError("fixture build failed")
            builds[name] = output.read_bytes()
        self.frontend_bytes = builds["frontend"]
        self.frontend_sha256 = hashlib.sha256(self.frontend_bytes).hexdigest()

        self._create("group_created", ["groupadd", "--system", self.group_name], (self.group_name,))
        self.gid = grp.getgrnam(self.group_name).gr_gid
        self._create("monitor_created", ["useradd", "--system", "--no-create-home", "--home-dir", "/", "--shell",
                                         "/usr/sbin/nologin", "--user-group", self.monitor_name], (self.monitor_name,))
        account = pwd.getpwnam(self.monitor_name)
        self.monitor_uid, self.monitor_gid = account.pw_uid, account.pw_gid
        if 0 in (self.gid, self.monitor_uid, self.monitor_gid):
            raise RuntimeError("disposable identity is privileged")

        # remozio: installed and attached; other: set-group-ID copy the profile does not attach;
        # control: copy without set-ID bits (an unconfined frontend, and the n6c image).
        self.installed, self.other, self.control = self.path("run", "remozio"), self.path("run", "other"), \
            self.path("run", "control")
        PL.write_root_file(self.installed, self.frontend_bytes, 0o2755, self.gid)
        PL.write_root_file(self.other, self.frontend_bytes, 0o2755, self.gid)
        PL.write_root_file(self.control, self.frontend_bytes, 0o755)
        for name in ("monitor", "probe"):
            PL.write_root_file(self.path("run", name), builds[name], 0o755)
        self.writable = self.path("w")
        os.mkdir(self.writable, 0o700)
        os.chown(self.writable, self.monitor_uid, self.monitor_gid)
        self.operator_groups = os.getgrouplist(self.operator.pw_name, self.operator.pw_gid)

        self.profiles = render_profiles(PROFILES.read_text(), self.tag, self.base)
        for role in ROLES:
            self.load_profile(self.name(role))
        modes = loaded_profiles()
        expected = {self.name(role): "complain" if role == "complain" else "enforce" for role in ROLES}
        members = grp.getgrgid(self.gid).gr_mem
        return {"frontendGroupHasNoMembers": members == [],
                "noAccountUsesFrontendGroupAsPrimary": all(entry.pw_gid != self.gid for entry in pwd.getpwall()),
                "operatorOutsideFrontendGroup": self.gid not in self.operator_groups,
                "installedImageExact": PL.installed_exact(self.installed, self.gid, self.frontend_sha256),
                "fixturesStaticNonPie": all(PL.static_non_pie(self.path("run", name))
                                            for name in ("remozio", "monitor", "probe")),
                "profilesLoadedInExpectedMode": all(modes.get(name) == mode for name, mode in expected.items())}

    def load_profile(self, name):
        """Kernel only (-K: no cache); -a refuses an existing name. Recorded before the tool runs."""
        path = self.path("profiles", name)
        PL.write_root_file(path, self.profiles[name].encode(), 0o600)
        self.loaded.append(name)
        if PL.run_owned([self.tools["apparmor_parser"], "-a", "-K", str(path)], self.timeout)[0] != 0:
            raise RuntimeError("profile load failed")

    def remove_profile(self, name):
        """By exact name through the kernel interface; only names this run loaded."""
        if name in self.loaded and name in loaded_profiles():
            with REMOVE_PROFILE.open("w") as stream:
                stream.write(name)
        return name not in loaded_profiles()

    # Owned processes --------------------------------------------------------------------------

    def spawn(self, arguments, identity, **options):
        """root: unconfined Root; operator: the operator's identity. stdio are pipes, so no
        inherited /dev/null descriptor is revalidated against a profile at exec."""
        extra = self.operator_options() if identity == "operator" else {"env": {}, "cwd": "/",
                                                                          "start_new_session": True}
        return subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                **extra, **options)

    def start_target(self, role, kind, deadline, owned, labels):
        """A target process and its probe argument."""
        if kind in ("root-sleeper", "operator-sleeper"):
            process = self.spawn([str(self.path("run", "probe")), "sleeper", self.target_seconds],
                                 "root" if kind == "root-sleeper" else "operator")
            owned.append(process)
            match = re.fullmatch(rb"S ([0-9a-f]{16}) ([0-9]{4}) ([0-9a-f]{32})\n", PL._read_exact(process, deadline, 57))
            if not match:
                raise ValueError("unexpected sleeper handshake")
            argument = f"{role}=s:{process.pid}:{match[1].decode()}:{int(match[2])}:{match[3].decode()}"
        else:
            image = {"installed": self.installed, "copy": self.control, "root-frontend": self.installed}[kind]
            process = self.spawn([str(image), "hold", str(self.path("s", "unused.sock"))],
                                 "root" if kind == "root-frontend" else "operator")
            owned.append(process)
            argument = f"{role}=f:{process.pid}:{self.read_hold(process, deadline)}:-:-"
        labels[role] = read_label(process.pid, self.tag)
        return argument

    @staticmethod
    def read_hold(process, deadline):
        line = PL._read_exact(process, deadline, 18)
        if not re.fullmatch(rb"R[0-9a-f]{16}\n", line):
            raise ValueError("unexpected hold handshake")
        return line[1:17].decode()

    def probe_arguments(self, mode, side, targets):
        return [str(self.path("run", "probe")), "probe", mode, str(self.monitor_uid), str(self.monitor_gid),
                self.fixture_seconds, str(self.writable) if side else "-", *targets]

    def unit_command(self, case, profile, arguments):
        unit = f"{PROFILE_PREFIX}{self.tag}-{case}.service"
        properties = [f"User={self.monitor_name}", f"Group={self.monitor_name}", "AmbientCapabilities=CAP_SYS_PTRACE",
                      "CapabilityBoundingSet=CAP_SYS_PTRACE", "NoNewPrivileges=yes", "WorkingDirectory=/",
                      f"RuntimeMaxSec={int(self.timeout)}"]
        if profile:
            properties.append(f"AppArmorProfile={profile}")
        return unit, [self.tools["systemd-run"], f"--unit={unit}", "--collect", "--quiet", "--pipe", "--wait",
                      "--service-type=exec", *(f"--property={item}" for item in properties), "--", *arguments]

    def stop_unit(self, unit):
        """Stop (a collected unit is already gone: exit 5), then require an empty cgroup."""
        code = PL.run_owned([self.tools["systemctl"], "stop", unit], self.timeout)[0]
        procs = CGROUP_SYSTEM / unit / "cgroup.procs"
        try:
            empty = procs.read_bytes().strip() == b""
        except FileNotFoundError:
            empty = True
        return code in (0, 5) and empty

    def unit_label(self, unit):
        deadline = time.monotonic() + 2
        while True:  # MainPID can read 0 for a moment after the start
            code, output = PL.run_owned([self.tools["systemctl"], "show", "--property=MainPID", "--value", unit],
                                        self.timeout)
            if code == 0 and re.fullmatch(rb"[1-9][0-9]{0,9}\n", output):
                return read_label(int(output), self.tag)
            if time.monotonic() >= deadline:
                return "not-measured"
            time.sleep(0.05)

    # Cases ------------------------------------------------------------------------------------

    def run_case(self, case):
        spec = CASES[case]
        if case == "f3":
            frontend_removed = self.remove_profile(self.name("frontend"))
            if not frontend_removed:
                return {"passed": False, "error_type": "ProfileRemovalFailed"}
        handler = {"monitor": self.monitor_case, "probe": self.probe_case, "userns": self.userns_case,
                   "absent": self.absent_case, "kill": self.kill_case}[spec["kind"]]
        try:
            result = handler(case, spec)
        except BaseException:
            self.unreaped = True  # the case did not report its processes as ended
            raise
        if result.get("cleanupReapedAllFixtureProcesses") is False:
            self.unreaped = True
        return result

    @staticmethod
    def _failed(error, clean, extra=None):
        return {"passed": False, "error_type": error, **(extra or {}), "cleanupReapedAllFixtureProcesses": clean}

    def _finish(self, result, clean):
        result["cleanupReapedAllFixtureProcesses"] = clean
        result["passed"] = result["passed"] and clean
        return result

    def monitor_case(self, case, spec):
        path = self.path("s", f"{case}.sock")
        listener = PL.make_listener(path, self.gid)
        owned, labels, error = [], {}, None
        deadline = time.monotonic() + self.timeout
        try:
            monitor = self.spawn([self.tools["aa-exec"], "-p", self.name("monitor"), "--", str(self.path("run", "monitor")),
                                  "cap", str(listener.fileno()), str(self.gid), str(self.installed),
                                  str(self.monitor_uid), str(self.monitor_gid), self.fixture_seconds],
                                 "root", pass_fds=(listener.fileno(),))
            owned.append(monitor)
            labels["monitor"] = read_label(monitor.pid, self.tag) \
                if wait_for_image(monitor.pid, self.path("run", "monitor"), deadline) else "not-measured"
            image = self.installed if spec["frontend"] == "installed" else self.other
            frontend = self.spawn([str(image), "hold", str(path)], "operator")
            owned.append(frontend)
            self.read_hold(frontend, deadline)
            labels["frontend"] = read_label(frontend.pid, self.tag)
            frontend.stdin.write(b"g")
            frontend.stdin.close()
            frontend.stdin = None
            # The monitor first: one that fails before its verdict still publishes its error
            # category, and the frontend, left waiting, then has no exit (frontendExit unknown).
            monitor_raw = PL._read_output(monitor, deadline)
            try:
                PL._read_output(frontend, min(deadline, time.monotonic() + 3))
            except subprocess.TimeoutExpired:
                pass
        except subprocess.TimeoutExpired:
            error = "TimeoutError"
        except PL.OutputLimitError:
            error = "OutputLimitError"
        except (ValueError, OSError):
            error = "CaseFailure"
        finally:
            clean = _retire_all(owned)
            listener.close()
            path.unlink(missing_ok=True)
        if error:
            return self._failed(error, clean, {"labels": labels})
        return self._finish(evaluate_monitor(case, monitor_raw, monitor.returncode, frontend.returncode, labels), clean)

    def probe_case(self, case, spec):
        owned, labels, error, unit, unit_clean = [], {}, None, None, True
        deadline = time.monotonic() + self.timeout
        start_refused = False
        try:
            targets = [self.start_target(role, kind, deadline, owned, labels) for role, kind in spec["targets"].items()]
            shape = spec["shape"]
            if shape in ("B", "none-B"):
                arguments = self.probe_arguments("nodrop", spec["side"], targets)
                unit, command = self.unit_command(case, self.name("probe") if shape == "B" else None, arguments)
                self.units.append(unit)
                probe = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         env=PL.TOOL_ENV, cwd="/", start_new_session=True)
            else:
                arguments = self.probe_arguments("drop", spec["side"], targets)
                profile = {"A": self.name("monitor"), "complain": self.name("complain")}.get(shape)
                probe = self.spawn([self.tools["aa-exec"], "-p", profile, "--", *arguments] if profile else arguments,
                                   "root")
            owned.append(probe)
            try:
                ready = PL._read_exact(probe, deadline, 2)
            except ValueError:
                ready = b""
            if ready != b"R\n":
                # A shape B unit that never reached its handshake: recorded, and the case fails
                # (systemd refusing the start and a probe that died early look the same here).
                if shape == "B" and probe.wait(timeout=max(0.1, deadline - time.monotonic())) != 0:
                    start_refused = True
                else:
                    raise ValueError("probe did not start")
            else:
                labels["probe"] = self.unit_label(unit) if unit else read_label(probe.pid, self.tag)
                probe.stdin.write(b"g")
                probe.stdin.close()
                probe.stdin = None
                raw = PL._read_output(probe, deadline)
        except subprocess.TimeoutExpired:
            error = "TimeoutError"
        except PL.OutputLimitError:
            error = "OutputLimitError"
        except (ValueError, OSError):
            error = "CaseFailure"
        finally:
            clean = _retire_all(owned)
            if unit:
                unit_clean = _succeeds(self.stop_unit, unit)
        if error:
            result = self._failed(error, clean and unit_clean, {"labels": labels})
        elif start_refused:
            result = {"passed": False, "unitStart": "refused", "labels": dict(sorted(labels.items()))}
        else:
            result = evaluate_probe(case, raw, probe.returncode, labels)
        if unit:
            result["unitStoppedAndCgroupEmpty"] = unit_clean
        return self._finish(result, clean and unit_clean)

    def userns_case(self, case, spec):
        owned, error, extra = [], None, {}
        deadline = time.monotonic() + self.timeout
        try:
            helper = self.spawn([str(self.path("run", "probe")), "userns-bind", str(self.installed), str(self.control),
                                 str(self.path("s", "unused.sock"))], "operator")
            owned.append(helper)
            raw = _read_line(helper, deadline)
            report = PL.parse_report(raw)
            if report.get("mount") == "ok":
                # Unexpected: record the bound image's label and whether a confined probe reaches it.
                address = self.read_hold(helper, deadline)
                extra["boundLabel"] = read_label(helper.pid, self.tag)
                probe = self.spawn([self.tools["aa-exec"], "-p", self.name("monitor"), "--",
                                    *self.probe_arguments("drop", False, [f"bound=f:{helper.pid}:{address}:-:-"])],
                                   "root")
                owned.append(probe)
                if PL._read_exact(probe, deadline, 2) == b"R\n":
                    probe.stdin.write(b"g")
                    probe.stdin.close()
                    probe.stdin = None
                    bound = PL.parse_report(PL._read_output(probe, deadline))
                    extra["boundSeize"] = bound.get("bound.seize", "other") if bound.get("bound.seize") in ERRNO \
                        else "other"
        except subprocess.TimeoutExpired:
            error = "TimeoutError"
        except PL.OutputLimitError:
            error = "OutputLimitError"
        except (ValueError, OSError):
            error = "CaseFailure"
        finally:
            clean = _retire_all(owned)
        if error:
            return self._failed(error, clean, extra)
        return self._finish({**evaluate_userns(raw), **extra}, clean)

    def absent_case(self, case, spec):
        """aa-exec with a profile name that is not loaded: the probe must never run."""
        owned, error = [], None
        deadline = time.monotonic() + self.timeout
        try:
            probe = self.spawn([self.tools["aa-exec"], "-p", self.name("absent"), "--",
                                *self.probe_arguments("drop", False, [])], "root")
            owned.append(probe)
            output = PL._read_output(probe, deadline)
        except subprocess.TimeoutExpired:
            error = "TimeoutError"
        except PL.OutputLimitError:
            error = "OutputLimitError"
        except (ValueError, OSError):
            error = "CaseFailure"
        finally:
            clean = _retire_all(owned)
        if error:
            return self._failed(error, clean)
        result = {"aaExecExit": "zero" if probe.returncode == 0 else "nonzero",
                  "probeOutput": "none" if output == b"" else "present"}
        result["passed"] = result == {"aaExecExit": "nonzero", "probeOutput": "none"}
        return self._finish(result, clean)

    def kill_case(self, case, spec):
        """A confined probe that waits past its deadline: the runner's kill must end it."""
        labels, error, killed = {}, None, False
        deadline = time.monotonic() + self.timeout
        probe = self.spawn([self.tools["aa-exec"], "-p", self.name("monitor"), "--",
                            *self.probe_arguments("drop", False, [])], "root")
        try:
            if PL._read_exact(probe, deadline, 2) != b"R\n":
                raise ValueError("probe did not start")
            labels["probe"] = read_label(probe.pid, self.tag)
            time.sleep(1)  # the case deadline, shortened: the probe still waits for its go byte
            if probe.poll() is None:
                try:
                    os.killpg(probe.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass  # it ended on its own between the poll and the kill: killedBySigkill stays false
                killed = probe.wait(timeout=3) == -signal.SIGKILL
        except subprocess.TimeoutExpired:
            error = "TimeoutError"
        except (ValueError, OSError):
            error = "CaseFailure"
        finally:
            clean = _retire(probe)
        if error:
            return self._failed(error, clean, {"labels": labels})
        result = {"labels": labels, "killedBySigkill": killed}
        mismatches = _labels_mismatch(spec, labels) + ([] if killed else ["killedBySigkill"])
        result.update(mismatches=sorted(mismatches), passed=not mismatches)
        return self._finish(result, clean)

    # Evidence and cleanup ---------------------------------------------------------------------

    def denials(self, since):
        """This run's AppArmor audit lines from the kernel log, summarized."""
        path = self.path("journal")
        try:
            # 0600: a raw kernel log excerpt, in a 0755 directory, until cleanup removes it.
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600), "wb") as output:
                subprocess.run([self.tools["journalctl"], "-k", "-o", "cat", "--no-pager", f"--since=@{int(since)}"],
                               stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL, env=PL.TOOL_ENV,
                               cwd="/", timeout=self.timeout, check=False)
            with open(path, "rb") as stream:
                text = stream.read(JOURNAL_LIMIT).decode("utf-8", "replace")
        except (OSError, subprocess.SubprocessError):
            return "unavailable"
        return summarize_denials(text, self.tag, self.base)

    def cleanup(self):
        """Units first, then profiles (every fixture process is already reaped: a removed
        profile does not keep its tasks confined), then the #728 files, user and group. Each
        step runs even when an earlier one fails, except one: while a unit or a fixture process
        may still live, the profiles stay loaded (until reboot), so nothing that holds
        CAP_SYS_PTRACE loses its confinement."""
        units = all([_succeeds(self.stop_unit, unit) for unit in self.units])
        if units and not self.unreaped:
            profiles = all([_succeeds(self.remove_profile, name) for name in self.loaded])
        else:
            profiles = not self.loaded
        state = super().cleanup()
        return {"transientUnitsStopped": units, "profilesRemoved": profiles, **state}


def _succeeds(action, *arguments):
    try:
        return bool(action(*arguments))
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return False


def preconditions(timeout):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("requires Linux x86_64")
    if os.geteuid() != 0 or os.getuid() != 0:
        raise RuntimeError("requires root")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 5 <= timeout <= 60:
        raise ValueError("timeout must be at least 5 and at most 60 seconds")
    operator = PL.operator_account()
    if not PL.root_owned_ancestry(PL.BASE_PARENT) or os.statvfs(PL.BASE_PARENT).f_flag & os.ST_NOSUID:
        raise RuntimeError("experiment parent must be root-owned and allow set-ID execution")
    tools = {name: shutil.which(name, path=PL.TOOL_ENV["PATH"]) for name in TOOLS}
    if not all(tools.values()):
        raise RuntimeError("missing AppArmor or systemd tools")
    if PL._policy_bytes("/sys/module/apparmor/parameters/enabled", 64) not in (b"Y\n", b"Y") \
            or not {"read", "trace"} <= set(_feature("ptrace/mask") or ()) or not REMOVE_PROFILE.exists():
        raise RuntimeError("AppArmor with ptrace mediation is required")
    if any(name.startswith(PROFILE_PREFIX) for name in loaded_profiles()):
        sys.stderr.write("An rmzmc- profile is already loaded, from an earlier run. Remove it first: write each "
                         "rmzmc- name in /sys/kernel/security/apparmor/profiles to "
                         "/sys/kernel/security/apparmor/.remove.\n")
        raise RuntimeError("experiment profile already loaded")
    return operator, tools


def measure(timeout=15):
    operator, tools = preconditions(timeout)
    host = PL.host_metadata()
    aa = apparmor_metadata(parser_version(tools["apparmor_parser"], timeout))
    run = Run(operator, timeout, tools)
    since = time.time() - 1
    setup, cases, denials = {}, {}, "not-measured"
    with PL.subreaper():
        try:
            setup = run.setup()
            # A failed setup check means the cases would not measure the design: none starts.
            if all(setup.values()):
                cases = {case: run.run_case(case) for case in CASES}
            denials = run.denials(since) if run.base_created else "not-measured"
        finally:
            cleanup = run.cleanup()
            if not all(cleanup.values()):
                sys.stderr.write(f"Disposable state not fully removed: inspect {PL.BASE_PARENT}/{BASE_PREFIX}*, the "
                                 "rmzcg*/rmzcm* system accounts, rmzmc-* transient units, and the rmzmc- profiles in "
                                 "/sys/kernel/security/apparmor/profiles. End every remaining fixture process and "
                                 "rmzmc- unit first, then remove each profile by writing its name to "
                                 "/sys/kernel/security/apparmor/.remove.\n")
    passed = (bool(setup) and all(setup.values()) and all(cleanup.values()) and set(cases) == set(CASES)
              and all(item["passed"] for item in cases.values()))
    return {"experiment": "linux-monitor-confinement-v1",
            "measuredAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "supervised": True, "trustedCode": False, "productionAdmission": False,
            "host": host, "apparmor": aa, "sources": source_hashes(),
            "build": {name: [*PL.CC_FLAGS, *extra] for name, (_source, extra) in BUILDS.items()},
            "installedImageSha256": getattr(run, "frontend_sha256", "not-measured"),
            "setup": setup, "cases": cases, "denials": denials, "cleanup": cleanup, "passed": passed,
            "limits": ["C measurement fixtures, not the production frontend or monitor",
                       "the policy confines by program, not by user: any instance of the installed frontend, a Root "
                       "one included, carries the frontend label (n7c)",
                       "procfs entries that are not ptrace-checked (status, most of stat) stay readable",
                       "one host, one kernel, one AppArmor version; a host with AppArmor off is not measured",
                       "no production refusal code, installed units, stopped handoff or executor"]}


def _cancel(_signum, _frame):
    raise KeyboardInterrupt()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--timeout", type=float, default=15, help="seconds per case (5 <= timeout <= 60)")
    args = parser.parse_args()
    previous = {number: signal.signal(number, _cancel) for number in (signal.SIGTERM, signal.SIGHUP)}
    try:
        try:
            report = measure(args.timeout)
        except KeyboardInterrupt:
            parser.exit(130, "Monitor confinement experiment cancelled.\n")
        except Exception:  # noqa: BLE001 - never publish a traceback with paths or PIDs
            parser.exit(2, "Monitor confinement experiment unavailable; no raw diagnostic data published.\n")
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
