import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-linux-monitor-confinement-experiment.py"
SPEC = importlib.util.spec_from_file_location("linux_monitor_confinement_experiment", SCRIPT)
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)
PL = EXPERIMENT.PL
TAG = "0123abcd"
OPERATOR = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator")


def first(expected):
    return {key: sorted(allowed)[0] for key, allowed in expected.items()}


def report(case, **changes):
    values = first(EXPERIMENT.CASES[case]["expect"])
    values.update(changes)
    return json.dumps(values).encode()


def labels(case, **changes):
    return {**EXPERIMENT.CASES[case]["labels"], **changes}


def rendered():
    return EXPERIMENT.render_profiles(EXPERIMENT.PROFILES.read_text(), TAG, EXPERIMENT.base_for(TAG))


def rules(text):
    """The rule lines of one rendered profile, without comments, the header or the brace."""
    lines = [line.strip() for line in text.splitlines()]
    body = lines[lines.index(next(line for line in lines if line.startswith("profile "))) + 1:]
    return [line for line in body if line and not line.startswith("#") and line != "}"]


def new_run():
    return EXPERIMENT.Run(OPERATOR, 15, {name: f"/usr/bin/{name}" for name in EXPERIMENT.TOOLS})


class CaseTableTests(unittest.TestCase):
    def test_every_plan_case_is_measured_and_profile_removal_runs_last(self):
        self.assertEqual(list(EXPERIMENT.CASES), ["p1c", "n1c", "n2c", "n3c", "n4c", "n5c", "n6c", "n7c", "c1", "c2",
                                                  "f1", "f2", "k1", "f3"])

    def test_probe_tables_use_the_probe_vocabulary(self):
        source = EXPERIMENT.PROBE.read_text()
        for case, spec in EXPERIMENT.CASES.items():
            if spec["kind"] != "probe":
                continue
            for key, allowed in spec["expect"].items():
                with self.subTest(case=case, key=key):
                    self.assertTrue(allowed <= EXPERIMENT.PROBE_VALUES)
                    self.assertIn(f'"{key.rpartition(".")[2]}"', source)
            self.assertIn("probe", spec["labels"])
            self.assertEqual(set(spec["labels"]) - {"probe"}, set(spec["targets"]))

    def test_monitor_cases_require_every_monitor_key_and_the_labels(self):
        for case in ("p1c", "n5c", "f3"):
            with self.subTest(case=case):
                expect = EXPERIMENT.CASES[case]["expect"]
                self.assertEqual(set(expect), set(PL.MONITOR_KEYS))
                self.assertEqual(expect["monitorAppArmor"], {"confined"})
        self.assertEqual(EXPERIMENT.CASES["p1c"]["expect"]["frontendAppArmor"], {"confined"})

    def test_controls_differ_from_the_confined_case_only_in_reach(self):
        confined, control = EXPERIMENT.CASES["n1c"]["expect"], EXPERIMENT.CASES["c1"]["expect"]
        differ = {key for key in confined.keys() & control.keys() if confined[key] != control[key]}
        self.assertEqual(differ, {"sleeper.seize", "sleeper.vmRead", "sleeper.pidfdGetfd", "sleeper.getfdCopyIsPipe",
                                  "sleeper.mapsRead"})
        self.assertEqual(EXPERIMENT.CASES["c1"]["labels"]["probe"], EXPERIMENT.UNCONFINED)
        self.assertEqual(EXPERIMENT.CASES["c2"]["shape"], "none-B")

    def test_mem_open_is_refused_by_the_permission_check_in_every_case(self):
        for case, spec in EXPERIMENT.CASES.items():
            for key, allowed in spec.get("expect", {}).items() if spec["kind"] == "probe" else ():
                if key.endswith(".memOpen"):
                    self.assertEqual(allowed, {"EACCES"}, case)

    def test_the_root_frontend_limit_is_recorded_as_reachable(self):
        spec = EXPERIMENT.CASES["n7c"]
        self.assertEqual(spec["targets"], {"root": "root-frontend"})
        self.assertEqual(spec["expect"]["root.seize"], {"ok"})
        self.assertEqual(spec["labels"]["root"], EXPERIMENT.FRONTEND_LABEL)


class ProfileTests(unittest.TestCase):
    def test_rendering_is_exact_and_names_every_profile(self):
        profiles = rendered()
        self.assertEqual(set(profiles), {f"rmzmc-{role}-{TAG}" for role in EXPERIMENT.ROLES})
        base = str(EXPERIMENT.base_for(TAG))
        for name, text in profiles.items():
            with self.subTest(name=name):
                self.assertTrue(text.startswith(EXPERIMENT.ABI_LINE + "\n\n"))
                self.assertNotIn("@@", text)
                self.assertEqual(text.count("\nprofile "), 1)
        self.assertIn(f"profile rmzmc-frontend-{TAG} {base}/run/remozio flags=(enforce) {{",
                      profiles[f"rmzmc-frontend-{TAG}"])

    def test_rendering_refuses_a_bad_tag_base_or_template(self):
        template = EXPERIMENT.PROFILES.read_text()
        with self.assertRaises(ValueError):
            EXPERIMENT.render_profiles(template, "ZZZZ", EXPERIMENT.base_for("ZZZZ"))
        with self.assertRaises(ValueError):
            EXPERIMENT.render_profiles(template, TAG, Path("/tmp/elsewhere"))
        with self.assertRaises(ValueError):
            EXPERIMENT.render_profiles(template.replace("abi <abi/4.0>,", ""), TAG, EXPERIMENT.base_for(TAG))
        with self.assertRaises(ValueError):
            EXPERIMENT.render_profiles(template + "\ncapability sys_admin,\n", TAG, EXPERIMENT.base_for(TAG))

    def test_template_includes_nothing(self):
        for line in EXPERIMENT.PROFILES.read_text().splitlines():
            self.assertNotRegex(line.strip(), r"^#?include\b")

    def test_ptrace_rules_name_only_the_experiment_labels(self):
        profiles = rendered()
        expected = {
            "frontend": {f"ptrace (readby, tracedby) peer=rmzmc-monitor-{TAG},",
                         f"ptrace (readby, tracedby) peer=rmzmc-probe-{TAG},"},
            "monitor": {f"ptrace (read, trace) peer=rmzmc-frontend-{TAG},"},
            "probe": {f"ptrace (read, trace) peer=rmzmc-frontend-{TAG},"},
            "complain": {f"ptrace (read, trace) peer=rmzmc-frontend-{TAG},"},
        }
        for role, lines in expected.items():
            with self.subTest(role=role):
                ptrace = {line for line in rules(profiles[f"rmzmc-{role}-{TAG}"]) if line.startswith("ptrace")}
                self.assertEqual(ptrace, lines)
        for text in profiles.values():
            for line in rules(text):
                if "peer=unconfined" in line:
                    self.assertTrue(line.startswith("signal (receive) set=("), line)

    def test_monitor_and_probe_grant_no_exec_and_one_write_rule(self):
        base = str(EXPERIMENT.base_for(TAG))
        for role in ("monitor", "probe"):
            with self.subTest(role=role):
                lines = rules(rendered()[f"rmzmc-{role}-{TAG}"])
                files = [line for line in lines if line.startswith("/")]
                for line in files:
                    perms = line.rstrip(",").rsplit(" ", 1)[1]
                    self.assertNotIn("x", perms)
                    self.assertTrue("w" not in perms or line == f"{base}/s/*.sock rw,", line)
                self.assertIn("deny network inet,", lines)
                self.assertIn("deny network inet6,", lines)
                self.assertFalse(any(line.startswith("network") for line in lines))
                self.assertFalse(any(re.search(r"/proc/\S*\b(mem|fd)\b", line) for line in files))

    def test_capabilities_are_exact(self):
        capabilities = {role: {line for line in rules(text) if line.startswith("capability")}
                        for role, text in ((name.split("-")[1], text) for name, text in rendered().items())}
        self.assertEqual(capabilities["frontend"], set())
        self.assertEqual(capabilities["probe"], {"capability sys_ptrace,"})
        self.assertEqual(capabilities["monitor"], {"capability sys_ptrace,", "capability setuid,",
                                                   "capability setgid,", "capability setpcap,"})

    def test_complain_profile_is_the_monitor_profile_in_complain_mode(self):
        profiles = rendered()
        monitor, complain = profiles[f"rmzmc-monitor-{TAG}"], profiles[f"rmzmc-complain-{TAG}"]
        self.assertIn(f"profile rmzmc-complain-{TAG} flags=(complain) {{", complain)
        # The same rules; its signals to itself name its own label.
        self.assertEqual(rules(monitor.replace(f"rmzmc-monitor-{TAG}", f"rmzmc-complain-{TAG}")), rules(complain))

    @unittest.skipUnless(shutil.which("apparmor_parser") and Path("/etc/apparmor.d/abi/4.0").is_file(),
                         "AppArmor parser with the 4.0 ABI file")
    def test_rendered_profiles_compile_without_warnings(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, text in rendered().items():
                path = Path(directory, name)
                path.write_text(text)
                with self.subTest(name=name):
                    result = subprocess.run(["apparmor_parser", "--warn=all", "-Q", "-K", str(path)],
                                            stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
                    self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))


class EvaluateTests(unittest.TestCase):
    def test_expected_outcome_passes_for_every_probe_case(self):
        for case, spec in EXPERIMENT.CASES.items():
            if spec["kind"] == "probe":
                with self.subTest(case=case):
                    self.assertTrue(EXPERIMENT.evaluate_probe(case, report(case), 0, labels(case))["passed"])

    def test_expected_outcome_passes_for_every_monitor_case(self):
        for case, spec in EXPERIMENT.CASES.items():
            if spec["kind"] == "monitor":
                exit_code = {"accepted": 0, "rejected": 2}[spec["frontendExit"]]
                with self.subTest(case=case):
                    self.assertTrue(EXPERIMENT.evaluate_monitor(case, report(case), 0, exit_code, labels(case))["passed"])

    def test_a_changed_value_or_label_fails(self):
        result = EXPERIMENT.evaluate_probe("n1c", report("n1c", **{"sleeper.seize": "ok"}), 0, labels("n1c"))
        self.assertEqual((result["passed"], result["mismatches"]), (False, ["probe.sleeper.seize"]))
        result = EXPERIMENT.evaluate_probe("n1c", report("n1c"), 0, labels("n1c", probe=EXPERIMENT.UNCONFINED))
        self.assertEqual(result["mismatches"], ["label.probe"])
        result = EXPERIMENT.evaluate_monitor("p1c", report("p1c", monitorAppArmor="unconfined"), 0, 0, labels("p1c"))
        self.assertEqual(result["mismatches"], ["monitor.monitorAppArmor"])
        result = EXPERIMENT.evaluate_monitor("n5c", report("n5c"), 0, 0, labels("n5c"))
        self.assertEqual(result["mismatches"], ["frontendExit"])

    def test_probe_error_and_exit_status_fail(self):
        result = EXPERIMENT.evaluate_probe("n4c", report("n4c", error="no-go"), 0, labels("n4c"))
        self.assertIn("probe.error", result["mismatches"])
        result = EXPERIMENT.evaluate_probe("n4c", report("n4c"), 3, labels("n4c"))
        self.assertEqual(result["mismatches"], ["probe.exitStatus"])

    def test_unknown_keys_values_or_shapes_publish_nothing(self):
        for raw in (report("n4c", extra="ok"), report("n4c", fileCreate="/private/path"), b"[1]", b"{",
                    b'{"a":"b","a":"c"}'):
            with self.subTest(raw=raw):
                result = EXPERIMENT.evaluate_probe("n4c", raw, 0, labels("n4c"))
                self.assertEqual(result["error_type"], "InvalidProbeReport")
                self.assertNotIn("probe", result)
        result = EXPERIMENT.evaluate_monitor("p1c", report("p1c", seize="/private/path"), 0, 0, labels("p1c"))
        self.assertEqual((result["error_type"], "monitor" in result), ("InvalidMonitorReport", False))

    def test_monitor_error_publishes_a_known_category_only(self):
        for error, published in (("accept-timeout", "accept-timeout"), ("/private/path", None)):
            result = EXPERIMENT.evaluate_monitor("p1c", json.dumps({"error": error}).encode(), 3, 0, labels("p1c"))
            self.assertEqual((result["error_type"], result.get("monitorError")), ("MonitorError", published))

    def test_user_namespace_case_accepts_a_refusal_or_an_unmapped_namespace(self):
        for helper, passed in (({"userns": "EPERM", "uidMap": "not-attempted", "mount": "not-attempted"}, True),
                               ({"userns": "ok", "uidMap": "EACCES", "mount": "EACCES"}, True),
                               ({"userns": "ok", "uidMap": "ok", "mount": "EPERM"}, True),
                               ({"userns": "ok", "uidMap": "ok", "mount": "ok"}, False),
                               ({"userns": "EINVAL", "uidMap": "not-attempted", "mount": "not-attempted"}, False)):
            with self.subTest(helper=helper):
                self.assertEqual(EXPERIMENT.evaluate_userns(json.dumps(helper).encode())["passed"], passed)
        self.assertEqual(EXPERIMENT.evaluate_userns(b'{"userns":"ok"}')["error_type"], "InvalidHelperReport")

    def test_frontend_exit_categories(self):
        self.assertEqual([EXPERIMENT.frontend_exit(code) for code in (0, 2, 10, 99, -9, None)],
                         ["accepted", "rejected", "connect-EACCES", "other", "signaled", "unknown"])


class LabelAndDenialTests(unittest.TestCase):
    def test_labels_replace_the_tag_and_publish_closed_values_only(self):
        self.assertEqual(EXPERIMENT.sanitize_label(f"rmzmc-monitor-{TAG} (enforce)\n".encode(), TAG),
                         EXPERIMENT.MONITOR_LABEL)
        self.assertEqual(EXPERIMENT.sanitize_label(b"unconfined\n", TAG), "unconfined")
        self.assertEqual(EXPERIMENT.sanitize_label(b"/usr/bin/other (enforce)\n", TAG), "other")
        self.assertEqual(EXPERIMENT.sanitize_label(b"rmzmc-monitor-ffffffff (enforce)\n", TAG), "other")
        self.assertEqual(EXPERIMENT.sanitize_label(None, TAG), "not-measured")

    def test_labels_accept_the_kernel_nul_terminator(self):
        self.assertEqual(EXPERIMENT.sanitize_label(f"rmzmc-probe-{TAG} (enforce)\0".encode(), TAG),
                         EXPERIMENT.PROBE_LABEL)
        self.assertEqual(EXPERIMENT.sanitize_label(b"unconfined\n\0", TAG), "unconfined")

    def test_stacked_labels_publish_known_parts_only(self):
        self.assertEqual(EXPERIMENT.sanitize_label(f"rmzmc-probe-{TAG}//&unconfined (mixed)\0".encode(), TAG),
                         "stack(probe+unconfined) (mixed)")
        self.assertEqual(EXPERIMENT.sanitize_label(f"unconfined//&rmzmc-probe-{TAG} (enforce)\n".encode(), TAG),
                         "stack(unconfined+probe) (enforce)")
        self.assertEqual(EXPERIMENT.sanitize_label(b"/usr/bin/x//&unconfined (enforce)", TAG),
                         "stack(other+unconfined) (enforce)")
        self.assertEqual(EXPERIMENT.sanitize_label(f"rmzmc-probe-{TAG}//&unconfined (secret)".encode(), TAG), "other")
        self.assertEqual(EXPERIMENT.sanitize_label(f"rmzmc-probe-{TAG}//child (enforce)".encode(), TAG), "other")
        self.assertEqual(EXPERIMENT.sanitize_label(("a//&" * 4 + "b (enforce)").encode(), TAG), "other")
        four = "//&".join(f"rmzmc-{role}-{TAG}" for role in ("frontend", "monitor", "probe", "complain"))
        self.assertEqual(EXPERIMENT.sanitize_label(f"{four} (enforce)".encode(), TAG),
                         "stack(frontend+monitor+probe+complain) (enforce)")
        self.assertEqual(EXPERIMENT.sanitize_label(f"rmzmc-probe-{TAG}//&unconfined".encode(), TAG), "other")

    def test_a_refused_seize_is_the_apparmor_eacces(self):
        for case in ("n1c", "n2c"):
            self.assertEqual(EXPERIMENT.CASES[case]["expect"]["sleeper.seize"], {"EACCES"})
        self.assertEqual(EXPERIMENT.CASES["n3c"]["expect"]["copy.seize"], {"EACCES"})
        self.assertEqual(EXPERIMENT.FRONTEND_REFUSED["seize"], "EACCES")
        for case in ("n5c", "f3"):
            self.assertEqual(EXPERIMENT.CASES[case]["expect"]["seize"], {"EACCES"})
        self.assertEqual(EXPERIMENT.CASES["n1c"]["expect"]["sleeper.vmRead"], {"EPERM"})

    def test_loaded_profiles_parses_names_and_modes(self):
        listing = b"rmzmc-frontend-0123abcd (enforce)\n/usr/bin/man (complain)\nbroken line\n"
        with patch.object(EXPERIMENT, "LOADED_PROFILES", Mock(read_bytes=Mock(return_value=listing))):
            self.assertEqual(EXPERIMENT.loaded_profiles(),
                             {"rmzmc-frontend-0123abcd": "enforce", "/usr/bin/man": "complain"})

    def test_denial_summary_keeps_closed_fields_only(self):
        base = EXPERIMENT.base_for(TAG)
        journal = "\n".join([
            f'audit: type=1400 audit(1.2:3): apparmor="DENIED" operation="ptrace" class="ptrace" '
            f'profile="rmzmc-monitor-{TAG}" pid=4242 comm="probe" requested_mask="trace" denied_mask="trace" '
            f'peer="unconfined"',
            f'audit: type=1400 audit(1.2:4): apparmor="DENIED" operation="ptrace" class="ptrace" '
            f'profile="rmzmc-monitor-{TAG}" pid=4243 comm="probe" requested_mask="trace" denied_mask="trace" '
            f'peer="unconfined"',
            f'audit: type=1400 audit(1.2:5): apparmor="DENIED" operation="open" class="file" '
            f'profile="rmzmc-monitor-{TAG}" name="/proc/4242/fd/" pid=4242 comm="monitor" requested_mask="r" '
            f'denied_mask="r" fsuid=999 ouid=0',
            f'audit: type=1400 audit(1.2:6): apparmor="DENIED" operation="mknod" class="file" '
            f'profile="rmzmc-probe-{TAG}" name="{base}/w/probe-created" pid=1 comm="probe" requested_mask="c" '
            f'denied_mask="c"',
            f'audit: type=1400 audit(1.2:7): apparmor="DENIED" operation="open" class="file" '
            f'profile="rmzmc-probe-{TAG}" name="/home/someone/secret" pid=1 comm="probe" requested_mask="r" '
            f'denied_mask="r"',
            'audit: type=1400 audit(1.2:8): apparmor="DENIED" operation="open" profile="/usr/bin/other" name="/x"',
            "unrelated kernel line",
        ])
        summary = EXPERIMENT.summarize_denials(journal, TAG, base)
        self.assertEqual(summary, [
            {"result": "DENIED", "profile": "monitor", "operation": "open", "class": "file", "mask": "r",
             "peer": "none", "signal": "none", "target": "/proc/<pid>/fd/", "count": 1},
            {"result": "DENIED", "profile": "monitor", "operation": "ptrace", "class": "ptrace", "mask": "trace",
             "peer": "unconfined", "signal": "none", "target": "none", "count": 2},
            {"result": "DENIED", "profile": "probe", "operation": "mknod", "class": "file", "mask": "c",
             "peer": "none", "signal": "none", "target": "<base>/w/probe-created", "count": 1},
            {"result": "DENIED", "profile": "probe", "operation": "open", "class": "file", "mask": "r",
             "peer": "none", "signal": "none", "target": "other", "count": 1},
        ])
        self.assertNotIn("4242", json.dumps(summary))
        self.assertNotIn(TAG, json.dumps(summary))


class RunTests(unittest.TestCase):
    def test_disposable_names_carry_this_experiment_prefix(self):
        run = new_run()
        self.assertEqual(run.base, EXPERIMENT.base_for(run.tag))
        self.assertEqual((run.group_name, run.monitor_name), (f"rmzcg{run.tag}", f"rmzcm{run.tag}"))
        self.assertEqual(run.name("probe"), f"rmzmc-probe-{run.tag}")

    def test_fixtures_get_pipes_and_no_inherited_environment(self):
        run = new_run()
        run.operator_groups = [1000]
        with patch.object(EXPERIMENT.subprocess, "Popen") as popen:
            run.spawn(["/x"], "root")
            run.spawn(["/x"], "operator")
        for invocation in popen.call_args_list:
            options = invocation.kwargs
            self.assertEqual((options["stdin"], options["stdout"], options["stderr"]), (subprocess.PIPE,) * 3)
            self.assertEqual((options["env"], options["cwd"], options["start_new_session"]), ({}, "/", True))
        self.assertEqual(popen.call_args_list[1].kwargs["user"], 1000)
        self.assertNotIn("user", popen.call_args_list[0].kwargs)

    def test_transient_unit_keeps_only_cap_sys_ptrace_under_no_new_privs(self):
        run = new_run()
        unit, command = run.unit_command("n2c", run.name("probe"), ["/probe", "probe"])
        self.assertEqual(unit, f"rmzmc-{run.tag}-n2c.service")
        properties = {item.split("=", 1)[1] for item in command if item.startswith("--property=")}
        self.assertEqual(properties, {f"User={run.monitor_name}", f"Group={run.monitor_name}",
                                      "AmbientCapabilities=CAP_SYS_PTRACE", "CapabilityBoundingSet=CAP_SYS_PTRACE",
                                      "NoNewPrivileges=yes", "WorkingDirectory=/", "RuntimeMaxSec=15",
                                      f"AppArmorProfile=rmzmc-probe-{run.tag}"})
        self.assertIn("--collect", command)
        self.assertEqual(command[-3:], ["--", "/probe", "probe"])
        _, control = run.unit_command("c2", None, ["/probe"])
        self.assertFalse(any("AppArmorProfile" in item for item in control))

    def test_remove_profile_touches_only_names_this_run_loaded(self):
        run = new_run()
        run.loaded = [run.name("monitor")]
        state = {run.name("monitor"): "enforce", "rmzmc-other-ffffffff": "enforce"}
        written = []

        def remove(name):
            written.append(name)
            state.pop(name)

        handle = Mock()
        handle.__enter__ = Mock(return_value=Mock(write=remove))
        handle.__exit__ = Mock(return_value=False)
        with patch.object(EXPERIMENT, "loaded_profiles", side_effect=lambda: dict(state)), \
             patch.object(EXPERIMENT, "REMOVE_PROFILE", Mock(open=Mock(return_value=handle))):
            self.assertFalse(run.remove_profile("rmzmc-other-ffffffff"))
            self.assertTrue(run.remove_profile(run.name("monitor")))
        self.assertEqual(written, [run.name("monitor")])

    def test_kernel_log_excerpt_is_private(self):
        run = new_run()
        with tempfile.TemporaryDirectory() as directory:
            run.path = lambda name: os.path.join(directory, name)
            run.tools = {"journalctl": "/usr/bin/true"}  # present on Linux and macOS
            with patch.object(EXPERIMENT, "summarize_denials", return_value=[]):
                self.assertEqual(run.denials(0), [])
            self.assertEqual(os.stat(os.path.join(directory, "journal")).st_mode & 0o777, 0o600)

    def test_cleanup_order_is_units_then_profiles_then_files_and_accounts(self):
        run = new_run()
        run.units, run.loaded = ["u.service"], ["a", "b"]
        order = Mock()
        order.stop_unit.return_value = order.remove_profile.return_value = True
        order.state.return_value = {"filesRemoved": True}
        with patch.object(run, "stop_unit", order.stop_unit), patch.object(run, "remove_profile", order.remove_profile), \
             patch.object(PL.Run, "cleanup", order.state):
            state = run.cleanup()
        self.assertEqual(order.mock_calls, [call.stop_unit("u.service"), call.remove_profile("a"),
                                            call.remove_profile("b"), call.state()])
        self.assertEqual(state, {"transientUnitsStopped": True, "profilesRemoved": True, "filesRemoved": True})

    def test_cleanup_continues_after_a_failed_profile_removal(self):
        run = new_run()
        run.units, run.loaded = ["u.service"], ["a", "b"]
        with patch.object(run, "stop_unit", return_value=True), \
             patch.object(run, "remove_profile", side_effect=[OSError(), True]) as remove, \
             patch.object(PL.Run, "cleanup", return_value={"filesRemoved": True}) as state:
            result = run.cleanup()
        self.assertEqual(remove.call_count, 2)
        state.assert_called_once_with()
        self.assertEqual((result["transientUnitsStopped"], result["profilesRemoved"]), (True, False))

    def test_cleanup_keeps_profiles_while_a_unit_may_still_run(self):
        run = new_run()
        run.units, run.loaded = ["u.service"], ["a"]
        with patch.object(run, "stop_unit", side_effect=RuntimeError()), \
             patch.object(run, "remove_profile") as remove, \
             patch.object(PL.Run, "cleanup", return_value={"filesRemoved": True}) as state:
            result = run.cleanup()
        remove.assert_not_called()
        state.assert_called_once_with()
        self.assertEqual((result["transientUnitsStopped"], result["profilesRemoved"]), (False, False))

    def test_cleanup_keeps_profiles_after_a_case_left_a_process(self):
        run = new_run()
        run.loaded = ["a"]
        with patch.object(run, "probe_case", return_value={"passed": False,
                                                           "cleanupReapedAllFixtureProcesses": False}):
            run.run_case("n1c")
        self.assertTrue(run.unreaped)
        with patch.object(run, "remove_profile") as remove, \
             patch.object(PL.Run, "cleanup", return_value={"filesRemoved": True}):
            result = run.cleanup()
        remove.assert_not_called()
        self.assertFalse(result["profilesRemoved"])


@contextlib.contextmanager
def linux_root():
    with contextlib.ExitStack() as stack:
        for owner, name, value in ((EXPERIMENT.platform, "system", "Linux"), (EXPERIMENT.platform, "machine", "x86_64"),
                                   (EXPERIMENT.os, "geteuid", 0), (EXPERIMENT.os, "getuid", 0)):
            stack.enter_context(patch.object(owner, name, return_value=value))
        stack.enter_context(patch.object(PL, "operator_account", return_value=OPERATOR))
        stack.enter_context(patch.object(PL, "root_owned_ancestry", return_value=True))
        stack.enter_context(patch.object(EXPERIMENT.os, "statvfs", return_value=SimpleNamespace(f_flag=0)))
        stack.enter_context(patch.object(EXPERIMENT.shutil, "which", side_effect=lambda name, path=None: f"/x/{name}"))
        yield


class PreconditionTests(unittest.TestCase):
    def policy(self, enabled=b"Y\n", mask=b"read trace\n"):
        values = {"/sys/module/apparmor/parameters/enabled": enabled,
                  str(EXPERIMENT.APPARMOR / "features/ptrace/mask"): mask}
        return lambda path, limit=4096: values.get(str(path))

    def test_refuses_without_root_or_with_a_bad_timeout(self):
        with patch.object(EXPERIMENT.os, "geteuid", return_value=1000), \
             patch.object(EXPERIMENT.platform, "system", return_value="Linux"), \
             patch.object(EXPERIMENT.platform, "machine", return_value="x86_64"):
            with self.assertRaisesRegex(RuntimeError, "requires root"):
                EXPERIMENT.preconditions(15)
        with linux_root():
            for timeout in (4, 61, float("nan"), "15"):
                with self.assertRaises(ValueError):
                    EXPERIMENT.preconditions(timeout)

    def test_refuses_without_apparmor_ptrace_mediation_or_the_remove_interface(self):
        for enabled, mask, remove in ((b"N\n", b"read trace\n", True), (b"Y\n", b"\n", True),
                                      (b"Y\n", b"read trace\n", False)):
            with self.subTest(enabled=enabled, mask=mask, remove=remove), linux_root(), \
                 patch.object(PL, "_policy_bytes", side_effect=self.policy(enabled, mask)), \
                 patch.object(EXPERIMENT, "REMOVE_PROFILE", Mock(exists=Mock(return_value=remove))), \
                 patch.object(EXPERIMENT, "loaded_profiles", return_value={}):
                with self.assertRaisesRegex(RuntimeError, "AppArmor with ptrace mediation"):
                    EXPERIMENT.preconditions(15)

    def test_refuses_while_an_experiment_profile_is_loaded(self):
        stderr = io.StringIO()
        with linux_root(), patch.object(PL, "_policy_bytes", side_effect=self.policy()), \
             patch.object(EXPERIMENT, "REMOVE_PROFILE", Mock(exists=Mock(return_value=True))), \
             patch.object(EXPERIMENT, "loaded_profiles", return_value={"rmzmc-probe-ffffffff": "enforce"}), \
             patch.object(EXPERIMENT.sys, "stderr", stderr):
            with self.assertRaisesRegex(RuntimeError, "already loaded"):
                EXPERIMENT.preconditions(15)
        self.assertIn("/sys/kernel/security/apparmor/.remove", stderr.getvalue())

    def measure_with(self, run):
        with patch.object(EXPERIMENT, "preconditions", return_value=(OPERATOR, {"apparmor_parser": "/x"})), \
             patch.object(PL, "host_metadata", return_value={}), \
             patch.object(EXPERIMENT, "apparmor_metadata", return_value={}), \
             patch.object(EXPERIMENT, "parser_version", return_value="test"), \
             patch.object(EXPERIMENT, "Run", return_value=run), \
             patch.object(PL, "subreaper", contextlib.nullcontext):
            return EXPERIMENT.measure()

    def test_a_failed_setup_check_starts_no_case_and_cleanup_still_runs(self):
        run = Mock(base_created=True)
        run.setup.return_value = {"profilesLoadedInExpectedMode": False}
        run.cleanup.return_value = {"profilesRemoved": True}
        run.denials.return_value = []
        result = self.measure_with(run)
        run.run_case.assert_not_called()
        run.cleanup.assert_called_once_with()
        self.assertEqual((result["passed"], result["cases"]), (False, {}))

    def test_every_case_must_run_and_pass(self):
        run = Mock(base_created=True)
        run.setup.return_value = {"profilesLoadedInExpectedMode": True}
        run.cleanup.return_value = {"profilesRemoved": True}
        run.denials.return_value = []
        run.run_case.return_value = {"passed": True}
        result = self.measure_with(run)
        self.assertEqual([item.args[0] for item in run.run_case.call_args_list], list(EXPERIMENT.CASES))
        self.assertTrue(result["passed"])
        run.cleanup.return_value = {"profilesRemoved": False}
        stderr = io.StringIO()
        with patch.object(EXPERIMENT.sys, "stderr", stderr):
            self.assertFalse(self.measure_with(run)["passed"])
        self.assertIn("rmzmc- profiles", stderr.getvalue())

    def test_a_second_signal_during_cleanup_does_not_stop_it(self):
        run = Mock(base_created=True)
        run.setup.side_effect = KeyboardInterrupt()

        def cleanup():
            os.kill(os.getpid(), signal.SIGTERM)
            removed.append(True)
            return {"profilesRemoved": False}

        removed = []
        run.cleanup.side_effect = cleanup
        stderr = io.StringIO()
        previous = signal.signal(signal.SIGTERM, EXPERIMENT._cancel)
        try:
            with patch.object(EXPERIMENT.sys, "stderr", stderr), self.assertRaises(KeyboardInterrupt):
                self.measure_with(run)
        finally:
            signal.signal(signal.SIGTERM, previous)
        self.assertEqual(removed, [True])
        self.assertIn("Disposable state not fully removed", stderr.getvalue())

    def test_main_reports_no_raw_data_on_failure(self):
        for error in (OSError("/private/path"), subprocess.TimeoutExpired("/private/path", 1)):
            stderr = io.StringIO()
            with self.subTest(error=type(error).__name__), \
                 patch.object(EXPERIMENT, "measure", side_effect=error), \
                 patch.object(sys, "argv", ["runner"]), patch.object(sys, "stderr", stderr):
                with self.assertRaises(SystemExit) as raised:
                    EXPERIMENT.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertNotIn("/private/path", stderr.getvalue())


FIXTURE_FLAGS = ("-std=c11", "-O2", "-Wall", "-Wextra", "-Werror")


@unittest.skipUnless(os.environ.get("REMOZIO_LINUX_MONITOR_CONFINEMENT_LIVE") == "1", "explicit live fixture checks")
@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86_64 fixtures")
class LiveFixtureTests(unittest.TestCase):
    """Unprivileged mechanics only. The confinement measurement is the supervised runner."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        build = Path(cls.directory.name)
        compiler = shutil.which("cc")
        if compiler is None:
            raise unittest.SkipTest("no C compiler")
        cls.probe, cls.frontend = build / "probe", build / "frontend"
        for output, source, extra in ((cls.probe, EXPERIMENT.PROBE, ("-static",)),
                                      (cls.frontend, PL.FRONTEND, ("-static", "-no-pie"))):
            subprocess.run([compiler, *FIXTURE_FLAGS, *extra, "-o", str(output), str(source)], check=True, timeout=120)
        cls.writable = build / "w"
        cls.writable.mkdir()

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def start(self, *arguments):
        process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   start_new_session=True)
        self.addCleanup(PL._retire, process)
        return process

    def test_fixtures_are_static_executables(self):
        self.assertTrue(PL.static_non_pie(self.probe))
        self.assertTrue(PL.static_non_pie(self.frontend))

    def test_sleeper_handshake_has_the_fixed_shape(self):
        sleeper = self.start(str(self.probe), "sleeper", "10")
        line = PL._read_exact(sleeper, EXPERIMENT.time.monotonic() + 10, 57)
        self.assertRegex(line, rb"\AS [0-9a-f]{16} [0-9]{4} [0-9a-f]{32}\n\Z")

    def test_unprivileged_probe_reports_every_key_in_the_closed_vocabulary(self):
        deadline = EXPERIMENT.time.monotonic() + 20
        sleeper = self.start(str(self.probe), "sleeper", "20")
        _, address, descriptor, canary = PL._read_exact(sleeper, deadline, 57).decode().split()
        frontend = self.start(str(self.frontend), "hold", "/nonexistent/s")
        marker = PL._read_exact(frontend, deadline, 18)[1:17].decode()
        probe = self.start(str(self.probe), "probe", "nodrop", str(os.getuid()), str(os.getgid()), "10",
                           str(self.writable), f"sleeper=s:{sleeper.pid}:{address}:{int(descriptor)}:{canary}",
                           f"frontend=f:{frontend.pid}:{marker}:-:-")
        self.assertEqual(PL._read_exact(probe, deadline, 2), b"R\n")
        probe.stdin.write(b"g")
        probe.stdin.close()
        probe.stdin = None
        values = PL.parse_report(PL._read_output(probe, deadline))
        expected = {*EXPERIMENT.IDENTITY_B, *(f"sleeper.{key}" for key in EXPERIMENT.SLEEPER_REACHED),
                    *(f"frontend.{key}" for key in EXPERIMENT.FRONTEND_REACHED), *EXPERIMENT.SIDE_WORKING}
        self.assertEqual(set(values), expected)
        self.assertTrue(set(values.values()) <= EXPERIMENT.PROBE_VALUES)
        self.assertEqual((values["selfDrop"], values["sleeper.statusRead"], values["fileCreate"]),
                         ("not-requested", "ok", "ok"))
        self.assertEqual(list(self.writable.iterdir()), [])

    def test_self_drop_requires_root_and_bad_targets_are_usage_errors(self):
        result = subprocess.run([str(self.probe), "probe", "drop", "1", "1", "5", "-"], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=30)
        self.assertEqual((result.returncode, PL.parse_report(result.stdout)), (3, {"selfDrop": "failed"}))
        for target in ("x=s:1:00:1:00", "x=q:1:0000000000000001:-:-", "role=f:1:0000000000000000:-:-"):
            result = subprocess.run([str(self.probe), "probe", "nodrop", "1", "1", "5", "-", target],
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            self.assertEqual(PL.parse_report(result.stdout), {"error": "usage"}, target)

    def test_user_namespace_helper_reports_closed_values(self):
        result = subprocess.run([str(self.probe), "userns-bind", str(self.frontend), str(self.probe), "/nonexistent/s"],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        values = PL.parse_report(result.stdout.splitlines()[0])
        self.assertEqual(set(values), {"userns", "uidMap", "mount"})
        self.assertTrue(set(values.values()) <= EXPERIMENT.PROBE_VALUES)


if __name__ == "__main__":
    unittest.main()
