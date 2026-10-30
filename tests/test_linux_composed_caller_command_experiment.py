import contextlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-linux-composed-caller-command-experiment.py"
SPEC = importlib.util.spec_from_file_location("linux_composed_caller_command_experiment", SCRIPT)
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)


def pure_worker():
    spec = importlib.util.spec_from_file_location("linux_composed_worker_unit_test", EXPERIMENT.WORKER)
    worker = importlib.util.module_from_spec(spec)
    # Stub library loading so the case table is importable on Mac without Linux libc calls.
    with patch("ctypes.CDLL"), patch("os.fork", create=True) as fork, patch("subprocess.Popen") as spawn:
        spec.loader.exec_module(worker)
    fork.assert_not_called()
    spawn.assert_not_called()
    return worker


def report(case, **changes):
    expected = EXPERIMENT.EXPECTED[case]
    owner = {key: value for key, value in expected.items() if key not in EXPERIMENT.SUPERVISOR_ONLY}
    owner.update(phase="result", reservations=expected["rows"], checkpointMatches=True,
                 remoteObservation=True, callerInheritableCapabilities=False)
    supervisor = {key: expected[key] for key in EXPERIMENT.SUPERVISOR_ONLY if key in expected}
    supervisor.update(ownerExit=0, markerExact=True, injected=EXPERIMENT.INJECTED.get(case),
                      allOwnedChildrenReaped=True, monitorExit=0,
                      outputBytes=EXPERIMENT.OUTPUT_LINE_BYTES * expected["markerLines"])
    for key, value in changes.items():
        (supervisor if key in supervisor and key not in owner else owner)[key] = value
    return {"case": case, "owner": owner, "supervisor": supervisor}


class ComposedValidationTests(unittest.TestCase):
    def test_every_expected_case_validates_with_fixed_checks(self):
        for case in EXPERIMENT.CASES:
            with self.subTest(case=case):
                result = EXPERIMENT.validate_result(json.dumps(report(case)), case, 0)
                self.assertTrue(result["passed"])
                self.assertTrue(all(value is True for value in result["checks"].values()))
                self.assertEqual(result["checks"].get("remoteObservation"), None if case.startswith("carrier") else True)

    def test_outcome_deviations_are_refused(self):
        for case, change in (("healthy-approve", {"ledgerPhase": "unknown"}),
                             ("healthy-approve", {"markerLines": 2}),
                             ("healthy-approve", {"replayRejected": False}),
                             ("monitor-death-B3", {"refusal": "grant"}),
                             ("monitor-death-B3", {"records": 3}),
                             ("grant-changed-B3", {"ledgerPhase": "succeeded"}),
                             ("dispatch-race-limitation", {"strictAdmission": True}),
                             ("dispatch-race-limitation", {"requesterLostDuringDispatch": False}),
                             ("healthy-decline", {"rows": True}),
                             ("stop-release", {"monitorReason": "held_stop"})):
            with self.subTest(case=case, change=change):
                with self.assertRaises(ValueError):
                    EXPERIMENT.validate_result(json.dumps(report(case, **change)), case, 0)

    def test_failed_checks_and_owner_errors_are_refused(self):
        for case, change in (("healthy-approve", {"ownerExit": 1}), ("healthy-approve", {"checkpointMatches": False}),
                             ("healthy-approve", {"remoteObservation": False}),
                             ("grant-revoked-B0", {"injected": None}), ("healthy-approve", {"injected": "kill-monitor"}),
                             ("healthy-approve", {"allOwnedChildrenReaped": False}),
                             ("healthy-approve", {"outputBytes": 0}), ("monitor-death-B4", {"outputBytes": 24}),
                             ("healthy-approve", {"error": "spawn"})):
            with self.subTest(case=case, change=change):
                with self.assertRaises(ValueError):
                    EXPERIMENT.validate_result(json.dumps(report(case, **change)), case, 0)

    def test_malformed_oversized_duplicate_and_failed_reports_are_refused(self):
        valid = json.dumps(report("healthy-approve"))
        for raw, code, case in ((valid, 1, "healthy-approve"), (valid, 0, "healthy-decline"),
                                (b"x" * (EXPERIMENT.MAX_OUTPUT_BYTES + 1), 0, "healthy-approve"),
                                ('{"case":"healthy-approve","case":"healthy-approve"}', 0, "healthy-approve"),
                                ('{"case":NaN}', 0, "healthy-approve"), ("[]", 0, "healthy-approve")):
            with self.subTest(raw=str(raw)[:40], code=code):
                with self.assertRaises(ValueError):
                    EXPERIMENT.validate_result(raw, case, code)

    def test_limitation_control_is_never_counted_as_strict_admission(self):
        expected = EXPERIMENT.EXPECTED["dispatch-race-limitation"]
        self.assertEqual((expected["spawned"], expected["requesterLostDuringDispatch"], expected["strictAdmission"]),
                         (True, True, False))
        self.assertEqual(expected["ledgerPhase"], "unknown")
        self.assertTrue(EXPERIMENT.EXPECTED["healthy-approve"]["strictAdmission"])
        self.assertEqual([case for case, value in EXPERIMENT.EXPECTED.items() if value.get("strictAdmission")],
                         ["healthy-approve"])


class ComposedCaseTableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.worker = pure_worker()

    def test_runner_and_worker_agree_on_cases_and_injections(self):
        self.assertEqual(set(EXPERIMENT.CASES), set(self.worker.CASES))
        for case, spec in self.worker.CASES.items():
            self.assertEqual(spec.get("inject"), EXPERIMENT.INJECTED.get(case))
            if "barrier" in spec:
                self.assertIn(spec["barrier"], self.worker.BARRIERS)
                self.assertTrue(case.endswith(spec["barrier"]) or case == "dispatch-race-limitation")

    def test_monitor_events_reuse_existing_probe_cases(self):
        for spec in self.worker.CASES.values():
            if "advance" in spec:
                self.assertIn(spec["advance"], self.worker.probe.CASES)


class ComposedRunnerTests(unittest.TestCase):
    def test_sources_cover_worker_frontend_owner_and_extracted_libraries(self):
        inventory = EXPERIMENT.source_hashes()
        for path in ("experiments/linux-composed-caller-command/composed.py",
                     "experiments/linux-composed-caller-command/frontend.c",
                     "experiments/linux-composed-caller-command/Sources/LinuxComposedCallerCommand/Owner.swift",
                     "experiments/linux-composed-caller-command/Sources/CComposedSupport/composed_support.c",
                     "experiments/linux-caller-monitor/probe.py",
                     "experiments/linux-os-capture/Sources/LinuxOSObservation/Observation.swift",
                     "experiments/linux-approval-command/Sources/LinuxApprovalFixtureCore/FixtureStore.swift",
                     "host/shared-core/Sources/RemozioHostCore/LinuxCurrentCommandElevationPolicy.swift"):
            self.assertEqual(len(inventory[path]), 64, path)

    def test_unsupported_host_or_elevation_never_builds(self):
        for system, uid in (("Darwin", 1000), ("Linux", 0)):
            with self.subTest(system=system, uid=uid), contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(EXPERIMENT.platform, "system", return_value=system))
                stack.enter_context(patch.object(EXPERIMENT.platform, "machine", return_value="x86_64"))
                for name in ("getuid", "geteuid"):
                    stack.enter_context(patch.object(EXPERIMENT.os, name, return_value=uid))
                build = stack.enter_context(patch.object(EXPERIMENT, "build"))
                with self.assertRaises(RuntimeError):
                    EXPERIMENT.measure(Path("/tmp/composed-unit"))
                build.assert_not_called()

    def test_relative_work_directory_and_bad_deadlines_refuse_before_build(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(EXPERIMENT.platform, "system", return_value="Linux"))
            stack.enter_context(patch.object(EXPERIMENT.platform, "machine", return_value="x86_64"))
            for name in ("getuid", "geteuid", "getgid", "getegid"):
                stack.enter_context(patch.object(EXPERIMENT.os, name, return_value=1000))
            build = stack.enter_context(patch.object(EXPERIMENT, "build"))
            for arguments in ((Path("relative"),), (Path("/tmp/composed-unit"), 0), (Path("/tmp/composed-unit"), 30, 1000)):
                with self.subTest(arguments=arguments):
                    with self.assertRaises(ValueError):
                        EXPERIMENT.measure(*arguments)
            build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
