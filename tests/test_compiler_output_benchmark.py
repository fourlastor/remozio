"""Benchmark comparisons require equivalent work and an isolated reset root."""
import copy
import importlib.util
import os
import signal
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, call, patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "compiler_output_benchmark", ROOT / "scripts/benchmark-compiler-output.py"
)
BENCHMARK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCHMARK)


class CompilerOutputBenchmarkTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="compiler benchmark tests ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def trials(self):
        timings = (("stream", 9), ("file", 6), ("quiet", 3),
                   ("quiet", 5), ("file", 8), ("stream", 11))
        return [
            {"mode": mode, "wallSeconds": wall,
             "childUserSeconds": wall / 2, "childSystemSeconds": wall / 10,
             "exitStatus": 0, "timedOut": False,
             "objects": {"count": 2, "bytes": 30, "sizesSha256": "a" * 64},
             "logBytes": 100}
            for mode, wall in timings
        ]

    def workspace(self):
        owner = self.root / "owned"
        owner.mkdir()
        snapshot = owner / "snapshot"
        snapshot.mkdir()
        work = owner / "work"
        work.mkdir()
        return work, snapshot, owner

    def test_trial_order_balances_forward_and_reverse_runs(self):
        cycle = ["stream", "file", "quiet", "quiet", "file", "stream"]
        for repetitions in (1, 2, 3):
            with self.subTest(repetitions=repetitions):
                self.assertEqual(BENCHMARK.trial_modes(repetitions), cycle * repetitions)
        for repetitions in (0, -1, 4):
            with self.subTest(repetitions=repetitions), self.assertRaises(BENCHMARK.BenchmarkError):
                BENCHMARK.trial_modes(repetitions)

    def test_inventory_counts_only_owned_object_files(self):
        build = self.root / "build"
        for name, size in (("debug/Main.build/main.o", 7), ("debug/Other.build/other.o", 13),
                           ("debug/Other.build/source.swift", 20),
                           ("checkouts/dependency/foreign.o", 31),
                           ("nested/repositories/foreign.o", 37),
                           ("artifacts/tool/foreign.o", 41)):
            path = build / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"x" * size)
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "foreign.o").write_bytes(b"outside")
        (build / "linked.o").symlink_to(outside / "foreign.o")
        (build / "linked-directory").symlink_to(outside, target_is_directory=True)
        self.assertEqual(BENCHMARK.inventory_objects(build), {
            "debug/Main.build/main.o": 7,
            "debug/Other.build/other.o": 13,
        })

    def test_summary_uses_balanced_sample_medians_and_ratios(self):
        summary = BENCHMARK.assess_trials(self.trials())
        for mode, minimum, median, maximum in (("stream", 9, 10, 11),
                                               ("file", 6, 7, 8),
                                               ("quiet", 3, 4, 5)):
            with self.subTest(mode=mode):
                result = summary["modes"][mode]
                self.assertEqual(result["samples"], 2)
                self.assertEqual(result["wallMedianSeconds"], median)
                self.assertEqual(result["wallMinSeconds"], minimum)
                self.assertEqual(result["wallMaxSeconds"], maximum)
                self.assertAlmostEqual(result["childCpuMedianSeconds"], median * .6)
        self.assertAlmostEqual(summary["comparisons"]["fileVsStreamWallRatio"], .7)
        self.assertAlmostEqual(summary["comparisons"]["quietVsFileWallRatio"], 4 / 7)
        self.assertTrue(summary["limitations"])

    def test_failed_empty_or_invalid_timing_trials_cannot_produce_comparisons(self):
        invalid = ({"exitStatus": 1}, {"timedOut": True}, {"wallSeconds": 0},
                   {"wallSeconds": -1},
                   {"objects": {"count": 0, "bytes": 0, "sizesSha256": "b" * 64}})
        for replacement in invalid:
            with self.subTest(replacement=replacement):
                trials = self.trials()
                affected = trials if "objects" in replacement else trials[:1]
                for trial in affected:
                    trial.update(copy.deepcopy(replacement))
                with self.assertRaises(BENCHMARK.BenchmarkError):
                    BENCHMARK.assess_trials(trials)

    def test_unequal_object_evidence_or_mode_counts_refuse_comparison(self):
        for field, value in (("count", 3), ("bytes", 31), ("sizesSha256", "b" * 64)):
            with self.subTest(field=field):
                trials = self.trials()
                trials[-1]["objects"][field] = value
                with self.assertRaises(BENCHMARK.BenchmarkError):
                    BENCHMARK.assess_trials(trials)
        for trials in ([], self.trials()[:-1], self.trials() + [copy.deepcopy(self.trials()[0])]):
            with self.subTest(sample_count=len(trials)), self.assertRaises(BENCHMARK.BenchmarkError):
                BENCHMARK.assess_trials(trials)

    def test_trial_output_modes_change_only_the_intended_sink_and_quiet_flag(self):
        command = ["swift", "build", "--jobs", "2"]
        environment = {"SYNTHETIC_BENCHMARK": "1"}
        evidence = self.trials()[0]["objects"]
        for mode in ("stream", "file", "quiet"):
            with self.subTest(mode=mode):
                log = self.root / f"{mode}.log"
                process = Mock(pid=12345, returncode=0)
                process.wait.return_value = 0
                with patch.object(BENCHMARK.subprocess, "Popen", return_value=process) as spawn, \
                     patch.object(BENCHMARK, "object_evidence", return_value=evidence):
                    result = BENCHMARK.measure_trial(mode, command, self.root, log, 5, environment)
                expected = command + (["--quiet"] if mode == "quiet" else [])
                self.assertEqual(spawn.call_args.args, (expected,))
                options = spawn.call_args.kwargs
                self.assertEqual(options["env"], environment)
                self.assertEqual(options["stdin"], subprocess.DEVNULL)
                self.assertTrue(options["start_new_session"])
                process.wait.assert_called_once_with(timeout=5)
                if mode == "stream":
                    self.assertIsNone(options["stdout"])
                    self.assertIsNone(options["stderr"])
                    self.assertIsNone(result["log"])
                    self.assertIsNone(result["logBytes"])
                    self.assertFalse(log.exists())
                else:
                    self.assertEqual(options["stdout"].name, str(log))
                    self.assertTrue(options["stdout"].closed)
                    self.assertEqual(options["stderr"], subprocess.STDOUT)
                    self.assertEqual(result["log"], str(log))
                    self.assertEqual(result["logBytes"], 0)
                self.assertEqual(result["command"], expected)
                self.assertEqual(result["exitStatus"], 0)
                self.assertFalse(result["timedOut"])
        self.assertEqual(command, ["swift", "build", "--jobs", "2"])

    def test_trial_timeout_kills_only_the_owned_group_and_records_failure(self):
        command = ["swift", "build"]
        process = Mock(pid=54321, returncode=None)
        process.wait.side_effect = [subprocess.TimeoutExpired(command, 1), -9]
        with patch.object(BENCHMARK.subprocess, "Popen", return_value=process), \
             patch.object(BENCHMARK.os, "killpg") as kill, \
             patch.object(BENCHMARK, "object_evidence", return_value=self.trials()[0]["objects"]):
            result = BENCHMARK.measure_trial("file", command, self.root,
                                             self.root / "timeout.log", 1, {})
        kill.assert_called_once_with(54321, signal.SIGKILL)
        self.assertEqual(process.wait.call_args_list, [call(timeout=1), call()])
        self.assertTrue(result["timedOut"])
        self.assertEqual(result["exitStatus"], -9)
        trials = self.trials()
        trials[1] = result
        with self.assertRaises(BENCHMARK.BenchmarkError):
            BENCHMARK.assess_trials(trials)

    def test_reset_restores_snapshot_metadata_and_preserves_outside_targets(self):
        work, snapshot, owner = self.workspace()
        source = snapshot / "input.swift"
        source.write_text("fixture source\n")
        source.chmod(0o640)
        timestamp = 1_700_000_000_123456789
        os.utime(source, ns=(timestamp, timestamp))
        outside = self.root / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_text("keep")
        (snapshot / "external-link").symlink_to(sentinel)
        (work / "stale").write_text("discard")
        (work / "external-directory").symlink_to(outside, target_is_directory=True)
        BENCHMARK.reset_workspace(work, snapshot, owner)
        restored = work / "input.swift"
        self.assertEqual(restored.read_bytes(), source.read_bytes())
        self.assertEqual(restored.stat().st_mtime_ns, timestamp)
        self.assertEqual(restored.stat().st_mode & 0o777, 0o640)
        self.assertFalse((work / "stale").exists())
        self.assertFalse((work / "external-directory").is_symlink())
        self.assertTrue((work / "external-link").is_symlink())
        self.assertEqual(os.readlink(work / "external-link"), str(sentinel))
        self.assertEqual(sentinel.read_text(), "keep")
        self.assertEqual(source.read_text(), "fixture source\n")

    def test_reset_rejects_paths_outside_direct_owned_children_before_deletion(self):
        work, snapshot, owner = self.workspace()
        marker = work / "marker"
        marker.write_text("keep")
        (snapshot / "source").write_text("snapshot")
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "sentinel").write_text("keep")
        nested = owner / "nested/work"
        nested.mkdir(parents=True)
        for target, original in ((owner, snapshot), (outside, snapshot), (nested, snapshot),
                                  (work, outside), (work, work),
                                  (owner / "nested/../snapshot", snapshot)):
            with self.subTest(work=target, snapshot=original), self.assertRaises(BENCHMARK.BenchmarkError):
                BENCHMARK.reset_workspace(target, original, owner)
            self.assertEqual(marker.read_text(), "keep")
            self.assertEqual((snapshot / "source").read_text(), "snapshot")
            self.assertEqual((outside / "sentinel").read_text(), "keep")

    def test_reset_refuses_symlink_roots(self):
        work, snapshot, owner = self.workspace()
        (work / "marker").write_text("keep")
        for name, target in (("work-link", work), ("snapshot-link", snapshot)):
            link = owner / name
            link.symlink_to(target, target_is_directory=True)
            arguments = (link, snapshot, owner) if name == "work-link" else (work, link, owner)
            with self.subTest(root=name), self.assertRaises(BENCHMARK.BenchmarkError):
                BENCHMARK.reset_workspace(*arguments)
        owner_link = self.root / "owner-link"
        owner_link.symlink_to(owner, target_is_directory=True)
        with self.assertRaises(BENCHMARK.BenchmarkError):
            BENCHMARK.reset_workspace(owner_link / "work", owner_link / "snapshot", owner_link)
        self.assertEqual((work / "marker").read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
