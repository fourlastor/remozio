#!/usr/bin/env python3
"""Fork-only, owned-process stack sampling of one unchanged native XCTest."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from typing import Any

TEST = (
    "RemozioCoreTests.GatewayRuntimeActivationOperationTests/"
    "testCompleteOperationPublishesOnlyTheOptionalGatewayAndReleasesTheWriterBeforeRegistration"
)
SAMPLE_DELAY = 2.0
SAMPLE_DURATION = 10
SAMPLE_TIMEOUT = 20.0
CLEANUP_TIMEOUT = 5.0
POLL_INTERVAL = 0.05


def resolve_xctest() -> Path:
    result = subprocess.run(
        ["/usr/bin/xcrun", "--find", "xctest"], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15,
    )
    value = result.stdout.strip()
    if not value or "\n" in value or not Path(value).is_absolute():
        raise ValueError("xcrun did not return one absolute XCTest loader path")
    loader = Path(value).resolve(strict=True)
    if not loader.is_file() or not os.access(loader, os.X_OK):
        raise ValueError("The resolved XCTest loader is not executable")
    return loader


@dataclass
class OwnedChild:
    process: subprocess.Popen[bytes]
    started: float
    ended: float | None = None
    usage: Any = None

    def poll(self) -> int | None:
        # Do not use Popen.poll/wait: wait4 provides this child's CPU accounting.
        if self.process.returncode is None:
            pid, status, usage = os.wait4(self.process.pid, os.WNOHANG)
            if pid:
                self.process.returncode = os.waitstatus_to_exitcode(status)
                self.ended = time.monotonic()
                self.usage = usage
        return self.process.returncode

    def stop(self) -> bool:
        # An unreaped session leader retains its PID, even if it has just exited.
        # Never signal the numeric group again after this object has reaped it.
        if self.process.returncode is None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + CLEANUP_TIMEOUT
        while self.poll() is None:
            if time.monotonic() >= deadline:
                return False
            time.sleep(POLL_INTERVAL)
        return True

    def result(self) -> dict[str, Any]:
        return {
            "pid": self.process.pid,
            "returncode": self.process.returncode,
            "wallSeconds": None if self.ended is None else self.ended - self.started,
            "userCPUSeconds": None if self.usage is None else self.usage.ru_utime,
            "systemCPUSeconds": None if self.usage is None else self.usage.ru_stime,
        }


def exact_test_summary(log: str) -> bool:
    summaries = re.findall(r"Executed (\d+) tests?, with (\d+) failures", log)
    case, method = TEST.split("/", 1)
    passed = re.findall(r"^Test Case '([^']+)' passed(?:\s|\()", log, re.MULTILINE)
    expected = {f"-[{case} {method}]", f"{case}.{method}", f"{case.rsplit('.', 1)[-1]}.{method}"}
    return (bool(summaries)
            and all(count == "1" and failures == "0" for count, failures in summaries)
            and len(passed) == 1 and passed[0] in expected
            and not re.search(r"\b(?:test|tests) skipped\b|\bskipped\s*\(", log, re.IGNORECASE))


def run_profile(bundle: Path, output: Path, timeout: float = 300.0) -> int:
    if not 30 <= timeout <= 600:
        raise ValueError("Test timeout must be between 30 and 600 seconds")
    bundle = bundle.resolve(strict=True)
    if not bundle.is_dir() or not re.fullmatch(r"RemozioCore.*Tests\.xctest", bundle.name):
        raise ValueError("Expected the built RemozioCore XCTest bundle")
    output = output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    report: dict[str, Any] = {
        "schemaVersion": 1, "bundle": str(bundle),
        "testTimeoutSeconds": timeout, "sampleDelaySeconds": SAMPLE_DELAY,
        "sampleDurationSeconds": SAMPLE_DURATION, "sampleTimeoutSeconds": SAMPLE_TIMEOUT,
        "accounting": "wait4 usage for each owned child; sampler CPU is separate from XCTest CPU",
        "test": {"specifier": TEST, "returncode": None},
        "sample": {"returncode": None}, "cleanupComplete": True,
    }
    target: OwnedChild | None = None
    sampler: OwnedChild | None = None
    sample_attempted = False
    test_timed_out = False
    sample_timed_out = False
    problem: str | None = None
    interrupted = False
    sample_path = output / "stacks.txt"
    try:
        loader = resolve_xctest()
        command = [str(loader), "-XCTest", TEST, str(bundle)]
        report["command"] = command
        env = dict(os.environ)
        with (output / "test.log").open("wb") as test_log, (output / "sample.log").open("wb") as sample_log:
            started = time.monotonic()
            target = OwnedChild(subprocess.Popen(
                command, stdout=test_log, stderr=subprocess.STDOUT,
                env=env, start_new_session=True,
            ), started)
            try:
                while True:
                    # Keep the target unreaped while sample can still inspect its PID.
                    # Even a naturally exited target retains that PID until wait4 reaps it.
                    if sampler is not None:
                        sampler.poll()
                    if sampler is None or sampler.process.returncode is not None:
                        if target.poll() is not None:
                            break
                    now = time.monotonic()
                    if now >= started + timeout:
                        test_timed_out = True
                        break
                    if not sample_attempted and now >= started + SAMPLE_DELAY:
                        sample_attempted = True
                        sample_command = ["/usr/bin/sample", str(target.process.pid), str(SAMPLE_DURATION), "-file", str(sample_path)]
                        report["sampleCommand"] = sample_command
                        try:
                            sampler = OwnedChild(subprocess.Popen(
                                sample_command, stdout=sample_log, stderr=subprocess.STDOUT,
                                start_new_session=True,
                            ), now)
                        except OSError:
                            problem = "sample_launch_failed"
                    if sampler is not None and not sample_timed_out and sampler.process.returncode is None and now >= sampler.started + SAMPLE_TIMEOUT:
                        sample_timed_out = True
                        problem = "sample_timed_out"
                        report["cleanupComplete"] = sampler.stop() and report["cleanupComplete"]
                    time.sleep(POLL_INTERVAL)
            finally:
                # Retire the sampler before reaping/signaling the target during aborts.
                if sampler is not None and sampler.process.returncode is None:
                    problem = problem or "sample_interrupted"
                    report["cleanupComplete"] = sampler.stop() and report["cleanupComplete"]
                if target.process.returncode is None:
                    report["cleanupComplete"] = target.stop() and report["cleanupComplete"]
    except KeyboardInterrupt:
        interrupted = True
        problem = "interrupted"
    except (OSError, ValueError, subprocess.SubprocessError):
        problem = "runner_setup_or_execution_failed"
    finally:
        if target is not None:
            report["test"] = {"specifier": TEST, **target.result(), "timedOut": test_timed_out}
        if sampler is not None:
            report["sample"] = {**sampler.result(), "timedOut": sample_timed_out}
        report["sample"]["attempted"] = sample_attempted
        report["sample"]["stackFilePresent"] = sample_path.is_file() and sample_path.stat().st_size > 0
        log_path = output / "test.log"
        report["test"]["exactOneTestPassed"] = log_path.is_file() and exact_test_summary(log_path.read_text(errors="replace"))
        sample_ok = sampler is not None and sampler.process.returncode == 0 and report["sample"]["stackFilePresent"] and not sample_timed_out
        if not sample_ok and problem is None:
            problem = "sample_failed_or_missing" if sample_attempted else "target_finished_before_sampling"
        if interrupted:
            status = 130
        elif test_timed_out:
            status = 124
        elif target is not None and target.process.returncode not in (None, 0):
            code = target.process.returncode
            status = code if code > 0 else 128 - code
        elif problem is not None or not report["cleanupComplete"] or not sample_ok or not report["test"]["exactOneTestPassed"]:
            status = 2
        else:
            status = 0
        report["problem"] = problem
        report["exitStatus"] = status
        (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="A new private diagnostic output directory")
    parser.add_argument("--timeout", default=300.0, type=float)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("The owned XCTest sampler requires macOS")
    try:
        return run_profile(args.bundle, args.output, args.timeout)
    except (OSError, ValueError):
        print("Cannot prepare the requested bundle/output directory", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
