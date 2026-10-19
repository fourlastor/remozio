#!/usr/bin/env python3
"""Exercise source-bound Swift build caching in a disposable local Git checkout."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path("Sources/CacheValue/Value.swift")
FILES = {
    "Package.swift": '''// swift-tools-version: 6.2
import PackageDescription
let package = Package(name: "CacheSmoke", products: [
    .executable(name: "CacheProbe", targets: ["CacheProbe"])
], targets: [
    .target(name: "CacheValue"),
    .executableTarget(name: "CacheProbe", dependencies: ["CacheValue"]),
    .testTarget(name: "CacheValueTests", dependencies: ["CacheValue"])
])
''',
    str(SOURCE): "public func currentValue() -> Int { 1 }\n",
    "Sources/CacheProbe/main.swift": "import CacheValue\nprint(currentValue())\n",
    "Tests/CacheValueTests/CacheValueTests.swift": '''import Foundation
import XCTest
@testable import CacheValue
final class CacheValueTests: XCTestCase {
    func testCurrentValue() throws {
        let expected = try XCTUnwrap(ProcessInfo.processInfo.environment["REMOZIO_SMOKE_EXPECTED_VALUE"].flatMap(Int.init))
        XCTAssertEqual(currentValue(), expected)
        print("CACHE-SMOKE-TEST:\\(currentValue())")
    }
}
''',
}


class SmokeFailure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


def command(arguments, *, cwd, env, log=None):
    result = subprocess.run(arguments, cwd=cwd, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            errors="replace", timeout=180)
    if log is not None:
        log.write_text(result.stdout)
    require(result.returncode == 0,
            f"{Path(arguments[0]).name} failed with exit {result.returncode}; log: {log}")
    return result.stdout


def frontend_commands(output):
    # Count package source compilation, including module emission. Manifest
    # interpretation is separate SwiftPM work and does not compile these targets.
    return sum("swift-frontend" in line and " -frontend " in line and
               ("/Sources/" in line or "/Tests/" in line) and
               re.search(r"(?:^|\s)-(?:c|emit-module)(?:\s|$)", line) is not None
               for line in output.splitlines())


def run_stage(name, fixture, output, swift, env, expected):
    started = time.monotonic()
    stage_env = {**env, "REMOZIO_SMOKE_EXPECTED_VALUE": str(expected)}
    build_log, test_log = output / f"{name}-build.log", output / f"{name}-test.log"
    build = command([swift, "build", "--package-path", str(fixture),
                     "--product", "CacheProbe", "-v"], cwd=fixture, env=stage_env, log=build_log)
    tests = command([swift, "test", "--package-path", str(fixture), "-v"],
                    cwd=fixture, env=stage_env, log=test_log)
    require(f"CACHE-SMOKE-TEST:{expected}" in tests,
            f"{name}: test execution marker is absent")
    products = command([swift, "build", "--package-path", str(fixture), "--show-bin-path"],
                       cwd=fixture, env=stage_env).strip()
    executable = Path(products) / "CacheProbe"
    require(executable.is_file(), f"{name}: executable is absent")
    result_log = output / f"{name}-result.log"
    result = command([str(executable)], cwd=fixture, env=stage_env, log=result_log).strip()
    require(result == str(expected), f"{name}: executable returned stale or incorrect output")
    return {"elapsedSeconds": round(time.monotonic() - started, 6),
            "frontendCompileCommands": frontend_commands(build) + frontend_commands(tests),
            "binaryResult": result, "testExecuted": True,
            "logs": [str(build_log), str(test_log), str(result_log)]}


def load_helper():
    spec = importlib.util.spec_from_file_location("remozio_ci_build_cache_smoke", ROOT / "scripts/ci-build-cache.py")
    helper = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = helper
    spec.loader.exec_module(helper)
    return helper


def experiment(output, report):
    helper = load_helper()
    swift, git, tar = (shutil.which(name) for name in ("swift", "git", "gtar"))
    tar = tar or shutil.which("tar")
    require(all((swift, git, tar)), "Swift, Git and tar must be available")
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    report["host"] = {"system": platform.system(), "architecture": platform.machine(),
                      "swift": command([swift, "--version"], cwd=ROOT, env=env).strip()}
    tar_version = command([tar, "--version"], cwd=ROOT, env=env)
    # GNU tar's --posix and bsdtar's --format=pax both select the POSIX extended
    # archive format, which preserves subsecond timestamps used by Swift builds.
    tar_format = "--posix" if "GNU tar" in tar_version else "--format=pax"
    report["archive"] = {"tool": tar_version.splitlines()[0], "format": "POSIX pax"}
    with tempfile.TemporaryDirectory(prefix="remozio-cache-smoke-") as temporary:
        scratch = Path(temporary)
        fixture = scratch / "checkout"
        fixture.mkdir()
        for relative, contents in FILES.items():
            path = fixture / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
        command([git, "init", "-q"], cwd=fixture, env=env)
        command([git, "add", "--", *FILES], cwd=fixture, env=env)
        command([git, "-c", "user.name=Cache Smoke", "-c", "user.email=cache-smoke@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "Synthetic cache inputs"], cwd=fixture, env=env)
        report["stages"] = {}
        cold = run_stage("cold", fixture, output, swift, env, 1)
        report["stages"]["cold"] = cold
        require(cold["frontendCompileCommands"] > 0, "cold: source compilation was not observed")
        inputs = helper.capture_inputs(fixture)
        cached_stat = (fixture / SOURCE).stat()
        manifest_path = fixture / ".build/cache-smoke-inputs.json"
        manifest_path.write_text(json.dumps(inputs))
        archive = scratch / "build-cache.tar"
        command([tar, tar_format, "-cf", str(archive), "-C", str(fixture), ".build"], cwd=fixture, env=env)
        shutil.rmtree(fixture / ".build")
        for relative in FILES:
            (fixture / relative).unlink()
        command([git, "checkout", "--", *FILES], cwd=fixture, env=env)
        fresh_stat = (fixture / SOURCE).stat()
        require(fresh_stat.st_mtime_ns != cached_stat.st_mtime_ns,
                "fresh checkout did not produce a distinct source timestamp")
        command([tar, "-xf", str(archive), "-C", str(fixture)], cwd=fixture, env=env)
        restored_inputs = json.loads(manifest_path.read_text())
        fresh_restore = helper.restore_inputs(fixture, restored_inputs)
        report["freshCheckoutRestore"] = fresh_restore
        require(not fresh_restore.get("requires_clean_build"), "unchanged checkout unnecessarily requires a clean build")
        require(fresh_restore["changed"] == 0 and fresh_restore["missing"] == 0,
                "fresh checkout has unexpected changed or missing inputs")
        require((fixture / SOURCE).stat().st_mtime_ns == cached_stat.st_mtime_ns,
                "unchanged source timestamp was not restored exactly")
        warm = run_stage("warm", fixture, output, swift, env, 1)
        report["stages"]["warm"] = warm
        require(warm["frontendCompileCommands"] == 0,
                "warm: source recompilation occurred after the archive and fresh checkout roundtrip")

        source = fixture / SOURCE
        report["documentationRestores"] = {}

        def documentation_stage(name, previous_inputs, changed_count, missing_count):
            current = helper.capture_inputs(fixture)
            restore = helper.restore_inputs(fixture, previous_inputs)
            report["documentationRestores"][name] = restore
            require(restore["changed"] == changed_count and restore["missing"] == missing_count
                    and restore["restored"] == len(FILES),
                    f"{name}: unexpected documentation restore counts: {restore}")
            require(not restore.get("requires_clean_build"),
                    f"{name}: ordinary documentation unnecessarily requires a clean build")
            require(source.stat().st_mtime_ns == cached_stat.st_mtime_ns,
                    f"{name}: unchanged source timestamp was not preserved exactly")
            require(helper.content_inventory(helper.capture_inputs(fixture))
                    == helper.content_inventory(current),
                    f"{name}: restoring timestamps changed tracked input content")
            restored = helper.capture_inputs(fixture)
            stage = run_stage(name, fixture, output, swift, env, 1)
            report["stages"][name] = stage
            require(stage["frontendCompileCommands"] == 0,
                    f"{name}: documentation change recompiled package source")
            proven_inputs = helper.capture_inputs(fixture)
            require(proven_inputs == restored,
                    f"{name}: build or test changed tracked input content or timestamps")
            require(source.stat().st_mtime_ns == cached_stat.st_mtime_ns,
                    f"{name}: build or test changed the unchanged source timestamp")
            return proven_inputs

        # Compare each change with the immediately preceding proven inventory.
        # The complete inventory still tracks these ordinary documentation files.
        documentation = Path("docs/experiments/cache-report.md")
        document = fixture / documentation
        document.parent.mkdir(parents=True, exist_ok=True)
        document.write_text("# Cache report\nInitial observations.\n")
        command([git, "add", "--", str(documentation)], cwd=fixture, env=env)
        documentation_inputs = documentation_stage("documentation-add", restored_inputs, 1, 0)

        previous_document_time = document.stat().st_mtime_ns
        document.write_text("# Cache report\nUpdated observations.\n")
        edit_time = max(time.time_ns(), previous_document_time + 1_000_000)
        os.utime(document, ns=(document.stat().st_atime_ns, edit_time))
        require(document.stat().st_mtime_ns != previous_document_time,
                "documentation-edit: ordinary edit did not produce a distinct timestamp")
        command([git, "add", "--", str(documentation)], cwd=fixture, env=env)
        documentation_inputs = documentation_stage("documentation-edit", documentation_inputs, 1, 0)

        renamed_documentation = documentation.with_name("renamed-cache-report.md")
        command([git, "mv", "--", str(documentation), str(renamed_documentation)],
                cwd=fixture, env=env)
        documentation_inputs = documentation_stage("documentation-rename", documentation_inputs, 1, 1)

        (fixture / renamed_documentation).unlink()
        command([git, "add", "-u", "--", str(renamed_documentation)], cwd=fixture, env=env)
        documentation_inputs = documentation_stage("documentation-remove", documentation_inputs, 0, 1)
        require(documentation_inputs == restored_inputs,
                "documentation-remove: tracked inputs did not return to the original proven inventory")

        original = source.read_bytes()
        changed = original.replace(b"{ 1 }", b"{ 2 }")
        require(original != changed and len(original) == len(changed), "mutation must change bytes but preserve size")
        source.write_bytes(changed)
        changed_time = source.stat().st_mtime_ns
        require(changed_time != cached_stat.st_mtime_ns,
                "ordinary source edit did not produce a distinct timestamp")
        incremental_restore = helper.restore_inputs(fixture, restored_inputs)
        report["sameSizeNewMtimeRestore"] = incremental_restore
        require(incremental_restore["changed"] == 1 and not incremental_restore.get("requires_clean_build"),
                "ordinary changed input did not retain incremental build eligibility")
        require(source.read_bytes() == changed and source.stat().st_mtime_ns == changed_time,
                "restoration modified the ordinary changed input")
        incremental = run_stage("incremental", fixture, output, swift, env, 2)
        report["stages"]["incremental"] = incremental
        require(incremental["frontendCompileCommands"] > 0,
                "incremental: changed source recompilation was not observed")

        changed = original.replace(b"{ 1 }", b"{ 3 }")
        require(original != changed and len(original) == len(changed), "collision mutation must preserve size")
        source.write_bytes(changed)
        os.utime(source, ns=(cached_stat.st_atime_ns, cached_stat.st_mtime_ns))
        change_restore = helper.restore_inputs(fixture, restored_inputs)
        report["sameSizeSameMtimeRestore"] = change_restore
        require(source.read_bytes() == changed and source.stat().st_mtime_ns == cached_stat.st_mtime_ns,
                "restoration modified the changed input")
        require(change_restore["changed"] >= 1 and change_restore.get("requires_clean_build") is True,
                "same-size, same-timestamp edit did not require invalidating cached output")
        # Mirror the workflow's conservative response; never rewrite changed
        # source timestamps to make the builder notice an edit.
        shutil.rmtree(fixture / ".build")
        changed_stage = run_stage("changed", fixture, output, swift, env, 3)
        report["stages"]["changed"] = changed_stage
        require(changed_stage["frontendCompileCommands"] > 0,
                "changed: source recompilation was not observed")
        report["passed"] = True
        report["limits"] = ["disposable dependency-free Swift package on the recorded host",
                            "no Xcode DerivedData reuse or timing improvement claim",
                            "every stage executes both the test and executable"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / ".build/ci-cache-smoke")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"experiment": "source-bound-swift-cache-v1", "passed": False}
    started = time.monotonic()
    try:
        experiment(output, report)
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    report["elapsedSeconds"] = round(time.monotonic() - started, 6)
    report_path = output / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"Swift cache smoke {'passed' if report['passed'] else 'failed'}; report: {report_path}")
    if not report["passed"]:
        print(report["error"], file=sys.stderr)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
