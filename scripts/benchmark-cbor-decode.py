#!/usr/bin/env python3
"""Paired synthetic debug CBOR decode benchmark; no repository mutation or network.

python3 benchmark-cbor-decode.py --repo ROOT --baseline SHA --output NEW_DIRECTORY
Requires cbor-decode-benchmark.swift beside this script. Use the target Mac Swift toolchain.
The candidate must contain only the exact supported membership-guard -> switch change.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import statistics
import struct
import subprocess
import sys
import time

SOURCE = "protocol/swift/Sources/RemozioProtocol/DeterministicCBOR.swift"
BASELINE_SHA = "d202c966e22688c1b8773631e8efd7a77ba13ad2"
OLD = b"        guard [0, 2, 3, 4, 5].contains(major) else { throw CBORError.unsupportedType }\n"
NEW = b"        switch major {\n        case 0, 2, 3, 4, 5: break\n        default: throw CBORError.unsupportedType\n        }\n"
CORPORA = ("scalar-heavy", "nested-synthetic")
FLAGS = ["-Onone", "-g", "-swift-version", "6", "-module-name", "CBORDecodeBenchmark"]
MAX_ITERATIONS = 2_000_000


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dump(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--swiftc", default="swiftc")
    parser.add_argument("--target", help="optional Swift target triple, e.g. arm64-apple-macosx26.0")
    parser.add_argument("--pairs", type=int, default=6)
    parser.add_argument("--target-seconds", type=float, default=1.25)
    args = parser.parse_args()
    if args.baseline != BASELINE_SHA:
        parser.error("baseline must be the explicitly reviewed full SHA " + BASELINE_SHA)
    if not 6 <= args.pairs <= 12 or args.pairs % 2:
        parser.error("pairs must be even and between 6 and 12")
    if not math.isfinite(args.target_seconds) or not 0.05 <= args.target_seconds <= 2:
        parser.error("target-seconds must be within 0.05..2; below 1 is only a harness smoke")
    flags = FLAGS + (["-target", args.target] if args.target else [])
    repo = args.repo.resolve(strict=True)
    candidate = (repo / SOURCE).read_bytes()
    baseline = subprocess.run(["git", "-C", str(repo), "show", f"{args.baseline}:{SOURCE}"],
                              check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=20).stdout
    if baseline.count(OLD) != 1 or candidate != baseline.replace(OLD, NEW):
        raise RuntimeError("refusing comparison: candidate is not the sole allowed same-position switch change")
    harness_path = Path(__file__).resolve().with_name("cbor-decode-benchmark.swift")
    harness = harness_path.read_bytes()
    swiftc = shutil.which(args.swiftc)
    if swiftc is None:
        raise RuntimeError("swiftc not found")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "raw").mkdir()
    (output / "build").mkdir()
    flags += ["-module-cache-path", str(output / "build" / "module-cache")]
    (output / "baseline.swift").write_bytes(baseline)
    (output / "candidate.swift").write_bytes(candidate)
    (output / "cbor-decode-benchmark.swift").write_bytes(harness)
    (output / "benchmark-cbor-decode.py").write_bytes(Path(__file__).read_bytes())
    commands: list[dict] = []

    def run(command: list[str], name: str, timeout: int = 30) -> bytes:
        started = time.monotonic()
        stdout_path, stderr_path = output / "raw" / (name + ".stdout"), output / "raw" / (name + ".stderr")
        with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
            process = None
            try:
                process = subprocess.Popen(command, stdout=out, stderr=err, start_new_session=True)
                code = process.wait(timeout=timeout)
            except BaseException as error:
                if process is not None and process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=10)
                commands.append({"name": name, "command": command, "timeoutSeconds": timeout,
                                 "timedOut": isinstance(error, subprocess.TimeoutExpired),
                                 "exception": type(error).__name__, "elapsedSeconds": time.monotonic() - started})
                dump(output / "commands.json", commands)
                raise
        commands.append({"name": name, "command": command, "returncode": code,
                         "elapsedSeconds": time.monotonic() - started})
        dump(output / "commands.json", commands)
        if code:
            raise RuntimeError(f"{name} failed with {code}; inspect retained raw logs")
        return stdout_path.read_bytes()

    try:
        version = run([swiftc, "--version"], "swift-version").decode()
        target_info = json.loads(run([swiftc, "-print-target-info", *(["-target", args.target] if args.target else [])], "swift-target-info"))
        head = run(["git", "-C", str(repo), "rev-parse", "HEAD"], "candidate-head").decode().strip()
        status = run(["git", "-C", str(repo), "status", "--porcelain=v1"], "candidate-status").decode()
        host = {"platform": platform.platform(), "machine": platform.machine(),
                "python": sys.version, "cpuCount": os.cpu_count(), "swiftc": swiftc,
                "swiftVersion": version, "swiftTargetInfo": target_info}
        if platform.system() == "Darwin":
            host["swVers"] = run(["/usr/bin/sw_vers"], "sw-vers").decode()
            host["xcodeVersion"] = run(["/usr/bin/xcodebuild", "-version"], "xcode-version").decode()
        metadata = {"schemaVersion": 1, "label": "synthetic decode microbenchmark, not actual retained plans or whole-suite speedup",
                    "baselineGitSHA": args.baseline, "candidateGitHEAD": head, "candidateStatus": status,
                    "sourceSHA256": {"baseline": sha(baseline), "candidate": sha(candidate)},
                    "harnessSHA256": sha(harness), "driverSHA256": sha(Path(__file__).read_bytes()),
                    "compilerFlags": flags, "host": host,
                    "measurement": "Swift monotonic wall and process CPU for decode batches; includes identical loop/result retention overhead; excludes build, corpus construction, encoding and hashing",
                    "workEquivalence": "identical framed canonical corpus bytes, decode call count and exact canonical decoded-result bytes/checksum; object-file equality is not applicable to this decode benchmark",
                    "targetSeconds": args.target_seconds, "pairsPerCorpus": args.pairs,
                    "caveats": ["synthetic inputs", "debug configuration only", "process startup excluded", "host load/thermal/OS variation", "no full-suite speedup inference", "short runs below one second are harness smoke only"]}
        dump(output / "metadata.json", metadata)
        executables = {}
        for mode in ("baseline", "candidate"):
            build = output / "build"
            # Same absolute source path/module/flags; only the proven same-position conditional differs.
            source = build / "DeterministicCBOR.swift"
            source.write_bytes(baseline if mode == "baseline" else candidate)
            (build / "Harness.swift").write_bytes(harness)
            executable = build / "benchmark"
            run([swiftc, *flags, str(source), str(build / "Harness.swift"), "-o", str(executable)],
                "build-" + mode, timeout=180)
            destination = output / ("benchmark-" + mode)
            shutil.copy2(executable, destination)
            executables[mode] = destination

        corpus_info = {}
        observations = []
        calibrations = []
        for corpus in CORPORA:
            descriptions = {}
            for mode in ("baseline", "candidate"):
                descriptions[mode] = json.loads(run([str(executables[mode]), "describe", corpus], f"describe-{corpus}-{mode}"))
            if descriptions["baseline"] != descriptions["candidate"]:
                raise RuntimeError("corpus or decoded results differ between modes")
            description = descriptions["baseline"]
            framed = b"".join(struct.pack(">Q", len(bytes.fromhex(value))) + bytes.fromhex(value)
                               for value in description["wireHex"])
            description["framedCorpusSHA256"] = sha(framed)
            corpus_info[corpus] = description
            (output / (corpus + ".framed.bin")).write_bytes(framed)
            dump(output / "corpora.json", corpus_info)

            def observation(mode: str, iterations: int, name: str) -> dict:
                value = json.loads(run([str(executables[mode]), "run", corpus, str(iterations)], name))
                expected = {"schemaVersion": 1, "corpus": corpus, "iterations": iterations,
                            "recordsPerIteration": description["recordsPerIteration"],
                            "decodeCalls": iterations * description["recordsPerIteration"],
                            "bytesPerIteration": description["bytesPerIteration"],
                            "decodedResultChecksumFNV1a64": description["decodedResultChecksumFNV1a64"]}
                if any(value.get(key) != val for key, val in expected.items()):
                    raise RuntimeError("decoded work or result mismatch: " + name)
                for key in ("wallSeconds", "processCPUSeconds"):
                    if not isinstance(value.get(key), (int, float)) or not math.isfinite(value[key]) or value[key] <= 0:
                        raise RuntimeError("invalid timing: " + name)
                return dict(value, mode=mode, framedCorpusSHA256=description["framedCorpusSHA256"])

            for mode in ("baseline", "candidate"):
                warm = observation(mode, 100, f"warm-{corpus}-{mode}")
                calibrations.append(dict(warm, phase="warmup"))
            iterations = 100
            for calibration_index in range(6):
                pair = [observation(mode, iterations, f"calibrate-{corpus}-{calibration_index}-{mode}")
                        for mode in ("baseline", "candidate")]
                calibrations.extend(dict(value, phase="calibration") for value in pair)
                elapsed = min(value["wallSeconds"] for value in pair)
                if elapsed >= args.target_seconds * 0.8 or iterations == MAX_ITERATIONS:
                    break
                iterations = min(MAX_ITERATIONS, max(iterations + 1, int(iterations * min(20, args.target_seconds / elapsed))))
            if min(value["wallSeconds"] for value in pair) < args.target_seconds * 0.8:
                raise RuntimeError("bounded calibration failed to reach a meaningful duration")
            dump(output / "calibration.json", calibrations)
            for pair_index in range(args.pairs):
                order = ("baseline", "candidate") if pair_index % 2 == 0 else ("candidate", "baseline")
                for position, mode in enumerate(order):
                    value = observation(mode, iterations, f"trial-{corpus}-{pair_index:02d}-{position}-{mode}")
                    observations.append(dict(value, pair=pair_index, order=position))
                    dump(output / "observations.json", observations)
        summary = {}
        for corpus in CORPORA:
            summary[corpus] = {}
            for mode in ("baseline", "candidate"):
                selected = [x for x in observations if x["corpus"] == corpus and x["mode"] == mode]
                summary[corpus][mode] = {"observations": len(selected), "iterations": selected[0]["iterations"]}
                for metric in ("wallSeconds", "processCPUSeconds"):
                    values = [x[metric] for x in selected]
                    summary[corpus][mode][metric] = {"median": statistics.median(values), "min": min(values), "max": max(values)}
        dump(output / "report.json", {"schemaVersion": 1, "status": "complete", "label": metadata["label"],
                                      "summary": summary, "observations": observations,
                                      "containsSubsecondObservations": any(x["wallSeconds"] < 1 for x in observations)})
        print(json.dumps({"status": "complete", "output": str(output), "summary": summary}, indent=2))
    except BaseException as error:
        dump(output / "failure.json", {"type": type(error).__name__, "message": str(error)})
        raise
    finally:
        files = []
        for path in sorted(output.rglob("*")):
            if path.is_file() and path.name != "manifest.json":
                data = path.read_bytes()
                files.append({"path": str(path.relative_to(output)), "bytes": len(data), "sha256": sha(data)})
        dump(output / "manifest.json", {"files": files})


if __name__ == "__main__":
    main()
