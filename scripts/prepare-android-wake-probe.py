#!/usr/bin/env python3
"""Prepare an isolated Android wake experiment. Builds and device work use ATC separately."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def prepare(destination):
    build = (ROOT / ".build").resolve()
    if not build.is_relative_to(ROOT):
        raise ValueError("The repository build directory must stay inside the checkout")
    destination = destination.absolute()
    if destination.parent.resolve() != build or destination.is_symlink():
        raise ValueError("Use a new direct child of the repository .build directory")
    if not os.environ.get("JAVA_HOME") or not os.environ.get("ANDROID_HOME"):
        raise ValueError("Set JAVA_HOME for JDK 21 and ANDROID_HOME for SDK 37")
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    paths = [Path(name) for name in names if name]
    for relative in paths:
        if relative.is_absolute() or ".." in relative.parts or ".git" in relative.parts:
            raise ValueError("Unsafe tracked path")
        source = ROOT / relative
        if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(ROOT):
            raise ValueError("The experiment requires ordinary tracked files")
    build.mkdir(exist_ok=True)
    destination.mkdir(parents=False, exist_ok=False)
    fixture = destination / "fixture"
    hashes = {}
    for relative in paths:
        source = ROOT / relative
        target = fixture / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        hashes[str(relative)] = hashlib.sha256(target.read_bytes()).hexdigest()
    gradle = fixture / "android/app/build.gradle.kts"
    text = gradle.read_text()
    before = '        targetSdk = 37\n'
    if text.count(before) != 1 or text.count('applicationIdSuffix = ".debug"') != 1:
        raise ValueError("The Android build configuration changed; inspect before adapting the probe")
    text = text.replace(before, before +
        '        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"\n' +
        '        testInstrumentationRunnerArguments["class"] = "dev.remozio.android.push.WakeDemandAndroidProbeTest"\n')
    text = text.replace('applicationIdSuffix = ".debug"', 'applicationIdSuffix = ".wakeprobe"')
    text = text.replace('    buildFeatures { compose = true }',
        '    installation { timeOutInMs = 60_000 }\n    buildFeatures { compose = true }')
    text = text.replace('dependencies {\n', 'dependencies {\n' +
        '    androidTestImplementation("androidx.test:runner:1.7.0")\n' +
        '    androidTestImplementation("androidx.test.ext:junit:1.3.0")\n' +
        '    androidTestImplementation("androidx.work:work-testing:2.12.0")\n' +
        '    androidTestImplementation("junit:junit:4.13.2")\n')
    gradle.write_text(text)
    manifest = fixture / "android/app/src/main/AndroidManifest.xml"
    text = manifest.read_text()
    if text.count('android:name=".RemozioApplication"') != 1:
        raise ValueError("The application manifest changed; inspect before adapting the probe")
    text = text.replace('android:name=".RemozioApplication"', 'android:name="android.app.Application"')
    anchor = '        <meta-data android:name="firebase_messaging_auto_init_enabled"'
    if text.count(anchor) != 1:
        raise ValueError("The provider manifest changed; inspect before adapting the probe")
    text = text.replace(anchor,
        '        <provider android:name="androidx.startup.InitializationProvider" android:authorities="${applicationId}.androidx-startup" tools:node="merge">\n' +
        '            <meta-data android:name="androidx.work.WorkManagerInitializer" tools:node="remove" />\n' +
        '        </provider>\n' + anchor)
    manifest.write_text(text)
    source = fixture / "experiments/android-wake-demand/WakeDemandAndroidProbeTest.kt"
    target = fixture / "android/app/src/androidTest/kotlin/dev/remozio/android/push/WakeDemandAndroidProbeTest.kt"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    environment = {key: os.environ[key] for key in ("JAVA_HOME", "ANDROID_HOME")}
    for name, tasks, timeout in [
        ("compile", [":android-app:assembleDebug", ":android-app:assembleDebugAndroidTest"], 1800),
        ("device", [":android-app:connectedDebugAndroidTest"], 600),
    ]:
        plan = {"version": 1, "steps": [{"id": name + "-wake-probe", "op": "gradle.tasks",
            "tasks": tasks, "workspace": str(fixture), "env": environment,
            "timeoutSec": timeout, "brief": True}]}
        (destination / (name + "-plan.json")).write_text(json.dumps(plan, indent=2) + "\n")
    proof = {"sourceHead": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "sourceHashes": hashes, "fixture": str(fixture), "package": "dev.remozio.android.wakeprobe",
        "plainSourceCopy": True, "buildsRun": False, "devicesChanged": False}
    (destination / "preparation.json").write_text(json.dumps(proof, indent=2) + "\n")
    print("Prepared isolated source fixture: " + str(destination))
    print("Validate and run compile-plan.json with ATC before claiming an emulator.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    prepare(parser.parse_args().destination)
