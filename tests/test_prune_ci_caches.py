"""The cache pruner deletes only superseded main entries of known families and never fails the run."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("prune_ci_caches", ROOT / "scripts/prune-ci-caches.py")
PRUNE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRUNE)

IDENTITY_A, IDENTITY_B = "a" * 64, "b" * 64


def entry(identifier, key, created, ref="refs/heads/main", size=1048576):
    return {"id": identifier, "key": key, "ref": ref, "created_at": f"2026-11-09T{created}Z", "size_in_bytes": size}


def mac(scope, identity, content):
    return f"mac-build-v1-{scope}-{identity}-{content * 64}"


def gradle(job, os, digest):
    return f"gradle-downloads-v1-{job}-{os}-{digest * 64}"


class FamilyTests(unittest.TestCase):
    def test_known_keys_group_by_scope_or_job_and_os(self):
        self.assertEqual(PRUNE.family(mac("experiments", IDENTITY_A, "1")), "mac-build-v1-experiments-")
        self.assertEqual(PRUNE.family(mac("mac", IDENTITY_B, "2")), "mac-build-v1-mac-")
        self.assertEqual(PRUNE.family(gradle("mac-interop", "macOS", "3")), "gradle-downloads-v1-mac-interop-macOS-")
        self.assertEqual(PRUNE.family(gradle("kotlin", "Linux", "4")), "gradle-downloads-v1-kotlin-Linux-")

    def test_unknown_keys_have_no_family(self):
        for key in ("setup-java-Linux-x64-gradle-0123", "gradle-v1-android-Linux-0123", "mac-build-v1-mac-zz-11",
                    gradle("kotlin", "Solaris", "4"), mac("Mac", IDENTITY_A, "1")):
            with self.subTest(key=key):
                self.assertIsNone(PRUNE.family(key))


class PlanTests(unittest.TestCase):
    def test_keeps_the_newest_entry_of_each_family_across_identities(self):
        old_identity = entry(1, mac("mac", IDENTITY_A, "1"), "01:00:00")
        older = entry(2, mac("mac", IDENTITY_B, "2"), "02:00:00")
        newest = entry(3, mac("mac", IDENTITY_B, "3"), "03:00:00")
        experiments = entry(4, mac("experiments", IDENTITY_B, "4"), "00:30:00")
        doomed = PRUNE.plan([newest, old_identity, experiments, older], keep=set())
        self.assertEqual([item["id"] for item in doomed], [1, 2])

    def test_keys_this_run_saved_stay_even_when_not_newest(self):
        saved = entry(1, gradle("kotlin", "Linux", "1"), "01:00:00")
        newer = entry(2, gradle("kotlin", "Linux", "2"), "02:00:00")
        stale = entry(3, gradle("kotlin", "Linux", "3"), "00:10:00")
        doomed = PRUNE.plan([saved, newer, stale], keep={saved["key"]})
        self.assertEqual([item["id"] for item in doomed], [3])

    def test_never_touches_pull_request_caches_or_unknown_families(self):
        main = entry(1, gradle("android", "Linux", "1"), "03:00:00")
        pull = entry(2, gradle("android", "Linux", "2"), "01:00:00", ref="refs/pull/600/merge")
        unknown = entry(3, "setup-java-Linux-x64-gradle-0123", "00:00:01")
        self.assertEqual(PRUNE.plan([main, pull, unknown], keep=set()), [])

    def test_a_single_entry_family_is_kept(self):
        self.assertEqual(PRUNE.plan([entry(1, mac("interop", IDENTITY_A, "1"), "01:00:00")], keep=set()), [])

    def test_equal_creation_times_keep_the_highest_id(self):
        first = entry(7, mac("mac", IDENTITY_A, "1"), "01:00:00")
        second = entry(9, mac("mac", IDENTITY_A, "2"), "01:00:00")
        self.assertEqual([item["id"] for item in PRUNE.plan([second, first], keep=set())], [7])


class RunTests(unittest.TestCase):
    def setUp(self):
        self.entries = [entry(1, mac("mac", IDENTITY_A, "1"), "01:00:00", size=3 * 1048576),
                        entry(2, mac("mac", IDENTITY_A, "2"), "02:00:00"),
                        entry(3, gradle("ios", "macOS", "3"), "01:00:00", ref="refs/pull/1/merge")]
        self.calls = []

    def api(self, *args, fail_delete=False, fail_list=False, fail_usage=False):
        def call(*arguments):
            self.calls.append(arguments)
            if arguments[0] == "--paginate":
                if fail_list:
                    raise subprocess.CalledProcessError(1, "gh", "HTTP 502")
                return "\n".join(json.dumps(item) for item in self.entries) + "\n"
            if arguments[0] == "--method":
                if fail_delete:
                    raise subprocess.CalledProcessError(1, "gh", "HTTP 403")
                return ""
            if fail_usage:
                raise subprocess.CalledProcessError(1, "gh", "HTTP 500")
            return json.dumps({"active_caches_count": 2, "active_caches_size_in_bytes": 1073741824})
        return call

    def run_prune(self, **options):
        output = io.StringIO()
        dry_run = options.pop("dry_run", False)
        with contextlib.redirect_stdout(output):
            status = PRUNE.run("owner/repo", set(), dry_run=dry_run, api=self.api(**options))
        return status, output.getvalue()

    def test_deletes_superseded_main_entries_and_reports_the_space_left(self):
        status, output = self.run_prune()
        self.assertEqual(status, 0)
        self.assertEqual([call for call in self.calls if call[0] == "--method"],
                         [("--method", "DELETE", "repos/owner/repo/actions/caches/1")])
        self.assertIn(f"Deleted {mac('mac', IDENTITY_A, '1')} (3 MB, created 2026-11-09T01:00:00Z)", output)
        self.assertIn("Freed 3 MB. The repository now holds 2 cache entries, 1.00 GB.", output)
        self.assertIn("ref=refs/heads/main", self.calls[0][1])

    def test_dry_run_deletes_nothing(self):
        status, output = self.run_prune(dry_run=True)
        self.assertEqual(status, 0)
        self.assertFalse(any(call[0] == "--method" for call in self.calls))
        self.assertIn(f"Would delete {mac('mac', IDENTITY_A, '1')}", output)
        self.assertIn("Would free 3 MB.", output)
        self.assertNotIn("cache/usage", " ".join(" ".join(call) for call in self.calls))

    def test_api_errors_are_warnings_and_never_fail_the_run(self):
        for options, expected in (({"fail_list": True}, "::warning::Could not list the main caches"),
                                  ({"fail_delete": True}, "::warning::Could not delete"),
                                  ({"fail_usage": True}, "::warning::Freed 3 MB, but could not read the cache usage")):
            with self.subTest(**options):
                self.calls = []
                status, output = self.run_prune(**options)
                self.assertEqual(status, 0)
                self.assertIn(expected, output)


if __name__ == "__main__":
    unittest.main()
