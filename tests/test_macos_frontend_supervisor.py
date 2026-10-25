import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from macos_fixture_cleanup import retire_owned_tree


@unittest.skipUnless(sys.platform == "darwin", "The supervisor requires Darwin private terminals")
class FrontendSupervisorGroupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="remozio-supervisor-test-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        source = Path(__file__).resolve().parents[1] / "experiments/command-frontend/job-supervisor.c"
        wrapper = cls.root / "supervisor.c"
        wrapper.write_text('''#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static int fixture_setpgid(pid_t child, pid_t group) {
    if (!child) {
        fputs("Unexpected child group assignment\\n", stderr);
        errno = EPERM; return -1;
    }
    if (getenv("REMOZIO_TEST_REFUSE_PARENT_GROUP")) { errno = EPERM; return -1; }
    return setpgid(child, group);
}
#define setpgid fixture_setpgid
''' + '#include ' + json.dumps(str(source)) + '\n')
        child = cls.root / "child.c"
        child.write_text('''#include <stdlib.h>
#include <unistd.h>
int main(void) {
    const char *value = getenv("REMOZIO_FIXTURE_TTY_SLAVE");
    if (!value) return 90;
    int terminal = atoi(value);
    if (getpgrp() != getpid() || getsid(0) != getppid() || tcgetpgrp(terminal) != getpgrp()) return 91;
    return 13;
}
''')
        cls.supervisor, cls.child = cls.root / "supervisor", cls.root / "child"
        for source_file, output in [(wrapper, cls.supervisor), (child, cls.child)]:
            result = subprocess.run(["xcrun", "clang", "-Wall", "-Wextra", "-Werror", str(source_file), "-o", str(output)],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)

    def invoke(self, *, refuse_parent=False):
        environment = {"PATH": "/usr/bin:/bin", "REMOZIO_FIXTURE_RESUME_MARKER": str(self.root / "unused-marker")}
        if refuse_parent:
            environment["REMOZIO_TEST_REFUSE_PARENT_GROUP"] = "1"
        process = subprocess.Popen([str(self.supervisor), str(self.child), "frontend", "stale", "target", "marker", "nested"],
            env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=10)
            return process.returncode, stdout, stderr
        finally:
            if process.poll() is None:
                retire_owned_tree(process)
            process.stdout.close()
            process.stderr.close()

    def test_parent_assigns_group_before_child_uses_its_terminal(self):
        status, stdout, stderr = self.invoke()
        self.assertEqual(status, 13, stderr.decode(errors="replace"))
        self.assertEqual(stdout, b"")
        self.assertNotIn(b"Unexpected child group assignment", stderr)

    def test_parent_group_failure_refuses_start_and_reaps_child(self):
        status, stdout, stderr = self.invoke(refuse_parent=True)
        self.assertEqual(status, 71, stderr.decode(errors="replace"))
        self.assertEqual(stdout, b"")
        self.assertIn(b"stage 71", stderr)


if __name__ == "__main__":
    unittest.main()
