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


@unittest.skipUnless(sys.platform == "darwin", "The supervisor requires Darwin terminal definitions")
class FrontendSupervisorPassiveDiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="remozio-supervisor-diagnostics-")
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        source = Path(__file__).resolve().parents[1] / "experiments/command-frontend/job-supervisor.c"
        wrapper = root / "diagnostics.c"
        wrapper.write_text('''#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
static struct termios fixture_seen;
static int fixture_errno, fixture_reads;
static int fixture_tcgetattr(int descriptor, struct termios *value) {
    (void)descriptor; fixture_reads++;
    if (fixture_errno) { errno = fixture_errno; return -1; }
    *value = fixture_seen; return 0;
}
#define tcgetattr fixture_tcgetattr
#define main fixture_supervisor_main
''' + '#include ' + json.dumps(str(source)) + '''
#undef main
int main(int argc, char **argv) {
    if (argc != 2) return 90;
    struct termios original = {0};
    bool reaped = true;
    uint64_t started = now(), deadline = started + 45000;
    if (!strcmp(argv[1], "unreaped")) { reaped = false; deadline = started; }
    else if (!strcmp(argv[1], "cancelled")) { reaped = false; cancelled = 1; }
    else if (!strcmp(argv[1], "read-error")) fixture_errno = EBADF;
    else if (!strcmp(argv[1], "mismatch")) {
        fixture_seen.c_iflag = IGNBRK; fixture_seen.c_cc[VINTR] = 3;
    } else if (!strcmp(argv[1], "pendin")) fixture_seen.c_lflag = PENDIN;
    else if (strcmp(argv[1], "restored")) return 91;
    bool complete = passive_frontend_complete(reaped, 13 << 8, 0, &original, started, deadline);
    printf("complete=%d terminalReads=%d\\n", complete, fixture_reads);
    return 0;
}
''')
        cls.program = root / "diagnostics"
        result = subprocess.run(["xcrun", "clang", "-Wall", "-Wextra", "-Werror", str(wrapper), "-o", str(cls.program)],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    def invoke(self, mode):
        result = subprocess.run([str(self.program), mode], env={"PATH": "/usr/bin:/bin"},
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout, result.stderr

    def test_restored_terminal_has_no_failure_diagnostic(self):
        output, error = self.invoke("restored")
        self.assertEqual(output, "complete=1 terminalReads=1\n")
        self.assertEqual(error, "")

    def test_pendin_keeps_the_existing_restoration_exception(self):
        output, error = self.invoke("pendin")
        self.assertEqual(output, "complete=1 terminalReads=1\n")
        self.assertEqual(error, "")

    def test_unreaped_child_reports_deadline_without_reading_terminal(self):
        output, error = self.invoke("unreaped")
        self.assertEqual(output, "complete=0 terminalReads=0\n")
        self.assertIn("reaped=0 cancelled=0", error)
        self.assertIn("deadlineReached=1 terminalChecked=0 terminalRead=0 terminalErrno=0", error)
        self.assertNotIn("Passive terminal mismatch", error)

    def test_terminal_read_failure_reports_errno_without_comparing_fields(self):
        output, error = self.invoke("read-error")
        self.assertEqual(output, "complete=0 terminalReads=1\n")
        self.assertIn("terminalChecked=1 terminalRead=0 terminalErrno=9", error)
        self.assertNotIn("Passive terminal mismatch", error)

    def test_mismatch_reports_field_changes_without_control_character_values(self):
        output, error = self.invoke("mismatch")
        self.assertEqual(output, "complete=0 terminalReads=1\n")
        self.assertIn("terminalChecked=1 terminalRead=1 terminalErrno=0", error)
        self.assertIn("iflagChanged=1 oflagChanged=0 cflagChanged=0 lflagChanged=0", error)
        self.assertIn("ispeedChanged=0 ospeedChanged=0 controlCharactersChanged=1", error)
        self.assertEqual(len(error.splitlines()), 2)

    def test_cancellation_is_distinct_from_deadline_expiry(self):
        output, error = self.invoke("cancelled")
        self.assertEqual(output, "complete=0 terminalReads=0\n")
        self.assertIn("reaped=0 cancelled=1", error)
        self.assertIn("deadlineReached=0 terminalChecked=0 terminalRead=0", error)


if __name__ == "__main__":
    unittest.main()
