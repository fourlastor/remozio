# Command readiness status

The command frontend displays the specific authenticated busy state while it waits for a fresh submission.
The caller keeps one configured deadline across reason changes and backoff.
An indefinite update drain does not extend that deadline.

When the deadline ends before admission, the CLI reports the last verified busy state and returns its status:

| Last verified state | CLI exit status |
| --- | --- |
| Update installing | 80 |
| Mac authority starting | 81 |
| Update waiting | 82 |
| Storage unavailable | 83 |

A lookup deadline without a verified busy response returns temporary failure, status 75.
Invalid readiness settings return status 78. A failed caller clock returns status 71.
The CLI preserves a verified target's own exit status.

These diagnostics grant no retry authority.
Only an authenticated response bound to the submission can prove that no request was admitted.
Lost replies and unknown admission outcomes do not permit automatic resubmission.
The existing readiness controller preserves cancellation, caller lifetime, and unread input.
It creates a fresh submission and requires a fresh decision after each verified refusal.
