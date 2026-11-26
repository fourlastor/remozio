# Linux single-owner fixtures

These C fixtures measure the [Linux single-owner design](../../docs/linux-single-owner-design.md)
(issue #988, PR1). They are measurement fixtures, not the product executor. They
do not install a service, approve a real decision or turn on production execution.

- `owner.c` is the owner O. It holds the caller's ptrace stop and starts the
  command through a prepared child K.
- `frontend.c` is the frontend C. It sends a fixed hello and its standard
  descriptors, then blocks.
- `probe.c` is the command. It writes one marker line and reports the state that
  it inherited.

The supervised run needs Root through `sudo` from an ordinary account:

```sh
sudo python3 scripts/run-linux-single-owner-experiment.py [--timeout 15] [--allow-sysctl]
```

The tests need no Root. They compile every build with warnings as errors and run
every case that needs no Root with unprivileged test builds:

```sh
python3 -m unittest tests.test_linux_single_owner_experiment
```

The cases, the stub authority, the cleanup and the report are described in
[the experiment document](../../docs/experiments/linux-single-owner.md). The
report holds booleans, categories and errno names only. It keeps
`strictAdmission` and `productionAdmission` false.
