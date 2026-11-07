"""Measure where the pinned connector spends its startup under the #520 sandbox. Synthetic credential only."""
import base64, hashlib, json, os, select, signal, subprocess, sys, time

binary, runs, label = sys.argv[1], int(sys.argv[2]), sys.argv[3]
token = base64.b64encode(json.dumps({"a": "a" * 32, "s": base64.b64encode(b"\x71" * 32).decode(),
                                     "t": "12345678-1234-4234-9234-123456789012"}, sort_keys=True,
                                    separators=(",", ":")).encode())
args = ["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny network-outbound)", binary,
        "--no-autoupdate", "--config", "/dev/fd/5", "--output", "json", "tunnel", "--edge", "127.0.0.1:7844",
        "--protocol", "http2", "--grace-period", "1s", "--metrics", "127.0.0.1:0", "run", "--token-file", "/dev/fd/4"]
results = []
os.makedirs('/tmp/measure', exist_ok=True)
for run in range(runs):
    with open("/tmp/m-token", "wb") as f: f.write(token)
    with open("/tmp/m-config", "wb") as f: f.write(b"{}\n")
    start = time.monotonic()
    p = subprocess.Popen(["/bin/bash", "-c", 'exec "$@" 4</tmp/m-token 5</tmp/m-config', "bash", *args],
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         cwd="/", start_new_session=True,
                         env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/empty", "LC_ALL": "C", "LANG": "C"})
    lines, pending, ident, metrics = [], b"", None, None
    deadline = start + 70
    while time.monotonic() < deadline:
        ready, _, _ = select.select([p.stdout], [], [], 0.05)
        if ready:
            chunk = os.read(p.stdout.fileno(), 65536)
            if not chunk: break
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                t = time.monotonic() - start
                try: msg = json.loads(line).get("message", "")
                except Exception: msg = line[:300].decode("utf-8", "replace")
                lines.append((round(t, 3), msg[:300]))
                if msg.startswith("Generated Connector ID"): ident = t
                if msg.startswith("Starting metrics server"): metrics = t
        if ident is not None and metrics is not None: break
        if p.poll() is not None: break
    os.killpg(p.pid, signal.SIGTERM)
    try: p.wait(5)
    except subprocess.TimeoutExpired: os.killpg(p.pid, signal.SIGKILL); p.wait()
    total = max(ident or 99, metrics or 99)
    results.append(total)
    slow = total > 5
    record = {"label": label, "run": run, "connectorID": ident and round(ident, 3),
              "metrics": metrics and round(metrics, 3), "exit": p.returncode, "count": len(lines)}
    print(json.dumps(record), flush=True)
    if slow or run == 0:
        with open(f"/tmp/measure/{label}.jsonl", "a") as f: f.write(json.dumps({**record, "lines": lines}) + "\n")
results.sort()
print(json.dumps({"label": label, "runs": runs, "median": results[len(results)//2], "max": results[-1],
                  "over5s": sum(r > 5 for r in results), "over60s": sum(r > 60 for r in results)}), flush=True)
