#!/usr/bin/env python3
"""Generate synthetic schema-4 codec vectors; never observe a real caller or device.

Run with --check to verify reproducibility without writing. Metadata and all paths,
identities, byte bindings and digests are invented. Legacy fixture files are never
read or written. The tiny encoder implements only the deterministic CBOR subset
needed here; Raw deliberately introduces malformed encodings for refusal controls.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "protocol/vectors/command-capture-v4.json"
PROFILE = "linux-protected-single-thread-v1"
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1
LIMITS = {"maxBytes": 32768, "maxDepth": 32, "maxItems": 4096}


class Raw(bytes):
    """Already encoded CBOR, including deliberately unsupported representations."""


def head(major, value):
    if not 0 <= value <= U64_MAX:
        raise ValueError("CBOR argument outside UInt64")
    if value < 24:
        return bytes([(major << 5) | value])
    for width, marker in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if value < 1 << (width * 8):
            return bytes([(major << 5) | marker]) + value.to_bytes(width, "big")
    raise AssertionError("unreachable")


def encode(value):
    if isinstance(value, Raw):
        return bytes(value)
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode("utf-8")
        return head(3, len(data)) + data
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(map(encode, value))
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(encode(key) + encode(value[key]) for key in sorted(value))
    raise TypeError(type(value))


def identity(device=1, inode=100):
    return {0: device, 1: inode}


def executable(path, inode):
    return {0: path, 1: identity(inode=inode), 2: bytes(range(32))}


def source(kind, marker=10):
    if kind == 0:
        return {0: 0, 1: None, 2: None, 3: None}
    return {0: kind, 1: bytes([marker]) * 16,
            2: b"/synthetic/stream/" + str(marker).encode(), 3: identity(2, 200 + marker)}


def base_capture():
    stdin = source(1)
    return {
        0: 4,
        1: executable(b"/synthetic/bin/command", 100),
        2: [b"command", b"", b"%s\n", b"a\xffb", "\u202ehidden".encode(), b"e\xcc\x81", "\u00e9".encode()],
        3: {0: b"/synthetic/work", 1: identity(inode=101)},
        4: {0: 0, 1: 0, 2: [0, 80], 3: "synthetic-root"},
        5: [{0: b"HOME", 1: b"/synthetic/home", 2: 0},
            {0: b"PATH", 1: b"/synthetic/bin", 2: 0},
            {0: b"USER_VALUE", 1: b"\xff\n", 2: 1}],
        6: copy.deepcopy(stdin), 7: 0, 8: 0,
        9: {0: PROFILE, 1: 1234, 2: b"\x11" * 16, 3: b"\x22" * 16, 4: 1,
            5: executable(b"/synthetic/bin/frontend", 300),
            6: {0: 1000, 1: 1000, 2: 1000, 3: 1000,
                4: 2000, 5: 2000, 6: 2000, 7: 2000, 8: [10, 2000]},
            7: 4321, 8: b"\x33" * 32},
        10: {0: 2, 1: [], 2: 4},
        11: "Synthetic unverified caller explanation",
        12: {0: b"\x01" * 16, 1: b"\x02" * 32, 2: b"\x03" * 16},
        13: {0: {0: stdin, 1: 0, 2: 0},
             1: {0: source(2, 11), 1: 1, 2: 1},
             2: {0: source(5, 12), 1: 2, 2: 2}, 3: None, 4: 0},
    }


def at(root, path):
    for key in path:
        root = root[key]
    return root


def changed(root, path, value):
    if not path:
        return value
    result = copy.deepcopy(root)
    at(result, path[:-1])[path[-1]] = value
    return result


def synced_input(root, path, value):
    """Change stdin source once and preserve the required duplicate observation."""
    result = changed(root, [6, *path], value)
    result[13][0][0] = copy.deepcopy(result[6])
    return result


def wire_row(name, value, **metadata):
    data = encode(value)
    return {"name": name, "hex": data.hex(), **metadata}


def expected(value):
    requester, credentials = value[9], value[9][6]
    streams = [value[13][n] for n in range(3)]
    return {
        "arguments": [data.hex() for data in value[2]],
        "environmentNames": [entry[0].hex() for entry in value[5]],
        "requestedExecutablePath": value[1][0].hex(),
        "requesterExecutablePath": requester[5][0].hex(),
        "requesterPID": requester[1], "processBinding": requester[2].hex(),
        "monitorIncarnation": requester[3].hex(), "execEpoch": str(requester[4]),
        "sessionID": requester[7], "codePolicyDigest": requester[8].hex(),
        "credentialUIDs": [credentials[n] for n in range(4)],
        "credentialGIDs": [credentials[n] for n in range(4, 8)],
        "supplementaryGroups": credentials[8], "inputKind": value[6][0],
        "streamKinds": [stream[0][0] for stream in streams],
        "streamAccess": [stream[1] for stream in streams],
        "streamFlags": [stream[2] for stream in streams],
        "ptyMask": value[13][4], "ancestry": value[10][0], "rationale": value[11],
        "captureSHA256": hashlib.sha256(encode(value)).hexdigest(),
    }


def generate():
    base = base_capture()
    valid, invalid, mutations = [], [], []

    def good(name, value):
        valid.append(wire_row(name, value, **expected(value)))

    def bad(name, path=None, value=None, *, root=None, **metadata):
        invalid.append(wire_row(name, root if root is not None else changed(base, path, value), **metadata))

    good("schema4-base", base)
    for epoch in (1 << 32, (1 << 63) + 1, U64_MAX):
        good(f"exec-epoch-{epoch}", changed(base, [9, 4], epoch))
    for session in (None, 1, (1 << 31) - 1):
        good(f"session-{session if session is not None else 'null'}", changed(base, [9, 7], session))
    good("pid-int32-max", changed(base, [9, 1], (1 << 31) - 1))
    good("pid-one", changed(base, [9, 1], 1))
    good("empty-supplementary-groups", changed(base, [9, 6, 8], []))
    good("supplementary-gid-uint32-max", changed(base, [9, 6, 8], [0, U32_MAX]))
    unsigned = copy.deepcopy(base)
    for key in range(8):
        unsigned[9][6][key] = U32_MAX if key < 4 else 0
    good("uid-uint32-max-gid-zero", unsigned)
    unsigned = copy.deepcopy(base)
    for key in range(8):
        unsigned[9][6][key] = 0 if key < 4 else U32_MAX
    good("uid-zero-gid-uint32-max", unsigned)
    for kind in range(9):
        value = copy.deepcopy(base)
        for stream in range(3):
            value[13][stream][0] = source(kind, 10 + stream)
            value[13][stream][1] = 0 if stream == 0 else 1
            value[13][stream][2] = (kind + stream) % 16
        value[6] = copy.deepcopy(value[13][0][0])
        good(f"retained-stream-kind-{kind}", value)
    for flags in range(16):
        value = copy.deepcopy(base)
        for stream in range(3):
            value[13][stream][1] = 2
            value[13][stream][2] = flags
        good(f"read-write-stream-flags-{flags}", value)
    good("optional-rationale-null", changed(base, [11], None))
    good("target-name-null", changed(base, [4, 3], None))
    good("environment-unsigned-byte-order", changed(base, [5], [
        {0: name, 1: b"", 2: 0} for name in (b"A", b"\x7f", b"\x80", b"\xff")]))
    raw = copy.deepcopy(base)
    raw[1][0] = b"/synthetic/cmd-\xff\n\t" + "\u202e".encode()
    raw[3][0] = b"/synthetic/work-\xfe\x1b" + "\u2066".encode()
    raw[9][5][0] = b"/synthetic/frontend-\xfd\r" + "\u202d".encode()
    raw[5][2][1] = b"\xff\n\r\t\x1b" + "\u202e\u2066".encode()
    for stream in range(3):
        raw[13][stream][0][2] = b"/synthetic/stream-\xfc\n" + "\u202e".encode()
    raw[6] = copy.deepcopy(raw[13][0][0])
    good("raw-path-control-bidi-nonutf8", raw)
    observations = copy.deepcopy(base)
    for stream in range(3):
        observations[13][stream][0][2] = None
        observations[13][stream][0][3] = None
    observations[6] = copy.deepcopy(observations[13][0][0])
    good("unavailable-stream-path-and-identity", observations)

    # Every mandatory field in every represented map has individual missing/extra
    # controls. Repeated stream maps get one representative closed-map check each.
    maps = [("root", []), ("command-executable", [1]), ("command-file", [1, 1]),
            ("directory", [3]), ("directory-file", [3, 1]), ("target", [4]),
            ("environment-entry", [5, 0]), ("root-input", [6]), ("requester", [9]),
            ("requester-executable", [9, 5]), ("requester-file", [9, 5, 1]),
            ("credentials", [9, 6]), ("ancestry", [10]), ("submission", [12]),
            ("layout", [13]), ("stdin-stream", [13, 0]),
            ("stdout-stream", [13, 1]), ("stderr-stream", [13, 2]),
            ("stdout-source", [13, 1, 0]), ("stdout-file", [13, 1, 0, 3])]
    for label, path in maps:
        for key in at(base, path):
            value = copy.deepcopy(base)
            del at(value, path)[key]
            bad(f"{label}-missing-{key}", root=value)
        value = copy.deepcopy(base)
        at(value, path)[99] = None
        bad(f"{label}-extra-key", root=value)
        bad(f"{label}-wrong-type", path, [])

    for schema in (1, 2, 3, 5):
        bad(f"inner-schema-{schema}", [0], schema)
    bad("inner-schema-text", [0], "4")
    bad("unknown-requester-profile", [9, 0], "linux-unknown-profile")
    for key in range(9):
        bad(f"requester-field-{key}-wrong-type", [9, key], False)
    for key, size in ((2, 16), (3, 16), (8, 32)):
        for length in (0, size - 1, size + 1):
            bad(f"requester-bytes-{key}-length-{length}", [9, key], b"\x01" * length)
    for key, label in ((1, "pid"), (7, "session")):
        for value in (0, 1 << 31, 1 << 32, -1):
            bad(f"{label}-out-of-range-{value}", [9, key], value)
    bad("pid-null", [9, 1], None)
    bad("exec-epoch-zero", [9, 4], 0)
    bad("exec-epoch-negative", [9, 4], -1)
    bad("exec-epoch-cbor-bignum-2pow64", [9, 4], Raw(b"\xc2\x49\x01" + b"\x00" * 8))
    for key in range(8):
        bad(f"credential-role-{key}-mismatch", [9, 6, key], at(base, [9, 6, key]) + 1)
        bad(f"credential-id-{key}-overflow", [9, 6, key], 1 << 32)
        bad(f"credential-id-{key}-wrong-type", [9, 6, key], "1000")
    for name, groups in (("unsorted", [20, 10]), ("duplicate", [10, 10]),
                         ("overflow", [1 << 32]), ("negative", [-1]), ("wrong-item", ["10"])):
        bad(f"supplementary-groups-{name}", [9, 6, 8], groups)
    bad("supplementary-groups-wrong-type", [9, 6, 8], None)
    for key, label in ((0, "complete"), (1, "partial")):
        bad(f"ancestry-{label}", [10, 0], key)
    for reason in (0, 1, 2, 3, 5):
        bad(f"ancestry-reason-{reason}", [10, 2], reason)
    bad("ancestry-nonempty", [10, 1], [{0: 1, 1: 0, 2: None, 3: 1000}])
    bad("ancestry-entries-wrong-type", [10, 1], None)
    bad("pty-io-mode", [7], 1)
    bad("unknown-io-mode", [7], 2)
    bad("continue-running", [8], 1)
    bad("unknown-disconnect", [8], 2)
    for mask in (1, 7, 8):
        bad(f"pty-mask-{mask}", [13, 4], mask)
    bad("pty-mask-wrong-type", [13, 4], False)
    terminal = {0: {0: source(3, 20), 1: 2, 2: 0}, 1: 4321, 2: 42}
    bad("terminal-in-pipes", [13, 3], terminal)
    bad("terminal-wrong-type", [13, 3], False)
    for stream in range(3):
        bad(f"stream-{stream}-bad-access", [13, stream, 1], 3)
        bad(f"stream-{stream}-wrong-access-type", [13, stream, 1], "0")
        bad(f"stream-{stream}-direction", [13, stream, 1], 1 if stream == 0 else 0)
        bad(f"stream-{stream}-flags-overflow", [13, stream, 2], 16)
        bad(f"stream-{stream}-flags-wrong-type", [13, stream, 2], False)
        bad(f"stream-{stream}-kind-unknown", [13, stream, 0, 0], 9)
        bad(f"stream-{stream}-binding-missing", [13, stream, 0, 1], None)
    bad("root-stdin-layout-mismatch", [6, 1], b"\x77" * 16)
    bad("root-input-null-with-binding", [6, 0], 0)
    for name, path in (("command", [1, 0]), ("directory", [3, 0]),
                       ("frontend", [9, 5, 0]), ("stream", [13, 1, 0, 2])):
        for suffix, value in (("relative", b"synthetic/relative"), ("empty", b""),
                              ("nul", b"/synthetic/\x00path"), ("text", "/synthetic/path")):
            bad(f"{name}-path-{suffix}", path, value)
    for path, name in (([1, 2], "command"), ([9, 5, 2], "frontend")):
        bad(f"{name}-hash-short", path, b"\x01" * 31)
        bad(f"{name}-hash-long", path, b"\x01" * 33)
    bad("argv-empty", [2], [])
    bad("argv-nul", [2, 1], b"\x00")
    bad("argv-text-item", [2, 0], "command")
    for name, value in (("empty", b""), ("equals", b"A=B"), ("nul", b"A\x00B"), ("text", "HOME")):
        bad(f"environment-name-{name}", [5, 0, 0], value)
    bad("environment-value-nul", [5, 2, 1], b"value\x00")
    bad("environment-value-text", [5, 2, 1], "value")
    bad("environment-source-unknown", [5, 2, 2], 2)
    bad("environment-duplicate-name", [5, 1, 0], b"HOME")
    bad("environment-unsorted", [5], list(reversed(base[5])))
    for key, size in ((0, 16), (1, 32), (2, 16)):
        bad(f"submission-{key}-short", [12, key], b"\x01" * (size - 1))
    bad("nonminimal-schema", [0], Raw(b"\x18\x04"))
    bad("noncanonical-root-order", root=Raw(head(5, len(base)) + b"".join(
        encode(key) + encode(base[key]) for key in reversed(base))))
    pairs = [(0, 4), (0, 4), *[(key, value) for key, value in base.items() if key != 0]]
    bad("duplicate-root-key", root=Raw(head(5, len(pairs)) + b"".join(encode(k) + encode(v) for k, v in pairs)))
    bad("trailing-byte", root=Raw(encode(base) + b"\x00"))
    bad("truncated-capture", root=Raw(encode(base)[:-1]))
    bad("indefinite-root-map", root=Raw(b"\xbf" + encode(base)[1:] + b"\xff"))
    bad("invalid-utf8-profile", [9, 0], Raw(b"\x61\xff"))
    for label, overrides in (("bytes", {"maxBytes": len(encode(base)) - 1}),
                             ("depth", {"maxDepth": 3}), ("items", {"maxItems": 32})):
        bad(f"budget-{label}", root=base, limits=LIMITS | overrides)

    def mutation(name, path, value, valid_capture=True, *, sync=False):
        capture = synced_input(base, path, value) if sync else changed(base, path, value)
        assert encode(capture) != encode(base), name
        mutations.append(wire_row(name, capture, base="schema4-base", field=name,
                                   captureSHA256=hashlib.sha256(encode(capture)).hexdigest(),
                                   validCapture=valid_capture))

    mutation("requester.profile", [9, 0], PROFILE + "-unknown", False)
    mutation("requester.pid", [9, 1], 1235)
    mutation("requester.processBinding", [9, 2], b"\x12" * 16)
    mutation("requester.monitorIncarnation", [9, 3], b"\x23" * 16)
    mutation("requester.execEpoch", [9, 4], 2)
    for suffix, path, value in (("path", [0], b"/synthetic/bin/other-frontend"),
                                ("device", [1, 0], 2), ("inode", [1, 1], 301),
                                ("sha256", [2], b"\x44" * 32)):
        mutation(f"requester.executable.{suffix}", [9, 5, *path], value)
    for key, label in enumerate(("realUID", "effectiveUID", "savedUID", "filesystemUID",
                                  "realGID", "effectiveGID", "savedGID", "filesystemGID")):
        mutation(f"requester.credentials.{label}", [9, 6, key], base[9][6][key] + 1, False)
    mutation("requester.credentials.supplementaryGroups", [9, 6, 8], [10, 2001])
    mutation("requester.sessionID", [9, 7], 4322)
    mutation("requester.codePolicyDigest", [9, 8], b"\x34" * 32)
    for stream, label in enumerate(("stdin", "stdout", "stderr")):
        for field, tail, value in (("kind", [0], 8), ("binding", [1], b"\x55" * 16),
                                    ("path", [2], b"/synthetic/mutated-stream"),
                                    ("identity", [3], None), ("device", [3, 0], 3),
                                    ("inode", [3, 1], 999)):
            mutation(f"layout.{label}.source.{field}", tail if stream == 0 else [13, stream, 0, *tail],
                     value, sync=stream == 0)
        mutation(f"layout.{label}.access", [13, stream, 1], 2 if stream != 2 else 1)
        mutation(f"layout.{label}.flags", [13, stream, 2], 15)
    mutation("layout.terminal", [13, 3], terminal, False)
    mutation("layout.ptyMask", [13, 4], 1, False)
    # The repeated root input and layout observation are independently signed;
    # an inconsistent mutation changes the digest even though admission rejects it.
    for key, label, value in ((0, "kind", 8), (1, "binding", b"\x66" * 16),
                              (2, "path", b"/synthetic/root-input"), (3, "identity", None)):
        mutation(f"rootInput.{label}", [6, key], value, False)

    names = [row["name"] for rows in (valid, invalid, mutations) for row in rows]
    assert len(names) == len(set(names)), "duplicate vector names"
    return {
        "schemaVersion": 4,
        "contract": {"kind": 0, "wireVersion": 1, "schemaVersion": 4, "requiredFeatures": []},
        "approval": "https://github.com/rock3r/remozio/issues/441#issuecomment-6253309933",
        "scope": "Synthetic codec fixtures only; no real caller, host attestation, TPM, phone or production issuance.",
        "generator": "scripts/generate-linux-capture-fixtures.py",
        "defaultLimits": LIMITS,
        "fieldDescriptions": {
            "hex": "Exact capture CBOR bytes, expected inner and selected schema 4 unless a test deliberately chooses another contract.",
            "execEpoch": "Unsigned UInt64 in decimal STRING form to avoid JSON signed/floating-point loss.",
            "arguments/environmentNames/*Path/processBinding/monitorIncarnation/codePolicyDigest": "Lowercase hex of original raw bytes; no normalization.",
            "credentialUIDs/credentialGIDs": "Four UInt32 roles in real/effective/saved/filesystem order. UID need not equal GID.",
            "sessionID": "Positive Int32-bounded UInt32 or explicit null.",
            "streamKinds/streamAccess/streamFlags": "Three integer wire tags/masks in stdin/stdout/stderr order.",
            "captureSHA256": "SHA256 of exact capture bytes, equal to issued request captureDigest.",
            "invalid.limits": "Override defaultLimits for this refusal control; budget cases contain otherwise valid base bytes.",
            "digestMutations": "Each row references base by name; hash exact raw bytes even when validCapture=false. Invalid mutations of fixed profile/credential roles/terminal/mask are never accepted captures.",
        },
        "valid": valid, "invalid": invalid, "digestMutations": mutations,
        "contractBindings": [
            {"name": "matching-linux-contract", "capture": "schema4-base", "outerSchema": 4, "selectedSchema": 4, "accepted": True},
            {"name": "outer-schema-mismatch", "capture": "schema4-base", "outerSchema": 3, "selectedSchema": 4, "accepted": False},
            {"name": "selected-schema-mismatch", "capture": "schema4-base", "outerSchema": 4, "selectedSchema": 3, "accepted": False},
            {"name": "outer-selected-legacy-inner-linux", "capture": "schema4-base", "outerSchema": 3, "selectedSchema": 3, "accepted": False},
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify committed output without writing")
    args = parser.parse_args()
    corpus = generate()
    rendered = json.dumps(corpus, indent=2, ensure_ascii=True) + "\n"
    if args.check:
        if OUTPUT.read_text() != rendered:
            raise SystemExit("Schema-4 fixture output is stale; rerun the generator.")
    else:
        OUTPUT.write_text(rendered)
    print("Schema-4 fixtures: " + ", ".join(f"{len(corpus[key])} {key}" for key in ("valid", "invalid", "digestMutations")))


if __name__ == "__main__":
    main()
