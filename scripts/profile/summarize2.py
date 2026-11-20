import collections, sys, re, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
ids = {el.attrib["id"]: el for el in root.iter() if "id" in el.attrib}
d = lambda el: ids.get(el.attrib["ref"], el) if el is not None and "ref" in el.attrib else el
def short(n):
    n = re.sub(r"\(.*", "", n)            # drop signature
    return n[:140]
selfc, incl, mod = collections.Counter(), collections.Counter(), collections.Counter()
total = 0
cats = collections.Counter()
CAT = [("sqlite", r"sqlite3|SQLite"), ("crypto/keys", r"Crypto|CryptoKit|SecKey|ccec|cc_|corecrypto|P256|Curve25519|SHA|HMAC|AES|ccsha|ccdigest|ccaes|ccrng"),
       ("cbor/codec", r"CBOR|Codable|JSONEncoder|JSONDecoder|PropertyList|decode|encode"),
       ("fs/syscalls", r"open\b|fsync|fcntl|__open|stat|getattrlist|mkdir|unlink|rename|write|read|close|fstat|clonefile|copyfile"),
       ("dyld/xctest", r"dyld|XCTest|ResultDataPublisher"), ("swift runtime", r"swift_|Swift"), ("malloc", r"malloc|free|_xzm")]
for row in root.iter("row"):
    w = d(row.find("weight")); w = int(w.text) if w is not None and w.text else 1_000_000
    tb = d(row.find("tagged-backtrace"))
    bt = d(tb.find("backtrace")) if tb is not None else None
    if bt is None: continue
    frames = [d(f) for f in bt.findall("frame")]
    names = [short(f.attrib.get("name", "?")) for f in frames]
    bins = []
    for f in frames:
        b = d(f.find("binary")); bins.append(b.attrib.get("name", "?") if b is not None else "?")
    total += w
    if names: selfc[names[0]] += w; mod[bins[0]] += w
    for n in set(names): incl[n] += w
    leaf = names[0] + " " + bins[0]
    for c, pat in CAT:
        if re.search(pat, leaf): cats[c] += w; break
    else: cats["other:" + bins[0]] += w
p = lambda c, k: [print(f"{v/1e9:6.2f} s {100*v/total:5.1f}%  {n}") for n, v in c.most_common(k)]
print(f"sampled CPU {total/1e9:.2f} s"); print("-- leaf binary"); p(mod, 12); print("-- leaf category"); p(cats, 14)
print("-- self"); p(selfc, 25)
print("-- inclusive (RemozioCore / tests)")
for n, v in incl.most_common(400):
    if re.search(r"Remozio|Test|Fixture|Store|Journal|Preparation|Machine|sqlite3_step|sqlite3_prepare|sqlite3_open|exec", n):
        print(f"{v/1e9:6.2f} s {100*v/total:5.1f}%  {n}")
