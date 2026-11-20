"""Summarize an xctrace time-profile export: CPU per thread, top self and inclusive frames, test frames."""
import collections, re, sys, xml.etree.ElementTree as ET

xml_path, log_path = sys.argv[1], sys.argv[2]
log = open(log_path, errors="replace").read()
for line in log.splitlines():
    if re.search(r"Test Case .* (passed|failed)|real|maximum resident|Executed", line):
        print("log:", line.strip())
try:
    root = ET.parse(xml_path).getroot()
except Exception as error:
    print("no trace:", error); sys.exit(0)
ids = {}
for el in root.iter():
    if "id" in el.attrib:
        ids[el.attrib["id"]] = el
def deref(el):
    return ids.get(el.attrib["ref"], el) if el is not None and "ref" in el.attrib else el
self_ns, incl_ns, thread_ns, test_ns = collections.Counter(), collections.Counter(), collections.Counter(), collections.Counter()
total = 0
for row in root.iter("row"):
    weight = deref(row.find("weight"))
    w = int(weight.text) if weight is not None and weight.text else 1_000_000
    total += w
    thread = deref(row.find("thread"))
    thread_ns[thread.attrib.get("fmt", "?") if thread is not None else "?"] += w
    bt = deref(row.find("backtrace"))
    if bt is None:
        continue
    names = []
    for fr in bt.findall("frame"):
        fr = deref(fr)
        names.append(fr.attrib.get("name", "?"))
    if names:
        self_ns[names[0]] += w
    for name in set(names):
        incl_ns[name] += w
    for name in names:
        if "Tests" in name and ("test" in name or "with" in name or "Fixture" in name):
            test_ns[name] += w
print(f"sampled CPU total: {total/1e9:.2f} s")
print("-- threads"); [print(f"{v/1e9:7.2f} s {k[:100]}") for k, v in thread_ns.most_common(8)]
print("-- self"); [print(f"{v/1e9:7.2f} s {k[:160]}") for k, v in self_ns.most_common(40)]
print("-- inclusive"); [print(f"{v/1e9:7.2f} s {k[:160]}") for k, v in incl_ns.most_common(80)]
print("-- test/fixture frames"); [print(f"{v/1e9:7.2f} s {k[:160]}") for k, v in test_ns.most_common(40)]
