"""Aggregate an xctrace System Trace syscall export: total duration and count per syscall name."""
import collections, sys, xml.etree.ElementTree as ET
try:
    root = ET.parse(sys.argv[1]).getroot()
except Exception as error:
    print("no syscall table:", error); sys.exit(0)
ids = {el.attrib["id"]: el for el in root.iter() if "id" in el.attrib}
def deref(el): return ids.get(el.attrib["ref"], el) if el is not None and "ref" in el.attrib else el
schema = root.find(".//schema")
cols = [c.findtext("mnemonic") for c in schema.findall("col")] if schema is not None else []
print("-- syscall columns:", cols)
dur, cnt = collections.Counter(), collections.Counter()
for row in root.iter("row"):
    kids = [deref(k) for k in row]
    name, d = "?", 0
    for col, k in zip(cols, kids):
        if k is None: continue
        if col in ("syscall", "name", "formatted-label") and name == "?": name = k.attrib.get("fmt", k.text or "?")
        if col == "duration" and k.text: d = int(k.text)
    dur[name] += d; cnt[name] += 1
print(f"-- syscalls by total duration (all threads), total {sum(dur.values())/1e9:.2f} s")
for name, d in dur.most_common(25): print(f"{d/1e9:8.3f} s {cnt[name]:7d}x {name}")
