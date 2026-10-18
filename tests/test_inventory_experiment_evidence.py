import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("inventory_probe", REPO / "scripts/run-installation-inventory-experiment.py")
PROBE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PROBE)

class InventoryEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="remozio-evidence-inputs-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.patch = patch.object(PROBE, "REPO", self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        for name in PROBE.SOURCES:
            self.write(name, "fixed input")
        self.transitive = [
            "protocol/swift/Sources/RemozioProtocol/DeterministicCBOR.swift",
            "host/shared-core/Sources/RemozioHostCore/DecisionVerifier.swift",
            "macos/core/Sources/RemozioCore/ReleaseDestinationLease.swift",
            "macos/core/Sources/RemozioMach/include/RemozioMach.h",
            "macos/core/Sources/RemozioMach/channel.c",
        ]
        for name in self.transitive:
            self.write(name, "initial source")

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def testTransitiveCodecLeaseAndNativeHeaderChangesAlterEvidence(self):
        for name in self.transitive:
            with self.subTest(name=name):
                before = PROBE.hashes()
                self.write(name, "changed implementation")
                after = PROBE.hashes()
                self.assertIn(name, before)
                self.assertNotEqual(before[name], after[name])
                self.assertNotEqual(before, after)
                self.write(name, "initial source")

    def testPackageManifestsAndDependencyLocksAlterEvidence(self):
        inputs = [name for name in PROBE.SOURCES if name.endswith(("Package.swift", "Package.resolved"))]
        self.assertIn("macos/core/Package.swift", inputs)
        self.assertIn("protocol/swift/Package.swift", inputs)
        self.assertIn("macos/core/Package.resolved", inputs)
        self.assertIn("host/shared-core/Package.swift", inputs)
        self.assertIn("host/shared-core/Package.resolved", inputs)
        for name in inputs:
            with self.subTest(name=name):
                before = PROBE.hashes()
                self.write(name, "changed dependency input")
                self.assertNotEqual(before[name], PROBE.hashes()[name])
                self.write(name, "fixed input")

    def testAddedAndRemovedSourceFilesAlterEvidence(self):
        for name in ["protocol/swift/Sources/RemozioProtocol/nested/NewCodec.swift",
                     "host/shared-core/Sources/RemozioHostCore/nested/NewVerifier.swift"]:
            with self.subTest(name=name):
                before = PROBE.hashes()
                self.write(name, "new source")
                added = PROBE.hashes()
                self.assertIn(name, added)
                self.assertNotEqual(before, added)
                (self.root / name).unlink()
                self.assertEqual(before, PROBE.hashes())

if __name__ == "__main__":
    unittest.main()
