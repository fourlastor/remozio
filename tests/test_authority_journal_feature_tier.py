"""Keep authority-journal version access in the resolver."""
from pathlib import Path
import re
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "macos" / "core" / "Sources" / "RemozioCore"
INDEPENDENT_STORES = {
    "ContinuityStore.swift",
    "GatewayDatabase.swift",
    "MachineUpdateRetainedSetupPromotionCatalog.swift",
    "PreparationIntentStore.swift",
    "SharedSetupImportJournal.swift",
}
VERSION_SQL = re.compile(
    r'\b(PRAGMA\s+(?:(?:"main"|main)\s*\.\s*)?(?:"user_version"|user_version\b)|pragma_user_version\b)',
    re.IGNORECASE,
)
LEGACY_TIER_API = re.compile(r"\b(storageSchemaVersion|submissionSchemaVersion)\b")
COMPATIBILITY_ACCESSOR = "public var storageSchemaVersion: UInt64 { get throws { try storageFormatVersion } }"


def bypasses_resolver(filename, source):
    if filename in INDEPENDENT_STORES or filename == "AuthorityJournalSchema.swift":
        return []
    if filename == "JournalDatabase.swift":
        source = source.replace(COMPATIBILITY_ACCESSOR, "", 1)
    return [match.group() for pattern in (VERSION_SQL, LEGACY_TIER_API) for match in pattern.finditer(source)]


class AuthorityJournalFeatureTierGuardTest(unittest.TestCase):
    def test_authority_journal_has_no_direct_version_access(self):
        violations = {
            path.name: matches
            for path in sorted(SOURCE.glob("*.swift"))
            if (matches := bypasses_resolver(path.name, path.read_text()))
        }
        self.assertFalse(violations, violations)

    def test_guard_catches_multiline_sql_and_legacy_comparison_variants(self):
        for expression in (
            'PRAGMA \n main.user_version = 18',
            'pragma main . "user_version"(18)',
            'SELECT user_version FROM pragma_user_version',
            "18 == tx.storageSchemaVersion",
            "try submissionSchemaVersion() >= 16",
            "guard (16...18).contains(try submissionSchemaVersion()) else { return }",
        ):
            with self.subTest(expression=expression):
                self.assertTrue(bypasses_resolver("GatewayAuthorityJournal.swift", expression))

    def test_guard_allows_resolver_independent_stores_and_physical_evidence(self):
        for filename in INDEPENDENT_STORES | {"AuthorityJournalSchema.swift"}:
            with self.subTest(filename=filename):
                self.assertFalse(bypasses_resolver(filename, "PRAGMA main.user_version=18"))
        self.assertFalse(bypasses_resolver("JournalDatabase.swift", COMPATIBILITY_ACCESSOR))
        self.assertFalse(bypasses_resolver("AuthorityJournalCutoverInspection.swift",
            "guard try transaction.storageFormatVersion == snapshot.schemaVersion else { return }"))
