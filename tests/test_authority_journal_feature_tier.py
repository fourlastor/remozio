"""Keep authority-journal version access in the resolver."""
from pathlib import Path
import re
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "macos" / "core" / "Sources" / "RemozioCore"
INDEPENDENT_STORES = {
    "ContinuityStore.swift",
    "GatewayDatabase.swift",
    "PreparationIntentStore.swift",
}
INDEPENDENT_READS_AND_WRITES = {
    "MachineUpdateRetainedSetupPromotionCatalog.swift": (
        'let schema: Int64 = try statement("PRAGMA user_version") { row in',
    ),
    "SharedSetupImportJournal.swift": (
        'guard try scalar("SELECT COUNT(*) FROM sqlite_master") == 0, try scalar("PRAGMA user_version") == 0,',
        r'try exec("PRAGMA application_id=\(Self.applicationID)"); try exec("PRAGMA user_version=2")',
        'guard try scalar("PRAGMA application_id") == Self.applicationID, try scalar("PRAGMA user_version") == 2,',
    ),
}
SWIFT_LITERAL_JOIN = re.compile(r'"{1,3}#*\s*\+\s*#*"{1,3}')
SQL_SCHEMA = r"""(?:\w+|'[^']+'|"[^"]+"|\[[^\]]+\]|`[^`]+`|\\#*\([^)\n]+\))"""
VERSION_SQL = re.compile(
    rf"""\b(PRAGMA\s+(?:{SQL_SCHEMA}\s*\.\s*)?['"`\[]?user_version\b|pragma_user_version\b)""",
    re.IGNORECASE,
)
TIER_STORAGE = re.compile(r"\bauthority_feature_tier_v1\b", re.IGNORECASE)
LEGACY_TIER_API = re.compile(r"\b(?:storageSchemaVersion\b|submissionSchemaVersion\s*(?=\())")
PHYSICAL_ACCESSOR = re.compile(r"\bstorageFormatVersion\b")
PHYSICAL_READER = re.compile(r"\b(?:AuthorityJournalSchema\s*\.\s*formatVersion\b|formatVersion\s*\(\s*on\s*:)")
COMPATIBILITY_ACCESSOR = "public var storageSchemaVersion: UInt64 { get throws { try storageFormatVersion } }"
PHYSICAL_ACCESSOR_IMPLEMENTATION = (
    COMPATIBILITY_ACCESSOR,
    "fileprivate func storageFormatVersion(_ token: UUID) throws -> UInt64 {",
    "var storageFormatVersion: UInt64 {",
    "do { return try owner.storageFormatVersion(token) }",
)


def omit_lines_once(source, allowed):
    remaining = set(allowed)
    lines = []
    for line in source.splitlines():
        exact = line.strip()
        if exact in remaining:
            remaining.remove(exact)
        else:
            lines.append(line)
    return "\n".join(lines)


def bypasses_resolver(filename, source):
    sql_source = omit_lines_once(source, INDEPENDENT_READS_AND_WRITES.get(filename, ()))
    sql_source = SWIFT_LITERAL_JOIN.sub("", sql_source).replace(r'\"', '"').replace(r"\n", " ").replace(r"\t", " ")
    violations = []
    if filename not in INDEPENDENT_STORES and filename != "AuthorityJournalSchema.swift":
        violations.extend(match.group() for match in VERSION_SQL.finditer(sql_source))
    if filename != "AuthorityJournalSchema.swift":
        violations.extend(match.group() for match in TIER_STORAGE.finditer(sql_source))
    if filename == "JournalDatabase.swift":
        source = omit_lines_once(source, PHYSICAL_ACCESSOR_IMPLEMENTATION)
    violations.extend(match.group() for match in LEGACY_TIER_API.finditer(source))
    if filename != "AuthorityJournalCutoverInspection.swift":
        violations.extend(match.group() for match in PHYSICAL_ACCESSOR.finditer(source))
    if filename not in {"AuthorityJournalSchema.swift", "JournalDatabase.swift"}:
        violations.extend(match.group() for match in PHYSICAL_READER.finditer(source))
    return violations


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
            "PRAGMA attached.'user_version'",
            r'PRAGMA \(schema).user_version',
            r'PRAGMA \"attached\" . \"user_version\"',
            'try exec("PRA" + "GMA aux.user_" + "version")',
            'try exec(#"PRAGMA "# +\n #"aux."# + #"user_version"#)',
            'SELECT user_version FROM pragma_user_version',
            'try exec("UPDATE main.authority_feature_tier_v1 SET tier=18")',
            "18 == tx.storageSchemaVersion",
            "try submissionSchemaVersion() >= 16",
            "guard (16...18).contains(try submissionSchemaVersion()) else { return }",
            "guard try tx.storageFormatVersion >= 16 else { return }",
            'let version = try AuthorityJournalSchema.formatVersion(on: db)',
        ):
            with self.subTest(expression=expression):
                self.assertTrue(bypasses_resolver("GatewayAuthorityJournal.swift", expression))

    def test_guard_allows_resolver_independent_stores_and_physical_evidence(self):
        for filename in INDEPENDENT_STORES | {"AuthorityJournalSchema.swift"}:
            with self.subTest(filename=filename):
                self.assertFalse(bypasses_resolver(filename, "PRAGMA main.user_version=18"))
        self.assertFalse(bypasses_resolver("AuthorityJournalSchema.swift",
            'try execute("UPDATE main.authority_feature_tier_v1 SET tier=18", on: db)'))
        for filename, lines in INDEPENDENT_READS_AND_WRITES.items():
            with self.subTest(filename=filename):
                self.assertFalse(bypasses_resolver(filename, "\n".join(lines)))
                self.assertTrue(bypasses_resolver(filename, "\n".join([*lines, lines[0]])))
                self.assertTrue(bypasses_resolver(filename, 'try exec("PRAGMA main.user_version=18")'))
        self.assertFalse(bypasses_resolver("JournalDatabase.swift", COMPATIBILITY_ACCESSOR))
        self.assertTrue(bypasses_resolver("JournalDatabase.swift", "try tx.storageFormatVersion >= 16"))
        self.assertFalse(bypasses_resolver("CommandAdmissionResult.swift", "let version = submissionSchemaVersion"))
        self.assertFalse(bypasses_resolver("AuthorityCodePolicy.swift", "let version = Self.formatVersion"))
        self.assertFalse(bypasses_resolver("AuthorityJournalCutoverInspection.swift",
            "guard try transaction.storageFormatVersion == snapshot.schemaVersion else { return }"))
