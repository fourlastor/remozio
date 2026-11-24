import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Covers the store-owned caches of pure installed-epoch validation, completion intent decode and retained publication decode.
/// It proves only reuse for exact inputs; native ownership and current database checks stay with their own tests.
final class PreparationPureValidationCacheTests: XCTestCase {
    private typealias Values = PreparationImmutableValueCache<Data>
    private struct Failure: Error, Equatable { let value: Int }

    func testTheValueCacheReusesOnlyTheExactKeyBytes() throws {
        let cache = Values(), key = PreparationImmutableValidationCache.key(domain: "test", [Data([1, 2])])
        var runs = 0
        XCTAssertEqual(cache.value(key: key) { runs += 1; return Data([9]) }, Data([9]))
        XCTAssertEqual(cache.value(key: key) { runs += 1; return Data([8]) }, Data([9]))
        XCTAssertEqual(runs, 1)
        var changed = key
        changed[changed.index(before: changed.endIndex)] ^= 1
        XCTAssertEqual(cache.value(key: changed) { runs += 1; return Data([7]) }, Data([7]))
        XCTAssertEqual(runs, 2)
        cache.clear()
        XCTAssertFalse(cache.contains(key) || cache.contains(changed))
    }

    func testTheValueCacheNeverStoresAFailure() {
        let cache = Values(), key = PreparationImmutableValidationCache.key(domain: "test", [Data([3])])
        var runs = 0
        for _ in 0..<2 {
            XCTAssertThrowsError(try cache.value(key: key) { runs += 1; throw Failure(value: 4) }) {
                XCTAssertEqual($0 as? Failure, Failure(value: 4))
            }
            XCTAssertFalse(cache.contains(key))
        }
        XCTAssertEqual(runs, 2)
    }

    func testTheValueCacheStaysBoundedAndRefusesOversizedKeys() {
        let cache = Values(capacity: 2, maximumBytes: 64)
        let keys = (0..<3).map { PreparationImmutableValidationCache.key(domain: "k", [Data([UInt8($0)])]) }
        for key in keys.prefix(2) { _ = cache.value(key: key) { key } }
        XCTAssertTrue(cache.contains(keys[0]) && cache.contains(keys[1]))
        _ = cache.value(key: keys[2]) { keys[2] }
        XCTAssertFalse(cache.contains(keys[0]) || cache.contains(keys[1]))
        XCTAssertTrue(cache.contains(keys[2]))
        let large = Data(repeating: 7, count: 65)
        _ = cache.value(key: large) { large }
        XCTAssertFalse(cache.contains(large))
    }

    func testTwoStoresNeverShareTheNewEntries() {
        let first = PreparationEpochDecodeCaches.unshared(), second = PreparationEpochDecodeCaches.unshared()
        let key = PreparationImmutableValidationCache.key(domain: "test", [Data([5])])
        first.installedValidations.insert(key)
        XCTAssertFalse(second.installedValidations.contains(key))
        XCTAssertFalse(first.installedCompletionIntents === second.installedCompletionIntents)
        XCTAssertFalse(first.completionPublications === second.completionPublications)
    }

    func testTheCandidateKeyChangesWithEveryCandidateField() throws {
        let app = try ReleaseComponent(role: .app, identifier: "com.example.remozio", generation: 1,
            relativePath: "Contents/MacOS/Remozio", codeDirectoryHash: nil, build: "4", teamID: nil, formats: [])
        let manifest = try ReleaseManifest(release: "0.1.0", build: "4", components: [app])
        let hash = Data(repeating: 1, count: 20)
        let base = SignedReleaseEvidence(manifest: manifest, codeDirectoryHashes: [.app: hash])
        let key = try PreparationEpochDecodeCaches.candidateKey(base)
        XCTAssertEqual(try PreparationEpochDecodeCaches.candidateKey(
            SignedReleaseEvidence(manifest: manifest, codeDirectoryHashes: [.app: hash])), key)
        var changedHash = hash; changedHash[19] ^= 1
        let otherManifest = try ReleaseManifest(release: "0.1.0", build: "5", components: [app])
        for other in [SignedReleaseEvidence(manifest: manifest, codeDirectoryHashes: [.app: changedHash]),
                      SignedReleaseEvidence(manifest: manifest, codeDirectoryHashes: [:]),
                      SignedReleaseEvidence(manifest: otherManifest, codeDirectoryHashes: [.app: hash]),
                      SignedReleaseEvidence(manifest: manifest, codeDirectoryHashes: [.app: hash],
                          dependencyCodeDirectoryHashes: ["Contents/Frameworks/A": hash])] {
            XCTAssertNotEqual(try PreparationEpochDecodeCaches.candidateKey(other), key)
        }
    }

    func testInstalledValidationReusesOnlyTheExactArchiveAndCandidate() throws {
        try MachineUpdateReplacementTests.withRetainedRuntimeCompatibilityFixture { f in
            try f.inject()
            let installed = try f.capture().runtime.setup.source.actual.installed
            let header = try installed.record.encoded, rows = installed.artifacts
            let caches = PreparationEpochDecodeCaches.unshared()
            let archive = try MachineUpdateInstalledReleaseEpoch.Archive.decode(record: header, artifacts: rows,
                candidate: f.candidate, caches: caches)
            let key = try XCTUnwrap(archive.validationKey(recordBytes: header, candidate: f.candidate))
            XCTAssertTrue(caches.installedValidations.contains(key))
            try archive.validate(candidate: f.candidate)
            let again = try MachineUpdateInstalledReleaseEpoch.Archive.decode(record: header, artifacts: rows,
                candidate: f.candidate, caches: caches)
            XCTAssertEqual(again.validationKey(recordBytes: header, candidate: f.candidate), key)

            // A different candidate has a different key, is refused by every check and is never remembered.
            var hashes = f.candidate.codeDirectoryHashes
            let role = try XCTUnwrap(hashes.keys.sorted { $0.rawValue < $1.rawValue }.first)
            var flipped = try XCTUnwrap(hashes[role]); flipped[flipped.startIndex] ^= 1; hashes[role] = flipped
            let other = SignedReleaseEvidence(manifest: f.candidate.manifest, codeDirectoryHashes: hashes,
                dependencyCodeDirectoryHashes: f.candidate.dependencyCodeDirectoryHashes)
            let otherKey = try XCTUnwrap(archive.validationKey(recordBytes: header, candidate: other))
            XCTAssertNotEqual(otherKey, key)
            var errors: [PreparationStoreError?] = []
            for _ in 0..<2 {
                XCTAssertThrowsError(try archive.validate(candidate: other)) { errors.append($0 as? PreparationStoreError) }
                XCTAssertFalse(caches.installedValidations.contains(otherKey))
            }
            XCTAssertEqual(errors.count, 2)
            XCTAssertNotNil(errors[0])
            XCTAssertEqual(errors[0], errors[1])

            // One changed artifact byte is refused on every read and never reuses the remembered success.
            let index = try XCTUnwrap(rows.firstIndex { $0.kind == 4 })
            var changed = rows, bytes = rows[index].bytes
            bytes[bytes.index(before: bytes.endIndex)] ^= 1
            changed[index] = .init(kind: rows[index].kind, accountID: rows[index].accountID, bytes: bytes)
            for _ in 0..<2 {
                XCTAssertThrowsError(try MachineUpdateInstalledReleaseEpoch.Archive.decode(record: header, artifacts: changed,
                    candidate: f.candidate, caches: caches)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                }
            }
            XCTAssertTrue(caches.installedValidations.contains(key))
        }
    }

    func testInstalledCompletionIntentReusesTheExactRowsOnly() throws {
        try MachineUpdateReplacementTests.withRetainedRuntimeCompatibilityFixture { f in
            try f.inject()
            let installed = try f.capture().runtime.setup.source.actual.installed
            let caches = PreparationEpochDecodeCaches.unshared()
            let archive = try MachineUpdateInstalledReleaseEpoch.Archive.decode(record: installed.record.encoded,
                artifacts: installed.artifacts, candidate: f.candidate, caches: caches)
            let first = try archive.completionIntent(), second = try archive.completionIntent()
            XCTAssertEqual(first, second)
            XCTAssertEqual(first, try installed.completionIntent())
            let header = try archive.artifact(4)
            let key = PreparationImmutableValidationCache.key(domain: "remozio.installed-release-epoch.completion-intent.v1",
                [header] + archive.artifacts.filter { $0.kind == 300 }.flatMap { [$0.accountID, $0.bytes] })
            XCTAssertTrue(caches.installedCompletionIntents.contains(key))
            var changed = header; changed[changed.index(before: changed.endIndex)] ^= 1
            XCTAssertFalse(caches.installedCompletionIntents.contains(PreparationImmutableValidationCache.key(
                domain: "remozio.installed-release-epoch.completion-intent.v1",
                [changed] + archive.artifacts.filter { $0.kind == 300 }.flatMap { [$0.accountID, $0.bytes] })))
        }
    }

    func testPromotionPublicationDecodeIsSharedOnlyForExactBytesAndNeverForAFailure() throws {
        let f = try RetainedSetupPromotionArchiveTests.Fixture()
        let caches = PreparationEpochDecodeCaches.unshared(), envelope = try f.envelope()
        let key = PreparationImmutableValidationCache.key(domain: "remozio.retained-setup-completion-publication.decode.v1", [envelope])
        let record = try MachineUpdateRetainedSetupPromotionIntentRecord.decode(f.record(), caches: caches)
        XCTAssertTrue(caches.completionPublications.contains(key))
        XCTAssertEqual(try record.publication().encoded, envelope)
        XCTAssertEqual(try MachineUpdateRetainedSetupPromotionIntentRecord.decode(f.record(), caches: caches), record)
        XCTAssertEqual(try MachineUpdateRetainedSetupPromotionIntentRecord.decode(f.record()), record)

        // One changed publication byte is refused on every read and leaves no entry.
        var bad = envelope; bad[bad.index(before: bad.endIndex)] ^= 1
        var fields = f.recordFields; fields[5] = .bytes(bad)
        let badKey = PreparationImmutableValidationCache.key(domain: "remozio.retained-setup-completion-publication.decode.v1", [bad])
        for _ in 0..<2 {
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionIntentRecord.decode(f.record(fields), caches: caches)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
            XCTAssertFalse(caches.completionPublications.contains(badKey))
        }
        XCTAssertTrue(caches.completionPublications.contains(key))
    }
}
