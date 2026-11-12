import CryptoKit
import Foundation
import SQLite3

/// Pins the actual catalog in a transaction. This reader grants no migration or writer authority.
enum MachineUpdateRetainedSetupPromotionCatalog {
    struct Frame: Equatable {
        let schemaVersion: Int64
        let protectedDigest: Data
        let promotionDigest: Data?

        func requireSame(as expected: Self) throws {
            guard self == expected else { throw PreparationStoreError.staleRevision }
        }
        func requireRetention(from expected: Self) throws {
            if expected.schemaVersion == 26 {
                guard schemaVersion == 27, protectedDigest == expected.protectedDigest,
                      expected.promotionDigest == nil, promotionDigest != nil else { throw PreparationStoreError.staleRevision }
            } else { try requireSame(as: expected) }
        }
    }

    static func capture(_ db: OpaquePointer) throws -> Frame {
        guard sqlite3_get_autocommit(db) == 0 else { throw PreparationStoreError.transactionActive }
        func statement<Value>(_ sql: String, _ body: (OpaquePointer) throws -> Value) throws -> Value {
            var row: OpaquePointer?
            let result = sqlite3_prepare_v2(db, sql, -1, &row, nil)
            guard result == SQLITE_OK, let row else { throw PreparationStoreError.storage(result) }
            defer { sqlite3_finalize(row) }
            return try body(row)
        }
        func step(_ row: OpaquePointer) throws -> Int32 {
            let result = sqlite3_step(row)
            guard result == SQLITE_ROW || result == SQLITE_DONE else { throw PreparationStoreError.storage(result) }
            return result
        }
        func number(_ value: UInt64) -> Data {
            var value = value.bigEndian
            return withUnsafeBytes(of: &value) { Data($0) }
        }
        func text(_ row: OpaquePointer, _ column: Int32) throws -> Data {
            let count = Int(sqlite3_column_bytes(row, column))
            guard sqlite3_column_type(row, column) == SQLITE_TEXT, (1...8192).contains(count),
                  let bytes = sqlite3_column_blob(row, column) else { throw PreparationStoreError.corruptRecord }
            let value = Data(bytes: bytes, count: count)
            guard String(data: value, encoding: .utf8) != nil else { throw PreparationStoreError.corruptRecord }
            return value
        }
        let schema: Int64 = try statement("PRAGMA user_version") { row in
            guard try step(row) == SQLITE_ROW, sqlite3_column_type(row, 0) == SQLITE_INTEGER else {
                throw PreparationStoreError.corruptRecord
            }
            let value = sqlite3_column_int64(row, 0)
            guard [Int64(26), 27, 28].contains(value), try step(row) == SQLITE_DONE else {
                throw PreparationStoreError.incompatibleStore
            }
            return value
        }
        let table = MachineUpdateRetainedSetupPromotionStorage.tableName
        let index = "sqlite_autoindex_" + table + "_1"
        var promotion = SHA256()
        let rows: [Data] = try statement("SELECT type,name,tbl_name,rootpage,sql FROM sqlite_schema ORDER BY type,name") { row in
            var rows: [Data] = [], excluded = Set<Data>(), count = 0
            while try step(row) == SQLITE_ROW {
                count += 1
                guard count <= 128, sqlite3_column_type(row, 3) == SQLITE_INTEGER else {
                    throw PreparationStoreError.corruptRecord
                }
                let type = try text(row, 0), name = try text(row, 1), owner = try text(row, 2)
                let page = sqlite3_column_int64(row, 3)
                let sql = sqlite3_column_type(row, 4) == SQLITE_NULL ? nil : try text(row, 4)
                guard page >= 0 else { throw PreparationStoreError.corruptRecord }
                var hash = SHA256()
                for value in [type, name, owner] { hash.update(data: number(UInt64(value.count))); hash.update(data: value) }
                hash.update(data: number(UInt64(page)))
                hash.update(data: Data([sql == nil ? 0 : 1]))
                if let sql { hash.update(data: number(UInt64(sql.count))); hash.update(data: sql) }
                let digest = Data(hash.finalize())
                if name == Data(table.utf8) || name == Data(index.utf8) {
                    guard schema >= 27, owner == Data(table.utf8), page > 0, excluded.insert(name).inserted else {
                        throw PreparationStoreError.incompatibleStore
                    }
                    if name == Data(table.utf8) {
                        guard type == Data("table".utf8), sql == Data(MachineUpdateRetainedSetupPromotionStorage.createSQL.utf8) else {
                            throw PreparationStoreError.incompatibleStore
                        }
                    } else {
                        guard type == Data("index".utf8), sql == nil else { throw PreparationStoreError.incompatibleStore }
                    }
                    promotion.update(data: digest)
                    continue
                }
                rows.append(digest)
            }
            let expected: Set<Data> = schema == 26 ? [] : Set([Data(table.utf8), Data(index.utf8)])
            guard excluded == expected else { throw PreparationStoreError.incompatibleStore }
            return rows
        }
        var hash = SHA256()
        hash.update(data: Data("Remozio/RetainedSetupPromotionProtectedCatalog/v1\0".utf8))
        hash.update(data: number(UInt64(schema == 26 ? 27 : schema)))
        hash.update(data: number(UInt64(rows.count)))
        for row in rows { hash.update(data: row) }
        guard sqlite3_get_autocommit(db) == 0 else { throw PreparationStoreError.transactionActive }
        return Frame(schemaVersion: schema, protectedDigest: Data(hash.finalize()),
            promotionDigest: schema == 26 ? nil : Data(promotion.finalize()))
    }
}
