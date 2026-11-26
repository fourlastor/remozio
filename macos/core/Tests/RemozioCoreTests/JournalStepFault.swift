import Foundation
import SQLite3

/// A one-shot result injected at a named statement on this fixture's connection.
final class JournalStepFault {
    private struct Fault {
        let sqlFragment: String
        let code: Int32
        var precedingSteps: Int
    }

    private var pending: Fault?

    func arm(_ sqlFragment: String, code: Int32, after precedingSteps: Int = 0) {
        pending = Fault(sqlFragment: sqlFragment, code: code, precedingSteps: precedingSteps)
    }

    func step(_ statement: OpaquePointer) -> Int32 {
        guard var fault = pending, let sql = sqlite3_sql(statement),
              String(cString: sql).contains(fault.sqlFragment) else { return sqlite3_step(statement) }
        if fault.precedingSteps == 0 {
            pending = nil
            return fault.code
        }
        fault.precedingSteps -= 1
        pending = fault
        return sqlite3_step(statement)
    }
}
