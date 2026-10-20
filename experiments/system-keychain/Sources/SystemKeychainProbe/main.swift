import Darwin
import Foundation

let report: Report
var exitCode: Int32 = 0
var attempted = false

do {
    let operation = try Operation.parse(Array(CommandLine.arguments.dropFirst()))
    switch operation { case .plan: break; default: attempted = true }
    report = try Controller(backend: SystemKeychain(), uid: getuid(), effectiveUID: geteuid()).run(operation)
} catch {
    report = Report.failure(error, requested: attempted, uid: geteuid()); exitCode = 77
}
let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
if let bytes = try? encoder.encode(report) { FileHandle.standardOutput.write(bytes); FileHandle.standardOutput.write(Data([10])) }
else { exitCode = 70 }
exit(exitCode)
