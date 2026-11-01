import Darwin
import Foundation
import RemozioUIAdapters

let usage = "Usage: remozio-ax-structure --pid PID --output /absolute/existing-folder/fixture.json\n"
let arguments = Array(CommandLine.arguments.dropFirst())
if arguments == ["--help"] {
    FileHandle.standardOutput.write(Data(usage.utf8))
    exit(0)
}
do {
    let request = try AXStructureProbeRequest(arguments: arguments)
    guard getuid() > 0, getuid() == geteuid() else { throw AXStructureProbeError.ordinaryUserRequired }
    let snapshot = try NativeAXStructureRecorder.capture(processID: request.processID)
    try AXStructureFixtureFile.save(snapshot, request: request)
    let result = "STRUCTURE_CAPTURE_SAVED nodes=\(snapshot.nodes.count) stop=\(snapshot.stop.rawValue)\n"
    FileHandle.standardOutput.write(Data(result.utf8))
} catch let error as AXStructureProbeError {
    FileHandle.standardError.write(Data(("Capture failed: " + error.rawValue + "\n").utf8))
    if error == .invalidArguments { FileHandle.standardError.write(Data(usage.utf8)) }
    exit(1)
} catch let error as AXStructureFailure {
    FileHandle.standardError.write(Data(("Capture failed: " + error.rawValue + "\n").utf8))
    exit(1)
} catch {
    FileHandle.standardError.write(Data("Capture failed: unavailable\n".utf8))
    exit(1)
}
